package jsruntime

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dop251/goja"
)

// Config bounds work performed by a Runtime. A zero CompileCacheEntries value
// disables the cache; all other limits must be positive.
type Config struct {
	MaxSourceBytes      int
	MaxInputBytes       int
	MaxOutputBytes      int
	MaxConcurrent       int
	ExecutionTimeout    time.Duration
	CompileCacheEntries int
}

// DefaultConfig returns conservative limits suitable for short MITM scripts.
func DefaultConfig() Config {
	return Config{
		MaxSourceBytes:      256 << 10,
		MaxInputBytes:       1 << 20,
		MaxOutputBytes:      1 << 20,
		MaxConcurrent:       32,
		ExecutionTimeout:    time.Second,
		CompileCacheEntries: 128,
	}
}

// CacheStats reports the current bounded compile cache size.
type CacheStats struct {
	Entries  int
	Capacity int
}

// Runtime compiles content-addressed scripts and executes each invocation in
// a fresh VM. Runtime is safe for concurrent use.
type Runtime struct {
	config         Config
	permits        atomic.Int64
	cache          programCache
	runtimeID      uint64
	closed         atomic.Bool
	closeOnce      sync.Once
	compileMu      sync.Mutex
	activeMu       sync.Mutex
	activeVMs      map[*goja.Runtime]struct{}
	activeSessions map[*Session]struct{}
}

var nextRuntimeID atomic.Uint64

// New creates a JavaScript runtime with the supplied resource limits.
func New(config Config) (*Runtime, error) {
	if config.MaxSourceBytes <= 0 || config.MaxInputBytes <= 0 || config.MaxOutputBytes <= 0 ||
		config.MaxConcurrent <= 0 || config.ExecutionTimeout <= 0 || config.CompileCacheEntries < 0 {
		return nil, fmt.Errorf("%w: byte limits, concurrency, and timeout must be positive; cache capacity cannot be negative", ErrInvalidConfig)
	}
	return &Runtime{
		config:    config,
		runtimeID: nextRuntimeID.Add(1),
		cache:     newProgramCache(config.CompileCacheEntries),
	}, nil
}

// Config returns the immutable limits used by this runtime.
func (r *Runtime) Config() Config {
	if r == nil {
		return Config{}
	}
	return r.config
}

// CacheStats reports the compile cache occupancy and configured capacity.
func (r *Runtime) CacheStats() CacheStats {
	if r == nil {
		return CacheStats{}
	}
	if r.closed.Load() {
		return CacheStats{Capacity: r.config.CompileCacheEntries}
	}
	return r.cache.stats()
}

// Compile returns a cached or newly compiled immutable program. Cache identity
// is derived from the complete source bytes, so changing a script always uses
// a new entry and cannot replace a different script by name.
func (r *Runtime) Compile(source string) (*CompiledScript, error) {
	if r == nil {
		return nil, newRuntimeError(KindCompile, errors.New("nil runtime"))
	}
	if r.closed.Load() {
		return nil, newRuntimeError(KindClosed, ErrClosed)
	}
	if len(source) > r.config.MaxSourceBytes {
		return nil, newRuntimeError(KindResourceLimit, fmt.Errorf("source is %d bytes; limit is %d", len(source), r.config.MaxSourceBytes))
	}
	key := sha256.Sum256([]byte(source))
	if compiled := r.cache.lookup(key); compiled != nil {
		if r.closed.Load() {
			return nil, newRuntimeError(KindClosed, ErrClosed)
		}
		return compiled, nil
	}

	r.compileMu.Lock()
	defer r.compileMu.Unlock()
	if r.closed.Load() {
		return nil, newRuntimeError(KindClosed, ErrClosed)
	}
	if compiled := r.cache.lookup(key); compiled != nil {
		if r.closed.Load() {
			return nil, newRuntimeError(KindClosed, ErrClosed)
		}
		return compiled, nil
	}
	program, err := guardPanic(KindCompile, func() (*goja.Program, error) {
		return goja.Compile(scriptName, source, false)
	})
	if err != nil {
		return nil, asRuntimeError(KindCompile, err)
	}
	if r.closed.Load() {
		return nil, newRuntimeError(KindClosed, ErrClosed)
	}
	compiled := &CompiledScript{
		program:    program,
		hash:       key,
		sourceSize: len(source),
		runtimeID:  r.runtimeID,
		engineID:   gojaEngineID,
	}
	if cached := r.cache.store(compiled, r.closed.Load); cached == nil {
		return nil, newRuntimeError(KindClosed, ErrClosed)
	} else {
		compiled = cached
	}
	if r.closed.Load() {
		return nil, newRuntimeError(KindClosed, ErrClosed)
	}
	return compiled, nil
}

// Close rejects new operations, interrupts executions that are active at the
// time of the call, and clears the compile cache. It does not wait for active
// calls to unwind or for an in-progress Goja compilation to finish. Goja
// compilation has no cancellation API; the source size limit bounds its input.
func (r *Runtime) Close() error {
	if r == nil {
		return nil
	}
	r.closeOnce.Do(func() {
		r.closed.Store(true)
		r.activeMu.Lock()
		active := make([]*goja.Runtime, 0, len(r.activeVMs))
		sessions := make([]*Session, 0, len(r.activeSessions))
		for vm := range r.activeVMs {
			active = append(active, vm)
		}
		for session := range r.activeSessions {
			sessions = append(sessions, session)
		}
		r.activeVMs = nil
		r.activeSessions = nil
		r.activeMu.Unlock()
		r.cache.clear()
		for _, session := range sessions {
			session.Close()
		}
		signal := &interruptSignal{kind: KindClosed, cause: ErrClosed}
		for _, vm := range active {
			interrupt(vm, signal)
		}
	})
	return nil
}

func (r *Runtime) newTrackedVM() (*goja.Runtime, error) {
	r.activeMu.Lock()
	defer r.activeMu.Unlock()
	if r.closed.Load() {
		return nil, newRuntimeError(KindClosed, ErrClosed)
	}
	vm := goja.New()
	if r.activeVMs == nil {
		r.activeVMs = make(map[*goja.Runtime]struct{})
	}
	r.activeVMs[vm] = struct{}{}
	return vm, nil
}

func (r *Runtime) releaseVM(vm *goja.Runtime) {
	r.activeMu.Lock()
	delete(r.activeVMs, vm)
	r.activeMu.Unlock()
}

func (r *Runtime) tryAcquire() bool {
	limit := int64(r.config.MaxConcurrent)
	for {
		active := r.permits.Load()
		if active >= limit {
			return false
		}
		if r.permits.CompareAndSwap(active, active+1) {
			return true
		}
	}
}

// Run compiles source (using the content cache) and executes it with input
// available as the JSON-compatible global variable input.
func (r *Runtime) Run(ctx context.Context, source string, input any) (any, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, contextError(err)
	}
	compiled, err := r.Compile(source)
	if err != nil {
		return nil, err
	}
	return r.RunCompiled(ctx, compiled, input)
}

// RunCompiled executes an immutable program in a new VM. Input and output
// cross the boundary as JSON values; no Go object is exposed to JavaScript.
func (r *Runtime) RunCompiled(ctx context.Context, compiled *CompiledScript, input any) (any, error) {
	return guardPanic(KindExecution, func() (any, error) {
		return r.runCompiled(ctx, compiled, input)
	})
}

func (r *Runtime) runCompiled(ctx context.Context, compiled *CompiledScript, input any) (any, error) {
	if r == nil {
		return nil, newRuntimeError(KindExecution, errors.New("nil runtime"))
	}
	if r.closed.Load() {
		return nil, newRuntimeError(KindClosed, ErrClosed)
	}
	if compiled == nil || compiled.program == nil {
		return nil, newRuntimeError(KindInvalidProgram, errors.New("nil compiled script"))
	}
	if compiled.runtimeID != r.runtimeID || compiled.engineID != gojaEngineID {
		return nil, newRuntimeError(KindInvalidProgram, ErrInvalidProgram)
	}
	if compiled.sourceSize > r.config.MaxSourceBytes {
		return nil, newRuntimeError(KindResourceLimit, fmt.Errorf("source is %d bytes; limit is %d", compiled.sourceSize, r.config.MaxSourceBytes))
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, contextError(err)
	}

	if !r.tryAcquire() {
		if err := ctx.Err(); err != nil {
			return nil, contextError(err)
		}
		return nil, newRuntimeError(KindResourceLimit, fmt.Errorf("maximum concurrent executions reached (%d)", r.config.MaxConcurrent))
	}
	defer r.permits.Add(-1)
	if err := ctx.Err(); err != nil {
		return nil, contextError(err)
	}

	inputJSON, err := guardPanic(KindInputConversion, func() ([]byte, error) {
		return marshalBoundedInput(input, r.config.MaxInputBytes)
	})
	if err != nil {
		if errors.Is(err, ErrResourceLimit) {
			return nil, newRuntimeError(KindResourceLimit, err)
		}
		return nil, asRuntimeError(KindInputConversion, err)
	}
	if r.closed.Load() {
		return nil, newRuntimeError(KindClosed, ErrClosed)
	}

	return r.execute(ctx, compiled, inputJSON)
}

func (r *Runtime) execute(ctx context.Context, compiled *CompiledScript, inputJSON []byte) (any, error) {
	vm, err := r.newTrackedVM()
	if err != nil {
		return nil, err
	}
	defer r.releaseVM(vm)
	if err := vm.Set("Promise", goja.Undefined()); err != nil {
		return nil, newRuntimeError(KindExecution, err)
	}

	jsonObject, ok := vm.Get("JSON").(*goja.Object)
	if !ok {
		return nil, newRuntimeError(KindExecution, errors.New("Goja JSON global is unavailable"))
	}
	parse, ok := goja.AssertFunction(jsonObject.Get("parse"))
	if !ok {
		return nil, newRuntimeError(KindExecution, errors.New("Goja JSON.parse is unavailable"))
	}
	stringify, ok := goja.AssertFunction(jsonObject.Get("stringify"))
	if !ok {
		return nil, newRuntimeError(KindExecution, errors.New("Goja JSON.stringify is unavailable"))
	}

	var output any
	outputBudget := &outputSizeBudget{limit: r.config.MaxOutputBytes}
	firstReplacerCall := true
	var lastHolder *goja.Object
	var lastHolderIsArray bool
	replacer := vm.ToValue(func(call goja.FunctionCall) goja.Value {
		isRoot := firstReplacerCall
		firstReplacerCall = false
		keySize, keyErr := limitedJSStringSize(vm, call.Argument(0), r.config.MaxOutputBytes)
		if keyErr != nil {
			panic(vm.NewGoError(keyErr))
		}
		value := call.Argument(1)
		var exported any
		valueType := value.ExportType()
		if valueType == goStringType {
			var encodedSize int
			encodedSize, keyErr = limitedJSStringSize(vm, value, r.config.MaxOutputBytes)
			if keyErr != nil {
				panic(vm.NewGoError(keyErr))
			}
			exported = outputJSONString{encodedSize: encodedSize}
		} else if valueType == goInt64Type || valueType == goFloat64Type {
			rawNumber := value.Export()
			switch number := rawNumber.(type) {
			case int64:
				encodedValue := value
				if _, isObject := value.(*goja.Object); isObject {
					encodedValue = vm.ToValue(number)
				}
				exported = outputJSONNumber{encodedSize: len(encodedValue.String())}
			case float64:
				if math.IsInf(number, 0) || math.IsNaN(number) {
					exported = outputJSONNumber{encodedSize: 4}
				} else {
					encodedValue := value
					if _, isObject := value.(*goja.Object); isObject {
						encodedValue = vm.ToValue(number)
					}
					exported = outputJSONNumber{encodedSize: len(encodedValue.String())}
				}
			}
		} else if _, ok := value.(*goja.Object); ok {
			exported = value
		} else {
			exported = value.Export()
		}
		arrayElement := false
		if !isRoot {
			if holder, ok := call.This.(*goja.Object); ok {
				if holder != lastHolder {
					lastHolder = holder
					lastHolderIsArray = isPlainArray(holder)
				}
				arrayElement = lastHolderIsArray
			}
		}
		if err := outputBudget.accept(keySize, exported, isRoot, arrayElement); err != nil {
			panic(vm.NewGoError(errOutputLimit))
		}
		return value
	})
	err = runInterruptibly(ctx, r.config.ExecutionTimeout, vm, func() error {
		inputValue, parseErr := parse(jsonObject, vm.ToValue(string(inputJSON)))
		if parseErr != nil {
			return asRuntimeError(KindInputConversion, parseErr)
		}
		if setErr := vm.Set("input", inputValue); setErr != nil {
			return newRuntimeError(KindExecution, setErr)
		}
		value, runErr := vm.RunProgram(compiled.program)
		if runErr != nil {
			return asRuntimeError(KindExecution, runErr)
		}
		if goja.IsUndefined(value) {
			output = nil
			return nil
		}

		serialized, serializeErr := stringify(jsonObject, value, replacer)
		if serializeErr != nil {
			if outputSizeError(serializeErr) {
				return newRuntimeError(KindResourceLimit, fmt.Errorf("output exceeds %d bytes", r.config.MaxOutputBytes))
			}
			return asRuntimeError(KindOutputConversion, serializeErr)
		}
		if goja.IsUndefined(serialized) {
			return newRuntimeError(KindOutputConversion, errors.New("script result is not JSON serializable"))
		}
		encoded := serialized.String()
		if len(encoded) > r.config.MaxOutputBytes {
			return newRuntimeError(KindResourceLimit, fmt.Errorf("output is %d bytes; limit is %d", len(encoded), r.config.MaxOutputBytes))
		}
		if err := json.Unmarshal([]byte(encoded), &output); err != nil {
			return newRuntimeError(KindOutputConversion, err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return output, nil
}

type interruptSignal struct {
	kind  ErrorKind
	cause error
}

func (s *interruptSignal) Error() string {
	if s == nil || s.cause == nil {
		return "javascript execution interrupted"
	}
	return s.cause.Error()
}

func (s *interruptSignal) Unwrap() error {
	if s == nil {
		return nil
	}
	return s.cause
}

func runInterruptibly(ctx context.Context, timeout time.Duration, vm *goja.Runtime, execute func() error) error {
	if err := ctx.Err(); err != nil {
		return contextError(err)
	}
	finished := make(chan struct{})
	watcherDone := make(chan struct{})
	signals := make(chan *interruptSignal, 1)
	const (
		stateRunning int32 = iota
		stateFinished
		stateInterrupted
	)
	var state atomic.Int32
	timer := time.NewTimer(timeout)
	go func() {
		defer close(watcherDone)
		var signal *interruptSignal
		select {
		case <-ctx.Done():
			err := ctx.Err()
			signal = &interruptSignal{kind: contextErrorKind(err), cause: err}
		case <-timer.C:
			if err := ctx.Err(); err != nil {
				signal = &interruptSignal{kind: contextErrorKind(err), cause: err}
			} else {
				signal = &interruptSignal{kind: KindTimeout, cause: ErrTimeout}
			}
		case <-finished:
			return
		}
		if state.CompareAndSwap(stateRunning, stateInterrupted) {
			signals <- signal
			interrupt(vm, signal)
		}
	}()
	completed := false
	defer func() {
		if !completed {
			completed = state.CompareAndSwap(stateRunning, stateFinished)
		}
		close(finished)
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		<-watcherDone
	}()

	err := execute()
	completed = state.CompareAndSwap(stateRunning, stateFinished)
	if !completed {
		// The interrupt watcher won the completion race. Wait for it to publish
		// the reason before returning, and never leave it racing with this VM.
		signal := <-signals
		var stack string
		var interrupted *goja.InterruptedError
		if errors.As(err, &interrupted) {
			stack = interrupted.String()
		}
		return &RuntimeError{Kind: signal.kind, Cause: signal.cause, Stack: stack}
	}
	if err != nil {
		return classifyInterrupt(err)
	}
	return nil
}

func interrupt(vm *goja.Runtime, signal *interruptSignal) {
	defer func() { _ = recover() }()
	vm.Interrupt(signal)
}

func classifyInterrupt(err error) error {
	var interrupted *goja.InterruptedError
	if !errors.As(err, &interrupted) {
		return err
	}
	if signal, ok := interrupted.Value().(*interruptSignal); ok {
		return &RuntimeError{Kind: signal.kind, Cause: signal.cause, Stack: interrupted.String()}
	}
	return &RuntimeError{Kind: KindExecution, Cause: interrupted, Stack: interrupted.String()}
}

func asRuntimeError(kind ErrorKind, err error) error {
	if err == nil {
		return nil
	}
	if runtimeErr, ok := err.(*RuntimeError); ok {
		return runtimeErr
	}
	classified := classifyInterrupt(err)
	if runtimeErr, ok := classified.(*RuntimeError); ok {
		return runtimeErr
	}
	var exception *goja.Exception
	if errors.As(err, &exception) {
		return &RuntimeError{Kind: kind, Cause: err, Stack: exception.String()}
	}
	return newRuntimeError(kind, err)
}

func contextError(err error) *RuntimeError {
	if errors.Is(err, context.DeadlineExceeded) {
		return newRuntimeError(KindTimeout, err)
	}
	return newRuntimeError(KindCanceled, err)
}

func contextErrorKind(err error) ErrorKind {
	if errors.Is(err, context.DeadlineExceeded) {
		return KindTimeout
	}
	return KindCanceled
}

func guardPanic[T any](kind ErrorKind, operation func() (T, error)) (value T, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			var zero T
			value = zero
			err = newRuntimeError(kind, fmt.Errorf("panic isolated: %v", recovered))
		}
	}()
	return operation()
}
