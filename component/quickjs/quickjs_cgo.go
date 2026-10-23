//go:build quickjs && cgo

package quickjs

/*
#cgo CFLAGS: -std=gnu11 -D_GNU_SOURCE -I${SRCDIR}/native
#cgo linux LDFLAGS: -lm
#cgo windows CFLAGS: -D__USE_MINGW_ANSI_STDIO
#cgo windows LDFLAGS: -lm -lpthread
#include <stdlib.h>
#include <string.h>
#include "bridge.h"
*/
import "C"

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"unsafe"
)

var (
	ErrUnavailable      = errors.New("quickjs: unavailable; build with -tags quickjs and CGO_ENABLED=1")
	ErrClosed           = errors.New("quickjs: object is closed")
	ErrContextsAlive    = errors.New("quickjs: close all contexts before closing the runtime")
	ErrCompiledAlive    = errors.New("quickjs: close all compiled scripts before closing the context")
	ErrNativeAllocation = errors.New("quickjs: native allocation failed")
	ErrInvalidSize      = errors.New("quickjs: size is not representable by the native platform")
)

// RuntimeOptions controls limits owned by one QuickJS runtime. A zero limit
// leaves QuickJS's default unchanged.
type RuntimeOptions struct {
	MemoryLimitBytes uint64
	MaxStackBytes    uint64
}

// Runtime serializes every QuickJS call. Its native state is private and must
// outlive all Context and CompiledScript handles created from it.
type Runtime struct {
	mu       sync.Mutex
	ptr      unsafe.Pointer
	contexts int
}

// Context is one JavaScript realm owned by a Runtime.
type Context struct {
	runtime  *Runtime
	ptr      unsafe.Pointer
	compiled int
	closed   bool
}

// CompiledScript owns a QuickJS bytecode value and must be closed before its
// Context. It cannot be used with another Context or Runtime.
type CompiledScript struct {
	context *Context
	ptr     unsafe.Pointer
	closed  bool
}

// NewRuntime creates one isolated QuickJS runtime. It does not create a
// Context and does not expose QuickJS pointers to callers.
func NewRuntime(options RuntimeOptions) (*Runtime, error) {
	memoryLimit, err := nativeSize(options.MemoryLimitBytes)
	if err != nil {
		return nil, fmt.Errorf("quickjs memory limit: %w", err)
	}
	stackLimit, err := nativeSize(options.MaxStackBytes)
	if err != nil {
		return nil, fmt.Errorf("quickjs stack limit: %w", err)
	}
	runtime := &Runtime{}
	runtime.ptr = C.qjs_runtime_new(memoryLimit, stackLimit)
	if runtime.ptr == nil {
		return nil, ErrNativeAllocation
	}
	return runtime, nil
}

// NewContext creates a realm attached to this Runtime.
func (runtime *Runtime) NewContext() (*Context, error) {
	if runtime == nil {
		return nil, ErrClosed
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.ptr == nil {
		return nil, ErrClosed
	}
	ptr := C.qjs_context_new(runtime.ptr)
	if ptr == nil {
		return nil, ErrNativeAllocation
	}
	runtime.contexts++
	return &Context{runtime: runtime, ptr: ptr}, nil
}

// Close releases the Runtime. It fails while any Context remains live.
func (runtime *Runtime) Close() error {
	if runtime == nil {
		return nil
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.ptr == nil {
		return nil
	}
	if runtime.contexts != 0 {
		return ErrContextsAlive
	}
	C.qjs_runtime_free(runtime.ptr)
	runtime.ptr = nil
	return nil
}

// Close releases the Context's owner reference. Any CompiledScript must be
// closed first. Pending QuickJS jobs remain owned by the Runtime.
func (context *Context) Close() error {
	if context == nil || context.runtime == nil {
		return nil
	}
	runtime := context.runtime
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if context.closed {
		return nil
	}
	if runtime.ptr == nil || context.ptr == nil {
		return ErrClosed
	}
	if context.compiled != 0 {
		return ErrCompiledAlive
	}
	C.qjs_context_free(context.ptr)
	context.ptr = nil
	context.closed = true
	runtime.contexts--
	return nil
}

// Eval executes source synchronously and returns QuickJS's string conversion
// of the resulting value. The result JSValue is freed inside the C wrapper.
func (context *Context) Eval(source string) (string, error) {
	return context.EvalContext(contextBackground, source)
}

// EvalContext executes source synchronously. Cancellation sets a C11 atomic
// flag read by QuickJS's C interrupt handler; it never calls back into Go.
func (context *Context) EvalContext(ctx context.Context, source string) (string, error) {
	if ctx == nil {
		ctx = contextBackground
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if context == nil || context.runtime == nil {
		return "", ErrClosed
	}
	runtime := context.runtime
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.ptr == nil || context.closed || context.ptr == nil {
		return "", ErrClosed
	}
	input, err := nativeInput(source)
	if err != nil {
		return "", err
	}
	defer C.free(input)

	C.qjs_interrupt_reset(runtime.ptr)
	stop, wait := startInterruptWatcher(ctx, runtime.ptr)
	if stop != nil {
		defer func() {
			close(stop)
			<-wait
		}()
	}
	var nativeResult C.qjs_eval_result
	C.qjs_context_eval(context.ptr, (*C.char)(input), C.size_t(len(source)), &nativeResult)
	result, evalErr := callEval(nativeResult)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return "", ctxErr
	}
	return result, evalErr
}

// Compile creates an owned QuickJS bytecode value without running it.
func (context *Context) Compile(source string) (*CompiledScript, error) {
	if context == nil || context.runtime == nil {
		return nil, ErrClosed
	}
	runtime := context.runtime
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.ptr == nil || context.closed || context.ptr == nil {
		return nil, ErrClosed
	}
	input, err := nativeInput(source)
	if err != nil {
		return nil, err
	}
	defer C.free(input)
	var compiled unsafe.Pointer
	var nativeResult C.qjs_eval_result
	C.qjs_context_compile(context.ptr, (*C.char)(input), C.size_t(len(source)), &compiled, &nativeResult)
	_, compileErr := callEval(nativeResult)
	if compileErr != nil {
		return nil, compileErr
	}
	if compiled == nil {
		return nil, ErrNativeAllocation
	}
	context.compiled++
	return &CompiledScript{context: context, ptr: compiled}, nil
}

// Eval executes a previously compiled script and retains its bytecode for
// subsequent calls. Each run receives a temporary duplicated JSValue.
func (script *CompiledScript) Eval() (string, error) {
	return script.EvalContext(contextBackground)
}

// EvalContext executes compiled bytecode and can interrupt synchronous JS.
func (script *CompiledScript) EvalContext(ctx context.Context) (string, error) {
	if ctx == nil {
		ctx = contextBackground
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if script == nil || script.context == nil || script.context.runtime == nil {
		return "", ErrClosed
	}
	context := script.context
	runtime := context.runtime
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.ptr == nil || context.closed || context.ptr == nil || script.closed || script.ptr == nil {
		return "", ErrClosed
	}
	C.qjs_interrupt_reset(runtime.ptr)
	stop, wait := startInterruptWatcher(ctx, runtime.ptr)
	if stop != nil {
		defer func() {
			close(stop)
			<-wait
		}()
	}
	var nativeResult C.qjs_eval_result
	C.qjs_context_run_compiled(context.ptr, script.ptr, &nativeResult)
	result, evalErr := callEval(nativeResult)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return "", ctxErr
	}
	return result, evalErr
}

// Close frees the bytecode value owned by this handle.
func (script *CompiledScript) Close() error {
	if script == nil || script.context == nil || script.context.runtime == nil {
		return nil
	}
	context := script.context
	runtime := context.runtime
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if script.closed {
		return nil
	}
	if runtime.ptr == nil || context.closed || context.ptr == nil || script.ptr == nil {
		return ErrClosed
	}
	C.qjs_compiled_free(context.ptr, script.ptr)
	script.ptr = nil
	script.closed = true
	context.compiled--
	return nil
}

// SetMemoryLimit changes QuickJS's per-Runtime allocator limit. A zero value
// removes the cap. It does not cap C bridge allocations, Go heap use, or RSS.
func (runtime *Runtime) SetMemoryLimit(bytes uint64) error {
	if runtime == nil {
		return ErrClosed
	}
	var native C.size_t
	if bytes == 0 {
		native = ^C.size_t(0)
	} else {
		var err error
		native, err = nativeSize(bytes)
		if err != nil {
			return err
		}
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.ptr == nil {
		return ErrClosed
	}
	C.qjs_runtime_set_memory_limit(runtime.ptr, native)
	return nil
}

// SetMaxStackSize changes QuickJS's maximum system stack use for this Runtime.
// A zero value disables QuickJS's stack limit.
func (runtime *Runtime) SetMaxStackSize(bytes uint64) error {
	if runtime == nil {
		return ErrClosed
	}
	native, err := nativeSize(bytes)
	if err != nil {
		return err
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.ptr == nil {
		return ErrClosed
	}
	C.qjs_runtime_set_max_stack_size(runtime.ptr, native)
	return nil
}

// MemoryUsage returns QuickJS Runtime allocator accounting only.
func (runtime *Runtime) MemoryUsage() (uint64, error) {
	if runtime == nil {
		return 0, ErrClosed
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.ptr == nil {
		return 0, ErrClosed
	}
	return uint64(C.qjs_runtime_memory_usage(runtime.ptr)), nil
}

// IsJobPending reports whether QuickJS has queued pending jobs.
func (runtime *Runtime) IsJobPending() (bool, error) {
	if runtime == nil {
		return false, ErrClosed
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.ptr == nil {
		return false, ErrClosed
	}
	return C.qjs_runtime_has_pending_job(runtime.ptr) != 0, nil
}

// ExecutePendingJob executes at most one queued job. It returns false when the
// queue is empty, true after one successful job, and an error for job failure.
func (runtime *Runtime) ExecutePendingJob() (bool, error) {
	if runtime == nil {
		return false, ErrClosed
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.ptr == nil {
		return false, ErrClosed
	}
	var message *C.char
	var messageLen C.size_t
	result := C.qjs_runtime_execute_pending_job(runtime.ptr, &message, &messageLen)
	if result < 0 {
		return false, consumeError(message, messageLen, "QuickJS pending job failed")
	}
	if result == 0 {
		return false, nil
	}
	return true, nil
}

func callEval(result C.qjs_eval_result) (string, error) {
	if result.status == 0 {
		value, err := consumeBuffer(result.value, result.value_len)
		if err != nil {
			return "", err
		}
		return value, nil
	}
	if result.status > 0 {
		return "", consumeError(result.error, result.error_len, "QuickJS exception")
	}
	return "", consumeError(result.error, result.error_len, ErrNativeAllocation.Error())
}

func consumeError(pointer *C.char, length C.size_t, fallback string) error {
	message, err := consumeBuffer(pointer, length)
	if err != nil {
		return err
	}
	if message == "" {
		message = fallback
	}
	return fmt.Errorf("quickjs: %s", message)
}

func consumeBuffer(pointer *C.char, length C.size_t) (string, error) {
	if pointer == nil {
		return "", ErrNativeAllocation
	}
	defer C.qjs_buffer_free(unsafe.Pointer(pointer))
	if uint64(length) > uint64(^uint(0)>>1) {
		return "", ErrInvalidSize
	}
	data := unsafe.Slice((*byte)(unsafe.Pointer(pointer)), int(length))
	return string(data), nil
}

func nativeInput(source string) (unsafe.Pointer, error) {
	length := C.size_t(len(source))
	if uint64(length) != uint64(len(source)) {
		return nil, ErrInvalidSize
	}
	pointer := C.malloc(length + 1)
	if pointer == nil {
		return nil, ErrNativeAllocation
	}
	if len(source) != 0 {
		data := []byte(source)
		C.memcpy(pointer, unsafe.Pointer(&data[0]), length)
	}
	C.memset(unsafe.Add(pointer, uintptr(length)), 0, 1)
	return pointer, nil
}

func nativeSize(value uint64) (C.size_t, error) {
	native := C.size_t(value)
	if uint64(native) != value {
		return 0, ErrInvalidSize
	}
	return native, nil
}

func startInterruptWatcher(ctx context.Context, state unsafe.Pointer) (chan struct{}, chan struct{}) {
	if ctx.Done() == nil {
		return nil, nil
	}
	stop := make(chan struct{})
	wait := make(chan struct{})
	go func() {
		defer close(wait)
		select {
		case <-ctx.Done():
			C.qjs_interrupt_request(state)
		case <-stop:
		}
	}()
	return stop, wait
}

var contextBackground = context.Background()

// enqueueThrowingJobForTest drives JS_ExecutePendingJob's exception branch with
// a native test job. It is intentionally unexported and not part of the adapter
// contract.
func (context *Context) enqueueThrowingJobForTest(message string) error {
	if context == nil || context.runtime == nil {
		return ErrClosed
	}
	runtime := context.runtime
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.ptr == nil || context.closed || context.ptr == nil {
		return ErrClosed
	}
	input, err := nativeInput(message)
	if err != nil {
		return err
	}
	defer C.free(input)
	if C.qjs_context_enqueue_throwing_job(context.ptr, (*C.char)(input), C.size_t(len(message))) < 0 {
		return fmt.Errorf("quickjs: unable to enqueue test job")
	}
	return nil
}
