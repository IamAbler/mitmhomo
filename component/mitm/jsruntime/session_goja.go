package jsruntime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/dop251/goja"
)

const maxSessionPendingTasks = 16

// RunSession executes one program in a fresh VM with engine-neutral host
// bindings. The VM remains owned by this call for its full lifetime; workers
// can only deliver JSON-compatible Completion values through Session.Next.
func (r *Runtime) RunSession(ctx context.Context, compiled *CompiledScript, options SessionOptions) (any, error) {
	return guardPanic(KindExecution, func() (any, error) {
		return r.runSession(ctx, compiled, options)
	})
}

func (r *Runtime) runSession(parent context.Context, compiled *CompiledScript, options SessionOptions) (any, error) {
	if r == nil {
		return nil, newRuntimeError(KindExecution, errors.New("nil runtime"))
	}
	if r.closed.Load() {
		return nil, newRuntimeError(KindClosed, ErrClosed)
	}
	if compiled == nil || compiled.program == nil || compiled.runtimeID != r.runtimeID || compiled.engineID != gojaEngineID {
		return nil, newRuntimeError(KindInvalidProgram, ErrInvalidProgram)
	}
	if compiled.sourceSize > r.config.MaxSourceBytes {
		return nil, newRuntimeError(KindResourceLimit, fmt.Errorf("source is %d bytes; limit is %d", compiled.sourceSize, r.config.MaxSourceBytes))
	}
	if parent == nil {
		parent = context.Background()
	}
	if err := validateSessionOptions(options); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidConfig, err)
	}
	if options.Timeout <= 0 {
		options.Timeout = r.config.ExecutionTimeout
	}
	if options.MaxPendingTasks <= 0 {
		options.MaxPendingTasks = 4
	}
	if !r.tryAcquire() {
		return nil, newRuntimeError(KindResourceLimit, fmt.Errorf("maximum concurrent executions reached (%d)", r.config.MaxConcurrent))
	}
	defer r.permits.Add(-1)

	ctx, cancel := context.WithTimeout(parent, options.Timeout)
	session := newSession(ctx, cancel, options.MaxPendingTasks)
	defer session.Close()
	if err := r.registerSession(session); err != nil {
		return nil, err
	}
	defer r.releaseSession(session)

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

	if err := installSessionGlobals(vm, parse, jsonObject, options.Globals, r.config.MaxInputBytes); err != nil {
		return nil, asRuntimeError(KindInputConversion, err)
	}
	callbacks := make(map[uint64]goja.Callable)
	var nextCallbackID uint64
	if err := installSessionBindings(vm, parse, jsonObject, options, session, callbacks, &nextCallbackID, r.config.MaxInputBytes); err != nil {
		return nil, newRuntimeError(KindExecution, err)
	}

	runJS := func(execute func() error) error {
		remaining := options.Timeout
		if deadline, ok := ctx.Deadline(); ok {
			remaining = time.Until(deadline)
		}
		if remaining <= 0 {
			remaining = time.Nanosecond
		}
		return runInterruptibly(ctx, remaining, vm, execute)
	}
	if err := runJS(func() error {
		_, err := vm.RunProgram(compiled.program)
		return err
	}); err != nil {
		if r.closed.Load() {
			return nil, newRuntimeError(KindClosed, ErrClosed)
		}
		return nil, asRuntimeError(KindExecution, err)
	}

	if !session.IsDone() && session.Pending() == 0 {
		session.Done(nil, false)
	}
	for !session.IsDone() {
		completion, waitErr := session.Next()
		if waitErr != nil {
			if r.closed.Load() {
				return nil, newRuntimeError(KindClosed, ErrClosed)
			}
			return nil, contextError(waitErr)
		}
		if err := ctx.Err(); err != nil {
			if r.closed.Load() {
				return nil, newRuntimeError(KindClosed, ErrClosed)
			}
			return nil, contextError(err)
		}
		callback, exists := callbacks[completion.CallbackID]
		delete(callbacks, completion.CallbackID)
		if exists && completion.CallbackID != 0 && !session.IsDone() {
			callbackArgs := make([]goja.Value, 0, len(completion.Args)+1)
			if completion.Err != nil {
				value, valueErr := sessionGojaValue(vm, parse, jsonObject, completion.Err.Error(), r.config.MaxInputBytes)
				if valueErr != nil {
					return nil, asRuntimeError(KindInputConversion, valueErr)
				}
				callbackArgs = append(callbackArgs, value)
			} else {
				callbackArgs = append(callbackArgs, goja.Null())
				for _, arg := range completion.Args {
					value, valueErr := sessionGojaValue(vm, parse, jsonObject, arg, r.config.MaxInputBytes)
					if valueErr != nil {
						return nil, asRuntimeError(KindInputConversion, valueErr)
					}
					callbackArgs = append(callbackArgs, value)
				}
			}
			if err := runJS(func() error {
				_, callbackErr := callback(goja.Undefined(), callbackArgs...)
				return callbackErr
			}); err != nil {
				if r.closed.Load() {
					return nil, newRuntimeError(KindClosed, ErrClosed)
				}
				return nil, asRuntimeError(KindExecution, err)
			}
		}
		if !session.IsDone() && session.Pending() == 0 {
			session.Done(nil, false)
		}
	}
	result, hasResult := session.Result()
	if !hasResult {
		return nil, nil
	}
	encoded, err := guardPanic(KindOutputConversion, func() ([]byte, error) {
		return marshalBoundedInput(result, r.config.MaxOutputBytes)
	})
	if err != nil {
		if errors.Is(err, ErrResourceLimit) {
			return nil, newRuntimeError(KindResourceLimit, err)
		}
		return nil, asRuntimeError(KindOutputConversion, err)
	}
	var output any
	if err := json.Unmarshal(encoded, &output); err != nil {
		return nil, asRuntimeError(KindOutputConversion, err)
	}
	return output, nil
}

func validateSessionOptions(options SessionOptions) error {
	if options.Timeout < 0 || options.Timeout > 30*time.Second {
		return fmt.Errorf("session timeout must be between zero and 30 seconds")
	}
	if options.MaxPendingTasks < 0 || options.MaxPendingTasks > maxSessionPendingTasks {
		return fmt.Errorf("maximum pending tasks must be between zero and %d", maxSessionPendingTasks)
	}
	if len(options.Bindings) > 64 {
		return errors.New("too many host bindings")
	}
	if len(options.Bindings) > 0 && options.Host == nil {
		return errors.New("host bindings require a SessionHost")
	}
	seen := make(map[string]struct{}, len(options.Bindings))
	for _, binding := range options.Bindings {
		name := strings.TrimPrefix(binding.Name, "$")
		if name == "" || strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".") || strings.Contains(name, "..") {
			return fmt.Errorf("invalid host binding name %q", binding.Name)
		}
		if _, exists := seen[name]; exists {
			return fmt.Errorf("duplicate host binding %q", binding.Name)
		}
		seen[name] = struct{}{}
		if binding.Async && binding.CallbackArg < 0 {
			return fmt.Errorf("async binding %q requires a callback argument index", binding.Name)
		}
		if !binding.Async && binding.CallbackArg != -1 {
			return fmt.Errorf("sync binding %q cannot have a callback argument", binding.Name)
		}
	}
	return nil
}

func installSessionGlobals(vm *goja.Runtime, parse goja.Callable, jsonObject *goja.Object, globals map[string]any, limit int) error {
	if len(globals) == 0 {
		return nil
	}
	encoded, err := marshalBoundedInput(globals, limit)
	if err != nil {
		return err
	}
	value, err := parse(jsonObject, vm.ToValue(string(encoded)))
	if err != nil {
		return err
	}
	object, ok := value.(*goja.Object)
	if !ok {
		return errors.New("host globals must be an object")
	}
	for _, name := range object.Keys() {
		if err := vm.Set(name, object.Get(name)); err != nil {
			return err
		}
	}
	return nil
}

func installSessionBindings(vm *goja.Runtime, parse goja.Callable, jsonObject *goja.Object, options SessionOptions, session *Session, callbacks map[uint64]goja.Callable, nextCallbackID *uint64, limit int) error {
	for _, binding := range options.Bindings {
		binding := binding
		name := binding.Name
		parts := strings.Split(name, ".")
		parent := vm.GlobalObject()
		for _, part := range parts[:len(parts)-1] {
			child := parent.Get(part)
			object, ok := child.(*goja.Object)
			if !ok {
				object = vm.NewObject()
				if err := parent.Set(part, object); err != nil {
					return err
				}
			}
			parent = object
		}
		function := vm.ToValue(func(call goja.FunctionCall) goja.Value {
			var callbackID uint64
			if binding.Async && binding.CallbackArg < len(call.Arguments) {
				callbackValue := call.Argument(binding.CallbackArg)
				if !goja.IsUndefined(callbackValue) && !goja.IsNull(callbackValue) {
					callback, ok := goja.AssertFunction(callbackValue)
					if !ok {
						panic(vm.NewGoError(fmt.Errorf("%s callback must be a function", binding.Name)))
					}
					*nextCallbackID++
					if *nextCallbackID == 0 {
						*nextCallbackID++
					}
					callbackID = *nextCallbackID
					callbacks[callbackID] = callback
				}
			}
			args := make([]any, 0, len(call.Arguments))
			for index, argument := range call.Arguments {
				if binding.Async && index == binding.CallbackArg {
					continue
				}
				value, err := exportSessionArgument(argument, limit)
				if err != nil {
					panic(vm.NewGoError(err))
				}
				args = append(args, value)
			}
			canonicalArgs, err := canonicalJSON(args, limit)
			if err != nil {
				panic(vm.NewGoError(err))
			}
			canonicalList, ok := canonicalArgs.([]any)
			if !ok {
				panic(vm.NewGoError(errors.New("host arguments are not a JSON array")))
			}
			result, err := options.Host.Call(session.ctx, session, HostCall{Name: binding.Name, Args: canonicalList, CallbackID: callbackID})
			if err != nil {
				panic(vm.NewGoError(err))
			}
			if binding.Async {
				return goja.Undefined()
			}
			value, err := sessionGojaValue(vm, parse, jsonObject, result, limit)
			if err != nil {
				panic(vm.NewGoError(err))
			}
			return value
		})
		if err := parent.Set(parts[len(parts)-1], function); err != nil {
			return err
		}
	}
	return nil
}

func exportSessionArgument(value goja.Value, limit int) (any, error) {
	if goja.IsUndefined(value) || goja.IsNull(value) {
		return nil, nil
	}
	encoded, err := marshalBoundedInput(value.Export(), limit)
	if err != nil {
		return nil, err
	}
	var result any
	if err := json.Unmarshal(encoded, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func canonicalJSON(value any, limit int) (any, error) {
	encoded, err := marshalBoundedInput(value, limit)
	if err != nil {
		return nil, err
	}
	var result any
	if err := json.Unmarshal(encoded, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func sessionGojaValue(vm *goja.Runtime, parse goja.Callable, jsonObject *goja.Object, value any, limit int) (goja.Value, error) {
	encoded, err := marshalBoundedInput(value, limit)
	if err != nil {
		return nil, err
	}
	parsed, err := parse(jsonObject, vm.ToValue(string(encoded)))
	if err != nil {
		return nil, err
	}
	return parsed, nil
}

func (r *Runtime) registerSession(session *Session) error {
	r.activeMu.Lock()
	defer r.activeMu.Unlock()
	if r.closed.Load() {
		return newRuntimeError(KindClosed, ErrClosed)
	}
	if r.activeSessions == nil {
		r.activeSessions = make(map[*Session]struct{})
	}
	r.activeSessions[session] = struct{}{}
	return nil
}

func (r *Runtime) releaseSession(session *Session) {
	r.activeMu.Lock()
	delete(r.activeSessions, session)
	r.activeMu.Unlock()
}
