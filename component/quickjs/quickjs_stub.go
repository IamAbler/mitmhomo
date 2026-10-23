//go:build !quickjs || !cgo

package quickjs

import (
	"context"
	"errors"
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

// Runtime is unavailable unless built with -tags quickjs and cgo enabled.
type Runtime struct{}

// Context is unavailable unless built with -tags quickjs and cgo enabled.
type Context struct{}

// CompiledScript is unavailable unless built with -tags quickjs and cgo enabled.
type CompiledScript struct{}

func NewRuntime(RuntimeOptions) (*Runtime, error) { return nil, ErrUnavailable }
func (*Runtime) Close() error                     { return ErrUnavailable }
func (*Runtime) NewContext() (*Context, error)    { return nil, ErrUnavailable }
func (*Runtime) SetMemoryLimit(uint64) error      { return ErrUnavailable }
func (*Runtime) SetMaxStackSize(uint64) error     { return ErrUnavailable }
func (*Runtime) MemoryUsage() (uint64, error)     { return 0, ErrUnavailable }
func (*Runtime) IsJobPending() (bool, error)      { return false, ErrUnavailable }
func (*Runtime) ExecutePendingJob() (bool, error) { return false, ErrUnavailable }

func (*Context) Close() error                { return ErrUnavailable }
func (*Context) Eval(string) (string, error) { return "", ErrUnavailable }
func (*Context) EvalContext(context.Context, string) (string, error) {
	return "", ErrUnavailable
}
func (*Context) Compile(string) (*CompiledScript, error) { return nil, ErrUnavailable }

func (*CompiledScript) Close() error { return ErrUnavailable }
func (*CompiledScript) Eval() (string, error) {
	return "", ErrUnavailable
}
func (*CompiledScript) EvalContext(context.Context) (string, error) {
	return "", ErrUnavailable
}
