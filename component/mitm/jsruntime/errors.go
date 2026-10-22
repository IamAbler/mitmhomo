package jsruntime

import (
	"errors"
	"fmt"
)

// ErrorKind identifies the stage that failed.
type ErrorKind string

const (
	KindCompile          ErrorKind = "compile"
	KindExecution        ErrorKind = "execution"
	KindTimeout          ErrorKind = "timeout"
	KindCanceled         ErrorKind = "canceled"
	KindResourceLimit    ErrorKind = "resource_limit"
	KindInputConversion  ErrorKind = "input_conversion"
	KindOutputConversion ErrorKind = "output_conversion"
	KindClosed           ErrorKind = "closed"
	KindInvalidProgram   ErrorKind = "invalid_program"
)

var (
	ErrCompile          = errors.New("javascript compilation failed")
	ErrExecution        = errors.New("javascript execution failed")
	ErrTimeout          = errors.New("javascript execution timed out")
	ErrCanceled         = errors.New("javascript execution canceled")
	ErrResourceLimit    = errors.New("javascript resource limit exceeded")
	ErrInputConversion  = errors.New("javascript input conversion failed")
	ErrOutputConversion = errors.New("javascript output conversion failed")
	ErrInvalidConfig    = errors.New("invalid javascript runtime configuration")
	ErrClosed           = errors.New("javascript runtime is closed")
	ErrInvalidProgram   = errors.New("compiled javascript program is invalid for this runtime")
)

// RuntimeError records the failure stage and, for JavaScript exceptions, the
// full Goja stack string. It supports errors.Is with the exported sentinels.
type RuntimeError struct {
	Kind  ErrorKind
	Cause error
	Stack string
}

func (e *RuntimeError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Cause == nil {
		return errorSentinel(e.Kind).Error()
	}
	return fmt.Sprintf("%s: %v", errorSentinel(e.Kind), e.Cause)
}

func (e *RuntimeError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

func (e *RuntimeError) Is(target error) bool {
	return e != nil && target == errorSentinel(e.Kind)
}

func errorSentinel(kind ErrorKind) error {
	switch kind {
	case KindCompile:
		return ErrCompile
	case KindExecution:
		return ErrExecution
	case KindTimeout:
		return ErrTimeout
	case KindCanceled:
		return ErrCanceled
	case KindResourceLimit:
		return ErrResourceLimit
	case KindInputConversion:
		return ErrInputConversion
	case KindOutputConversion:
		return ErrOutputConversion
	case KindClosed:
		return ErrClosed
	case KindInvalidProgram:
		return ErrInvalidProgram
	default:
		return ErrExecution
	}
}

func newRuntimeError(kind ErrorKind, cause error) *RuntimeError {
	return &RuntimeError{Kind: kind, Cause: cause}
}
