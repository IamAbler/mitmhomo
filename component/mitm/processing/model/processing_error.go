package model

import (
	"errors"
	"fmt"
)

// ProcessingErrorKind is a stable, machine-readable processing failure class.
type ProcessingErrorKind uint8

const (
	ProcessingErrorInvalidInput ProcessingErrorKind = iota + 1
	ProcessingErrorCompile
	ProcessingErrorExecution
	ProcessingErrorInvalidOutput
	ProcessingErrorResourceLimit
	ProcessingErrorTimeout
	ProcessingErrorCanceled
	ProcessingErrorClosed
	ProcessingErrorBodyRead
	ProcessingErrorProtocol
	ProcessingErrorUpstream
	ProcessingErrorEgress
)

// ProcessingErrorOrigin identifies the component that introduced a failure.
type ProcessingErrorOrigin uint8

const (
	ProcessingOriginInvalid ProcessingErrorOrigin = iota
	ProcessingOriginProcessor
	ProcessingOriginRequest
	ProcessingOriginConnection
	ProcessingOriginUpstream
	ProcessingOriginProtocol
)

var processingErrorSentinels = map[ProcessingErrorKind]error{
	ProcessingErrorInvalidInput:  errors.New("processing invalid input"),
	ProcessingErrorCompile:       errors.New("processing compile failure"),
	ProcessingErrorExecution:     errors.New("processing execution failure"),
	ProcessingErrorInvalidOutput: errors.New("processing invalid output"),
	ProcessingErrorResourceLimit: errors.New("processing resource limit"),
	ProcessingErrorTimeout:       errors.New("processing timeout"),
	ProcessingErrorCanceled:      errors.New("processing canceled"),
	ProcessingErrorClosed:        errors.New("processing closed"),
	ProcessingErrorBodyRead:      errors.New("processing body read failure"),
	ProcessingErrorProtocol:      errors.New("processing protocol failure"),
	ProcessingErrorUpstream:      errors.New("processing upstream failure"),
	ProcessingErrorEgress:        errors.New("processing egress failure"),
}

// ErrorSentinel returns the errors.Is sentinel associated with kind.
func ErrorSentinel(kind ProcessingErrorKind) error { return processingErrorSentinels[kind] }

// ProcessingError carries typed failure metadata without relying on message text.
type ProcessingError struct {
	Kind         ProcessingErrorKind
	Origin       ProcessingErrorOrigin
	Phase        Phase
	ProcessorID  string
	InvocationID InvocationID
	Cause        error
}

func NewProcessingError(kind ProcessingErrorKind, origin ProcessingErrorOrigin, phase Phase, processorID string, invocationID InvocationID, cause error) *ProcessingError {
	return &ProcessingError{Kind: kind, Origin: origin, Phase: phase, ProcessorID: processorID, InvocationID: invocationID, Cause: cause}
}

func (e *ProcessingError) Error() string {
	if e == nil {
		return "<nil>"
	}
	label := "unknown processing error"
	if sentinel := ErrorSentinel(e.Kind); sentinel != nil {
		label = sentinel.Error()
	}
	if e.Cause != nil {
		return fmt.Sprintf("%s: %v", label, e.Cause)
	}
	return label
}

func (e *ProcessingError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

func (e *ProcessingError) Is(target error) bool {
	if e == nil || target == nil {
		return false
	}
	if sentinel := ErrorSentinel(e.Kind); sentinel != nil && target == sentinel {
		return true
	}
	return errors.Is(e.Cause, target)
}
