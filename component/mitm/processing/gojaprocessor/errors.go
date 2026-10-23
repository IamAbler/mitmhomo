package gojaprocessor

import (
	"context"
	"errors"
	"fmt"

	"github.com/metacubex/mihomo/component/mitm/jsruntime"
	"github.com/metacubex/mihomo/component/mitm/processing/model"
)

func processingFailure(kind model.ProcessingErrorKind, input model.Input, processorID string, cause error) error {
	key := input.Key()
	return model.NewProcessingError(kind, model.ProcessingOriginProcessor, key.Phase, processorID, key.Invocation, cause)
}

func invalidOutput(input model.Input, processorID string, cause error) error {
	return processingFailure(model.ProcessingErrorInvalidOutput, input, processorID, errors.Join(model.ErrInvalid, cause))
}

func inputError(input model.Input, processorID string, cause error) error {
	kind := model.ProcessingErrorInvalidInput
	switch {
	case errors.Is(cause, model.ErrBodyLimit):
		kind = model.ProcessingErrorBodyLimitExceeded
	case errors.Is(cause, model.ErrBodyUnavailable):
		kind = model.ProcessingErrorBodyRead
	case errors.Is(cause, model.ErrResourceLimit):
		kind = model.ProcessingErrorResourceLimit
	}
	return processingFailure(kind, input, processorID, cause)
}

func runtimeError(input model.Input, processorID string, err error) error {
	var runtimeErr *jsruntime.RuntimeError
	if errors.As(err, &runtimeErr) {
		switch runtimeErr.Kind {
		case jsruntime.KindCompile:
			return processingFailure(model.ProcessingErrorCompile, input, processorID, err)
		case jsruntime.KindTimeout:
			return processingFailure(model.ProcessingErrorTimeout, input, processorID, err)
		case jsruntime.KindCanceled:
			return processingFailure(model.ProcessingErrorCanceled, input, processorID, err)
		case jsruntime.KindInputResourceLimit:
			return processingFailure(model.ProcessingErrorResourceLimit, input, processorID, err)
		case jsruntime.KindResourceLimit:
			return processingFailure(model.ProcessingErrorOutputLimitExceeded, input, processorID, err)
		case jsruntime.KindInputConversion:
			return processingFailure(model.ProcessingErrorInvalidInput, input, processorID, err)
		case jsruntime.KindOutputConversion:
			return invalidOutput(input, processorID, err)
		case jsruntime.KindClosed:
			return processingFailure(model.ProcessingErrorClosed, input, processorID, err)
		default:
			return processingFailure(model.ProcessingErrorExecution, input, processorID, err)
		}
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return processingFailure(model.ProcessingErrorTimeout, input, processorID, err)
	case errors.Is(err, context.Canceled):
		return processingFailure(model.ProcessingErrorCanceled, input, processorID, err)
	case errors.Is(err, jsruntime.ErrClosed):
		return processingFailure(model.ProcessingErrorClosed, input, processorID, err)
	default:
		return processingFailure(model.ProcessingErrorExecution, input, processorID, err)
	}
}

func configFailure(id, message string) error {
	return model.NewProcessingError(model.ProcessingErrorInvalidConfiguration, model.ProcessingOriginProcessor, model.PhaseInvalid, id, "", fmt.Errorf("%w: %s", model.ErrInvalid, message))
}
