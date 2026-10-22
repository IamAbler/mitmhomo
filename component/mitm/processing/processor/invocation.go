package processor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/metacubex/mihomo/component/mitm/processing/model"
)

var alreadyClosed = func() <-chan struct{} {
	c := make(chan struct{})
	close(c)
	return c
}()

const maxExecutionResources = 16

// Invocation has two independent terminal signals: Await observes logicalDone,
// while executionDone closes only after Finish has released execution resources.
// Parent-context cancellation is materialized as LogicalDone when Await or
// Finish observes it; no per-invocation watcher goroutine is created.
type Invocation struct {
	mu sync.Mutex

	key           model.InvocationKey
	processorID   string
	parentCtx     context.Context
	executionCtx  context.Context
	cancelExec    context.CancelCauseFunc
	logicalDone   chan struct{}
	executionDone chan struct{}

	result          model.DoneResult
	resultErr       error
	cleanupErr      error
	logical         bool
	finishing       bool
	executed        bool
	finishingResult model.DoneResult
	resources       []io.Closer
	onExecutionDone func()
}

// Completion is the single-use producer capability associated with an
// Invocation. Finish must be called only after the backend's final access to
// the VM, Input, and execution-lease-protected resources.
type Completion struct{ invocation *Invocation }

func validKey(key model.InvocationKey) bool {
	return key.TransactionID != "" && key.Invocation != "" && key.Revision != 0 && (key.Phase == model.RequestPhase || key.Phase == model.ResponsePhase)
}

func processingError(kind model.ProcessingErrorKind, origin model.ProcessingErrorOrigin, key model.InvocationKey, processorID string, cause error) *model.ProcessingError {
	return model.NewProcessingError(kind, origin, key.Phase, processorID, key.Invocation, cause)
}

func contextError(cause error, origin model.ProcessingErrorOrigin, key model.InvocationKey, processorID string) error {
	if cause == nil {
		cause = context.Canceled
	}
	kind := model.ProcessingErrorCanceled
	if errors.Is(cause, context.DeadlineExceeded) {
		kind = model.ProcessingErrorTimeout
	}
	return processingError(kind, origin, key, processorID, cause)
}

func newInvocation(ctx context.Context, key model.InvocationKey, processorID string, resources []io.Closer) (*Invocation, *Completion) {
	if ctx == nil {
		ctx = context.Background()
	}
	executionCtx, cancel := context.WithCancelCause(ctx)
	i := &Invocation{
		key:           key,
		processorID:   processorID,
		parentCtx:     ctx,
		executionCtx:  executionCtx,
		cancelExec:    cancel,
		logicalDone:   make(chan struct{}),
		executionDone: make(chan struct{}),
		resources:     append([]io.Closer(nil), resources...),
	}
	c := &Completion{invocation: i}
	if !validKey(key) {
		i.terminalize(processingError(model.ProcessingErrorInvalidInput, model.ProcessingOriginProcessor, key, processorID, model.ErrInvalid), false)
		return i, c
	}
	if cause := context.Cause(ctx); ctx.Err() != nil {
		i.terminalize(contextError(cause, model.ProcessingOriginRequest, key, processorID), false)
		return i, c
	}
	return i, c
}

// NewInvocation creates a no-resource invocation. Backend implementations that
// transfer CopyLease, generation pin, or admission ownership should use
// NewInvocationWithResources so Finish releases those resources exactly once.
func NewInvocation(ctx context.Context, key model.InvocationKey) (*Invocation, *Completion) {
	return newInvocation(ctx, key, "", nil)
}

// NewInvocationWithResources transfers the supplied execution resources to the
// Invocation on success. They are closed only by Finish, never by Cancel/Await.
func NewInvocationWithResources(ctx context.Context, key model.InvocationKey, resources ...io.Closer) (*Invocation, *Completion, error) {
	if !validKey(key) {
		return nil, nil, model.NewProcessingError(model.ProcessingErrorInvalidInput, model.ProcessingOriginProcessor, key.Phase, "", key.Invocation, model.ErrInvalid)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Err() != nil {
		return nil, nil, contextError(context.Cause(ctx), model.ProcessingOriginRequest, key, "")
	}
	for _, resource := range resources {
		if resource == nil {
			return nil, nil, model.NewProcessingError(model.ProcessingErrorInvalidInput, model.ProcessingOriginProcessor, key.Phase, "", key.Invocation, model.ErrInvalid)
		}
	}
	if len(resources) > maxExecutionResources {
		return nil, nil, model.NewProcessingError(model.ProcessingErrorResourceLimit, model.ProcessingOriginProcessor, key.Phase, "", key.Invocation, model.ErrResourceLimit)
	}
	i, c := newInvocation(ctx, key, "", resources)
	return i, c, nil
}

func (i *Invocation) Key() model.InvocationKey {
	if i == nil {
		return model.InvocationKey{}
	}
	return i.key
}

// Context is the per-invocation execution context. Await's waiting context is
// separate; canceling it calls Cancel and therefore cancels this context.
func (i *Invocation) Context() context.Context {
	if i == nil {
		return context.Background()
	}
	return i.executionCtx
}

func (i *Invocation) ExecutionDone() <-chan struct{} {
	if i == nil {
		return alreadyClosed
	}
	return i.executionDone
}

func (i *Invocation) LogicalDone() <-chan struct{} {
	if i == nil {
		return alreadyClosed
	}
	return i.logicalDone
}

// terminalize elects the sole logical result. It never waits for execution.
func (i *Invocation) terminalize(err error, cancelExecution bool) bool {
	if i == nil {
		return false
	}
	i.mu.Lock()
	if i.logical {
		i.mu.Unlock()
		return false
	}
	i.logical = true
	i.result = model.DoneResult{}
	i.resultErr = err
	close(i.logicalDone)
	i.mu.Unlock()
	if cancelExecution {
		i.cancelExec(err)
	}
	return true
}

// Cancel makes the logical result unavailable and requests cooperative backend
// cancellation. It does not release execution resources or close ExecutionDone.
func (i *Invocation) Cancel(cause error) {
	if i == nil {
		return
	}
	if cause == nil {
		cause = context.Canceled
	}
	var typed error
	var existing *model.ProcessingError
	if errors.As(cause, &existing) {
		typed = cause
	} else {
		typed = contextError(cause, model.ProcessingOriginProcessor, i.key, i.processorID)
	}
	i.terminalize(typed, true)
}

// Close is an idempotent logical cancellation. It never waits for backend exit.
func (i *Invocation) Close() error {
	if i == nil {
		return nil
	}
	i.terminalize(processingError(model.ProcessingErrorClosed, model.ProcessingOriginProcessor, i.key, i.processorID, model.ErrClosed), true)
	return nil
}

func completionFailure(err error, key model.InvocationKey, processorID string) error {
	if err == nil {
		return nil
	}
	var processing *model.ProcessingError
	if errors.As(err, &processing) {
		return err
	}
	kind := model.ProcessingErrorExecution
	if errors.Is(err, model.ErrResourceLimit) {
		kind = model.ProcessingErrorResourceLimit
	} else if errors.Is(err, context.DeadlineExceeded) {
		kind = model.ProcessingErrorTimeout
	} else if errors.Is(err, context.Canceled) {
		kind = model.ProcessingErrorCanceled
	}
	return processingError(kind, model.ProcessingOriginProcessor, key, processorID, err)
}

func (i *Invocation) releaseResources(resources []io.Closer) error {
	var result error
	for _, resource := range resources {
		if resource != nil {
			result = errors.Join(result, resource.Close())
		}
	}
	return result
}

// Finish synchronously releases all execution leases before publishing a normal
// result or closing ExecutionDone. A blocking Closer therefore blocks normal
// Await, while Cancel and Close remain independent because Closer calls run
// outside the Invocation lock. A late Finish still returns true once because
// it proves real execution exit and performs resource cleanup.
func (c *Completion) Finish(result model.DoneResult, err error) bool {
	if c == nil || c.invocation == nil {
		_ = result.Release()
		return false
	}
	i := c.invocation
	i.mu.Lock()
	if i.finishing || i.executed {
		// A duplicate call that carries the same payload must not release the
		// result already retained by this Invocation.
		same := result.Same(i.result) || i.finishing && result.Same(i.finishingResult)
		i.mu.Unlock()
		if !same {
			_ = result.Release()
		}
		return false
	}
	i.finishing = true
	i.finishingResult = result
	resources := i.resources
	i.resources = nil
	i.mu.Unlock()

	candidate := model.DoneResult{}
	candidateErr := completionFailure(err, i.key, i.processorID)
	if err != nil {
		if result.Kind() != model.ResultInvalid {
			_ = result.Release()
			candidateErr = processingError(model.ProcessingErrorInvalidOutput, model.ProcessingOriginProcessor, i.key, i.processorID, errors.Join(err, model.ErrInvalid))
		}
	} else if !result.Valid() {
		_ = result.Release()
		candidateErr = processingError(model.ProcessingErrorInvalidOutput, model.ProcessingOriginProcessor, i.key, i.processorID, model.ErrInvalid)
	} else if phaseErr := result.ValidateForPhase(i.key.Phase); phaseErr != nil {
		_ = result.Release()
		candidateErr = processingError(model.ProcessingErrorInvalidOutput, model.ProcessingOriginProcessor, i.key, i.processorID, phaseErr)
	} else {
		candidate = result
	}

	resourceErr := i.releaseResources(resources)
	if resourceErr != nil {
		if candidate.Kind() != model.ResultInvalid {
			_ = candidate.Release()
			candidate = model.DoneResult{}
		}
		candidateErr = processingError(model.ProcessingErrorExecution, model.ProcessingOriginProcessor, i.key, i.processorID, errors.Join(candidateErr, resourceErr))
	}

	i.mu.Lock()
	discard := false
	firstLogical := false
	if !i.logical {
		if i.parentCtx.Err() != nil {
			cause := context.Cause(i.parentCtx)
			i.logical = true
			i.resultErr = contextError(cause, model.ProcessingOriginRequest, i.key, i.processorID)
			close(i.logicalDone)
		}
	}
	if !i.logical {
		i.logical = true
		i.result = candidate
		i.resultErr = candidateErr
		close(i.logicalDone)
		firstLogical = true
	} else if candidate.Kind() != model.ResultInvalid {
		discard = true
	}
	i.mu.Unlock()
	var resultReleaseErr error
	if discard {
		resultReleaseErr = candidate.Release()
	}

	if i.parentCtx.Err() != nil {
		cause := context.Cause(i.parentCtx)
		i.terminalize(contextError(cause, model.ProcessingOriginRequest, i.key, i.processorID), true)
	}
	i.mu.Lock()
	i.cleanupErr = errors.Join(i.cleanupErr, resourceErr, resultReleaseErr)
	i.executed = true
	close(i.executionDone)
	onExecutionDone := i.onExecutionDone
	i.mu.Unlock()
	if firstLogical {
		cause := candidateErr
		if cause == nil {
			cause = context.Canceled
		}
		i.cancelExec(cause)
	}
	if onExecutionDone != nil {
		onExecutionDone()
	}
	return true
}

// Await waits for the logical result. Its context is an invocation-level wait
// budget: canceling it terminalizes the invocation with Processor origin and
// requests execution cancellation. The parent execution context is independent
// and is classified with Request origin.
func (i *Invocation) Await(ctx context.Context) (model.DoneResult, error) {
	if i == nil {
		return model.DoneResult{}, model.NewProcessingError(model.ProcessingErrorInvalidInput, model.ProcessingOriginProcessor, model.PhaseInvalid, "", "", model.ErrInvalid)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		i.mu.Lock()
		if i.logical {
			result, err := i.result, i.resultErr
			i.mu.Unlock()
			return result, err
		}
		done := i.logicalDone
		i.mu.Unlock()
		select {
		case <-done:
			continue
		case <-i.parentCtx.Done():
			cause := context.Cause(i.parentCtx)
			i.terminalize(contextError(cause, model.ProcessingOriginRequest, i.key, i.processorID), true)
		case <-ctx.Done():
			cause := context.Cause(ctx)
			i.terminalize(contextError(cause, model.ProcessingOriginProcessor, i.key, i.processorID), true)
		}
	}
}

// CleanupError returns resource-release failures that occurred after a logical
// cancellation had already fixed Await's result.
func (i *Invocation) CleanupError() error {
	if i == nil {
		return nil
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.cleanupErr
}

func (i *Invocation) String() string {
	if i == nil {
		return "<nil invocation>"
	}
	return fmt.Sprintf("Invocation{%s/%s r%d phase=%d}", i.key.TransactionID, i.key.Invocation, i.key.Revision, i.key.Phase)
}
