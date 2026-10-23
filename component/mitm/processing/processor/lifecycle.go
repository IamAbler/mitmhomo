package processor

import (
	"context"
	"errors"
	"io"
	"sync"

	"github.com/metacubex/mihomo/component/mitm/processing/model"
)

// Lifecycle provides a small, explicit per-Processor execution admission cap
// and the Start/Close linearization boundary. It is not a production global
// quota and holds no lock while cancelling or waiting for an Invocation.
type Lifecycle struct {
	mu          sync.Mutex
	processorID string
	capacity    int
	closed      bool
	active      map[*Invocation]struct{}
	changed     chan struct{}
}

func NewLifecycle(capacity int) (*Lifecycle, error) {
	return NewProcessorLifecycle("", capacity)
}

func NewProcessorLifecycle(processorID string, capacity int) (*Lifecycle, error) {
	if capacity <= 0 {
		return nil, model.NewProcessingError(model.ProcessingErrorInvalidInput, model.ProcessingOriginProcessor, model.PhaseInvalid, processorID, "", model.ErrInvalid)
	}
	return &Lifecycle{processorID: processorID, capacity: capacity, active: make(map[*Invocation]struct{}), changed: make(chan struct{})}, nil
}

func (l *Lifecycle) signalLocked() {
	close(l.changed)
	l.changed = make(chan struct{})
}

func lifecycleError(kind model.ProcessingErrorKind, key model.InvocationKey, processorID string, cause error) error {
	return model.NewProcessingError(kind, model.ProcessingOriginProcessor, key.Phase, processorID, key.Invocation, cause)
}

// Begin atomically checks closed/admission state and registers an Invocation.
// A successful return linearizes before any concurrent Close; Close then sees
// and cancels this Invocation. Failure transfers no resource ownership.
func (l *Lifecycle) Begin(ctx context.Context, key model.InvocationKey) (*Invocation, *Completion, error) {
	return l.BeginWithResources(ctx, key)
}

// BeginWithResources transfers the resources only on success. Capacity remains
// occupied until Completion.Finish closes ExecutionDone, even after Cancel.
func (l *Lifecycle) BeginWithResources(ctx context.Context, key model.InvocationKey, resources ...io.Closer) (*Invocation, *Completion, error) {
	if l == nil {
		return nil, nil, model.NewProcessingError(model.ProcessingErrorClosed, model.ProcessingOriginProcessor, key.Phase, "", key.Invocation, model.ErrClosed)
	}
	if !validKey(key) {
		return nil, nil, lifecycleError(model.ProcessingErrorInvalidInput, key, l.processorID, model.ErrInvalid)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil, nil, lifecycleError(model.ProcessingErrorClosed, key, l.processorID, model.ErrClosed)
	}
	if ctx.Err() != nil {
		cause := context.Cause(ctx)
		kind := model.ProcessingErrorCanceled
		if errors.Is(cause, context.DeadlineExceeded) {
			kind = model.ProcessingErrorTimeout
		}
		origin := model.TimeoutScopeOrigin(model.TimeoutScopeOf(ctx))
		l.mu.Unlock()
		return nil, nil, model.NewProcessingError(kind, origin, key.Phase, l.processorID, key.Invocation, cause)
	}
	if len(l.active) >= l.capacity {
		l.mu.Unlock()
		return nil, nil, lifecycleError(model.ProcessingErrorResourceLimit, key, l.processorID, model.ErrResourceLimit)
	}
	for _, resource := range resources {
		if resource == nil {
			l.mu.Unlock()
			return nil, nil, lifecycleError(model.ProcessingErrorInvalidInput, key, l.processorID, model.ErrInvalid)
		}
	}
	if len(resources) > maxExecutionResources {
		l.mu.Unlock()
		return nil, nil, lifecycleError(model.ProcessingErrorResourceLimit, key, l.processorID, model.ErrResourceLimit)
	}
	i, completion := newInvocation(ctx, key, l.processorID, resources)
	i.onExecutionDone = func() { l.executionDone(i) }
	l.active[i] = struct{}{}
	l.signalLocked()
	l.mu.Unlock()
	return i, completion, nil
}

func (l *Lifecycle) executionDone(i *Invocation) {
	l.mu.Lock()
	if _, ok := l.active[i]; ok {
		delete(l.active, i)
		l.signalLocked()
	}
	l.mu.Unlock()
}

// Close is idempotent, rejects future Begin calls, and requests cancellation of
// active invocations without waiting for their execution resources to exit.
func (l *Lifecycle) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	active := make([]*Invocation, 0, len(l.active))
	for invocation := range l.active {
		active = append(active, invocation)
	}
	l.signalLocked()
	l.mu.Unlock()
	for _, invocation := range active {
		_ = invocation.Close()
	}
	return nil
}

// WaitClosed requires Close to have been requested and remains bounded by ctx.
func (l *Lifecycle) WaitClosed(ctx context.Context) error {
	if l == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		l.mu.Lock()
		if !l.closed {
			l.mu.Unlock()
			return model.NewProcessingError(model.ProcessingErrorInvalidInput, model.ProcessingOriginProcessor, model.PhaseInvalid, l.processorID, "", model.ErrInvalid)
		}
		if len(l.active) == 0 {
			l.mu.Unlock()
			return nil
		}
		changed := l.changed
		l.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			cause := context.Cause(ctx)
			kind := model.ProcessingErrorCanceled
			if errors.Is(cause, context.DeadlineExceeded) {
				kind = model.ProcessingErrorTimeout
			}
			return model.NewProcessingError(kind, model.ProcessingOriginProcessor, model.PhaseInvalid, l.processorID, "", cause)
		}
	}
}

func (l *Lifecycle) Active() int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.active)
}
