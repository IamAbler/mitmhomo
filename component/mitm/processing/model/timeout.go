package model

import (
	"context"
	"time"
)

// TimeoutScope identifies which owner supplied the effective deadline on a
// Context. It is diagnostic metadata only; cancellation still uses Context.
type TimeoutScope uint8

const (
	TimeoutScopeUnknown TimeoutScope = iota
	TimeoutScopeTransaction
	TimeoutScopeRequestPhase
	TimeoutScopeResponsePhase
	TimeoutScopeBody
	TimeoutScopeProcessor
	TimeoutScopeCleanup
)

type timeoutScopeKey struct{}

// WithTimeoutScope creates a child deadline and tags it only when that child
// deadline is earlier than its parent's. A zero duration inherits the parent.
// Context.WithTimeout guarantees a child can never extend its parent deadline.
func WithTimeoutScope(parent context.Context, timeout time.Duration, scope TimeoutScope) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	if timeout <= 0 || parent.Err() != nil {
		return parent, func() {}
	}
	if parentDeadline, ok := parent.Deadline(); ok && time.Until(parentDeadline) <= timeout {
		return parent, func() {}
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	return context.WithValue(ctx, timeoutScopeKey{}, scope), cancel
}

// WithDeadlineScope preserves an already-computed absolute invocation
// deadline while moving execution under the Transaction's cancellation tree.
func WithDeadlineScope(parent context.Context, deadline time.Time, scope TimeoutScope) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	if parent.Err() != nil {
		return parent, func() {}
	}
	if parentDeadline, ok := parent.Deadline(); ok && !deadline.Before(parentDeadline) {
		return parent, func() {}
	}
	ctx, cancel := context.WithDeadline(parent, deadline)
	return context.WithValue(ctx, timeoutScopeKey{}, scope), cancel
}

func TimeoutScopeOf(ctx context.Context) TimeoutScope {
	if ctx == nil {
		return TimeoutScopeUnknown
	}
	scope, _ := ctx.Value(timeoutScopeKey{}).(TimeoutScope)
	return scope
}

func TimeoutScopeOrigin(scope TimeoutScope) ProcessingErrorOrigin {
	if scope == TimeoutScopeProcessor {
		return ProcessingOriginProcessor
	}
	return ProcessingOriginRequest
}

// TimeoutPolicy defines independent nested budgets. Zero disables that local
// cap and inherits its parent Context. Defaults reuse the existing MITM
// request window and M4.8 failed-candidate cleanup wait.
type TimeoutPolicy struct {
	Transaction   time.Duration
	RequestPhase  time.Duration
	ResponsePhase time.Duration
	BodyIO        time.Duration
	CleanupWait   time.Duration
}

func DefaultTimeoutPolicy() TimeoutPolicy {
	return TimeoutPolicy{
		Transaction:   120 * time.Second,
		RequestPhase:  120 * time.Second,
		ResponsePhase: 120 * time.Second,
		BodyIO:        120 * time.Second,
		CleanupWait:   100 * time.Millisecond,
	}
}

func (p TimeoutPolicy) valid() bool {
	return p.Transaction >= 0 && p.RequestPhase >= 0 && p.ResponsePhase >= 0 && p.BodyIO >= 0 && p.CleanupWait >= 0
}

func (p TimeoutPolicy) Phase(phase Phase) (time.Duration, TimeoutScope) {
	if phase == ResponsePhase {
		return p.ResponsePhase, TimeoutScopeResponsePhase
	}
	return p.RequestPhase, TimeoutScopeRequestPhase
}

// ResourceLimits separates byte accounting from Body-owner and invocation
// concurrency capacities. A zero optional limit is allowed for tests or a
// deliberately disabled resource class; defaults are positive and bounded.
type ResourceLimits struct {
	TransactionBytes     int64
	BodyBufferBytes      int64
	ProcessorOutputBytes int64
}

func DefaultResourceLimits() ResourceLimits {
	return ResourceLimits{
		TransactionBytes:     DefaultTransactionBudgetBytes,
		BodyBufferBytes:      DefaultBodyBufferBytes,
		ProcessorOutputBytes: DefaultProcessorOutputBytes,
	}
}

func (l ResourceLimits) valid() bool {
	return l.TransactionBytes >= 0 && l.BodyBufferBytes >= 0 && l.ProcessorOutputBytes >= 0
}

func (l ResourceLimits) OutputLimit(requested int64) int64 {
	if requested <= 0 || requested > l.ProcessorOutputBytes {
		return l.ProcessorOutputBytes
	}
	return requested
}

func (l ResourceLimits) BodyLimit(requested int64) int64 {
	if requested <= 0 || requested > l.BodyBufferBytes {
		return l.BodyBufferBytes
	}
	return requested
}
