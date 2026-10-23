package processor

import (
	"context"
	"errors"
	"sync/atomic"

	"github.com/metacubex/mihomo/component/mitm/processing/model"
)

const DefaultInvocationCapacity = 64

var ErrInvocationCapacity = errors.Join(model.ErrCapacityExhausted, model.ErrResourceLimit)

var defaultInvocationPool = NewInvocationPool(DefaultInvocationCapacity)

// InvocationPool bounds framework-owned concurrent Processor executions.
// Admission rejects immediately when full; it does not queue callers or create
// waiting goroutines. A permit belongs to Invocation until real ExecutionDone.
type InvocationPool struct {
	slots    chan struct{}
	rejected atomic.Uint64
}

func NewInvocationPool(capacity int) *InvocationPool {
	if capacity <= 0 {
		panic("invalid invocation capacity")
	}
	return &InvocationPool{slots: make(chan struct{}, capacity)}
}

func DefaultInvocationPool() *InvocationPool { return defaultInvocationPool }

type InvocationPermit struct {
	pool   *InvocationPool
	closed atomic.Bool
}

func (p *InvocationPool) Acquire(ctx context.Context) (*InvocationPermit, error) {
	if p == nil {
		return nil, ErrInvocationCapacity
	}
	if ctx != nil && ctx.Err() != nil {
		return nil, context.Cause(ctx)
	}
	select {
	case p.slots <- struct{}{}:
		if ctx != nil && ctx.Err() != nil {
			<-p.slots
			return nil, context.Cause(ctx)
		}
		return &InvocationPermit{pool: p}, nil
	default:
		p.rejected.Add(1)
		return nil, ErrInvocationCapacity
	}
}

func (p *InvocationPool) Capacity() int {
	if p == nil {
		return 0
	}
	return cap(p.slots)
}

func (p *InvocationPool) Occupied() int {
	if p == nil {
		return 0
	}
	return len(p.slots)
}

func (p *InvocationPool) Rejected() uint64 {
	if p == nil {
		return 0
	}
	return p.rejected.Load()
}

func (p *InvocationPermit) Close() error {
	if p == nil || p.pool == nil || !p.closed.CompareAndSwap(false, true) {
		return nil
	}
	<-p.pool.slots
	return nil
}
