package generation

import (
	"context"
	"errors"
	"sync"
)

var ErrCleanupCapacity = errors.New("generation cleanup ownership capacity exhausted")

// CleanupPool bounds retained owners AND goroutines. Reserve must precede
// resource construction; a blocked destructor retains its slot until real exit.
// This is a lifecycle ownership bound, not Processor execution scheduling.
type CleanupPool struct {
	slots   chan struct{}
	mu      sync.Mutex
	changed chan struct{}
}

func NewCleanupPool(capacity int) *CleanupPool {
	if capacity <= 0 {
		panic("invalid cleanup capacity")
	}
	return &CleanupPool{slots: make(chan struct{}, capacity), changed: make(chan struct{})}
}

var DefaultCleanupPool = NewCleanupPool(16)

type CleanupReservation struct {
	pool     *CleanupPool
	mu       sync.Mutex
	attached bool
	released bool
}

func (p *CleanupPool) Reserve() (*CleanupReservation, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	select {
	case p.slots <- struct{}{}:
		return &CleanupReservation{pool: p}, nil
	default:
		return nil, ErrCleanupCapacity
	}
}

// Release is only for an unused reservation. Once attached, the Generation
// owns the slot; callers cannot abandon it on cancellation or timeout.
func (r *CleanupReservation) Release() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.attached && !r.released {
		r.released = true
		r.pool.release()
	}
}
func (r *CleanupReservation) Attach(g *Generation) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	g.mu.Lock()
	defer g.mu.Unlock()
	if r.attached || r.released || g.state != Building || g.dispatchCleanup != nil {
		return ErrUnavailable
	}
	r.attached = true
	g.dispatchCleanup = func(cleanup func()) { go func() { defer r.pool.release(); cleanup() }() }
	return nil
}
func (p *CleanupPool) Outstanding() int { return len(p.slots) }

func (p *CleanupPool) release() {
	p.mu.Lock()
	defer p.mu.Unlock()
	<-p.slots
	close(p.changed)
	p.changed = make(chan struct{})
}

// WaitIdle is observation only; cancellation cannot discard any live owner.
func (p *CleanupPool) WaitIdle(ctx context.Context) error {
	for {
		p.mu.Lock()
		if len(p.slots) == 0 {
			p.mu.Unlock()
			return nil
		}
		changed := p.changed
		p.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return context.Cause(ctx)
		}
	}
}
