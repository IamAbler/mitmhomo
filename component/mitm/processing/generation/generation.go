// Package generation owns immutable processing configurations and explicit leases.
// There is no global lookup on a stream or execution path.
package generation

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"

	"github.com/metacubex/mihomo/component/mitm/processing/model"
)

type State uint8

const (
	Building State = iota
	Active
	Retiring
	Closed
)

var ErrUnavailable = errors.New("generation unavailable")
var sequence atomic.Uint64

// Generation takes exclusive ownership of resources on construction. Resources
// close in reverse order, outside all admission locks. Done includes cleanup.
type Generation struct {
	mu                                    sync.Mutex
	id                                    model.GenerationID
	state                                 State
	connections, transactions, executions int
	resources                             []io.Closer
	closing                               bool
	done                                  chan struct{}
	err                                   error
	observer                              func(error)
	dispatchCleanup func(func())
}

func New(resources ...io.Closer) *Generation {
	return &Generation{id: model.GenerationID(sequence.Add(1)), resources: append([]io.Closer(nil), resources...), done: make(chan struct{})}
}
func (g *Generation) ID() model.GenerationID { return g.id }

// ObserveCleanup installs diagnostics before activation. Errors also remain
// available through WaitClosed and CloseError.
func (g *Generation) ObserveCleanup(observer func(error)) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.state != Building {
		return ErrUnavailable
	}
	g.observer = observer
	return nil
}
func (g *Generation) State() State { g.mu.Lock(); defer g.mu.Unlock(); return g.state }
func (g *Generation) Activate() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.state != Building {
		return ErrUnavailable
	}
	g.state = Active
	return nil
}

// Retire releases publisher ownership. Existing parents retain admission for
// children, but independent connection admission is permanently revoked.
func (g *Generation) Retire() {
	g.RetireDeferred()()
}

// RetireDeferred revokes independent Bind immediately. The caller owns the
// returned idempotent cleanup continuation and must run it outside publication
// locks. A live lease may instead elect cleanup on its eventual release.
func (g *Generation) RetireDeferred() func() {
	g.mu.Lock()
	if g.state == Building || g.state == Active {
		g.state = Retiring
	}
	cleanup := g.cleanupLocked()
	g.mu.Unlock()
	if cleanup {
		var once sync.Once
		return func() { once.Do(g.runCleanup) }
	}
	return func() {}
}
func (g *Generation) Close() error          { g.Retire(); return g.CloseError() }
func (g *Generation) CloseError() error     { g.mu.Lock(); defer g.mu.Unlock(); return g.err }
func (g *Generation) Done() <-chan struct{} { return g.done }
func (g *Generation) WaitClosed(ctx context.Context) error {
	select {
	case <-g.done:
		return g.CloseError()
	case <-ctx.Done():
		return context.Cause(ctx)
	}
}
func (g *Generation) cleanupLocked() bool {
	if g.state != Retiring || g.closing || g.connections+g.transactions+g.executions != 0 {
		return false
	}
	g.closing = true
	return true
}
func (g *Generation) cleanup() {
	var err error
	for i := len(g.resources) - 1; i >= 0; i-- {
		if g.resources[i] != nil {
			err = errors.Join(err, g.resources[i].Close())
		}
	}
	g.mu.Lock()
	g.resources = nil
	g.err = err
	g.state = Closed
	close(g.done)
	observer := g.observer
	g.observer = nil
	g.mu.Unlock()
	if observer != nil {
		observer(err)
	}
}

func (g *Generation) runCleanup() {
	if g.dispatchCleanup!=nil {g.dispatchCleanup(g.cleanup)} else {g.cleanup()}
}

// Lease is a capability. Child admission and parent Close share the same lock,
// so a released parent can never resurrect a drained generation.
type Lease struct {
	g      *Generation
	kind   uint8
	closed bool
}

func (g *Generation) Bind() (*Lease, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.state != Active {
		return nil, ErrUnavailable
	}
	g.connections++
	return &Lease{g: g}, nil
}
func (l *Lease) ID() model.GenerationID { return l.g.id }
func (l *Lease) child(kind uint8) (*Lease, error) {
	g := l.g
	g.mu.Lock()
	defer g.mu.Unlock()
	if l.closed || g.closing || g.state == Closed || l.kind == 2 {
		return nil, ErrUnavailable
	}
	if kind == 1 {
		g.transactions++
	} else {
		g.executions++
	}
	return &Lease{g: g, kind: kind}, nil
}
func (l *Lease) Transaction() (*Lease, error) { return l.child(1) }
func (l *Lease) Execution() (*Lease, error)   { return l.child(2) }
func (l *Lease) Close() error {
	g := l.g
	g.mu.Lock()
	if l.closed {
		g.mu.Unlock()
		return nil
	}
	l.closed = true
	switch l.kind {
	case 0:
		g.connections--
	case 1:
		g.transactions--
	case 2:
		g.executions--
	}
	cleanup := g.cleanupLocked()
	g.mu.Unlock()
	if cleanup {
		g.runCleanup()
	}
	return nil
}

// Publisher serializes publication with Bind; no raw pointer/Acquire gap exists.
// A candidate belongs to the caller until Publish succeeds.
type Publisher struct {
	mu      sync.Mutex
	current *Generation
	closed  bool
}

func (p *Publisher) Publish(g *Generation) error {
	p.mu.Lock()
	if p.closed || g == nil {
		p.mu.Unlock()
		return ErrUnavailable
	}
	if err := g.Activate(); err != nil {
		p.mu.Unlock()
		return err
	}
	old := p.current
	p.current = g
	cleanup := func() {}
	if old != nil {
		cleanup = old.RetireDeferred()
	}
	// Retire outside the publisher lock: a blocking closer must not block Bind.
	p.mu.Unlock()
	cleanup()
	return nil
}
func (p *Publisher) Bind() (*Lease, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.current == nil {
		return nil, ErrUnavailable
	}
	return p.current.Bind()
}
func (p *Publisher) Close() error {
	p.mu.Lock()
	old := p.current
	p.current = nil
	p.closed = true
	cleanup := func() {}
	if old != nil {
		cleanup = old.RetireDeferred()
	}
	p.mu.Unlock()
	if old != nil {
		cleanup()
		return old.CloseError()
	}
	return nil
}
