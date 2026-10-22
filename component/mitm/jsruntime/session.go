package jsruntime

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/component/mitm/scripthost"
)

var (
	ErrSessionDone = errors.New("javascript session is already complete")
	ErrSessionBusy = errors.New("javascript session asynchronous task limit reached")
)

// Binding, HostCall and SessionHost are kept as aliases for callers that
// already use the jsruntime session API. Their contract lives in scripthost.
type Binding = scripthost.Binding
type HostCall = scripthost.HostCall
type SessionHost = scripthost.Host

// SessionOptions configures one isolated script execution.
type SessionOptions struct {
	Globals         map[string]any
	Bindings        []Binding
	Host            SessionHost
	Timeout         time.Duration
	MaxPendingTasks int
}

// Completion is delivered to the VM owner. The callback is always invoked by
// that owner, never by the worker that produced the result.
type Completion struct {
	CallbackID uint64
	Args       []any
	Err        error
}

// Session owns the bounded cross-goroutine event queue for one VM. Methods
// that mutate completion state are intended to be called by the VM owner;
// Schedule is safe to call from that owner while workers only deliver events.
type Session struct {
	taskMu    sync.Mutex
	ctx       context.Context
	taskCtx   context.Context
	taskStop  context.CancelFunc
	execStop  context.CancelFunc
	permits   chan struct{}
	completed chan Completion
	pending   atomic.Int32
	closed    atomic.Bool
	done      bool
	result    any
	hasResult bool
}

func newSession(ctx context.Context, execStop context.CancelFunc, maxPending int) *Session {
	taskCtx, taskStop := context.WithCancel(ctx)
	return &Session{
		ctx:       ctx,
		taskCtx:   taskCtx,
		taskStop:  taskStop,
		execStop:  execStop,
		permits:   make(chan struct{}, maxPending),
		completed: make(chan Completion, maxPending),
	}
}

// Schedule starts one bounded worker. A permit remains held until the VM
// owner consumes its result, so both in-flight work and queued completions are
// included in MaxPendingTasks.
func (s *Session) Schedule(callbackID uint64, work func(context.Context) ([]any, error)) error {
	if s == nil || work == nil {
		return fmt.Errorf("invalid asynchronous task")
	}
	s.taskMu.Lock()
	defer s.taskMu.Unlock()
	if s.done || s.closed.Load() {
		return ErrSessionDone
	}
	if err := s.taskCtx.Err(); err != nil {
		return context.Cause(s.taskCtx)
	}
	select {
	case s.permits <- struct{}{}:
	default:
		return ErrSessionBusy
	}
	if err := s.taskCtx.Err(); err != nil {
		<-s.permits
		return context.Cause(s.taskCtx)
	}
	s.pending.Add(1)
	go func() {
		completion := Completion{CallbackID: callbackID}
		completion.Args, completion.Err = work(s.taskCtx)
		select {
		case s.completed <- completion:
		case <-s.taskCtx.Done():
		}
	}()
	return nil
}

// Done records the first completion. Once called, outstanding host work is
// canceled and its callbacks are discarded, while the current JavaScript
// stack is allowed to finish.
func (s *Session) Done(value any, hasValue bool) bool {
	if s == nil {
		return false
	}
	s.taskMu.Lock()
	defer s.taskMu.Unlock()
	if s.done || s.closed.Load() {
		return false
	}
	s.done = true
	s.result = value
	s.hasResult = hasValue
	s.taskStop()
	return true
}

func (s *Session) IsDone() bool {
	if s == nil {
		return false
	}
	s.taskMu.Lock()
	done := s.done
	s.taskMu.Unlock()
	return done
}

func (s *Session) Result() (any, bool) {
	if s == nil {
		return nil, false
	}
	s.taskMu.Lock()
	result, hasResult := s.result, s.hasResult
	s.taskMu.Unlock()
	return result, hasResult
}

func (s *Session) Pending() int {
	if s == nil {
		return 0
	}
	return int(s.pending.Load())
}

// Next waits for the next worker completion or the session deadline. It
// releases the task permit before returning so a callback may enqueue another
// bounded operation.
func (s *Session) Next() (Completion, error) {
	if s == nil {
		return Completion{}, errors.New("nil javascript session")
	}
	select {
	case completion := <-s.completed:
		<-s.permits
		s.pending.Add(-1)
		return completion, nil
	case <-s.ctx.Done():
		return Completion{}, s.ctx.Err()
	}
}

// Close prevents additional work and cancels workers that have not completed.
func (s *Session) Close() {
	if s == nil {
		return
	}
	s.taskMu.Lock()
	if s.closed.CompareAndSwap(false, true) {
		s.taskStop()
		if s.execStop != nil {
			s.execStop()
		}
	}
	s.taskMu.Unlock()
}
