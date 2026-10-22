package processor

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/metacubex/mihomo/component/mitm/processing/model"
)

type observedFinalizer struct {
	done      <-chan struct{}
	lifecycle *Lifecycle
	closed    atomic.Int32
	early     atomic.Bool
}

func (p *observedFinalizer) Close() error { p.closed.Add(1); return nil }
func (p *observedFinalizer) FinalizeExecution() {
	select {
	case <-p.done:
	default:
		p.early.Store(true)
	}
	if p.lifecycle.Active() != 0 {
		p.early.Store(true)
	}
	p.Close()
}
func TestGenerationFinalizerAfterExecutionDoneAndAdmission(t *testing.T) {
	life, _ := NewLifecycle(1)
	pin := &observedFinalizer{lifecycle: life}
	gate := &gatedCloser{entered: make(chan struct{}), release: make(chan struct{})}
	invocation, completion, e := life.BeginWithResources(context.Background(), testKey(1), pin, gate)
	if e != nil {
		t.Fatal(e)
	}
	pin.done = invocation.ExecutionDone()
	finished := make(chan struct{})
	go func() { completion.Finish(model.Continue(), nil); close(finished) }()
	<-gate.entered
	invocation.Cancel(context.Canceled)
	if _, e = invocation.Await(context.Background()); e == nil {
		t.Fatal("cancel")
	}
	if pin.closed.Load() != 0 || life.Active() != 1 {
		t.Fatal("early release")
	}
	close(gate.release)
	<-finished
	if pin.closed.Load() != 1 || pin.early.Load() || gate.count.Load() != 1 {
		t.Fatal("execution barrier")
	}
	completion.Finish(model.Continue(), nil)
	if pin.closed.Load() != 1 {
		t.Fatal("duplicate finalization")
	}
}
