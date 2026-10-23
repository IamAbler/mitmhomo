package generation

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/metacubex/mihomo/component/mitm/processing/model"
	"github.com/metacubex/mihomo/component/mitm/processing/pipeline"
)

func TestDeferredRetireAndExecutionReleaseCompetition(t *testing.T) {
	for i := 0; i < 100; i++ {
		resource := &closer{}
		g := New(resource)
		g.Activate()
		conn, _ := g.Bind()
		execution, _ := conn.Execution()
		conn.Close()
		gate := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); <-gate; cleanup := g.RetireDeferred(); cleanup(); cleanup() }()
		go func() { defer wg.Done(); <-gate; execution.Close() }()
		close(gate)
		wg.Wait()
		if e := g.WaitClosed(context.Background()); e != nil || resource.n.Load() != 1 {
			t.Fatal("cleanup ownership")
		}
	}
}
func TestFailedPlanReturnsExplicitOwnerWithoutClosing(t *testing.T) {
	resource := &blockingCloser{entered: make(chan struct{}), release: make(chan struct{})}
	_, err := NewPlan([]pipeline.Entry{{Class: pipeline.Script}}, resource)
	var failure *BuildError
	if !errors.As(err, &failure) {
		t.Fatal("owner missing")
	}
	if resource.n.Load() != 0 || failure.Pending.State() != Building {
		t.Fatal("constructor ran destructor")
	}
	pool := NewCleanupPool(1)
	slot, e := pool.Reserve()
	if e != nil {
		t.Fatal(e)
	}
	if e = slot.Attach(failure.Pending); e != nil {
		t.Fatal(e)
	}
	failure.Pending.Retire()
	<-resource.entered
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if !errors.Is(failure.Pending.WaitClosed(canceled), context.Canceled) {
		t.Fatal("wait did not cancel")
	}
	if _, e = pool.Reserve(); !errors.Is(e, ErrCleanupCapacity) || !errors.Is(e, model.ErrCapacityExhausted) {
		t.Fatal("blocked cleanup lost its reservation")
	}
	close(resource.release)
	if e = failure.Pending.WaitClosed(context.Background()); e != nil {
		t.Fatal(e)
	}
	if resource.n.Load() != 1 {
		t.Fatal("close count")
	}
	if e = pool.WaitIdle(context.Background()); e != nil || pool.Outstanding() != 0 {
		t.Fatal("cleanup owner not released")
	}
}

func BenchmarkManagedGenerationCleanup(b *testing.B) {
	pool := NewCleanupPool(1)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		slot, e := pool.Reserve()
		if e != nil {
			b.Fatal(e)
		}
		g := New()
		if e = slot.Attach(g); e != nil {
			b.Fatal(e)
		}
		g.Activate()
		g.Retire()
		if e = g.WaitClosed(context.Background()); e != nil {
			b.Fatal(e)
		}
		if e = pool.WaitIdle(context.Background()); e != nil {
			b.Fatal(e)
		}
	}
}
