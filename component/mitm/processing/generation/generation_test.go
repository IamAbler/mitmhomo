package generation

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

type closer struct {
	n   atomic.Int32
	err error
}

func (c *closer) Close() error { c.n.Add(1); return c.err }
func TestRetiredParentAdmission(t *testing.T) {
	c := &closer{err: errors.New("cleanup")}
	g := New(c)
	var p Publisher
	if err := p.Publish(g); err != nil {
		t.Fatal(err)
	}
	conn, err := p.Bind()
	if err != nil {
		t.Fatal(err)
	}
	next := New()
	if err := p.Publish(next); err != nil {
		t.Fatal(err)
	}
	if _, err = g.Bind(); err == nil {
		t.Fatal("retired bind")
	}
	stream, err := conn.Transaction()
	if err != nil {
		t.Fatal(err)
	}
	execution, err := stream.Execution()
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	stream.Close()
	if c.n.Load() != 0 {
		t.Fatal("early cleanup")
	}
	if _, err = conn.Execution(); err == nil {
		t.Fatal("closed parent")
	}
	execution.Close()
	execution.Close()
	g.Retire()
	g.Close()
	if c.n.Load() != 1 || !errors.Is(g.WaitClosed(context.Background()), c.err) {
		t.Fatal("cleanup ownership")
	}
	p.Close()
}
func TestPublishBindCompetition(t *testing.T) {
	for round := 0; round < 100; round++ {
		var p Publisher
		old := New()
		p.Publish(old)
		gate := make(chan struct{})
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-gate
				l, e := p.Bind()
				if e == nil {
					child, e := l.Execution()
					if e != nil {
						t.Error(e)
					} else {
						child.Close()
					}
					l.Close()
				}
			}()
		}
		for i := 0; i < 2; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-gate
				if e := p.Publish(New()); e != nil {
					t.Error(e)
				}
			}()
		}
		close(gate)
		wg.Wait()
		p.Close()
		if old.State() != Closed {
			t.Fatal("old leaked")
		}
	}
}
func TestBuildingAndClose(t *testing.T) {
	c := &closer{}
	g := New(c)
	if _, e := g.Bind(); e == nil {
		t.Fatal("building bind")
	}
	g.Close()
	if e := g.Activate(); e == nil {
		t.Fatal("resurrection")
	}
	if c.n.Load() != 1 {
		t.Fatal("cleanup")
	}
}
func BenchmarkGenerationBindRelease(b *testing.B) {
	g := New()
	g.Activate()
	defer g.Close()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		l, _ := g.Bind()
		l.Close()
	}
}
func BenchmarkGenerationParallelBind(b *testing.B) {
	var p Publisher
	p.Publish(New())
	defer p.Close()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			l, _ := p.Bind()
			l.Close()
		}
	})
}
func BenchmarkGenerationPublishRetire(b *testing.B) {
	var p Publisher
	defer p.Close()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		p.Publish(New())
	}
}
func BenchmarkGenerationPublishWithConnection(b *testing.B) {
	var p Publisher
	p.Publish(New())
	defer p.Close()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		l, _ := p.Bind()
		p.Publish(New())
		l.Close()
	}
}

type blockingCloser struct {
	entered, release chan struct{}
	n                atomic.Int32
}

func (c *blockingCloser) Close() error { c.n.Add(1); close(c.entered); <-c.release; return nil }
func TestCleanupDoesNotHoldAdmissionLock(t *testing.T) {
	c := &blockingCloser{entered: make(chan struct{}), release: make(chan struct{})}
	g := New(c)
	var p Publisher
	p.Publish(g)
	finished := make(chan struct{})
	go func() { p.Publish(New()); close(finished) }()
	<-c.entered
	l, e := p.Bind()
	if e != nil {
		t.Fatal(e)
	}
	l.Close()
	if _, e = g.Bind(); e == nil {
		t.Fatal("closing bind")
	}
	g.Retire()
	g.Close()
	select {
	case <-g.Done():
		t.Fatal("cleanup not complete")
	default:
	}
	close(c.release)
	<-finished
	if e = g.WaitClosed(context.Background()); e != nil || c.n.Load() != 1 {
		t.Fatal("cleanup")
	}
	p.Close()
}
func TestCloseAcquireCompetition(t *testing.T) {
	for round := 0; round < 100; round++ {
		c := &closer{}
		g := New(c)
		g.Activate()
		parent, _ := g.Bind()
		g.Retire()
		gate := make(chan struct{})
		done := make(chan struct{})
		child := make(chan *Lease, 1)
		go func() { <-gate; l, _ := parent.Execution(); child <- l }()
		go func() { <-gate; parent.Close(); close(done) }()
		close(gate)
		l := <-child
		<-done
		if l != nil {
			if c.n.Load() != 0 {
				t.Fatal("acquired after destruction")
			}
			l.Close()
		}
		if c.n.Load() != 1 {
			t.Fatal("not closed exactly once")
		}
	}
}
func TestPublisherFailurePreservesActive(t *testing.T) {
	var p Publisher
	g := New()
	p.Publish(g)
	bad := New()
	bad.Close()
	if e := p.Publish(bad); e == nil {
		t.Fatal("closed candidate")
	}
	l, e := p.Bind()
	if e != nil || l.ID() != g.ID() {
		t.Fatal("changed active")
	}
	l.Close()
	p.Close()
}

func BenchmarkGenerationActiveFastPath(b *testing.B) {
	g := New()
	g.Activate()
	defer g.Close()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if g.State() != Active {
			b.Fatal("inactive")
		}
	}
}
func TestWaitClosedTimeoutDoesNotRelease(t *testing.T) {
	c := &closer{}
	g := New(c)
	g.Activate()
	l, _ := g.Bind()
	g.Retire()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if !errors.Is(g.WaitClosed(ctx), context.Canceled) || c.n.Load() != 0 {
		t.Fatal("timeout released resources")
	}
	l.Close()
	if c.n.Load() != 1 {
		t.Fatal("drain")
	}
}
