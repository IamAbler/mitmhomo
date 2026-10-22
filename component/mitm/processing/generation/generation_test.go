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
