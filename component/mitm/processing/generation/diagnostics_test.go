package generation

import (
	"context"
	"errors"
	"testing"
)

type diagnosticCloser struct {
	entered, release chan struct{}
	err              error
}

func (c diagnosticCloser) Close() error {
	close(c.entered)
	<-c.release
	return c.err
}

func TestCleanupDiagnosticsRetainBlockedOwner(t *testing.T) {
	pool := NewCleanupPool(1)
	want := errors.New("cleanup failed")
	c := diagnosticCloser{make(chan struct{}), make(chan struct{}), want}
	g := New(c)
	slot, err := pool.Reserve()
	if err != nil {
		t.Fatal(err)
	}
	if err = slot.Attach(g); err != nil {
		t.Fatal(err)
	}
	g.Retire()
	<-c.entered
	slot.Release() // Attached ownership cannot be abandoned.
	if _, err = pool.Reserve(); !errors.Is(err, ErrCleanupCapacity) {
		t.Fatal(err)
	}
	s := pool.Stats()
	if s.Capacity != 1 || s.Occupied != 1 || s.Cleaning != 1 || s.Rejected != 1 || s.Failures != 0 {
		t.Fatalf("blocked stats: %+v", s)
	}
	close(c.release)
	if err = pool.WaitIdle(context.Background()); err != nil {
		t.Fatal(err)
	}
	s = pool.Stats()
	if s.Occupied != 0 || s.Cleaning != 0 || s.Failures != 1 || !errors.Is(s.LastError, want) {
		t.Fatalf("completed stats: %+v", s)
	}
	slot, err = pool.Reserve()
	if err != nil {
		t.Fatal(err)
	}
	slot.Release()
	slot.Release()
	if pool.Stats().Occupied != 0 {
		t.Fatal("duplicate release")
	}
}
