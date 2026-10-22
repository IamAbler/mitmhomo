package mitm

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// A batch owns all request goroutines and their cancellation. Call Close with
// defer in the same scope as the batch (not per-cycle t.Cleanup in a soak).
type m35Batch struct {
	ctx               context.Context
	cancel            context.CancelFunc
	abort             func()
	total             int
	results           chan error
	wg                sync.WaitGroup
	waitOnce          sync.Once
	done              chan struct{}
	completed, failed atomic.Int32
}

func newM35Batch(parent context.Context, total int, timeout time.Duration, abort func()) *m35Batch {
	ctx, cancel := context.WithTimeout(parent, timeout)
	return &m35Batch{ctx: ctx, cancel: cancel, abort: abort, total: total, results: make(chan error, total), done: make(chan struct{})}
}
func (b *m35Batch) Go(run func(context.Context) error) {
	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		err := run(b.ctx)
		if err != nil {
			b.failed.Add(1)
		}
		b.completed.Add(1)
		b.results <- err
	}()
}
func (b *m35Batch) summary() string {
	completed, failed := b.completed.Load(), b.failed.Load()
	return fmt.Sprintf("total=%d completed=%d failed=%d unfinished=%d", b.total, completed, failed, b.total-int(completed))
}
func (b *m35Batch) join() <-chan struct{} {
	b.waitOnce.Do(func() { go func() { b.wg.Wait(); close(b.done) }() })
	return b.done
}
func (b *m35Batch) Close(t *testing.T) {
	t.Helper()
	b.cancel()
	select {
	case <-b.join():
		return
	case <-time.After(time.Second):
	}
	// Cancellation should suffice. Abort the owned socket if an I/O operation
	// still hasn't returned, then bound teardown itself rather than hanging tests.
	if b.abort != nil {
		b.abort()
	}
	select {
	case <-b.done:
	case <-time.After(2 * time.Second):
		t.Errorf("batch teardown timed out: %s", b.summary())
	}
}
func (b *m35Batch) collect() ([]error, error) {
	results := make([]error, 0, b.total)
	for len(results) < b.total {
		select {
		case err := <-b.results:
			results = append(results, err)
		case <-b.ctx.Done():
			// Prefer already-finished results if the deadline became ready at
			// the same instant; an arbitrary select choice must not fail a
			// completed batch.
			for len(results) < b.total {
				select {
				case err := <-b.results:
					results = append(results, err)
				default:
					return results, fmt.Errorf("batch deadline/cancel: %s: %w", b.summary(), b.ctx.Err())
				}
			}
		}
	}
	return results, nil
}
func (b *m35Batch) Wait(t *testing.T) []error {
	t.Helper()
	results, err := b.collect()
	if err != nil {
		b.cancel()
		if b.abort != nil {
			b.abort()
		}
		b.Close(t)
		t.Fatalf("%v; after cancellation: %s", err, b.summary())
	}
	return results
}
func (b *m35Batch) Await(t *testing.T, ch <-chan struct{}, n int, timeout time.Duration) {
	t.Helper()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for i := 0; i < n; i++ {
		select {
		case <-ch:
		case <-timer.C:
			b.cancel()
			if b.abort != nil {
				b.abort()
			}
			b.Close(t)
			t.Fatalf("barrier timed out (%d/%d): %s", i, n, b.summary())
		case <-b.ctx.Done():
			b.Close(t)
			t.Fatalf("batch canceled at barrier (%d/%d): %s", i, n, b.summary())
		}
	}
}

func TestM35BatchTimeoutAccounting(t *testing.T) {
	b := newM35Batch(context.Background(), 3, 50*time.Millisecond, nil)
	release := make(chan struct{})
	defer b.Close(t)
	defer close(release)
	b.Go(func(context.Context) error { return nil })
	b.Go(func(context.Context) error { return fmt.Errorf("expected worker failure") })
	b.Go(func(ctx context.Context) error { <-ctx.Done(); <-release; return ctx.Err() })
	// Acknowledge both quick workers, then return their results for collect.
	quick := make([]error, 0, 2)
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	for len(quick) < 2 {
		select {
		case err := <-b.results:
			quick = append(quick, err)
		case <-timer.C:
			t.Fatal("quick workers did not complete")
		}
	}
	for _, err := range quick {
		b.results <- err
	}
	_, err := b.collect()
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Contains(t, err.Error(), "completed=2 failed=1 unfinished=1")
	// Deferred release permits the canceled worker to finish before Close joins.
}
