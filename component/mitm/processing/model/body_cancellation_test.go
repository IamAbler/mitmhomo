package model

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type controlledBody struct {
	entered, release chan struct{}
	once             sync.Once
	reads, closes    atomic.Int32
	result           error
}

func newControlledBody() *controlledBody {
	return &controlledBody{entered: make(chan struct{}), release: make(chan struct{})}
}
func (r *controlledBody) Read(p []byte) (int, error) {
	r.reads.Add(1)
	r.once.Do(func() { close(r.entered) })
	<-r.release
	if r.result != nil {
		return 0, r.result
	}
	return copy(p, "late"), io.EOF
}
func (r *controlledBody) Close() error { r.closes.Add(1); return nil }
func awaitBody[T any](t testing.TB, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(5 * time.Second):
		t.Fatal("body operation did not finish")
	}
	var zero T
	return zero
}
func assertBodyOpen(t testing.TB, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
		t.Fatal("physical completion reported early")
	default:
	}
}

func TestBodyDeadlineReleasesCallerNotExecution(t *testing.T) {
	reader := newControlledBody()
	var release sync.Once
	unblock := func() { release.Do(func() { close(reader.release) }) }
	defer unblock()
	pool := NewBodyExecutionPool(1)
	ledger := testLedger(t, -1)
	broker, err := NewBodyBroker(context.Background(), BodySource{Reader: reader, Owner: FrameworkOwned, DeclaredLength: -1, Executions: pool}, ledger)
	if err != nil {
		t.Fatal(err)
	}
	tx, metadata := testTransaction(t, context.Background(), ledger, NewBodySlot(broker))
	metadata.Close()
	initial := ledger.Current()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	returned := make(chan error, 1)
	go func() { returned <- tx.PrepareBodyContext(ctx, FullBuffered, 1024) }()
	awaitBody(t, reader.entered)
	if err = awaitBody(t, returned); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	awaitBody(t, broker.LogicalDone())
	assertBodyOpen(t, broker.ExecutionDone())
	if ledger.Current() <= initial || reader.closes.Load() != 0 || pool.Occupied() != 1 {
		t.Fatal("early resource release")
	}
	terminated := make(chan struct{})
	go func() { tx.Terminate(context.DeadlineExceeded); close(terminated) }()
	awaitBody(t, terminated)
	if tx.State() != Terminated {
		t.Fatal("termination blocked")
	}
	closed, cancelClose := context.WithCancel(context.Background())
	cancelClose()
	if err = tx.CloseContext(closed); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if tx.State() != Closed || reader.closes.Load() != 0 {
		t.Fatal("logical close waited or closed source during Read")
	}
	assertBodyOpen(t, broker.ExecutionDone())
	unblock()
	awaitBody(t, broker.ExecutionDone())
	if err = tx.Close(); err != nil {
		t.Fatal(err)
	}
	if pool.Occupied() != 0 || ledger.Current() != 0 || reader.closes.Load() != 1 || reader.reads.Load() != 1 {
		t.Fatal("late cleanup leaked or duplicated")
	}
}

func TestTransactionCloseUsesCleanupBudgetWithoutReleasingBlockedReader(t *testing.T) {
	reader := newControlledBody()
	var release sync.Once
	unblock := func() { release.Do(func() { close(reader.release) }) }
	defer unblock()
	pool := NewBodyExecutionPool(1)
	ledger := testLedger(t, -1)
	broker, err := NewBodyBroker(context.Background(), BodySource{Reader: reader, Owner: FrameworkOwned, DeclaredLength: -1, Executions: pool}, ledger)
	if err != nil {
		t.Fatal(err)
	}
	policy := DefaultTimeoutPolicy()
	policy.CleanupWait = 25 * time.Millisecond
	tx, metadata := testTransactionWithPolicy(t, context.Background(), ledger, NewBodySlot(broker), &policy)
	metadata.Close()
	prepared := make(chan error, 1)
	go func() { prepared <- tx.PrepareBodyContext(context.Background(), FullBuffered, 16) }()
	awaitBody(t, reader.entered)
	if err = tx.Close(); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Close exceeded or ignored its cleanup wait budget: %v", err)
	}
	assertBodyOpen(t, broker.ExecutionDone())
	if reader.closes.Load() != 0 || pool.Occupied() != 1 {
		t.Fatal("cleanup timeout released a live Reader owner")
	}
	unblock()
	if err = awaitBody(t, prepared); !errors.Is(err, context.Canceled) {
		t.Fatalf("late body operation lost transaction cancellation: %v", err)
	}
	awaitBody(t, broker.ExecutionDone())
	if err = tx.Close(); err != nil {
		t.Fatal(err)
	}
	if pool.Occupied() != 0 || reader.closes.Load() != 1 || ledger.Current() != 0 {
		t.Fatalf("physical cleanup did not recover: pool=%d closes=%d bytes=%d", pool.Occupied(), reader.closes.Load(), ledger.Current())
	}
}

func TestTransactionBodyIOTimeoutIsAppliedOutsidePipeline(t *testing.T) {
	reader := newControlledBody()
	var release sync.Once
	unblock := func() { release.Do(func() { close(reader.release) }) }
	defer unblock()
	pool := NewBodyExecutionPool(1)
	ledger := testLedger(t, -1)
	broker, err := NewBodyBroker(context.Background(), BodySource{Reader: reader, Owner: FrameworkOwned, DeclaredLength: -1, Executions: pool}, ledger)
	if err != nil {
		t.Fatal(err)
	}
	policy := DefaultTimeoutPolicy()
	policy.BodyIO = 25 * time.Millisecond
	tx, metadata := testTransactionWithPolicy(t, context.Background(), ledger, NewBodySlot(broker), &policy)
	metadata.Close()
	returned := make(chan error, 1)
	go func() { returned <- tx.PrepareBodyContext(context.Background(), FullBuffered, 16) }()
	awaitBody(t, reader.entered)
	if err = awaitBody(t, returned); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Transaction BodyIO timeout did not reach the Reader: %v", err)
	}
	assertBodyOpen(t, broker.ExecutionDone())
	if pool.Occupied() != 1 || reader.closes.Load() != 0 {
		t.Fatal("BodyIO timeout released a live source owner")
	}
	unblock()
	awaitBody(t, broker.ExecutionDone())
	if err = tx.Close(); err != nil {
		t.Fatal(err)
	}
	if pool.Occupied() != 0 || ledger.Current() != 0 || reader.closes.Load() != 1 {
		t.Fatal("BodyIO timeout did not drain exactly once")
	}
}

func TestBodyExplicitInterruptAndAdmission(t *testing.T) {
	for _, interruptible := range []bool{false, true} {
		t.Run(map[bool]string{false: "noncooperative", true: "interruptible"}[interruptible], func(t *testing.T) {
			reader := newControlledBody()
			var release sync.Once
			unblock := func() { release.Do(func() { close(reader.release) }) }
			defer unblock()
			pool := NewBodyExecutionPool(1)
			ledger := testLedger(t, -1)
			source := BodySource{Reader: reader, Owner: TransportOwned, DeclaredLength: -1, Executions: pool}
			if interruptible {
				source.Interrupt = unblock
			}
			broker, err := NewBodyBroker(context.Background(), source, ledger)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			returned := make(chan error, 1)
			go func() { returned <- broker.Prepare(ctx, FullBuffered, 32) }()
			awaitBody(t, reader.entered)
			busyLease := NewCopyLease(ledger)
			_, err = broker.Snapshot(busyLease)
			busyLease.Close()
			if !errors.Is(err, ErrBodyBusy) {
				t.Fatal(err)
			}
			duplicateCtx, stopDuplicate := context.WithCancel(context.Background())
			duplicate := make(chan error, 1)
			go func() { duplicate <- broker.Prepare(duplicateCtx, FullBuffered, 32) }()
			stopDuplicate()
			if err = awaitBody(t, duplicate); !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			if reader.reads.Load() != 1 {
				t.Fatal("duplicate concurrent Read")
			}
			cancel()
			if err = awaitBody(t, returned); !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			if !interruptible {
				assertBodyOpen(t, broker.ExecutionDone())
				broker.CloseLogical()
				if _, err = NewBodyBroker(context.Background(), source, ledger); !errors.Is(err, ErrBodyCapacity) || !errors.Is(err, ErrResourceLimit) {
					t.Fatal(err)
				}
				if reader.closes.Load() != 0 || pool.Occupied() != 1 {
					t.Fatal("cancellation abandoned owner")
				}
				unblock()
			}
			awaitBody(t, broker.ExecutionDone())
			if err = broker.Close(); err != nil {
				t.Fatal(err)
			}
			if pool.Occupied() != 0 || ledger.Current() != 0 || reader.closes.Load() != 1 {
				t.Fatal("drain failed")
			}
			replacement := io.NopCloser(&emptyBodyReader{})
			next, err := NewBodyBroker(context.Background(), BodySource{Reader: replacement, Owner: FrameworkOwned, DeclaredLength: -1, Executions: pool}, ledger)
			if err != nil {
				t.Fatal("slot was not reusable", err)
			}
			next.Close()
		})
	}
}

type emptyBodyReader struct{}

func (*emptyBodyReader) Read([]byte) (int, error) { return 0, io.EOF }

func TestBodyCanceledAndStaleReadCannotPublish(t *testing.T) {
	for _, mode := range []string{"parent-cancel", "revision-change"} {
		t.Run(mode, func(t *testing.T) {
			reader := newControlledBody()
			var release sync.Once
			unblock := func() { release.Do(func() { close(reader.release) }) }
			defer unblock()
			ledger := testLedger(t, -1)
			broker, err := NewBodyBroker(context.Background(), BodySource{Reader: reader, Owner: FrameworkOwned, DeclaredLength: -1}, ledger)
			if err != nil {
				t.Fatal(err)
			}
			parent, cancel := context.WithCancelCause(context.Background())
			defer cancel(context.Canceled)
			tx, metadata := testTransaction(t, parent, ledger, NewBodySlot(broker))
			metadata.Close()
			input, copy, err := tx.Snapshot("before-read")
			if err != nil {
				t.Fatal(err)
			}
			defer copy.Close()
			returned := make(chan error, 1)
			go func() { returned <- tx.PrepareBodyContext(context.Background(), FullBuffered, 32) }()
			awaitBody(t, reader.entered)
			if mode == "parent-cancel" {
				// Hold only the test's state barrier: the real Read no longer holds it.
				func() {
					tx.mu.Lock()
					defer tx.mu.Unlock()
					unblock()
					cancel(context.DeadlineExceeded)
					err = awaitBody(t, returned)
				}()
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal(err)
				}
			} else {
				if err = tx.UpdateRequest(input.Key().Revision, input.Request()); err != nil {
					t.Fatal(err)
				}
				unblock()
				if err = awaitBody(t, returned); !errors.Is(err, ErrStaleRevision) {
					t.Fatal(err)
				}
			}
			awaitBody(t, broker.ExecutionDone())
			if broker.Info().State != Faulted || reader.closes.Load() != 1 || reader.reads.Load() != 1 {
				t.Fatal("late body published")
			}
			copy.Close()
			tx.Close()
			if ledger.Current() != 0 {
				t.Fatal("late body charge leaked")
			}
		})
	}
}

func TestBodyReadFinishTerminateCompetition(t *testing.T) {
	for round := 0; round < 40; round++ {
		reader := newControlledBody()
		var release sync.Once
		unblock := func() { release.Do(func() { close(reader.release) }) }
		defer unblock()
		if round%2 == 0 {
			reader.result = io.ErrUnexpectedEOF
		}
		ledger := testLedger(t, -1)
		broker, err := NewBodyBroker(context.Background(), BodySource{Reader: reader, Owner: FrameworkOwned, DeclaredLength: -1}, ledger)
		if err != nil {
			t.Fatal(err)
		}
		tx, metadata := testTransaction(t, context.Background(), ledger, NewBodySlot(broker))
		metadata.Close()
		returned := make(chan error, 1)
		go func() { returned <- tx.PrepareBody(FullBuffered, 32) }()
		awaitBody(t, reader.entered)
		gate := make(chan struct{})
		var joined sync.WaitGroup
		joined.Add(2)
		go func() { defer joined.Done(); <-gate; unblock() }()
		go func() { defer joined.Done(); <-gate; tx.Terminate(context.DeadlineExceeded) }()
		close(gate)
		joined.Wait()
		_ = awaitBody(t, returned)
		tx.Close()
		awaitBody(t, broker.ExecutionDone())
		if tx.State() != Closed || reader.closes.Load() != 1 || reader.reads.Load() != 1 || ledger.Current() != 0 {
			t.Fatal("race leaked or duplicated resources")
		}
	}
}

type blockingBodyCloser struct {
	entered, release chan struct{}
	closes           atomic.Int32
}

func (*blockingBodyCloser) Read([]byte) (int, error) { return 0, io.EOF }
func (r *blockingBodyCloser) Close() error {
	r.closes.Add(1)
	close(r.entered)
	<-r.release
	return nil
}
func TestBodyBlockedDisposalRetainsExecutionOwner(t *testing.T) {
	reader := &blockingBodyCloser{entered: make(chan struct{}), release: make(chan struct{})}
	var release sync.Once
	unblock := func() { release.Do(func() { close(reader.release) }) }
	defer unblock()
	ledger := testLedger(t, -1)
	pool := NewBodyExecutionPool(1)
	broker, err := NewBodyBroker(context.Background(), BodySource{Reader: reader, Owner: TransportOwned, DeclaredLength: -1, Executions: pool}, ledger)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(context.Canceled)
	returned := make(chan error, 1)
	go func() { returned <- broker.Prepare(ctx, FullBuffered, 32) }()
	awaitBody(t, reader.entered)
	cancel(context.DeadlineExceeded)
	if err = awaitBody(t, returned); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	broker.CloseLogical()
	assertBodyOpen(t, broker.ExecutionDone())
	if ledger.Current() == 0 || pool.Occupied() != 1 || reader.closes.Load() != 1 {
		t.Fatal("blocked disposer lost ownership")
	}
	unblock()
	awaitBody(t, broker.ExecutionDone())
	broker.Close()
	if ledger.Current() != 0 || pool.Occupied() != 0 || reader.closes.Load() != 1 {
		t.Fatal("disposal duplicated or leaked")
	}
}

func TestBodyGlobalOwnerCapacityCannotBeBypassed(t *testing.T) {
	var brokers []*BodyBroker
	defer func() {
		for _, broker := range brokers {
			broker.Close()
		}
	}()
	for i := 0; i < 64; i++ {
		ledger := testLedger(t, 0)
		broker, err := NewBodyBroker(context.Background(), BodySource{Reader: io.NopCloser(&emptyBodyReader{}), Owner: FrameworkOwned, DeclaredLength: -1, Executions: NewBodyExecutionPool(1000)}, ledger)
		if err != nil {
			t.Fatal(i, err)
		}
		brokers = append(brokers, broker)
	}
	if _, err := NewBodyBroker(context.Background(), BodySource{Reader: io.NopCloser(&emptyBodyReader{}), Owner: FrameworkOwned, DeclaredLength: -1, Executions: NewBodyExecutionPool(1000)}, testLedger(t, 0)); !errors.Is(err, ErrBodyCapacity) {
		t.Fatal(err)
	}
	if defaultBodyExecutions.Occupied() != 64 {
		t.Fatal("global cap bypassed")
	}
}

func TestBodyStreamingCancellationAndBorrowedBuffer(t *testing.T) {
	for _, interruptible := range []bool{false, true} {
		t.Run(map[bool]string{false: "retained-read", true: "safe-interrupt"}[interruptible], func(t *testing.T) {
			reader := newControlledBody()
			var once sync.Once
			unblock := func() { once.Do(func() { close(reader.release) }) }
			defer unblock()
			ledger := testLedger(t, 0)
			pool := NewBodyExecutionPool(1)
			source := BodySource{Reader: reader, Owner: FrameworkOwned, DeclaredLength: -1, Executions: pool}
			if interruptible {
				source.Interrupt = unblock
			}
			broker, err := NewBodyBroker(context.Background(), source, ledger)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			stream, err := broker.TakeStream(ctx)
			if err != nil {
				t.Fatal(err)
			}
			buffer := make([]byte, 16)
			readReturned := make(chan error, 1)
			go func() { _, err := stream.Read(buffer); readReturned <- err }()
			awaitBody(t, reader.entered)
			if _, err = stream.Read(make([]byte, 1)); !errors.Is(err, ErrBodyBusy) {
				t.Fatal("concurrent stream Read accepted", err)
			}
			cancel()
			awaitBody(t, broker.LogicalDone())
			if !interruptible {
				assertBodyOpen(t, broker.ExecutionDone())
				if pool.Occupied() != 1 || reader.closes.Load() != 0 {
					t.Fatal("stream lost borrowed resources")
				}
				if err = broker.CloseContext(ctx); !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
				unblock()
			}
			if err = awaitBody(t, readReturned); !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			broker.Close()
			awaitBody(t, broker.ExecutionDone())
			if reader.closes.Load() != 1 || reader.reads.Load() != 1 || pool.Occupied() != 0 || ledger.Current() != 0 {
				t.Fatal("stream drain leaked")
			}
		})
	}
}

func TestBodyStreamingReadHasNoPerReadAllocation(t *testing.T) {
	ledger := testLedger(t, 0)
	broker, constructionErr := NewBodyBroker(context.Background(), BodySource{Reader: io.NopCloser(&generatedBody{10000}), Owner: FrameworkOwned, DeclaredLength: 10000}, ledger)
	if constructionErr != nil {
		t.Fatal(constructionErr)
	}
	defer broker.Close()
	stream, err := broker.TakeStream(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 1)
	allocations := testing.AllocsPerRun(100, func() { _, err = stream.Read(buffer) })
	if err != nil || allocations != 0 {
		t.Fatalf("stream Read: %v, allocations=%g", err, allocations)
	}
}

func BenchmarkBodyStreaming32MiB(b *testing.B) {
	ledger, _ := NewLedger(0, nil)
	b.ReportAllocs()
	b.SetBytes(32 << 20)
	for i := 0; i < b.N; i++ {
		broker, err := NewBodyBroker(context.Background(), BodySource{Reader: io.NopCloser(&generatedBody{32 << 20}), Owner: TransportOwned, DeclaredLength: 32 << 20}, ledger)
		if err != nil {
			b.Fatal(err)
		}
		stream, err := broker.TakeStream(context.Background())
		if err != nil {
			b.Fatal(err)
		}
		if _, err = io.Copy(io.Discard, stream); err != nil {
			b.Fatal(err)
		}
		broker.Close()
	}
}
