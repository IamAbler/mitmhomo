package model

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

func testHead(t testing.TB, lease *CopyLease, method, target string) RequestHead {
	t.Helper()
	u, err := ParseURL(lease, target, MITMHTTPS)
	if err != nil {
		t.Fatal(err)
	}
	h, err := NewHeaderBlock(lease, []HeaderField{{"X-Test", []string{"original"}}})
	if err != nil {
		t.Fatal(err)
	}
	return RequestHead{Method: method, URL: u, Authority: "host-override.example", Headers: h}
}
func testTransaction(t testing.TB, ctx context.Context, l *Ledger, source BodySlot) (*Transaction, *CopyLease) {
	return testTransactionWithPolicy(t, ctx, l, source, nil)
}

func testTransactionWithPolicy(t testing.TB, ctx context.Context, l *Ledger, source BodySlot, policy *TimeoutPolicy) (*Transaction, *CopyLease) {
	t.Helper()
	lease := NewCopyLease(l)
	head := testHead(t, lease, "POST", "https://example.test/a%2Fb?b=2&a=&b=1")
	tx, err := NewTransaction(ctx, TransactionOptions{ID: "tx-1", Generation: 7, Connection: ConnectionView{ID: "conn-1", StreamID: "stream-1", Downstream: ProtocolInfo{Major: 2, Known: true}}, OriginalIngress: head, Request: head, RequestBody: source, Ledger: l, Timeouts: policy})
	if err != nil {
		lease.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { tx.Close(); lease.Close() })
	return tx, lease
}

func TestTransactionSnapshotIsolationAndRevision(t *testing.T) {
	l := testLedger(t, -1)
	b, _ := testBody(t, context.Background(), strings.NewReader("old"), FrameworkOwned, 3, l)
	tx, sourceLease := testTransaction(t, context.Background(), l, NewBodySlot(b))
	sourceLease.Close()
	if err := tx.PrepareBody(FullBuffered, 3); err != nil {
		t.Fatal(err)
	}
	first, firstLease, err := tx.Snapshot("first")
	if err != nil {
		t.Fatal(err)
	}
	defer firstLease.Close()
	second, secondLease, err := tx.Snapshot("second")
	if err != nil {
		t.Fatal(err)
	}
	defer secondLease.Close()
	if first.Key().Generation != 7 || first.Key().Revision != 1 || first.Key().Invocation == second.Key().Invocation || first.Key().Phase != RequestPhase {
		t.Fatal("identity lost")
	}
	head := first.Request()
	head.Method = "PATCH"
	values, _, err := head.Headers.Values("x-test")
	if err != nil {
		t.Fatal(err)
	}
	values[0] = "outside"
	body, err := first.Body().BytesCopy()
	if err != nil {
		t.Fatal(err)
	}
	body[0] = 'X'
	if err := tx.UpdateRequest(first.Key().Revision, head); err != nil {
		t.Fatal(err)
	}
	if err := tx.UpdateRequest(first.Key().Revision, head); !errors.Is(err, ErrStaleRevision) {
		t.Fatal("stale revision accepted", err)
	}
	if err := tx.ReplaceBody(tx.Revision(), []byte("new")); err != nil {
		t.Fatal(err)
	}
	current, lease, err := tx.Snapshot("third")
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	if current.Request().Method != "PATCH" || first.Request().Method != "POST" || current.OriginalIngress().Method != "POST" || current.OriginalPhaseRequest().Method != "POST" {
		t.Fatal("metadata snapshots aliased")
	}
	if current.Request().Authority == current.Request().URL.Host() {
		t.Fatal("authority conflated with target")
	}
	for _, item := range []struct {
		input Input
		want  string
	}{{first, "old"}, {second, "old"}, {current, "new"}} {
		got, err := item.input.Body().BytesCopy()
		if err != nil || string(got) != item.want {
			t.Fatal("body snapshots aliased", err)
		}
		values, _, err := item.input.Request().Headers.Values("x-test")
		if err != nil || values[0] != "original" {
			t.Fatal("header snapshot aliased")
		}
	}
	tx.Close()
	if l.Current() == 0 {
		t.Fatal("Transaction.Close released live execution inputs")
	}
	if _, err := first.Body().BytesCopy(); err != nil {
		t.Fatal("live input invalidated by transaction close", err)
	}
	firstLease.Close()
	secondLease.Close()
	lease.Close()
	if l.Current() != 0 {
		t.Fatalf("remaining copy charges=%d", l.Current())
	}
}

func TestTransactionResponseEntryAndFailureRollback(t *testing.T) {
	l := testLedger(t, -1)
	tx, sourceLease := testTransaction(t, context.Background(), l, BodySlot{})
	sourceLease.Close()
	lease := testLease(t, l)
	headers, _ := NewHeaderBlock(lease, []HeaderField{{"Set-Cookie", []string{"a=1", "b=2"}}})
	response := ResponseHead{Status: 200, Headers: headers}
	before := l.Current()
	if err := tx.EnterResponse(tx.Revision(), response, ResponseHead{Status: 101}, BodySlot{}, OriginUpstream); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	if l.Current() != before || tx.Phase() != RequestPhase || tx.Revision() != 1 {
		t.Fatal("failed response entry partially committed")
	}
	b, _ := testBody(t, context.Background(), strings.NewReader("response"), TransportOwned, 8, l)
	if err := tx.EnterResponse(1, response, response, NewBodySlot(b), OriginUpstream); err != nil {
		t.Fatal(err)
	}
	if err := tx.PrepareBody(FullBuffered, 8); err != nil {
		t.Fatal(err)
	}
	response.Status = 201
	if err := tx.UpdateResponse(tx.Revision(), response); err != nil {
		t.Fatal(err)
	}
	input, inputLease, err := tx.Snapshot("response")
	if err != nil {
		t.Fatal(err)
	}
	defer inputLease.Close()
	current, ok := input.Response()
	if !ok || current.Status != 201 || input.OriginalResponse().Status != 200 || input.OriginalPhaseResponse().Status != 200 || input.Origin() != OriginUpstream {
		t.Fatal("response phase lost originals")
	}
	if err := tx.UpdateRequest(tx.Revision(), input.Request()); !errors.Is(err, ErrInvalid) {
		t.Fatal("response stage changed request")
	}
	if err := tx.EnterResponse(tx.Revision(), response, response, BodySlot{}, OriginSynthetic); !errors.Is(err, ErrInvalid) {
		t.Fatal("response entered twice")
	}
}

func TestResponseBodyUsesTransactionBudget(t *testing.T) {
	transactionLedger := testLedger(t, -1)
	tx, sourceLease := testTransaction(t, context.Background(), transactionLedger, BodySlot{})
	sourceLease.Close()
	responseLedger := testLedger(t, -1)
	body, _ := testBody(t, context.Background(), strings.NewReader("response"), TransportOwned, 8, responseLedger)
	if err := tx.EnterResponse(tx.Revision(), ResponseHead{Status: 200}, ResponseHead{Status: 200}, NewBodySlot(body), OriginUpstream); err != nil {
		t.Fatal(err)
	}
	beforeTransaction := tx.Ledger().Current()
	beforeResponse := responseLedger.Current()
	if err := tx.PrepareBody(FullBuffered, 8); err != nil {
		t.Fatal(err)
	}
	if tx.Ledger().Current() < beforeTransaction+8 {
		t.Fatal("response body bytes escaped the Transaction ledger")
	}
	if responseLedger.Current() != beforeResponse {
		t.Fatal("response body kept charging its detached construction ledger")
	}
}

func TestTransactionBodyReplacementRespectsDefaultBufferCap(t *testing.T) {
	ledger := testLedger(t, -1)
	body, source := testBody(t, context.Background(), strings.NewReader("source"), TransportOwned, -1, ledger)
	tx, metadata := testTransaction(t, context.Background(), ledger, NewBodySlot(body))
	metadata.Close()
	before := tx.Revision()
	replacement := make([]byte, DefaultBodyBufferBytes+1)
	if err := tx.ReplaceBody(before, replacement); !errors.Is(err, ErrBodyLimit) {
		t.Fatalf("oversized body replacement was accepted: %v", err)
	}
	if tx.Revision() != before || source.reads.Load() != 0 || body.Info().State != UnreadStream {
		t.Fatal("rejected body replacement mutated the Transaction or consumed its source")
	}
}

func TestTransactionDeadlineTerminateAndClose(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	l := testLedger(t, -1)
	tx, lease := testTransaction(t, ctx, l, BodySlot{})
	lease.Close()
	deadline, ok := tx.Deadline()
	parentDeadline, _ := ctx.Deadline()
	if !ok || !deadline.Equal(parentDeadline) {
		t.Fatal("deadline not inherited")
	}
	cause := errors.New("owner abort")
	tx.Terminate(cause)
	if tx.State() != Terminated || !errors.Is(tx.CancellationCause(), cause) {
		t.Fatal("termination lost cause")
	}
	if _, _, err := tx.Snapshot("late"); !errors.Is(err, ErrClosed) {
		t.Fatal("snapshot after termination accepted")
	}
	tx.Close()
	tx.Close()
	if tx.State() != Closed || !errors.Is(tx.CancellationCause(), cause) || l.Current() != 0 {
		t.Fatal("close not terminal/idempotent")
	}
}

func TestTransactionTimeoutInheritsParentAndEnforcesItsOwnDeadline(t *testing.T) {
	parent, cancelParent := context.WithCancelCause(context.Background())
	policy := DefaultTimeoutPolicy()
	policy.Transaction = time.Second
	ledger := testLedger(t, -1)
	tx, sourceLease := testTransactionWithTimeout(t, parent, ledger, policy)
	sourceLease.Close()
	cancelParent(context.Canceled)
	select {
	case <-tx.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("parent cancellation did not propagate")
	}
	if !errors.Is(tx.CancellationCause(), context.Canceled) {
		t.Fatalf("parent cause was lost: %v", tx.CancellationCause())
	}
	tx.Close()

	deadlineParent, cancelDeadlineParent := context.WithTimeout(context.Background(), 500*time.Millisecond)
	policy.Transaction = time.Second
	txParentDeadline, sourceLeaseParent := testTransactionWithTimeout(t, deadlineParent, testLedger(t, -1), policy)
	sourceLeaseParent.Close()
	parentDeadline, _ := deadlineParent.Deadline()
	if got, ok := txParentDeadline.Deadline(); !ok || got.After(parentDeadline) {
		t.Fatal("transaction deadline exceeded its parent")
	}
	cancelDeadlineParent()
	txParentDeadline.Close()

	policy = DefaultTimeoutPolicy()
	policy.Transaction = 30 * time.Millisecond
	tx2, sourceLease2 := testTransactionWithTimeout(t, context.Background(), testLedger(t, -1), policy)
	defer sourceLease2.Close()
	select {
	case <-tx2.Context().Done():
		if !errors.Is(tx2.CancellationCause(), context.DeadlineExceeded) {
			t.Fatalf("transaction timeout cause was lost: %v", tx2.CancellationCause())
		}
	case <-time.After(time.Second):
		t.Fatal("transaction total timeout was not enforced")
	}
	tx2.Close()
}

func testTransactionWithTimeout(t testing.TB, ctx context.Context, ledger *Ledger, policy TimeoutPolicy) (*Transaction, *CopyLease) {
	t.Helper()
	lease := NewCopyLease(ledger)
	head := testHead(t, lease, "POST", "https://example.test/timeout")
	tx, err := NewTransaction(ctx, TransactionOptions{
		ID: "tx-timeout", Generation: 9, Connection: ConnectionView{ID: "conn-timeout"},
		OriginalIngress: head, Request: head, Ledger: ledger, Timeouts: &policy,
	})
	if err != nil {
		lease.Close()
		t.Fatal(err)
	}
	return tx, lease
}

func TestConcurrentTransactionSnapshotAndClose(t *testing.T) {
	l := testLedger(t, -1)
	tx, sourceLease := testTransaction(t, context.Background(), l, BodySlot{})
	sourceLease.Close()
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			input, lease, err := tx.Snapshot("concurrent")
			if err != nil {
				if !errors.Is(err, ErrClosed) && !errors.Is(err, context.Canceled) {
					t.Error(err)
				}
				return
			}
			defer lease.Close()
			if values, _, err := input.Request().Headers.Values("x-test"); err != nil || values[0] != "original" {
				t.Error("live snapshot invalid after Close", err)
			}
		}()
	}
	wg.Add(1)
	go func() { defer wg.Done(); <-start; tx.Close() }()
	close(start)
	wg.Wait()
	if l.Current() != 0 {
		t.Fatal("concurrent inputs leaked")
	}
}

func TestTransactionBudgetFailureHasNoPartialOccupancy(t *testing.T) {
	l := testLedger(t, 20000)
	tx, sourceLease := testTransaction(t, context.Background(), l, BodySlot{})
	sourceLease.Close()
	before := l.Current()
	reservation, err := l.Reserve(20000 - before - 10)
	if err != nil {
		t.Fatal(err)
	}
	full := l.Current()
	if _, _, err := tx.Snapshot("too-large"); !errors.Is(err, ErrResourceLimit) {
		t.Fatal(err)
	}
	if l.Current() != full {
		t.Fatal("failed snapshot retained partial reservations")
	}
	reservation.Release()
	input, lease, err := tx.Snapshot("valid")
	if err != nil {
		t.Fatal(err)
	}
	if input.Request().URL.RawQuery() != "b=2&a=&b=1" {
		t.Fatal("query changed")
	}
	lease.Close()
	if l.Current() != before {
		t.Fatal("completed snapshot leaked")
	}
}

func TestTransactionBodyStreamBoundary(t *testing.T) {
	l := testLedger(t, -1)
	b, _ := testBody(t, context.Background(), strings.NewReader("abc"), TransportOwned, 3, l)
	tx, sourceLease := testTransaction(t, context.Background(), l, NewBodySlot(b))
	sourceLease.Close()
	stream, err := tx.TakeBody()
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.ReplaceBody(tx.Revision(), []byte("new")); !errors.Is(err, ErrBodyClaimed) {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, stream); err != nil {
		t.Fatal(err)
	}
	stream.Close()
	tx.Close()
}

func TestConcurrentTransactionRevisionAdmission(t *testing.T) {
	l := testLedger(t, -1)
	tx, sourceLease := testTransaction(t, context.Background(), l, BodySlot{})
	sourceLease.Close()
	input, lease, err := tx.Snapshot("owner-checkpoint")
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	first, second := input.Request(), input.Request()
	first.Method, second.Method = "PATCH", "PUT"
	gate := make(chan struct{})
	results := make(chan error, 2)
	go func() { <-gate; results <- tx.UpdateRequest(1, first) }()
	go func() { <-gate; results <- tx.UpdateRequest(1, second) }()
	close(gate)
	success := 0
	for i := 0; i < 2; i++ {
		err := <-results
		if err == nil {
			success++
		} else if !errors.Is(err, ErrStaleRevision) {
			t.Fatal(err)
		}
	}
	if success != 1 || tx.Revision() != 2 || input.Request().Method != "POST" {
		t.Fatal("stale writer overwrote current revision")
	}
}
