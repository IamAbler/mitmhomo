package model

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
)

func TestCommitRequestPatchIsAtomicAndRevisionBound(t *testing.T) {
	ledger := testLedger(t, -1)
	body, _ := testBody(t, context.Background(), strings.NewReader("old"), FrameworkOwned, 3, ledger)
	tx, sourceLease := testTransaction(t, context.Background(), ledger, NewBodySlot(body))
	sourceLease.Close()
	input, inputLease, err := tx.Snapshot("commit-request")
	if err != nil {
		t.Fatal(err)
	}
	defer inputLease.Close()
	result, err := ChangeRequest(RequestPatch{
		Method:  Optional[string]{Present: true, Value: "PATCH"},
		Headers: []HeaderEdit{{Kind: HeaderSet, Name: "X-Test", Values: []string{"changed"}}},
		Body:    BodyEdit{Kind: BodyReplace, Bytes: []byte("new")},
	}, ledger, 16)
	if err != nil {
		t.Fatal(err)
	}
	defer result.Release()
	kind, err := tx.Commit(input, result)
	if err != nil || kind != ResultRequestChange || tx.Revision() != 2 {
		t.Fatalf("commit failed: kind=%d revision=%d err=%v", kind, tx.Revision(), err)
	}
	if _, err := tx.Commit(input, result); !errors.Is(err, ErrStaleRevision) {
		t.Fatalf("stale input committed: %v", err)
	}
	current, lease, err := tx.Snapshot("after-request-commit")
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	values, _, err := current.Request().Headers.Values("x-test")
	if err != nil || len(values) != 1 || values[0] != "changed" || current.Request().Method != "PATCH" {
		t.Fatalf("request patch missing: method=%q values=%v err=%v", current.Request().Method, values, err)
	}
	got, err := current.Body().BytesCopy()
	if err != nil || string(got) != "new" {
		t.Fatalf("body patch missing: %q err=%v", got, err)
	}
	if input.Request().Method != "POST" {
		t.Fatal("committing changed the detached input")
	}
}

func TestCommitFailureDoesNotPartiallyApplyHead(t *testing.T) {
	ledger := testLedger(t, -1)
	body, _ := testBody(t, context.Background(), strings.NewReader("old"), FrameworkOwned, 3, ledger)
	tx, sourceLease := testTransaction(t, context.Background(), ledger, NewBodySlot(body))
	sourceLease.Close()
	stream, err := tx.TakeBody()
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	input, inputLease, err := tx.Snapshot("failed-commit")
	if err != nil {
		t.Fatal(err)
	}
	defer inputLease.Close()
	result, err := ChangeRequest(RequestPatch{
		Method:  Optional[string]{Present: true, Value: "PATCH"},
		Headers: []HeaderEdit{{Kind: HeaderSet, Name: "X-Test", Values: []string{"changed"}}},
		Body:    BodyEdit{Kind: BodyReplace, Bytes: []byte("new")},
	}, ledger, 16)
	if err != nil {
		t.Fatal(err)
	}
	defer result.Release()
	if _, err := tx.Commit(input, result); !errors.Is(err, ErrBodyClaimed) {
		t.Fatalf("expected claimed body failure: %v", err)
	}
	current, lease, err := tx.Snapshot("after-failed-commit")
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	if current.Request().Method != "POST" || tx.Revision() != 1 || tx.Outcome() != ExchangePending {
		t.Fatal("failed commit partially changed transaction metadata")
	}
	values, _, err := current.Request().Headers.Values("x-test")
	if err != nil || values[0] != "original" {
		t.Fatalf("failed commit changed headers: %v %v", values, err)
	}
}

func TestCommitRespondTransfersIndependentSyntheticOwnership(t *testing.T) {
	ledger := testLedger(t, -1)
	tx, sourceLease := testTransaction(t, context.Background(), ledger, BodySlot{})
	sourceLease.Close()
	input, inputLease, err := tx.Snapshot("respond")
	if err != nil {
		t.Fatal(err)
	}
	defer inputLease.Close()
	headersLease := NewCopyLease(ledger)
	headers, err := NewHeaderBlock(headersLease, []HeaderField{{Name: "Content-Type", Values: []string{"text/plain"}}})
	if err != nil {
		t.Fatal(err)
	}
	trailers, err := NewTrailerView(TrailerUnavailable, HeaderBlock{}, HeaderBlock{})
	if err != nil {
		t.Fatal(err)
	}
	synthetic, err := NewSyntheticResponse(200, headers, []byte("hello"), trailers, ledger, 32)
	if err != nil {
		t.Fatal(err)
	}
	result, err := Respond(synthetic)
	if err != nil {
		t.Fatal(err)
	}
	if kind, err := tx.Commit(input, result); err != nil || kind != ResultRespond {
		t.Fatalf("respond commit failed: kind=%d err=%v", kind, err)
	}
	if err := result.Release(); err != nil {
		t.Fatal(err)
	}
	owned, ok := tx.TakeSynthetic()
	if !ok {
		t.Fatal("transaction did not retain its synthetic response")
	}
	if _, ok := tx.TakeSynthetic(); ok {
		t.Fatal("synthetic response transferred twice")
	}
	got, err := owned.BodyBytesCopy()
	if err != nil || string(got) != "hello" || owned.Status() != 200 {
		t.Fatalf("transaction response lost ownership: status=%d body=%q err=%v", owned.Status(), got, err)
	}
	_ = owned.Release()
	_ = headersLease.Close()
}

func TestClaimMainUpstreamIsSingleAndGenerationBound(t *testing.T) {
	ledger := testLedger(t, -1)
	tx, sourceLease := testTransaction(t, context.Background(), ledger, BodySlot{})
	sourceLease.Close()
	input, lease, err := tx.Snapshot("claim-upstream")
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	if revision, err := tx.ClaimMainUpstream(input); err != nil || revision != 2 || tx.Outcome() != ExchangeUpstreamIssued {
		t.Fatalf("main upstream was not claimed: revision=%d outcome=%d err=%v", revision, tx.Outcome(), err)
	}
	if _, err := tx.ClaimMainUpstream(input); !errors.Is(err, ErrStaleRevision) {
		t.Fatalf("duplicate/stale upstream claim accepted: %v", err)
	}
	egress, egressLease, err := tx.Snapshot("after-upstream")
	if err != nil {
		t.Fatalf("read-only request egress snapshot failed: %v", err)
	}
	defer egressLease.Close()
	if _, err := tx.Commit(egress, Continue()); !errors.Is(err, ErrClosed) {
		t.Fatalf("request result committed after upstream claim: %v", err)
	}
}

func TestCommitBindsConnectionAndSingleInvocation(t *testing.T) {
	ledger := testLedger(t, -1)
	firstTx, firstLease := testTransaction(t, context.Background(), ledger, BodySlot{})
	firstLease.Close()
	input, inputLease, err := firstTx.Snapshot("first-owner")
	if err != nil {
		t.Fatal(err)
	}
	defer inputLease.Close()

	otherConnectionHeadLease := NewCopyLease(ledger)
	otherHead := testHead(t, otherConnectionHeadLease, "POST", "https://example.test/a%2Fb?b=2&a=&b=1")
	otherTx, err := NewTransaction(context.Background(), TransactionOptions{
		ID: "tx-1", Generation: 7, Connection: ConnectionView{ID: "other-connection"},
		OriginalIngress: otherHead, Request: otherHead, Ledger: ledger,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer otherTx.Close()
	otherConnectionHeadLease.Close()
	result := Continue()
	if _, err := otherTx.Commit(input, result); !errors.Is(err, ErrInvalid) {
		t.Fatalf("different connection accepted an input key: %v", err)
	}

	first, firstInputLease, err := firstTx.Snapshot("first-invocation")
	if err != nil {
		t.Fatal(err)
	}
	defer firstInputLease.Close()
	_, supersedingLease, err := firstTx.Snapshot("superseding-invocation")
	if err != nil {
		t.Fatal(err)
	}
	defer supersedingLease.Close()
	if _, err := firstTx.Commit(first, result); !errors.Is(err, ErrInvalid) {
		t.Fatalf("superseded invocation committed: %v", err)
	}
}

func TestContinueCommitConsumesInvocationRevision(t *testing.T) {
	ledger := testLedger(t, -1)
	tx, sourceLease := testTransaction(t, context.Background(), ledger, BodySlot{})
	sourceLease.Close()
	input, lease, err := tx.Snapshot("continue-once")
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	if kind, err := tx.Commit(input, Continue()); err != nil || kind != ResultContinue || tx.Revision() != 2 {
		t.Fatalf("Continue did not commit its revision: kind=%d rev=%d err=%v", kind, tx.Revision(), err)
	}
	if _, err := tx.Commit(input, Continue()); !errors.Is(err, ErrStaleRevision) {
		t.Fatalf("same result committed twice: %v", err)
	}
}

func TestPipelinePhasePermitSerializesConcurrentRunners(t *testing.T) {
	for round := 0; round < 20; round++ {
		ledger := testLedger(t, -1)
		tx, sourceLease := testTransaction(t, context.Background(), ledger, BodySlot{})
		sourceLease.Close()
		start := make(chan struct{})
		ready := make(chan struct{}, 2)
		type acquired struct {
			permit *PipelinePhasePermit
			err    error
		}
		results := make(chan acquired, 2)
		var wg sync.WaitGroup
		for i := 0; i < 2; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				ready <- struct{}{}
				<-start
				permit, skipped, err := tx.AcquirePipelinePhase(context.Background(), RequestPhase)
				if skipped {
					err = ErrInvalid
				}
				results <- acquired{permit: permit, err: err}
			}()
		}
		<-ready
		<-ready
		close(start)
		first := <-results
		if first.err != nil || first.permit == nil {
			t.Fatalf("round %d: first phase acquisition failed: %v", round, first.err)
		}
		first.permit.Release()
		second := <-results
		if second.permit != nil || !errors.Is(second.err, ErrInvalid) {
			t.Fatalf("round %d: concurrent phase replay was allowed: %+v", round, second)
		}
		wg.Wait()
	}
}
