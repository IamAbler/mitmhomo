package model

import (
	"context"
	"errors"
	"strings"
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
	if _, _, err := tx.Snapshot("after-upstream"); !errors.Is(err, ErrClosed) {
		t.Fatalf("request input remained open after upstream claim: %v", err)
	}
}
