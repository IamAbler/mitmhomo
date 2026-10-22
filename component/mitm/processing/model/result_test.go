package model

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func resultFixture(t testing.TB, limit int64) (*Ledger, *CopyLease) {
	t.Helper()
	ledger, err := NewLedger(limit, nil)
	if err != nil {
		t.Fatal(err)
	}
	return ledger, NewCopyLease(ledger)
}

func TestDoneResultKindsAndPhaseMatrix(t *testing.T) {
	ledger, inputLease := resultFixture(t, -1)
	defer inputLease.Close()
	headers, err := NewHeaderBlock(inputLease, []HeaderField{{Name: "X-Original", Values: []string{"a", "b"}}})
	if err != nil {
		t.Fatal(err)
	}
	trailers, err := NewTrailerView(TrailerComplete, HeaderBlock{}, HeaderBlock{})
	if err != nil {
		t.Fatal(err)
	}
	before := ledger.Current()

	requestChange, err := ChangeRequest(RequestPatch{Method: Optional[string]{Present: true, Value: "PATCH"}}, ledger, 64)
	if err != nil {
		t.Fatal(err)
	}
	responseChange, err := ChangeResponse(ResponsePatch{Status: Optional[int]{Present: true, Value: 201}}, ledger, 64)
	if err != nil {
		t.Fatal(err)
	}
	synthetic, err := NewSyntheticResponse(202, headers, []byte("ok"), trailers, ledger, 64)
	if err != nil {
		t.Fatal(err)
	}
	respond, err := Respond(synthetic)
	if err != nil {
		t.Fatal(err)
	}
	reject, err := Reject("policy_block", ledger)
	if err != nil {
		t.Fatal(err)
	}
	abort, err := Abort("stop exchange", ledger)
	if err != nil {
		t.Fatal(err)
	}
	results := []DoneResult{Continue(), requestChange, responseChange, respond, StopPhase(), reject, abort}
	wants := []ResultKind{ResultContinue, ResultRequestChange, ResultResponseChange, ResultRespond, ResultStopPhase, ResultReject, ResultAbort}
	for i, result := range results {
		if !result.Valid() || result.Kind() != wants[i] {
			t.Fatalf("result %d: kind=%d valid=%v", i, result.Kind(), result.Valid())
		}
		if err := result.ValidateForPhase(RequestPhase); err != nil && result.Kind() != ResultResponseChange {
			t.Errorf("request phase rejected %d: %v", result.Kind(), err)
		}
		if err := result.ValidateForPhase(ResponsePhase); err != nil && result.Kind() != ResultRequestChange && result.Kind() != ResultRespond {
			t.Errorf("response phase rejected %d: %v", result.Kind(), err)
		}
		if result.Kind() == ResultRequestChange || result.Kind() == ResultResponseChange || result.Kind() == ResultRespond {
			if err := result.Release(); err != nil {
				t.Fatal(err)
			}
		}
	}
	if code, ok, err := reject.RejectCode(); err != nil || !ok || code != "policy_block" {
		t.Fatalf("Reject payload invalid: %q %v %v", code, ok, err)
	}
	if reason, ok, err := abort.AbortReason(); err != nil || !ok || reason != "stop exchange" {
		t.Fatalf("Abort payload invalid: %q %v %v", reason, ok, err)
	}
	_ = reject.Release()
	_ = abort.Release()
	if (DoneResult{}).Kind() != ResultInvalid || (DoneResult{}).Valid() || (DoneResult{}).ValidateForPhase(RequestPhase) == nil {
		t.Fatal("zero result must be invalid")
	}
	if _, err := ChangeRequest(RequestPatch{Body: BodyEdit{Kind: BodyReplace, Bytes: []byte("x")}}, ledger, 0); !errors.Is(err, ErrResourceLimit) {
		t.Fatal("request patch body above its output cap accepted")
	}
	if ledger.Current() != before {
		t.Fatalf("result resources leaked: current=%d before=%d", ledger.Current(), before)
	}
}

func TestRequestPatchCopiesInputsAndPreservesURLAndHeaderSemantics(t *testing.T) {
	ledger, sourceLease := resultFixture(t, -1)
	defer sourceLease.Close()
	u, err := ParseURL(sourceLease, "https://example.test/a%2Fb?x=1&x=2&empty=", MITMHTTPS)
	if err != nil {
		t.Fatal(err)
	}
	values := []string{"first", "second"}
	body := []byte("payload")
	patch := RequestPatch{
		Method:    Optional[string]{Present: true, Value: "POST"},
		URL:       Optional[URLValue]{Present: true, Value: u},
		Authority: Optional[string]{Present: true, Value: "proxy.example:443"},
		Headers: []HeaderEdit{
			{Kind: HeaderSet, Name: "X-Multi", Values: values},
			{Kind: HeaderAdd, Name: "X-Multi", Values: []string{"third"}},
		},
		Body:     BodyEdit{Kind: BodyReplace, Bytes: body},
		Trailers: []HeaderEdit{{Kind: HeaderSet, Name: "X-End", Values: []string{"done"}}},
	}
	result, err := ChangeRequest(patch, ledger, 32)
	if err != nil {
		t.Fatal(err)
	}
	values[0] = "mutated"
	body[0] = 'X'
	copy1, ok, err := result.RequestPatch()
	if err != nil || !ok {
		t.Fatal(err)
	}
	copy1.Headers[0].Values[0] = "reader mutation"
	copy1.Body.Bytes[0] = 'Y'
	copy2, _, err := result.RequestPatch()
	if err != nil {
		t.Fatal(err)
	}
	if copy2.Headers[0].Values[0] != "first" || string(copy2.Body.Bytes) != "payload" {
		t.Fatal("result constructor or getter leaked mutable storage")
	}
	if copy2.Method.Value != "POST" || copy2.Authority.Value != "proxy.example:443" || copy2.URL.Value.EscapedPath() != "/a%2Fb" || copy2.URL.Value.RawQuery() != "x=1&x=2&empty=" || copy2.URL.Value.ForceQuery() {
		t.Fatalf("URL or request fields lost: method=%q path=%q query=%q force=%v", copy2.Method.Value, copy2.URL.Value.EscapedPath(), copy2.URL.Value.RawQuery(), copy2.URL.Value.ForceQuery())
	}
	forceQuery, err := ParseURL(sourceLease, "https://example.test/path?", MITMHTTPS)
	if err != nil || !forceQuery.ForceQuery() {
		t.Fatal("explicit empty query marker was lost", err)
	}
	if copy2.Body.Kind != BodyReplace || len(copy2.Trailers) != 1 || copy2.Headers[0].Values[1] != "second" || copy2.Headers[1].Values[0] != "third" {
		t.Fatal("body replacement, repeated query, multi-value header, or trailer edit lost")
	}
	keep, err := ChangeRequest(RequestPatch{Method: Optional[string]{Present: true, Value: "GET"}, Body: BodyEdit{Kind: BodyKeep}}, ledger, 32)
	if err != nil {
		t.Fatal(err)
	}
	keepPatch, _, err := keep.RequestPatch()
	if err != nil || keepPatch.Body.Kind != BodyKeep {
		t.Fatal("Keep body not preserved", err)
	}
	empty, err := ChangeRequest(RequestPatch{Body: BodyEdit{Kind: BodyReplace, Bytes: []byte{}}}, ledger, 32)
	if err != nil {
		t.Fatal(err)
	}
	emptyPatch, _, err := empty.RequestPatch()
	if err != nil || emptyPatch.Body.Kind != BodyReplace || len(emptyPatch.Body.Bytes) != 0 {
		t.Fatal("replace-empty body conflated with Keep", err)
	}
	_ = result.Release()
	_ = keep.Release()
	_ = empty.Release()
}

func TestHeaderEditConflictsAndManagedFields(t *testing.T) {
	ledger, lease := resultFixture(t, -1)
	defer lease.Close()
	block, err := NewHeaderBlock(lease, []HeaderField{{Name: "X-One", Values: []string{"1"}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, patch := range []RequestPatch{
		{Headers: []HeaderEdit{{Kind: HeaderReplaceAll, Block: block}, {Kind: HeaderSet, Name: "X-Two", Values: []string{"2"}}}},
		{Headers: []HeaderEdit{{Kind: HeaderReplaceAll, Name: "X-One", Block: block}}},
		{Headers: []HeaderEdit{{Kind: HeaderSet, Name: "Content-Length", Values: []string{"0"}}}},
		{Headers: []HeaderEdit{{Kind: HeaderAdd, Name: ":authority", Values: []string{"x"}}}},
		{Headers: []HeaderEdit{{Kind: HeaderRemove, Name: "Transfer-Encoding", Values: []string{"chunked"}}}},
		{Headers: []HeaderEdit{{Kind: HeaderSet, Name: "X-Bad", Values: []string{"bad\r\nvalue"}}}},
	} {
		if result, err := ChangeRequest(patch, ledger, 16); err == nil {
			_ = result.Release()
			t.Fatalf("invalid header patch accepted: %+v", patch)
		}
	}
	clear, err := ChangeRequest(RequestPatch{Headers: []HeaderEdit{{Kind: HeaderReplaceAll}}}, ledger, 16)
	if err != nil {
		t.Fatalf("empty ReplaceAll should clear all headers: %v", err)
	}
	copy, ok, err := clear.RequestPatch()
	if err != nil || !ok || copy.Headers[0].Kind != HeaderReplaceAll || copy.Headers[0].Block.Len() != 0 {
		t.Fatal("empty ReplaceAll did not survive", err)
	}
	_ = clear.Release()
}

func TestSyntheticResponseBoundedImmutableAndStatusValidation(t *testing.T) {
	ledger, inputLease := resultFixture(t, -1)
	defer inputLease.Close()
	headers, err := NewHeaderBlock(inputLease, []HeaderField{{Name: "Set-Cookie", Values: []string{"a=1", "b=2"}}})
	if err != nil {
		t.Fatal(err)
	}
	trailers, err := NewTrailerView(TrailerComplete, HeaderBlock{}, HeaderBlock{})
	if err != nil {
		t.Fatal(err)
	}
	body := []byte{}
	synthetic, err := NewSyntheticResponse(200, headers, body, trailers, ledger, 0)
	if err != nil {
		t.Fatal(err)
	}
	responseResult, err := Respond(synthetic)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Respond(synthetic); err == nil {
		t.Fatal("SyntheticResponse ownership transferred more than once")
	}
	if err := synthetic.Release(); !errors.Is(err, ErrReleased) {
		t.Fatalf("transferred synthetic payload remained caller-owned: %v", err)
	}
	response, ok := responseResult.SyntheticResponse()
	if !ok || response.Status() != 200 {
		t.Fatal("synthetic response unavailable")
	}
	copy, err := response.BodyBytesCopy()
	if err != nil || copy == nil || len(copy) != 0 {
		t.Fatalf("empty synthetic body not retained: %#v, %v", copy, err)
	}
	entries, err := response.Headers().Entries()
	if err != nil || len(entries) != 1 || len(entries[0].Values) != 2 {
		t.Fatal("multi-value synthetic headers lost", err)
	}
	entries[0].Values[0] = "changed"
	again, _, err := response.Headers().Values("set-cookie")
	if err != nil || again[0] != "a=1" {
		t.Fatal("synthetic header getter leaked a mutable slice", err)
	}
	_ = responseResult.Release()
	for _, status := range []int{0, 100, 199, 600} {
		if _, err := NewSyntheticResponse(status, HeaderBlock{}, nil, trailers, ledger, 0); err == nil {
			t.Errorf("invalid synthetic status %d accepted", status)
		}
	}
	if _, err := NewSyntheticResponse(204, HeaderBlock{}, []byte("x"), trailers, ledger, 10); err == nil {
		t.Fatal("204 with body accepted")
	}
	if _, err := NewSyntheticResponse(200, HeaderBlock{}, []byte("too big"), trailers, ledger, 1); !errors.Is(err, ErrResourceLimit) {
		t.Fatal("synthetic body above cap accepted")
	}
	pending, err := NewTrailerView(TrailerPending, HeaderBlock{}, HeaderBlock{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewSyntheticResponse(200, HeaderBlock{}, nil, pending, ledger, 1); err == nil {
		t.Fatal("pending synthetic trailers accepted")
	}
	declared, err := NewHeaderBlock(inputLease, []HeaderField{{Name: "X-Checksum"}})
	if err != nil {
		t.Fatal(err)
	}
	values, err := NewHeaderBlock(inputLease, []HeaderField{{Name: "X-Checksum", Values: []string{"abc"}}})
	if err != nil {
		t.Fatal(err)
	}
	completeTrailer, err := NewTrailerView(TrailerComplete, declared, values)
	if err != nil {
		t.Fatal(err)
	}
	withTrailer, err := NewSyntheticResponse(200, HeaderBlock{}, []byte("body"), completeTrailer, ledger, 16)
	if err != nil {
		t.Fatalf("complete trailers rejected: %v", err)
	}
	_ = withTrailer.Release()
}

func TestDoneResultStageAndHTTPBasicValidation(t *testing.T) {
	ledger, lease := resultFixture(t, -1)
	defer lease.Close()
	responseStatus, err := ChangeResponse(ResponsePatch{Status: Optional[int]{Present: true, Value: 204}}, ledger, 16)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ChangeResponse(ResponsePatch{Status: Optional[int]{Present: true, Value: 204}, Body: BodyEdit{Kind: BodyReplace, Bytes: []byte("x")}}, ledger, 16); err == nil {
		t.Fatal("204 body replacement accepted")
	}
	if _, err := ChangeResponse(ResponsePatch{Trailers: []HeaderEdit{{Kind: HeaderSet, Name: "X-Trailer", Values: []string{"x"}}}}, ledger, 16); err == nil {
		t.Fatal("trailer edit without body replacement accepted")
	}
	for _, status := range []int{100, 199, 600} {
		if _, err := ChangeResponse(ResponsePatch{Status: Optional[int]{Present: true, Value: status}}, ledger, 16); err == nil {
			t.Errorf("invalid status %d accepted", status)
		}
	}
	requestChange, err := ChangeRequest(RequestPatch{Method: Optional[string]{Present: true, Value: "PATCH"}}, ledger, 16)
	if err != nil {
		t.Fatal(err)
	}
	if requestChange.ValidateForPhase(ResponsePhase) == nil || responseStatus.ValidateForPhase(RequestPhase) == nil || (DoneResult{}).ValidateForPhase(PhaseInvalid) == nil {
		t.Fatal("illegal phase combination accepted")
	}
	tx, sourceLease := testTransaction(t, context.Background(), ledger, BodySlot{})
	defer sourceLease.Close()
	defer tx.Close()
	if err := tx.EnterResponse(tx.Revision(), ResponseHead{Status: 200}, ResponseHead{Status: 200}, BodySlot{}, OriginUpstream); err != nil {
		t.Fatal(err)
	}
	input, inputLease, err := tx.Snapshot("response-check")
	if err != nil {
		t.Fatal(err)
	}
	defer inputLease.Close()
	if err := responseStatus.ValidateForInput(input); err != nil {
		t.Fatalf("empty 204 response patch rejected: %v", err)
	}
	_ = responseStatus.Release()
	_ = requestChange.Release()
	if err := tx.Close(); err != nil {
		t.Fatal(err)
	}

	headTx, sourceLease := testTransaction(t, context.Background(), ledger, BodySlot{})
	defer sourceLease.Close()
	defer headTx.Close()
	requestInput, requestLease, err := headTx.Snapshot("head-request")
	if err != nil {
		t.Fatal(err)
	}
	headRequest := requestInput.Request()
	headRequest.Method = "HEAD"
	if err := headTx.UpdateRequest(requestInput.Key().Revision, headRequest); err != nil {
		requestLease.Close()
		t.Fatal(err)
	}
	requestLease.Close()
	headInput, headLease, err := headTx.Snapshot("head-final")
	if err != nil {
		t.Fatal(err)
	}
	defer headLease.Close()
	headSynthetic, err := NewSyntheticResponse(200, HeaderBlock{}, []byte("representation"), TrailerView{}, ledger, 64)
	if err != nil {
		t.Fatal(err)
	}
	headResult, err := Respond(headSynthetic)
	if err != nil {
		t.Fatal(err)
	}
	if err := headResult.ValidateForInput(headInput); err == nil {
		t.Fatal("HEAD synthetic response body accepted")
	}
	_ = headResult.Release()
	if err := headResult.Release(); err != nil {
		t.Fatal(err)
	}
	profileURL, err := ParseURL(sourceLease, "http://other.example/", AbsoluteURL)
	if err != nil {
		t.Fatal(err)
	}
	profileResult, err := ChangeRequest(RequestPatch{URL: Optional[URLValue]{Present: true, Value: profileURL}}, ledger, 16)
	if err != nil {
		t.Fatal(err)
	}
	if err := profileResult.ValidateForInput(headInput); err == nil {
		t.Fatal("request URL changed its security profile")
	}
	_ = profileResult.Release()
	reject, err := Reject("policy", ledger)
	if err != nil {
		t.Fatal(err)
	}
	_ = reject.Release()
	if _, err := Abort(strings.Repeat("x", maxDecisionText+1), ledger); err == nil {
		t.Fatal("unbounded abort reason accepted")
	}
}

func TestDoneResultBudgetFailureAndOwnershipTransfer(t *testing.T) {
	ledger, err := NewLedger(200, nil)
	if err != nil {
		t.Fatal(err)
	}
	inputLedger, err := NewLedger(-1, nil)
	if err != nil {
		t.Fatal(err)
	}
	inputLease := NewCopyLease(inputLedger)
	defer inputLease.Close()
	inputURL, err := ParseURL(inputLease, "https://example.test/", MITMHTTPS)
	if err != nil {
		t.Fatal(err)
	}
	before := ledger.Current()
	if _, err := ChangeRequest(RequestPatch{URL: Optional[URLValue]{Present: true, Value: inputURL}}, ledger, 0); !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("budget exhaustion not reported: %v", err)
	}
	if ledger.Current() != before {
		t.Fatal("failed result construction retained budget")
	}
	result, err := ChangeRequest(RequestPatch{Method: Optional[string]{Present: true, Value: "GET"}}, ledger, 0)
	if err != nil {
		t.Fatal(err)
	}
	owned := ledger.Current() - before
	if owned <= 0 {
		t.Fatal("result payload was not charged")
	}
	if err := result.Release(); err != nil {
		t.Fatal(err)
	}
	if ledger.Current() != before {
		t.Fatal("result payload budget was not returned after release")
	}
}

func TestProcessingErrorIsAsAndIs(t *testing.T) {
	cause := errors.New("disk quota")
	processing := NewProcessingError(ProcessingErrorResourceLimit, ProcessingOriginProcessor, RequestPhase, "p1", "inv-1", cause)
	if !errors.Is(processing, ErrorSentinel(ProcessingErrorResourceLimit)) || !errors.Is(processing, cause) {
		t.Fatal("errors.Is did not match typed kind/cause")
	}
	var got *ProcessingError
	if !errors.As(processing, &got) || got.Kind != ProcessingErrorResourceLimit || got.Origin != ProcessingOriginProcessor || got.ProcessorID != "p1" || got.InvocationID != "inv-1" {
		t.Fatal("errors.As lost structured fields")
	}
}
