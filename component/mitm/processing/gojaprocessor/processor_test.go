package gojaprocessor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/mitm/processing/model"
	"github.com/metacubex/mihomo/component/mitm/processing/pipeline"
)

var testTransactionSequence atomic.Uint64

func testConfig(source string) Config {
	return Config{ID: "goja-test", Source: source, Request: true}
}

func testTransaction(t testing.TB, generationID model.GenerationID, body []byte) *model.Transaction {
	t.Helper()
	ledger, err := model.NewLedger(-1, nil)
	if err != nil {
		t.Fatal(err)
	}
	lease := model.NewCopyLease(ledger)
	urlValue, err := model.ParseURL(lease, "https://example.test/start?b=2&a=1", model.MITMHTTPS)
	if err != nil {
		t.Fatal(err)
	}
	headers, err := model.NewHeaderBlock(lease, []model.HeaderField{{Name: "X-Test", Values: []string{"original"}}})
	if err != nil {
		t.Fatal(err)
	}
	trailers, err := model.NewTrailerView(model.TrailerUnavailable, model.HeaderBlock{}, model.HeaderBlock{})
	if err != nil {
		t.Fatal(err)
	}
	request := model.RequestHead{Method: "POST", URL: urlValue, Authority: "example.test", Headers: headers, Trailers: trailers}
	var bodyReader io.ReadCloser
	declaredLength := int64(0)
	if body != nil {
		bodyReader = io.NopCloser(bytes.NewReader(body))
		declaredLength = int64(len(body))
	}
	bodyBroker, err := model.NewBodyBroker(context.Background(), model.BodySource{Reader: bodyReader, Owner: model.FrameworkOwned, DeclaredLength: declaredLength}, ledger)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := model.NewTransaction(context.Background(), model.TransactionOptions{
		ID:              fmt.Sprintf("tx-%d", testTransactionSequence.Add(1)),
		Generation:      generationID,
		Connection:      model.ConnectionView{ID: "conn-1", StreamID: "stream-1", Downstream: model.ProtocolInfo{Major: 2, Known: true}},
		OriginalIngress: request,
		Request:         request,
		RequestBody:     model.NewBodySlot(bodyBroker),
		Ledger:          ledger,
	})
	_ = lease.Close()
	if err != nil {
		_ = bodyBroker.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = tx.Close()
		if remaining := ledger.Current(); remaining != 0 {
			t.Errorf("transaction retained %d ledger bytes after close", remaining)
		}
	})
	return tx
}

func addResponse(t testing.TB, tx *model.Transaction, body []byte) {
	t.Helper()
	lease := model.NewCopyLease(tx.Ledger())
	headers, err := model.NewHeaderBlock(lease, []model.HeaderField{{Name: "Content-Type", Values: []string{"text/plain"}}})
	if err != nil {
		t.Fatal(err)
	}
	trailers, err := model.NewTrailerView(model.TrailerUnavailable, model.HeaderBlock{}, model.HeaderBlock{})
	if err != nil {
		t.Fatal(err)
	}
	response := model.ResponseHead{Status: 200, Headers: headers, Trailers: trailers}
	var bodyReader io.ReadCloser
	if body != nil {
		bodyReader = io.NopCloser(bytes.NewReader(body))
	}
	broker, err := model.NewBodyBroker(context.Background(), model.BodySource{Reader: bodyReader, Owner: model.FrameworkOwned, DeclaredLength: int64(len(body))}, tx.Ledger())
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.EnterResponse(tx.Revision(), response, response, model.NewBodySlot(broker), model.OriginUpstream); err != nil {
		_ = broker.Close()
		t.Fatal(err)
	}
	_ = lease.Close()
}

func newTestProcessor(t testing.TB, config Config) *Processor {
	t.Helper()
	backend, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = backend.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := backend.WaitClosed(ctx); err != nil {
			t.Errorf("processor did not drain: %v", err)
		}
	})
	return backend
}

func newTestRunner(t testing.TB, backend *Processor, options pipeline.Options) *pipeline.Runner {
	t.Helper()
	runner, err := pipeline.NewRunner([]pipeline.Entry{{Class: pipeline.Script, Processor: backend}}, options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = runner.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := runner.WaitClosed(ctx); err != nil {
			t.Errorf("pipeline did not drain: %v", err)
		}
	})
	return runner
}

func processingKindIs(err error, kind model.ProcessingErrorKind) bool {
	var processingErr *model.ProcessingError
	return errors.As(err, &processingErr) && processingErr.Kind == kind
}

func TestGojaResultsExecuteThroughFrameworkPipeline(t *testing.T) {
	tests := []struct {
		name        string
		source      string
		wantKind    model.ResultKind
		wantOutcome pipeline.Outcome
		wantStopped bool
	}{
		{name: "continue", source: `function process(input) { return {kind:"continue"}; }`, wantKind: model.ResultContinue, wantOutcome: pipeline.ContinueUpstream},
		{name: "request change", source: `function process(input) { return {kind:"request_change",request:{method:"PATCH",url:"https://example.test/next?q=2",authority:"next.test",headers:[{op:"set",name:"X-JS",values:["set"]},{op:"add",name:"X-JS",values:["added"]}],body:{encoding:"base64",data:"AP8="}}}; }`, wantKind: model.ResultRequestChange, wantOutcome: pipeline.ContinueUpstream},
		{name: "respond", source: `function process(input) { return {kind:"respond",response:{status:201,headers:[{name:"Content-Type",values:["text/plain"]}],body:{encoding:"base64",data:"b2s="}}}; }`, wantKind: model.ResultRespond, wantOutcome: pipeline.SyntheticReady},
		{name: "stop phase", source: `function process(input) { return {kind:"stop_phase"}; }`, wantKind: model.ResultStopPhase, wantOutcome: pipeline.ContinueUpstream, wantStopped: true},
		{name: "reject", source: `function process(input) { return {kind:"reject",code:"blocked"}; }`, wantKind: model.ResultReject, wantOutcome: pipeline.Rejected},
		{name: "abort", source: `function process(input) { return {kind:"abort",reason:"policy stop"}; }`, wantKind: model.ResultAbort, wantOutcome: pipeline.Aborted},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			backend := newTestProcessor(t, testConfig(test.source))
			tx := testTransaction(t, 7, nil)
			runner := newTestRunner(t, backend, pipeline.Options{})
			report, err := runner.Run(context.Background(), tx, model.RequestPhase)
			if err != nil {
				t.Fatal(err)
			}
			if report.LastResult != test.wantKind || report.Outcome != test.wantOutcome || report.Stopped != test.wantStopped {
				t.Fatalf("report = %+v", report)
			}
			switch test.wantKind {
			case model.ResultRequestChange:
				input, inputLease, err := tx.Snapshot("verify-request-change")
				if err != nil {
					t.Fatal(err)
				}
				defer inputLease.Close()
				request := input.Request()
				if request.Method != "PATCH" || request.URL.String() != "https://example.test/next?q=2" || request.Authority != "next.test" {
					t.Fatalf("request patch was not committed: %+v", request)
				}
				values, _, err := request.Headers.Values("X-JS")
				if err != nil || len(values) != 2 || values[0] != "set" || values[1] != "added" {
					t.Fatalf("header patch values = %v, err = %v", values, err)
				}
				body, err := input.Body().BytesCopy()
				if err != nil || !bytes.Equal(body, []byte{0, 255}) {
					t.Fatalf("request body = %v, err = %v", body, err)
				}
			case model.ResultRespond:
				synthetic, ok := tx.TakeSynthetic()
				if !ok || synthetic.Status() != 201 {
					t.Fatal("synthetic response was not committed")
				}
				body, err := synthetic.BodyBytesCopy()
				if err != nil || string(body) != "ok" {
					t.Fatalf("synthetic body = %q, err = %v", body, err)
				}
				if err := synthetic.Release(); err != nil {
					t.Fatal(err)
				}
			case model.ResultReject:
				decisionLease := model.NewCopyLease(tx.Ledger())
				outcome, code, _, err := tx.DecisionCopy(decisionLease)
				_ = decisionLease.Close()
				if err != nil || outcome != model.ExchangeRejected || code != "blocked" {
					t.Fatalf("reject decision = %v %q, err = %v", outcome, code, err)
				}
			}
		})
	}
}

func TestGojaResponseChangeThroughPipeline(t *testing.T) {
	config := Config{ID: "response-js", Source: `function process(input) { if (input.phase !== "response" || input.response.status !== 200) throw new Error("bad response input"); return {kind:"response_change",response:{status:202,headers:[{op:"set",name:"X-Response",values:["changed"]}],body:{encoding:"base64",data:"AQI="}}}; }`, Response: true}
	backend := newTestProcessor(t, config)
	tx := testTransaction(t, 7, nil)
	addResponse(t, tx, []byte("before"))
	runner := newTestRunner(t, backend, pipeline.Options{})
	report, err := runner.Run(context.Background(), tx, model.ResponsePhase)
	if err != nil {
		t.Fatal(err)
	}
	if report.LastResult != model.ResultResponseChange || report.Outcome != pipeline.ResponseComplete {
		t.Fatalf("report = %+v", report)
	}
	input, lease, err := tx.Snapshot("verify-response-change")
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	response, ok := input.Response()
	if !ok || response.Status != 202 {
		t.Fatalf("response = %+v, present=%v", response, ok)
	}
	values, _, err := response.Headers.Values("X-Response")
	if err != nil || len(values) != 1 || values[0] != "changed" {
		t.Fatalf("response header = %v, err = %v", values, err)
	}
	body, err := input.Body().BytesCopy()
	if err != nil || !bytes.Equal(body, []byte{1, 2}) {
		t.Fatalf("response body = %v, err = %v", body, err)
	}
}

func TestGojaInputMutationIsDetached(t *testing.T) {
	config := Config{
		ID: "input-isolation", Source: `function process(input) {
  if (input.phase !== "request" || input.body.available !== true || input.body.encoding !== "base64" || input.body.base64 !== "AP8=") throw new Error("input body unavailable");
  input.request.method = "DELETE";
  input.request.headers[0].values[0] = "mutated";
  input.body.base64 = "AA==";
  return {kind:"continue"};
}`,
		Request: true, RequestBody: model.FullBuffered,
	}
	backend := newTestProcessor(t, config)
	tx := testTransaction(t, 7, []byte{0, 255})
	runner := newTestRunner(t, backend, pipeline.Options{})
	if _, err := runner.Run(context.Background(), tx, model.RequestPhase); err != nil {
		t.Fatal(err)
	}
	input, lease, err := tx.Snapshot("verify-input-isolation")
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	if input.Request().Method != "POST" {
		t.Fatalf("JavaScript changed the Transaction method to %q", input.Request().Method)
	}
	values, _, err := input.Request().Headers.Values("X-Test")
	if err != nil || values[0] != "original" {
		t.Fatalf("JavaScript changed the Transaction header: %v %v", values, err)
	}
	actualBody, err := input.Body().BytesCopy()
	if err != nil || !bytes.Equal(actualBody, []byte{0, 255}) {
		t.Fatalf("JavaScript changed the Transaction body: %v %v", actualBody, err)
	}
}
