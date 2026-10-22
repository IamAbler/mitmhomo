package pipeline

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/mitm/processing/model"
	"github.com/metacubex/mihomo/component/mitm/processing/processor"
)

type fakeProcessor struct {
	descriptor processor.Descriptor
	lifecycle  *processor.Lifecycle
	onStart    func(*processor.Invocation, *processor.Completion, model.Input)
	mutateKey  func(model.InvocationKey) model.InvocationKey
	startErr   error
	starts     atomic.Int64
}

func newFake(t testing.TB, id string, requirements processor.Requirements, onStart func(*processor.Invocation, *processor.Completion, model.Input)) *fakeProcessor {
	t.Helper()
	lifecycle, err := processor.NewProcessorLifecycle(id, 32)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeProcessor{
		descriptor: processor.Descriptor{ID: id, Backend: "fake", ContractVersion: 1, Request: true, Response: true, RequestNeeds: requirements, ResponseNeeds: requirements},
		lifecycle:  lifecycle, onStart: onStart,
	}
}

func (p *fakeProcessor) Describe() processor.Descriptor { return p.descriptor.Clone() }
func (p *fakeProcessor) Start(ctx context.Context, input model.Input, resources ...io.Closer) (*processor.Invocation, error) {
	p.starts.Add(1)
	if p.startErr != nil {
		return nil, p.startErr
	}
	key := input.Key()
	if p.mutateKey != nil {
		key = p.mutateKey(key)
	}
	invocation, completion, err := p.lifecycle.BeginWithResources(ctx, key, resources...)
	if err != nil {
		return nil, err
	}
	if p.onStart != nil {
		p.onStart(invocation, completion, input)
	} else if !completion.Finish(model.Continue(), nil) {
		return nil, model.ErrInvalid
	}
	return invocation, nil
}
func (p *fakeProcessor) Close() error                         { return p.lifecycle.Close() }
func (p *fakeProcessor) WaitClosed(ctx context.Context) error { return p.lifecycle.WaitClosed(ctx) }

type countingBody struct {
	reader  *strings.Reader
	readErr error
	reads   atomic.Int64
	closes  atomic.Int64
}

func newCountingBody(text string) *countingBody {
	return &countingBody{reader: strings.NewReader(text)}
}
func (b *countingBody) Read(p []byte) (int, error) {
	b.reads.Add(1)
	if b.readErr != nil {
		return 0, b.readErr
	}
	return b.reader.Read(p)
}
func (b *countingBody) Close() error { b.closes.Add(1); return nil }

type countCloser struct{ closes atomic.Int64 }

func (c *countCloser) Close() error { c.closes.Add(1); return nil }

type failingCloser struct {
	closes atomic.Int64
	err    error
}

func (c *failingCloser) Close() error { c.closes.Add(1); return c.err }

func newTransaction(t testing.TB, id, body string) (*model.Transaction, *model.Ledger, *countingBody) {
	t.Helper()
	var reader *countingBody
	declared := int64(0)
	if body != "" {
		reader = newCountingBody(body)
		declared = int64(len(body))
	}
	return newTransactionConfigured(t, id, "conn-"+id, "stream-1", reader, declared)
}

func newTransactionConfigured(t testing.TB, id, connectionID, streamID string, reader *countingBody, declaredLength int64) (*model.Transaction, *model.Ledger, *countingBody) {
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
	if reader != nil {
		bodyReader = reader
	}
	broker, err := model.NewBodyBroker(context.Background(), model.BodySource{Reader: bodyReader, Owner: model.FrameworkOwned, DeclaredLength: declaredLength}, ledger)
	if err != nil {
		t.Fatal(err)
	}
	slot := model.NewBodySlot(broker)
	tx, err := model.NewTransaction(context.Background(), model.TransactionOptions{
		ID: id, Generation: 7, Connection: model.ConnectionView{ID: connectionID, StreamID: streamID, Downstream: model.ProtocolInfo{Major: 2, Known: true}},
		OriginalIngress: request, Request: request, RequestBody: slot, Ledger: ledger,
	})
	_ = lease.Close()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = tx.Close()
		if got := ledger.Current(); got != 0 {
			t.Errorf("transaction leaked %d budget bytes", got)
		}
	})
	return tx, ledger, reader
}

func mustRequestChange(t testing.TB, ledger *model.Ledger, patch model.RequestPatch) model.DoneResult {
	t.Helper()
	result, err := model.ChangeRequest(patch, ledger, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func mustResponseChange(t testing.TB, ledger *model.Ledger, patch model.ResponsePatch) model.DoneResult {
	t.Helper()
	result, err := model.ChangeResponse(patch, ledger, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func finish(t testing.TB, completion *processor.Completion, result model.DoneResult, err error) {
	t.Helper()
	if !completion.Finish(result, err) {
		t.Errorf("fake completion rejected: %v", err)
	}
}

func value(t testing.TB, input model.Input, name string) string {
	t.Helper()
	values, ok, err := input.Request().Headers.Values(name)
	if err != nil || !ok || len(values) != 1 {
		t.Fatalf("missing header %s: values=%v ok=%t err=%v", name, values, ok, err)
	}
	return values[0]
}

func TestRunnerOrdersHooksScriptAndIncrementalRewrite(t *testing.T) {
	tx, ledger, _ := newTransaction(t, "order", "")
	newSet := func(input model.Input, name, v string) model.DoneResult {
		return mustRequestChange(t, ledger, model.RequestPatch{Headers: []model.HeaderEdit{{Kind: model.HeaderSet, Name: name, Values: []string{v}}}})
	}
	hookLate := newFake(t, "hook-late", processor.Requirements{}, func(_ *processor.Invocation, c *processor.Completion, in model.Input) {
		if value(t, in, "X-Hook-Early") != "yes" {
			t.Error("higher priority hook ran before lower priority hook")
		}
		finish(t, c, newSet(in, "X-Hook-Late", "yes"), nil)
	})
	hookEarly := newFake(t, "hook-early", processor.Requirements{}, func(_ *processor.Invocation, c *processor.Completion, in model.Input) {
		finish(t, c, newSet(in, "X-Hook-Early", "yes"), nil)
	})
	var secondScript atomic.Int64
	scriptFirst := newFake(t, "script-first", processor.Requirements{}, func(_ *processor.Invocation, c *processor.Completion, in model.Input) {
		if value(t, in, "X-Hook-Late") != "yes" {
			t.Error("script did not observe committed hooks")
		}
		finish(t, c, newSet(in, "X-Script", "first"), nil)
	})
	scriptSecond := newFake(t, "script-second", processor.Requirements{}, func(_ *processor.Invocation, c *processor.Completion, in model.Input) {
		secondScript.Add(1)
		finish(t, c, newSet(in, "X-Script", "second"), nil)
	})
	rewriteFirst := newFake(t, "rewrite-first", processor.Requirements{}, func(_ *processor.Invocation, c *processor.Completion, in model.Input) {
		if value(t, in, "X-Script") != "first" {
			t.Error("rewrite did not observe the selected script result")
		}
		finish(t, c, newSet(in, "X-Rewrite", "one"), nil)
	})
	rewriteSecond := newFake(t, "rewrite-second", processor.Requirements{}, func(_ *processor.Invocation, c *processor.Completion, in model.Input) {
		if value(t, in, "X-Rewrite") != "one" {
			t.Error("rewrite rules did not see incremental changes")
		}
		finish(t, c, newSet(in, "X-Rewrite", "two"), nil)
	})
	runner, err := NewRunner([]Entry{
		{Class: Rewrite, Processor: rewriteSecond, Priority: 2},
		{Class: Script, Processor: scriptSecond, Priority: 2, Match: func(Metadata) bool { return true }},
		{Class: InternalHook, Processor: hookLate, Priority: 10},
		{Class: Rewrite, Processor: rewriteFirst, Priority: 1},
		{Class: Script, Processor: scriptFirst, Priority: 1, Match: func(Metadata) bool { return true }},
		{Class: InternalHook, Processor: hookEarly, Priority: 1},
	}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	report, err := runner.Run(context.Background(), tx, model.RequestPhase)
	if err != nil || report.Outcome != ContinueUpstream || report.LastResult != model.ResultRequestChange {
		t.Fatalf("request pipeline failed: report=%+v err=%v", report, err)
	}
	if secondScript.Load() != 0 {
		t.Fatal("script stage did not use first-match selection")
	}
	input, lease, err := tx.Snapshot("egress")
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	if value(t, input, "X-Rewrite") != "two" || tx.Outcome() != model.ExchangeUpstreamIssued {
		t.Fatal("request result or one-shot upstream state missing")
	}
	if _, err := runner.Run(context.Background(), tx, model.RequestPhase); err == nil {
		t.Fatal("request phase replay was accepted")
	}
}

func TestRunnerResponseAndBodyReplacementVisibleToNextProcessor(t *testing.T) {
	tx, ledger, _ := newTransaction(t, "response", "")
	requestRunner, _ := NewRunner(nil, Options{})
	if _, err := requestRunner.Run(context.Background(), tx, model.RequestPhase); err != nil {
		t.Fatal(err)
	}
	responseLease := model.NewCopyLease(ledger)
	responseHeaders, _ := model.NewHeaderBlock(responseLease, []model.HeaderField{{Name: "Content-Encoding", Values: []string{"gzip"}}, {Name: "ETag", Values: []string{"old"}}})
	response := model.ResponseHead{Status: 200, Headers: responseHeaders}
	body := newCountingBody("old-response")
	broker, err := model.NewBodyBroker(context.Background(), model.BodySource{Reader: body, Owner: model.TransportOwned, DeclaredLength: int64(len("old-response"))}, ledger)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.EnterResponse(tx.Revision(), response, response, model.NewBodySlot(broker), model.OriginUpstream); err != nil {
		t.Fatal(err)
	}
	_ = responseLease.Close()
	responseHook := newFake(t, "response-hook", processor.Requirements{}, func(_ *processor.Invocation, c *processor.Completion, _ model.Input) {
		finish(t, c, mustResponseChange(t, ledger, model.ResponsePatch{Headers: []model.HeaderEdit{{Kind: model.HeaderSet, Name: "X-Response-Hook", Values: []string{"ran"}}}}), nil)
	})
	responseScript := newFake(t, "response-script", processor.Requirements{}, func(_ *processor.Invocation, c *processor.Completion, in model.Input) {
		responseHead, ok := in.Response()
		values, _, err := responseHead.Headers.Values("X-Response-Hook")
		if !ok || err != nil || len(values) != 1 || values[0] != "ran" {
			t.Error("response script did not observe internal response hook")
		}
		finish(t, c, mustResponseChange(t, ledger, model.ResponsePatch{Headers: []model.HeaderEdit{{Kind: model.HeaderSet, Name: "X-Response-Script", Values: []string{"ran"}}}}), nil)
	})
	first := newFake(t, "response-change", processor.Requirements{Body: model.FullBuffered, MaxBodyBytes: 64}, func(_ *processor.Invocation, c *processor.Completion, in model.Input) {
		responseHead, ok := in.Response()
		values, _, headerErr := responseHead.Headers.Values("X-Response-Script")
		if !ok || headerErr != nil || len(values) != 1 || values[0] != "ran" {
			t.Error("response rewrite did not observe script result")
		}
		bodyCopy, err := in.Body().BytesCopy()
		if err != nil || string(bodyCopy) != "old-response" {
			t.Errorf("first response input body=%q err=%v", bodyCopy, err)
		}
		finish(t, c, mustResponseChange(t, ledger, model.ResponsePatch{Body: model.BodyEdit{Kind: model.BodyReplace, Bytes: []byte("replacement")}}), nil)
	})
	second := newFake(t, "response-observer", processor.Requirements{Body: model.FullBuffered, MaxBodyBytes: 64}, func(_ *processor.Invocation, c *processor.Completion, in model.Input) {
		bodyCopy, err := in.Body().BytesCopy()
		if err != nil || string(bodyCopy) != "replacement" {
			t.Errorf("next Processor did not observe replaced body: %q err=%v", bodyCopy, err)
		}
		finish(t, c, model.Continue(), nil)
	})
	runner, _ := NewRunner([]Entry{
		{Class: Rewrite, Processor: second, Priority: 2},
		{Class: Script, Processor: responseScript},
		{Class: InternalHook, Processor: responseHook, Priority: 1},
		{Class: Rewrite, Processor: first, Priority: 1},
	}, Options{})
	report, err := runner.Run(context.Background(), tx, model.ResponsePhase)
	if err != nil || report.Outcome != ResponseComplete || report.LastResult != model.ResultContinue {
		t.Fatalf("response pipeline failed: report=%+v err=%v", report, err)
	}
	if body.closes.Load() != 1 {
		t.Fatalf("old transport-owned response body closed %d times", body.closes.Load())
	}
}

func TestRunnerControlResults(t *testing.T) {
	tests := []struct {
		name    string
		result  func(*testing.T, *model.Ledger) model.DoneResult
		outcome Outcome
		kind    model.ExchangeOutcome
		stopped bool
	}{
		{name: "continue", result: func(*testing.T, *model.Ledger) model.DoneResult { return model.Continue() }, outcome: ContinueUpstream, kind: model.ExchangeUpstreamIssued},
		{name: "change", result: func(t *testing.T, l *model.Ledger) model.DoneResult {
			return mustRequestChange(t, l, model.RequestPatch{Method: model.Optional[string]{Present: true, Value: "PUT"}})
		}, outcome: ContinueUpstream, kind: model.ExchangeUpstreamIssued},
		{name: "stop-phase", result: func(*testing.T, *model.Ledger) model.DoneResult { return model.StopPhase() }, outcome: ContinueUpstream, kind: model.ExchangeUpstreamIssued, stopped: true},
		{name: "reject", result: func(t *testing.T, l *model.Ledger) model.DoneResult {
			result, err := model.Reject("policy", l)
			if err != nil {
				t.Fatal(err)
			}
			return result
		}, outcome: Rejected, kind: model.ExchangeRejected},
		{name: "abort", result: func(t *testing.T, l *model.Ledger) model.DoneResult {
			result, err := model.Abort("protocol", l)
			if err != nil {
				t.Fatal(err)
			}
			return result
		}, outcome: Aborted, kind: model.ExchangeAborted},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tx, ledger, _ := newTransaction(t, "control-"+test.name, "")
			fake := newFake(t, "control", processor.Requirements{}, func(_ *processor.Invocation, c *processor.Completion, _ model.Input) {
				finish(t, c, test.result(t, ledger), nil)
			})
			runner, _ := NewRunner([]Entry{{Class: Script, Processor: fake}}, Options{})
			report, err := runner.Run(context.Background(), tx, model.RequestPhase)
			if err != nil || report.Outcome != test.outcome || report.Stopped != test.stopped || tx.Outcome() != test.kind {
				t.Fatalf("control result mismatch: report=%+v tx=%d err=%v", report, tx.Outcome(), err)
			}
			if test.kind == model.ExchangeRejected || test.kind == model.ExchangeAborted {
				decisionLease := model.NewCopyLease(ledger)
				outcome, code, reason, decisionErr := tx.DecisionCopy(decisionLease)
				if decisionErr != nil || outcome != test.kind || test.kind == model.ExchangeRejected && code != "policy" || test.kind == model.ExchangeAborted && reason != "protocol" {
					_ = decisionLease.Close()
					t.Fatalf("terminal decision payload unavailable: outcome=%d code=%q reason=%q err=%v", outcome, code, reason, decisionErr)
				}
				_ = decisionLease.Close()
			}
		})
	}
	t.Run("respond-skips-response", func(t *testing.T) {
		tx, ledger, _ := newTransaction(t, "control-respond", "")
		fake := newFake(t, "respond", processor.Requirements{}, func(_ *processor.Invocation, c *processor.Completion, _ model.Input) {
			headerLease := model.NewCopyLease(ledger)
			headers, _ := model.NewHeaderBlock(headerLease, []model.HeaderField{{Name: "Content-Type", Values: []string{"text/plain"}}})
			trailers, _ := model.NewTrailerView(model.TrailerUnavailable, model.HeaderBlock{}, model.HeaderBlock{})
			synthetic, err := model.NewSyntheticResponse(200, headers, []byte("synthetic"), trailers, ledger, 64)
			_ = headerLease.Close()
			if err != nil {
				t.Error(err)
				return
			}
			result, err := model.Respond(synthetic)
			if err != nil {
				t.Error(err)
				return
			}
			finish(t, c, result, nil)
		})
		response := newFake(t, "must-skip", processor.Requirements{}, nil)
		requestRunner, _ := NewRunner([]Entry{{Class: Script, Processor: fake}}, Options{})
		responseRunner, _ := NewRunner([]Entry{{Class: Script, Processor: response}}, Options{})
		if report, err := requestRunner.Run(context.Background(), tx, model.RequestPhase); err != nil || report.Outcome != SyntheticReady {
			t.Fatalf("Respond failed: %+v %v", report, err)
		}
		if report, err := responseRunner.Run(context.Background(), tx, model.ResponsePhase); err != nil || report.Outcome != SkippedSyntheticResponse || response.starts.Load() != 0 {
			t.Fatalf("synthetic entered response pipeline: report=%+v starts=%d err=%v", report, response.starts.Load(), err)
		}
		owned, ok := tx.TakeSynthetic()
		if !ok {
			t.Fatal("synthetic response missing")
		}
		body, err := owned.BodyBytesCopy()
		if err != nil || string(body) != "synthetic" {
			t.Fatalf("synthetic payload lost after result release: %q %v", body, err)
		}
		_ = owned.Release()
	})
}

func TestRunnerInvalidAndPhaseMismatchResultsFailClosed(t *testing.T) {
	for _, test := range []struct {
		name   string
		result func(*testing.T, *model.Ledger) model.DoneResult
	}{
		{name: "invalid", result: func(*testing.T, *model.Ledger) model.DoneResult { return model.DoneResult{} }},
		{name: "wrong-phase", result: func(t *testing.T, l *model.Ledger) model.DoneResult {
			return mustResponseChange(t, l, model.ResponsePatch{Status: model.Optional[int]{Present: true, Value: 201}})
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			tx, ledger, _ := newTransaction(t, "invalid-"+test.name, "")
			fake := newFake(t, "invalid-output", processor.Requirements{}, func(_ *processor.Invocation, c *processor.Completion, _ model.Input) {
				finish(t, c, test.result(t, ledger), nil)
			})
			runner, _ := NewRunner([]Entry{{Class: Rewrite, Processor: fake}}, Options{})
			_, err := runner.Run(context.Background(), tx, model.RequestPhase)
			var processing *model.ProcessingError
			if !errors.As(err, &processing) || processing.Kind != model.ProcessingErrorInvalidOutput || tx.Revision() != 1 {
				t.Fatalf("invalid output was accepted: error=%v revision=%d", err, tx.Revision())
			}
		})
	}
}

func TestPipelinePreservesContextAndUpstreamFailureKinds(t *testing.T) {
	t.Run("parent-cancel", func(t *testing.T) {
		tx, _, _ := newTransaction(t, "parent-cancel", "")
		fake := newFake(t, "cancelled", processor.Requirements{}, nil)
		runner, _ := NewRunner([]Entry{{Class: Rewrite, Processor: fake}}, Options{})
		ctx, cancel := context.WithCancelCause(context.Background())
		cancel(context.Canceled)
		_, err := runner.Run(ctx, tx, model.RequestPhase)
		var processing *model.ProcessingError
		if !errors.As(err, &processing) || processing.Kind != model.ProcessingErrorCanceled || fake.starts.Load() != 0 || tx.State() != model.Terminated {
			t.Fatalf("parent cancellation was not terminal: error=%v starts=%d state=%d", err, fake.starts.Load(), tx.State())
		}
	})
	t.Run("upstream-classification", func(t *testing.T) {
		tx, _, _ := newTransaction(t, "upstream-classification", "")
		fake := newFake(t, "upstream-error", processor.Requirements{}, nil)
		fake.startErr = model.NewProcessingError(model.ProcessingErrorUpstream, model.ProcessingOriginUpstream, model.RequestPhase, "upstream-error", "", errors.New("upstream unavailable"))
		runner, _ := NewRunner([]Entry{{Class: Rewrite, Processor: fake}}, Options{})
		_, err := runner.Run(context.Background(), tx, model.RequestPhase)
		var processing *model.ProcessingError
		if !errors.As(err, &processing) || processing.Kind != model.ProcessingErrorUpstream {
			t.Fatalf("upstream error was collapsed into Processor error: %v", err)
		}
	})
}

func TestExecutionResourceCleanupFailureCannotFailOpen(t *testing.T) {
	tx, _, _ := newTransaction(t, "cleanup-failure", "")
	resource := &failingCloser{err: errors.New("close failed")}
	fake := newFake(t, "must-not-start", processor.Requirements{}, nil)
	runner, _ := NewRunner([]Entry{{Class: Rewrite, Processor: fake, AllowFailOpen: true, FailOpenSafe: func(error) bool { return true }}}, Options{
		AcquireExecution: func(context.Context, processor.Descriptor, model.InvocationKey) ([]io.Closer, error) {
			return []io.Closer{resource}, errors.New("resource admission failed")
		},
	})
	_, err := runner.Run(context.Background(), tx, model.RequestPhase)
	if err == nil || fake.starts.Load() != 0 || resource.closes.Load() != 1 || tx.State() != model.Terminated {
		t.Fatalf("resource cleanup failure was masked: err=%v starts=%d closes=%d state=%d", err, fake.starts.Load(), resource.closes.Load(), tx.State())
	}
}

func TestInvocationCleanupFailureCannotFailOpen(t *testing.T) {
	tx, _, _ := newTransaction(t, "invocation-cleanup-failure", "")
	resource := &failingCloser{err: errors.New("execution lease close failed")}
	fake := newFake(t, "cleanup-error", processor.Requirements{}, func(_ *processor.Invocation, completion *processor.Completion, _ model.Input) {
		finish(t, completion, model.DoneResult{}, errors.New("processor failed"))
	})
	runner, _ := NewRunner([]Entry{{Class: Rewrite, Processor: fake, AllowFailOpen: true, FailOpenSafe: func(error) bool { return true }}}, Options{
		AcquireExecution: func(context.Context, processor.Descriptor, model.InvocationKey) ([]io.Closer, error) {
			return []io.Closer{resource}, nil
		},
	})
	_, err := runner.Run(context.Background(), tx, model.RequestPhase)
	if err == nil || resource.closes.Load() != 1 || fake.lifecycle.Active() != 0 || tx.State() != model.Terminated {
		t.Fatalf("Invocation cleanup failure was masked: err=%v closes=%d active=%d state=%d", err, resource.closes.Load(), fake.lifecycle.Active(), tx.State())
	}
}

func TestRejectPayloadBudgetTransfersToTransaction(t *testing.T) {
	tx, ledger, _ := newTransaction(t, "reject-budget", "")
	baseline := ledger.Current()
	var outputCharge atomic.Int64
	fake := newFake(t, "reject-budget", processor.Requirements{}, func(_ *processor.Invocation, c *processor.Completion, _ model.Input) {
		before := ledger.Current()
		result, err := model.Reject("policy", ledger)
		if err != nil {
			t.Error(err)
			return
		}
		outputCharge.Store(ledger.Current() - before)
		finish(t, c, result, nil)
	})
	runner, _ := NewRunner([]Entry{{Class: Script, Processor: fake}}, Options{})
	if report, err := runner.Run(context.Background(), tx, model.RequestPhase); err != nil || report.Outcome != Rejected {
		t.Fatalf("reject failed: report=%+v err=%v", report, err)
	}
	if want, got := baseline+outputCharge.Load(), ledger.Current(); got != want {
		t.Fatalf("output budget was not transferred/released: want ledger=%d got=%d", want, got)
	}
}

func TestRunnerDetectsRevisionMismatchBeforeCommit(t *testing.T) {
	tx, ledger, _ := newTransaction(t, "revision", "")
	fake := newFake(t, "revision-race", processor.Requirements{}, func(_ *processor.Invocation, c *processor.Completion, input model.Input) {
		head := input.Request()
		head.Method = "PUT"
		if err := tx.UpdateRequest(input.Key().Revision, head); err != nil {
			t.Errorf("external owner update failed: %v", err)
		}
		finish(t, c, mustRequestChange(t, ledger, model.RequestPatch{Method: model.Optional[string]{Present: true, Value: "PATCH"}}), nil)
	})
	runner, _ := NewRunner([]Entry{{Class: Rewrite, Processor: fake}}, Options{})
	_, err := runner.Run(context.Background(), tx, model.RequestPhase)
	var processing *model.ProcessingError
	if !errors.As(err, &processing) || processing.Kind != model.ProcessingErrorProtocol || tx.Revision() != 2 {
		t.Fatalf("stale result was not rejected: error=%v revision=%d", err, tx.Revision())
	}
}

func TestRunnerRejectsMismatchedInvocationKeyAndReleasesItsResult(t *testing.T) {
	tx, ledger, _ := newTransaction(t, "invocation-key", "")
	fake := newFake(t, "wrong-invocation", processor.Requirements{}, func(_ *processor.Invocation, completion *processor.Completion, _ model.Input) {
		finish(t, completion, mustRequestChange(t, ledger, model.RequestPatch{Method: model.Optional[string]{Present: true, Value: "PATCH"}}), nil)
	})
	fake.mutateKey = func(key model.InvocationKey) model.InvocationKey {
		key.Invocation = "wrong-key"
		return key
	}
	runner, _ := NewRunner([]Entry{{Class: Rewrite, Processor: fake}}, Options{})
	_, err := runner.Run(context.Background(), tx, model.RequestPhase)
	var processing *model.ProcessingError
	if !errors.As(err, &processing) || processing.Kind != model.ProcessingErrorInvalidOutput || fake.lifecycle.Active() != 0 || tx.Revision() != 1 {
		t.Fatalf("mismatched Invocation key was accepted or retained: err=%v active=%d revision=%d", err, fake.lifecycle.Active(), tx.Revision())
	}
}

func TestBodyRequirementsMatchingPrefixReplayAndReplacement(t *testing.T) {
	t.Run("none-does-not-read", func(t *testing.T) {
		tx, _, body := newTransaction(t, "body-none", "payload")
		fake := newFake(t, "body-none", processor.Requirements{}, func(_ *processor.Invocation, c *processor.Completion, input model.Input) {
			if input.Body().Info().State != model.UnreadStream {
				t.Errorf("Body state changed: %+v", input.Body().Info())
			}
			finish(t, c, model.Continue(), nil)
		})
		runner, _ := NewRunner([]Entry{{Class: Rewrite, Processor: fake}}, Options{})
		if _, err := runner.Run(context.Background(), tx, model.RequestPhase); err != nil {
			t.Fatal(err)
		}
		if body.reads.Load() != 0 {
			t.Fatalf("None requirement read source %d times", body.reads.Load())
		}
	})
	t.Run("full-buffer-only-after-match", func(t *testing.T) {
		tx, ledger, body := newTransaction(t, "body-match", "payload")
		unmatched := newFake(t, "unmatched", processor.Requirements{Body: model.FullBuffered, MaxBodyBytes: 32}, nil)
		matched := newFake(t, "matched", processor.Requirements{Body: model.FullBuffered, MaxBodyBytes: 32}, func(_ *processor.Invocation, c *processor.Completion, input model.Input) {
			data, err := input.Body().BytesCopy()
			if err != nil || string(data) != "payload" {
				t.Errorf("buffered body=%q err=%v", data, err)
			}
			finish(t, c, model.Continue(), nil)
		})
		runner, _ := NewRunner([]Entry{
			{Class: Rewrite, Processor: unmatched, Match: func(m Metadata) bool { return m.Request.URL.Path() == "/no-match" }},
			{Class: Rewrite, Processor: matched, Match: func(m Metadata) bool { return m.Request.URL.Path() == "/start" }},
		}, Options{})
		if _, err := runner.Run(context.Background(), tx, model.RequestPhase); err != nil {
			t.Fatal(err)
		}
		if unmatched.starts.Load() != 0 || matched.starts.Load() != 1 || body.reads.Load() == 0 {
			t.Fatalf("metadata/body order mismatch: unmatched=%d matched=%d reads=%d", unmatched.starts.Load(), matched.starts.Load(), body.reads.Load())
		}
		_ = ledger
	})
	t.Run("prefix-replay-survives-fail-open", func(t *testing.T) {
		tx, _, _ := newTransaction(t, "body-prefix", "abcdef")
		oversize := newFake(t, "body-limit", processor.Requirements{Body: model.FullBuffered, MaxBodyBytes: 2}, nil)
		observer := newFake(t, "prefix-observer", processor.Requirements{}, func(_ *processor.Invocation, c *processor.Completion, input model.Input) {
			if input.Body().Info().State != model.PrefixReplay {
				t.Errorf("oversize prefix lost: %+v", input.Body().Info())
			}
			finish(t, c, model.Continue(), nil)
		})
		runner, _ := NewRunner([]Entry{
			{Class: Rewrite, Processor: oversize, AllowFailOpen: true},
			{Class: Rewrite, Processor: observer},
		}, Options{})
		report, err := runner.Run(context.Background(), tx, model.RequestPhase)
		if err != nil || len(report.Recoveries) != 1 || oversize.starts.Load() != 0 || observer.starts.Load() != 1 {
			t.Fatalf("Body limit fallback failed: report=%+v err=%v", report, err)
		}
		stream, err := tx.TakeBody()
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(stream)
		if err != nil || string(got) != "abcdef" {
			t.Fatalf("PrefixReplay lost bytes: %q err=%v", got, err)
		}
		_ = stream.Close()
	})
	t.Run("read-error-cannot-fail-open", func(t *testing.T) {
		body := &countingBody{reader: strings.NewReader(""), readErr: io.ErrClosedPipe}
		tx, _, _ := newTransactionConfigured(t, "body-read-error", "conn-body-read-error", "stream-1", body, -1)
		fake := newFake(t, "body-read-error", processor.Requirements{Body: model.FullBuffered, MaxBodyBytes: 64}, nil)
		runner, _ := NewRunner([]Entry{{Class: Rewrite, Processor: fake, AllowFailOpen: true, FailOpenSafe: func(error) bool { return true }}}, Options{})
		_, err := runner.Run(context.Background(), tx, model.RequestPhase)
		var processing *model.ProcessingError
		if !errors.As(err, &processing) || processing.Kind != model.ProcessingErrorBodyRead || fake.starts.Load() != 0 {
			t.Fatalf("Body read failure was masked: error=%v starts=%d", err, fake.starts.Load())
		}
	})
}

func TestRequestBodyCanBeReplacedWhenOriginalSourceIsUnavailable(t *testing.T) {
	tx, ledger, _ := newTransaction(t, "body-replacement-from-empty", "")
	replace := newFake(t, "replace-empty-body", processor.Requirements{}, func(_ *processor.Invocation, completion *processor.Completion, _ model.Input) {
		finish(t, completion, mustRequestChange(t, ledger, model.RequestPatch{Body: model.BodyEdit{Kind: model.BodyReplace, Bytes: []byte("new-body")}}), nil)
	})
	observe := newFake(t, "observe-empty-body-replacement", processor.Requirements{Body: model.FullBuffered, MaxBodyBytes: 32}, func(_ *processor.Invocation, completion *processor.Completion, input model.Input) {
		body, err := input.Body().BytesCopy()
		if err != nil || string(body) != "new-body" {
			t.Errorf("replacement Body unavailable to next Processor: %q err=%v", body, err)
		}
		finish(t, completion, model.Continue(), nil)
	})
	runner, _ := NewRunner([]Entry{{Class: Rewrite, Processor: replace, Priority: 1}, {Class: Rewrite, Processor: observe, Priority: 2}}, Options{})
	if report, err := runner.Run(context.Background(), tx, model.RequestPhase); err != nil || report.Outcome != ContinueUpstream {
		t.Fatalf("body replacement on Unavailable source failed: report=%+v err=%v", report, err)
	}
}

func TestFailOpenRollsBackOnlyCurrentEntryAndFailClosedTerminates(t *testing.T) {
	t.Run("recoverable-legacy-entry", func(t *testing.T) {
		tx, ledger, _ := newTransaction(t, "fail-open", "")
		hook := newFake(t, "committed-hook", processor.Requirements{}, func(_ *processor.Invocation, c *processor.Completion, _ model.Input) {
			finish(t, c, mustRequestChange(t, ledger, model.RequestPatch{Headers: []model.HeaderEdit{{Kind: model.HeaderSet, Name: "X-Prior", Values: []string{"kept"}}}}), nil)
		})
		legacy := newFake(t, "legacy-fails", processor.Requirements{}, func(_ *processor.Invocation, c *processor.Completion, _ model.Input) {
			finish(t, c, model.DoneResult{}, errors.New("processor failed"))
		})
		rewrite := newFake(t, "rewrite-after-fallback", processor.Requirements{}, func(_ *processor.Invocation, c *processor.Completion, in model.Input) {
			if value(t, in, "X-Prior") != "kept" {
				t.Error("fail-open discarded a prior committed entry")
			}
			finish(t, c, mustRequestChange(t, ledger, model.RequestPatch{Headers: []model.HeaderEdit{{Kind: model.HeaderSet, Name: "X-After", Values: []string{"ran"}}}}), nil)
		})
		runner, _ := NewRunner([]Entry{
			{Class: InternalHook, Processor: hook},
			{Class: Script, Processor: legacy, Profile: LegacyProfile, FailOpenSafe: func(error) bool { return true }},
			{Class: Rewrite, Processor: rewrite},
		}, Options{})
		report, err := runner.Run(context.Background(), tx, model.RequestPhase)
		if err != nil || report.Outcome != ContinueUpstream || len(report.Recoveries) != 1 {
			t.Fatalf("legacy fallback failed: report=%+v err=%v", report, err)
		}
		input, lease, err := tx.Snapshot("after-fallback")
		if err != nil {
			t.Fatal(err)
		}
		defer lease.Close()
		if value(t, input, "X-Prior") != "kept" || value(t, input, "X-After") != "ran" {
			t.Fatal("successful prior/current entries were not preserved")
		}
	})
	t.Run("strict-default", func(t *testing.T) {
		tx, _, _ := newTransaction(t, "fail-closed", "")
		fake := newFake(t, "strict-fails", processor.Requirements{}, func(_ *processor.Invocation, c *processor.Completion, _ model.Input) {
			finish(t, c, model.DoneResult{}, errors.New("processor failed"))
		})
		runner, _ := NewRunner([]Entry{{Class: Rewrite, Processor: fake}}, Options{})
		_, err := runner.Run(context.Background(), tx, model.RequestPhase)
		var processing *model.ProcessingError
		if !errors.As(err, &processing) || processing.Kind != model.ProcessingErrorExecution || tx.State() != model.Terminated {
			t.Fatalf("strict failure was opened: %v state=%d", err, tx.State())
		}
	})
}

func TestStartFailureReturnsResourcesAndAwaitTimeoutKeepsExecutionLeases(t *testing.T) {
	t.Run("start-failure", func(t *testing.T) {
		tx, _, _ := newTransaction(t, "start-failure", "")
		generation := &countCloser{}
		fake := newFake(t, "start-fails", processor.Requirements{}, nil)
		fake.startErr = errors.New("admission failed")
		runner, _ := NewRunner([]Entry{{Class: Rewrite, Processor: fake}}, Options{AcquireGeneration: func(context.Context, model.GenerationID) (io.Closer, error) { return generation, nil }})
		_, err := runner.Run(context.Background(), tx, model.RequestPhase)
		if err == nil || generation.closes.Load() != 1 {
			t.Fatalf("Start failure did not release caller-owned resources: err=%v closes=%d", err, generation.closes.Load())
		}
	})
	t.Run("late-finish", func(t *testing.T) {
		tx, ledger, _ := newTransaction(t, "late-finish", "")
		generation := &countCloser{}
		started := make(chan struct {
			invocation *processor.Invocation
			completion *processor.Completion
			input      model.Input
		}, 1)
		fake := newFake(t, "late", processor.Requirements{}, func(inv *processor.Invocation, completion *processor.Completion, input model.Input) {
			started <- struct {
				invocation *processor.Invocation
				completion *processor.Completion
				input      model.Input
			}{inv, completion, input}
		})
		runner, _ := NewRunner([]Entry{{Class: Rewrite, Processor: fake}}, Options{AcquireGeneration: func(context.Context, model.GenerationID) (io.Closer, error) { return generation, nil }})
		ctx, cancel := context.WithCancelCause(context.Background())
		type runResult struct {
			report Report
			err    error
		}
		done := make(chan runResult, 1)
		go func() { report, err := runner.Run(ctx, tx, model.RequestPhase); done <- runResult{report, err} }()
		handle := <-started
		ledgerBeforeCancel := ledger.Current()
		cancel(context.DeadlineExceeded)
		result := <-done
		var processing *model.ProcessingError
		if !errors.As(result.err, &processing) || processing.Kind != model.ProcessingErrorTimeout {
			t.Fatalf("Await timeout was not classified: %v", result.err)
		}
		if generation.closes.Load() != 0 || !channelOpen(handle.invocation.ExecutionDone()) || fake.lifecycle.Active() != 1 || ledger.Current() < ledgerBeforeCancel {
			t.Fatal("Await timeout released resources or admission before execution exit")
		}
		if value(t, handle.input, "X-Test") != "original" {
			t.Fatal("Input CopyLease expired before ExecutionDone")
		}
		ledgerBeforeLateFinish := ledger.Current()
		late := mustRequestChange(t, ledger, model.RequestPatch{Method: model.Optional[string]{Present: true, Value: "PATCH"}})
		finish(t, handle.completion, late, nil)
		select {
		case <-handle.invocation.ExecutionDone():
		case <-time.After(time.Second):
			t.Fatal("late Finish did not close ExecutionDone")
		}
		if generation.closes.Load() != 1 || fake.lifecycle.Active() != 0 || tx.Revision() != 1 || ledger.Current() >= ledgerBeforeLateFinish {
			t.Fatalf("late result committed or resources leaked: close=%d active=%d revision=%d", generation.closes.Load(), fake.lifecycle.Active(), tx.Revision())
		}
		_ = fake.Close()
		if err := fake.WaitClosed(context.Background()); err != nil {
			t.Fatal(err)
		}
	})
}

func TestDescriptorTotalTimeoutCancelsAwaitWithoutReleasingExecutionLease(t *testing.T) {
	tx, _, _ := newTransaction(t, "total-timeout", "")
	type pending struct {
		invocation *processor.Invocation
		completion *processor.Completion
	}
	started := make(chan pending, 1)
	fake := newFake(t, "total-timeout", processor.Requirements{TotalTimeout: time.Nanosecond}, func(inv *processor.Invocation, completion *processor.Completion, _ model.Input) {
		started <- pending{invocation: inv, completion: completion}
	})
	runner, _ := NewRunner([]Entry{{Class: Rewrite, Processor: fake}}, Options{})
	type runResult struct{ err error }
	done := make(chan runResult, 1)
	go func() {
		_, err := runner.Run(context.Background(), tx, model.RequestPhase)
		done <- runResult{err: err}
	}()
	handle := <-started
	var result runResult
	select {
	case result = <-done:
	case <-time.After(time.Second):
		t.Fatal("TotalTimeout did not cancel Await")
	}
	var processing *model.ProcessingError
	if !errors.As(result.err, &processing) || processing.Kind != model.ProcessingErrorTimeout {
		t.Fatalf("TotalTimeout classification mismatch: %v", result.err)
	}
	if !channelOpen(handle.invocation.ExecutionDone()) || fake.lifecycle.Active() != 1 {
		t.Fatal("Await timeout released execution resources before Finish")
	}
	finish(t, handle.completion, model.Continue(), nil)
	if channelOpen(handle.invocation.ExecutionDone()) || fake.lifecycle.Active() != 0 || tx.Revision() != 1 {
		t.Fatal("late Finish committed or failed to release execution resources")
	}
	_ = runner.Close()
	if err := runner.WaitClosed(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestMultipleTransactionsRunConcurrentlyAndGenerationStaysConnectionScoped(t *testing.T) {
	for round := 0; round < 20; round++ {
		tx1, _, _ := newTransactionConfigured(t, "parallel-a", "conn-h2", "stream-1", nil, 0)
		tx2, _, _ := newTransactionConfigured(t, "parallel-b", "conn-h2", "stream-3", nil, 0)
		var active, peak atomic.Int64
		started := make(chan struct{}, 2)
		release := make(chan struct{})
		generationIDs := make(chan model.GenerationID, 2)
		fake := newFake(t, "parallel", processor.Requirements{}, func(_ *processor.Invocation, c *processor.Completion, input model.Input) {
			current := active.Add(1)
			for old := peak.Load(); current > old && !peak.CompareAndSwap(old, current); old = peak.Load() {
			}
			started <- struct{}{}
			<-release
			active.Add(-1)
			finish(t, c, model.Continue(), nil)
		})
		runner, _ := NewRunner([]Entry{{Class: Rewrite, Processor: fake}}, Options{AcquireGeneration: func(_ context.Context, id model.GenerationID) (io.Closer, error) {
			generationIDs <- id
			return &countCloser{}, nil
		}})
		var wg sync.WaitGroup
		for _, tx := range []*model.Transaction{tx1, tx2} {
			wg.Add(1)
			go func(tx *model.Transaction) {
				defer wg.Done()
				if _, err := runner.Run(context.Background(), tx, model.RequestPhase); err != nil {
					t.Error(err)
				}
			}(tx)
		}
		<-started
		<-started
		if peak.Load() != 2 {
			t.Fatalf("different Transactions did not overlap, peak=%d", peak.Load())
		}
		close(release)
		wg.Wait()
		if first, second := <-generationIDs, <-generationIDs; first != 7 || second != 7 {
			t.Fatalf("connection generation changed between streams: %d %d", first, second)
		}
	}
}

func TestTransactionCloseRacesAtomicCommit(t *testing.T) {
	for round := 0; round < 20; round++ {
		tx, ledger, _ := newTransaction(t, "close-race", "")
		started := make(chan struct {
			invocation *processor.Invocation
			completion *processor.Completion
		}, 1)
		fake := newFake(t, "close-race", processor.Requirements{}, func(inv *processor.Invocation, c *processor.Completion, _ model.Input) {
			started <- struct {
				invocation *processor.Invocation
				completion *processor.Completion
			}{inv, c}
		})
		runner, _ := NewRunner([]Entry{{Class: Rewrite, Processor: fake}}, Options{})
		runDone := make(chan error, 1)
		go func() { _, err := runner.Run(context.Background(), tx, model.RequestPhase); runDone <- err }()
		handle := <-started
		barrier := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); <-barrier; _ = tx.Close() }()
		go func() { defer wg.Done(); <-barrier; finish(t, handle.completion, model.Continue(), nil) }()
		close(barrier)
		wg.Wait()
		<-runDone
		if revision := tx.Revision(); revision < 1 || revision > 3 {
			t.Fatalf("non-atomic close/commit revision %d", revision)
		}
		if err := tx.Close(); err != nil {
			t.Fatal(err)
		}
		_ = fake.Close()
		if err := fake.WaitClosed(context.Background()); err != nil {
			t.Fatal(err)
		}
		if ledger.Current() != 0 {
			t.Fatalf("round %d leaked budget: %d", round, ledger.Current())
		}
	}
}

func TestRunnerWaitClosedDrainsProcessorNotJustOneInvocation(t *testing.T) {
	tx1, _, _ := newTransaction(t, "drain-a", "")
	tx2, _, _ := newTransaction(t, "drain-b", "")
	type pending struct {
		invocation *processor.Invocation
		completion *processor.Completion
	}
	started := make(chan pending, 2)
	fake := newFake(t, "drain", processor.Requirements{}, func(inv *processor.Invocation, completion *processor.Completion, _ model.Input) {
		started <- pending{invocation: inv, completion: completion}
	})
	runner, _ := NewRunner([]Entry{{Class: Rewrite, Processor: fake}}, Options{})
	runErrors := make(chan error, 2)
	for _, tx := range []*model.Transaction{tx1, tx2} {
		go func(tx *model.Transaction) {
			_, err := runner.Run(context.Background(), tx, model.RequestPhase)
			runErrors <- err
		}(tx)
	}
	first, second := <-started, <-started
	if err := runner.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := runner.WaitClosed(ctx); err == nil {
		t.Fatal("WaitClosed treated active executions as drained")
	}
	finish(t, first.completion, model.Continue(), nil)
	finish(t, second.completion, model.Continue(), nil)
	if err := runner.WaitClosed(context.Background()); err != nil {
		t.Fatalf("WaitClosed returned before all invocations exited: %v", err)
	}
	<-runErrors
	<-runErrors
}

func channelOpen(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return false
	default:
		return true
	}
}
