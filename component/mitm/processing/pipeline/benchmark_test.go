package pipeline

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/metacubex/mihomo/component/mitm/processing/model"
	"github.com/metacubex/mihomo/component/mitm/processing/processor"
)

func benchmarkTransaction(b *testing.B, id string, body string) (*model.Transaction, *model.Ledger) {
	b.Helper()
	ledger, err := model.NewLedger(-1, nil)
	if err != nil {
		b.Fatal(err)
	}
	lease := model.NewCopyLease(ledger)
	urlValue, err := model.ParseURL(lease, "https://example.test/benchmark", model.MITMHTTPS)
	if err != nil {
		b.Fatal(err)
	}
	headers, err := model.NewHeaderBlock(lease, nil)
	if err != nil {
		b.Fatal(err)
	}
	trailers, err := model.NewTrailerView(model.TrailerUnavailable, model.HeaderBlock{}, model.HeaderBlock{})
	if err != nil {
		b.Fatal(err)
	}
	request := model.RequestHead{Method: "POST", URL: urlValue, Authority: "example.test", Headers: headers, Trailers: trailers}
	var reader io.ReadCloser
	if body != "" {
		reader = io.NopCloser(strings.NewReader(body))
	}
	broker, err := model.NewBodyBroker(context.Background(), model.BodySource{Reader: reader, Owner: model.FrameworkOwned, DeclaredLength: int64(len(body))}, ledger)
	if err != nil {
		b.Fatal(err)
	}
	bodySlot := model.NewBodySlot(broker)
	tx, err := model.NewTransaction(context.Background(), model.TransactionOptions{
		ID: id, Generation: 7, Connection: model.ConnectionView{ID: "conn-benchmark", StreamID: "stream-1"},
		OriginalIngress: request, Request: request, RequestBody: bodySlot, Ledger: ledger,
	})
	_ = lease.Close()
	if err != nil {
		b.Fatal(err)
	}
	return tx, ledger
}

func benchmarkRunner(b *testing.B, entries []Entry) *Runner {
	b.Helper()
	runner, err := NewRunner(entries, Options{})
	if err != nil {
		b.Fatal(err)
	}
	return runner
}

func BenchmarkPipeline3ProcessorNoBody(b *testing.B) {
	first := newFake(b, "no-body-1", processor.Requirements{}, nil)
	second := newFake(b, "no-body-2", processor.Requirements{}, nil)
	third := newFake(b, "no-body-3", processor.Requirements{}, nil)
	runner := benchmarkRunner(b, []Entry{
		{Class: InternalHook, Processor: first, Priority: 1},
		{Class: InternalHook, Processor: second, Priority: 2},
		{Class: Rewrite, Processor: third},
	})
	defer func() { _ = runner.Close(); _ = runner.WaitClosed(context.Background()) }()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		tx, _ := benchmarkTransaction(b, fmt.Sprintf("bench-none-%d", i), "")
		b.StartTimer()
		if _, err := runner.Run(context.Background(), tx, model.RequestPhase); err != nil {
			b.Fatal(err)
		}
		b.StopTimer()
		_ = tx.Close()
		b.StartTimer()
	}
}

func BenchmarkPipelineNoProcessor(b *testing.B) {
	runner := benchmarkRunner(b, nil)
	defer func() { _ = runner.Close(); _ = runner.WaitClosed(context.Background()) }()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		tx, _ := benchmarkTransaction(b, fmt.Sprintf("bench-empty-%d", i), "")
		b.StartTimer()
		report, err := runner.Run(context.Background(), tx, model.RequestPhase)
		if err != nil || report.Outcome != ContinueUpstream {
			b.Fatalf("empty Pipeline report=%+v err=%v", report, err)
		}
		b.StopTimer()
		_ = tx.Close()
		b.StartTimer()
	}
}

func BenchmarkPipelineSingleContinue(b *testing.B) {
	continueProcessor := newFake(b, "single-continue", processor.Requirements{}, nil)
	runner := benchmarkRunner(b, []Entry{{Class: Script, Processor: continueProcessor}})
	defer func() { _ = runner.Close(); _ = runner.WaitClosed(context.Background()) }()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		tx, _ := benchmarkTransaction(b, fmt.Sprintf("bench-continue-%d", i), "")
		b.StartTimer()
		if _, err := runner.Run(context.Background(), tx, model.RequestPhase); err != nil {
			b.Fatal(err)
		}
		b.StopTimer()
		_ = tx.Close()
		b.StartTimer()
	}
}

func BenchmarkPipelinePrefixReplay(b *testing.B) {
	const bodySize = 64 << 10
	body := strings.Repeat("p", bodySize)
	oversize := newFake(b, "prefix-limit", processor.Requirements{Body: model.FullBuffered, MaxBodyBytes: 1024}, nil)
	observer := newFake(b, "prefix-observer", processor.Requirements{}, nil)
	runner := benchmarkRunner(b, []Entry{
		{Class: Script, Processor: oversize, AllowFailOpen: true, FailOpenSafe: func(error) bool { return true }},
		{Class: Rewrite, Processor: observer},
	})
	defer func() { _ = runner.Close(); _ = runner.WaitClosed(context.Background()) }()
	b.ReportAllocs()
	b.SetBytes(bodySize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		tx, _ := benchmarkTransaction(b, fmt.Sprintf("bench-prefix-%d", i), body)
		b.StartTimer()
		report, err := runner.Run(context.Background(), tx, model.RequestPhase)
		if err != nil || len(report.Recoveries) != 1 {
			b.Fatalf("PrefixReplay fallback report=%+v err=%v", report, err)
		}
		if info := tx.BodyInfo(model.RequestPhase); info.State != model.PrefixReplay {
			b.Fatalf("body state = %v, want PrefixReplay", info.State)
		}
		b.StopTimer()
		stream, err := tx.TakeBody()
		if err != nil {
			b.Fatal(err)
		}
		if _, err := io.Copy(io.Discard, stream); err != nil {
			b.Fatal(err)
		}
		_ = stream.Close()
		_ = tx.Close()
		b.StartTimer()
	}
}

func BenchmarkPipelineBodyLogicalClose(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		tx, _ := benchmarkTransaction(b, fmt.Sprintf("bench-logical-close-%d", i), "payload")
		b.StartTimer()
		tx.CloseBodyLogical(model.RequestPhase)
		b.StopTimer()
		_ = tx.Close()
		b.StartTimer()
	}
}

func BenchmarkPipelineRequestChangeContinue(b *testing.B) {
	var ledger *model.Ledger
	change := newFake(b, "request-change", processor.Requirements{}, func(_ *processor.Invocation, completion *processor.Completion, _ model.Input) {
		result, err := model.ChangeRequest(model.RequestPatch{Headers: []model.HeaderEdit{{Kind: model.HeaderSet, Name: "X-Benchmark", Values: []string{"changed"}}}}, ledger, 64)
		if err != nil {
			b.Error(err)
			return
		}
		finish(b, completion, result, nil)
	})
	continueProcessor := newFake(b, "request-continue", processor.Requirements{}, nil)
	runner := benchmarkRunner(b, []Entry{{Class: Rewrite, Processor: change, Priority: 1}, {Class: Rewrite, Processor: continueProcessor, Priority: 2}})
	defer func() { _ = runner.Close(); _ = runner.WaitClosed(context.Background()) }()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		tx, currentLedger := benchmarkTransaction(b, fmt.Sprintf("bench-change-%d", i), "")
		ledger = currentLedger
		b.StartTimer()
		if _, err := runner.Run(context.Background(), tx, model.RequestPhase); err != nil {
			b.Fatal(err)
		}
		b.StopTimer()
		_ = tx.Close()
		b.StartTimer()
	}
}

func BenchmarkPipelineFullBuffered(b *testing.B) {
	const bodySize = 64 << 10
	body := strings.Repeat("b", bodySize)
	full := newFake(b, "full-buffered", processor.Requirements{Body: model.FullBuffered, MaxBodyBytes: bodySize}, func(_ *processor.Invocation, completion *processor.Completion, input model.Input) {
		if _, err := input.Body().BytesCopy(); err != nil {
			b.Error(err)
			return
		}
		finish(b, completion, model.Continue(), nil)
	})
	runner := benchmarkRunner(b, []Entry{{Class: Script, Processor: full}})
	defer func() { _ = runner.Close(); _ = runner.WaitClosed(context.Background()) }()
	b.ReportAllocs()
	b.SetBytes(bodySize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		tx, _ := benchmarkTransaction(b, fmt.Sprintf("bench-full-%d", i), body)
		b.StartTimer()
		if _, err := runner.Run(context.Background(), tx, model.RequestPhase); err != nil {
			b.Fatal(err)
		}
		b.StopTimer()
		_ = tx.Close()
		b.StartTimer()
	}
}

func BenchmarkPipelineSyntheticResponse(b *testing.B) {
	var ledger *model.Ledger
	respond := newFake(b, "synthetic", processor.Requirements{}, func(_ *processor.Invocation, completion *processor.Completion, _ model.Input) {
		headersLease := model.NewCopyLease(ledger)
		headers, err := model.NewHeaderBlock(headersLease, nil)
		if err != nil {
			b.Error(err)
			return
		}
		trailers, err := model.NewTrailerView(model.TrailerUnavailable, model.HeaderBlock{}, model.HeaderBlock{})
		if err != nil {
			b.Error(err)
			return
		}
		synthetic, err := model.NewSyntheticResponse(200, headers, []byte("synthetic response body"), trailers, ledger, 128)
		_ = headersLease.Close()
		if err != nil {
			b.Error(err)
			return
		}
		result, err := model.Respond(synthetic)
		if err != nil {
			b.Error(err)
			return
		}
		finish(b, completion, result, nil)
	})
	runner := benchmarkRunner(b, []Entry{{Class: Script, Processor: respond}})
	defer func() { _ = runner.Close(); _ = runner.WaitClosed(context.Background()) }()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		tx, currentLedger := benchmarkTransaction(b, fmt.Sprintf("bench-synthetic-%d", i), "")
		ledger = currentLedger
		b.StartTimer()
		if _, err := runner.Run(context.Background(), tx, model.RequestPhase); err != nil {
			b.Fatal(err)
		}
		owned, ok := tx.TakeSynthetic()
		if !ok {
			b.Fatal("synthetic output not transferred")
		}
		if _, err := owned.BodyBytesCopy(); err != nil {
			b.Fatal(err)
		}
		_ = owned.Release()
		b.StopTimer()
		_ = tx.Close()
		b.StartTimer()
	}
}

func BenchmarkPipelineFailOpen(b *testing.B) {
	failing := newFake(b, "fallback", processor.Requirements{}, func(_ *processor.Invocation, completion *processor.Completion, _ model.Input) {
		finish(b, completion, model.DoneResult{}, errors.New("recoverable processor failure"))
	})
	continued := newFake(b, "after-fallback", processor.Requirements{}, nil)
	runner := benchmarkRunner(b, []Entry{
		{Class: Script, Processor: failing, AllowFailOpen: true, FailOpenSafe: func(error) bool { return true }},
		{Class: Rewrite, Processor: continued},
	})
	defer func() { _ = runner.Close(); _ = runner.WaitClosed(context.Background()) }()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		tx, _ := benchmarkTransaction(b, fmt.Sprintf("bench-failopen-%d", i), "")
		b.StartTimer()
		if _, err := runner.Run(context.Background(), tx, model.RequestPhase); err != nil {
			b.Fatal(err)
		}
		b.StopTimer()
		_ = tx.Close()
		b.StartTimer()
	}
}

type awaitCancelContext struct {
	context.Context
	calls atomic.Int64
	done  chan struct{}
	fail  error
}

func newAwaitCancelContext(fail error) *awaitCancelContext {
	return &awaitCancelContext{Context: context.Background(), done: make(chan struct{}), fail: fail}
}

func (c *awaitCancelContext) Done() <-chan struct{} {
	if c.calls.Add(1) == 2 {
		close(c.done)
	}
	return c.done
}

func (c *awaitCancelContext) Err() error {
	select {
	case <-c.done:
		return c.fail
	default:
		return nil
	}
}

func BenchmarkPipelineCancelTimeout(b *testing.B) {
	b.Run("cancel", func(b *testing.B) { benchmarkPipelineAwaitFailure(b, context.Canceled) })
	b.Run("timeout", func(b *testing.B) { benchmarkPipelineAwaitFailure(b, context.DeadlineExceeded) })
}

func benchmarkPipelineAwaitFailure(b *testing.B, cause error) {
	var lastCompletion atomic.Pointer[processor.Completion]
	var lastInvocation atomic.Pointer[processor.Invocation]
	waiting := newFake(b, "await-cancel", processor.Requirements{}, func(invocation *processor.Invocation, completion *processor.Completion, _ model.Input) {
		lastInvocation.Store(invocation)
		lastCompletion.Store(completion)
	})
	runner := benchmarkRunner(b, []Entry{{Class: Rewrite, Processor: waiting}})
	defer func() { _ = runner.Close(); _ = runner.WaitClosed(context.Background()) }()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		tx, _ := benchmarkTransaction(b, fmt.Sprintf("bench-cancel-%d", i), "")
		ctx := newAwaitCancelContext(cause)
		b.StartTimer()
		_, err := runner.Run(ctx, tx, model.RequestPhase)
		if err == nil {
			b.Fatal("Await cancellation was not reported")
		}
		completion, invocation := lastCompletion.Load(), lastInvocation.Load()
		if completion == nil || invocation == nil || !completion.Finish(model.Continue(), nil) {
			b.Fatal("late cleanup failed")
		}
		b.StopTimer()
		_ = tx.Close()
		lastCompletion.Store(nil)
		lastInvocation.Store(nil)
		b.StartTimer()
	}
}
