package generation

import (
	"context"
	"io"
	"sync/atomic"
	"testing"

	"github.com/metacubex/mihomo/component/mitm/processing/model"
	"github.com/metacubex/mihomo/component/mitm/processing/pipeline"
	"github.com/metacubex/mihomo/component/mitm/processing/processor"
)

type asyncProcessor struct {
	lifecycle *processor.Lifecycle
	started   chan *processor.Invocation
	finish    chan *processor.Completion
	closes    atomic.Int32
}

func (p *asyncProcessor) Describe() processor.Descriptor {
	return processor.Descriptor{ID: "async", Backend: "test", ContractVersion: 1, Request: true}
}
func (p *asyncProcessor) Start(ctx context.Context, input model.Input, resources ...io.Closer) (*processor.Invocation, error) {
	i, c, e := p.lifecycle.BeginWithResources(ctx, input.Key(), resources...)
	if e == nil {
		p.started <- i
		p.finish <- c
	}
	return i, e
}
func (p *asyncProcessor) Close() error                         { p.closes.Add(1); return p.lifecycle.Close() }
func (p *asyncProcessor) WaitClosed(ctx context.Context) error { return p.lifecycle.WaitClosed(ctx) }
func transaction(t testing.TB, id model.GenerationID) *model.Transaction {
	t.Helper()
	ledger, e := model.NewLedger(-1, nil)
	if e != nil {
		t.Fatal(e)
	}
	copy := model.NewCopyLease(ledger)
	defer copy.Close()
	u, e := model.ParseURL(copy, "https://example.test/", model.MITMHTTPS)
	if e != nil {
		t.Fatal(e)
	}
	headers, e := model.NewHeaderBlock(copy, nil)
	if e != nil {
		t.Fatal(e)
	}
	trailers, e := model.NewTrailerView(model.TrailerUnavailable, model.HeaderBlock{}, model.HeaderBlock{})
	if e != nil {
		t.Fatal(e)
	}
	head := model.RequestHead{Method: "GET", URL: u, Authority: "example.test", Headers: headers, Trailers: trailers}
	broker, e := model.NewBodyBroker(context.Background(), model.BodySource{Owner: model.FrameworkOwned}, ledger)
	if e != nil {
		t.Fatal(e)
	}
	tx, e := model.NewTransaction(context.Background(), model.TransactionOptions{ID: "tx", Generation: id, Connection: model.ConnectionView{ID: "conn", StreamID: "1"}, OriginalIngress: head, Request: head, RequestBody: model.NewBodySlot(broker), Ledger: ledger})
	if e != nil {
		t.Fatal(e)
	}
	return tx
}
func TestPipelineCancelRetainsGenerationUntilExecutionDone(t *testing.T) {
	lifecycle, _ := processor.NewLifecycle(1)
	p := &asyncProcessor{lifecycle: lifecycle, started: make(chan *processor.Invocation, 1), finish: make(chan *processor.Completion, 1)}
	plan, e := NewPlan([]pipeline.Entry{{Class: pipeline.Script, Processor: p}})
	if e != nil {
		t.Fatal(e)
	}
	var publisher Publisher
	publisher.Publish(plan.Generation)
	conn, _ := publisher.Bind()
	stream, _ := conn.Transaction()
	runner, e := plan.Runner(stream)
	if e != nil {
		t.Fatal(e)
	}
	tx := transaction(t, plan.Generation.ID())
	defer tx.Close()
	ctx, cancel := context.WithCancel(context.Background())
	returned := make(chan error, 1)
	go func() { _, e := runner.Run(ctx, tx, model.RequestPhase); returned <- e }()
	invocation := <-p.started
	completion := <-p.finish
	publisher.Publish(New())
	conn.Close()
	cancel()
	if e := <-returned; e == nil {
		t.Fatal("cancel ignored")
	}
	stream.Close()
	select {
	case <-invocation.ExecutionDone():
		t.Fatal("execution ended early")
	default:
	}
	if plan.Generation.State() != Retiring || p.closes.Load() != 0 || lifecycle.Active() != 1 {
		t.Fatal("early release")
	}
	if !completion.Finish(model.Continue(), nil) {
		t.Fatal("finish")
	}
	select {
	case <-invocation.ExecutionDone():
	default:
		t.Fatal("execution not done")
	}
	if plan.Generation.State() != Closed || p.closes.Load() != 1 || lifecycle.Active() != 0 {
		t.Fatal("not drained")
	}
	publisher.Close()
}
func TestPlanBuildFailureCleansOwnedResources(t *testing.T) {
	c := &closer{}
	plan, e := NewPlan([]pipeline.Entry{{Class: pipeline.Script}}, c)
	if e == nil || plan != nil || c.n.Load() != 1 {
		t.Fatal("candidate cleanup")
	}
}
