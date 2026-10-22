package generation

import (
	"context"
	"errors"
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
	var failure *BuildError
	if !errors.As(e, &failure) || plan != nil {
		t.Fatal("missing cleanup owner")
	}
	if err := failure.Pending.Close(); err != nil {
		t.Fatal(err)
	}
	if c.n.Load() != 1 {
		t.Fatal("candidate cleanup")
	}
}

func TestEmptyPlanRejectsForeignAndClosedParent(t *testing.T) {
	plan, e := NewPlan(nil)
	if e != nil {
		t.Fatal(e)
	}
	var p Publisher
	p.Publish(plan.Generation)
	l, _ := p.Bind()
	r, _ := plan.Runner(l)
	tx := transaction(t, plan.Generation.ID()+1)
	defer tx.Close()
	if _, e = r.Run(context.Background(), tx, model.RequestPhase); e == nil {
		t.Fatal("foreign generation")
	}
	l.Close()
	tx2 := transaction(t, plan.Generation.ID())
	defer tx2.Close()
	if _, e = r.Run(context.Background(), tx2, model.RequestPhase); e == nil {
		t.Fatal("closed parent")
	}
	p.Close()
}
func BenchmarkGenerationPipeline(b *testing.B) {
	life, _ := processor.NewLifecycle(1)
	p := &syncProcessor{life}
	plan, e := NewPlan([]pipeline.Entry{{Class: pipeline.Script, Processor: p}})
	if e != nil {
		b.Fatal(e)
	}
	var pub Publisher
	pub.Publish(plan.Generation)
	defer pub.Close()
	conn, _ := pub.Bind()
	defer conn.Close()
	r, _ := plan.Runner(conn)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		tx := transaction(b, plan.Generation.ID())
		b.StartTimer()
		_, e := r.Run(context.Background(), tx, model.RequestPhase)
		if e != nil {
			b.Fatal(e)
		}
		b.StopTimer()
		tx.Close()
		b.StartTimer()
	}
}

type syncProcessor struct{ l *processor.Lifecycle }

func (p *syncProcessor) Describe() processor.Descriptor {
	return processor.Descriptor{ID: "sync", Backend: "test", ContractVersion: 1, Request: true}
}
func (p *syncProcessor) Start(ctx context.Context, in model.Input, resources ...io.Closer) (*processor.Invocation, error) {
	i, c, e := p.l.BeginWithResources(ctx, in.Key(), resources...)
	if e == nil {
		c.Finish(model.Continue(), nil)
	}
	return i, e
}
func (p *syncProcessor) Close() error                         { return p.l.Close() }
func (p *syncProcessor) WaitClosed(ctx context.Context) error { return p.l.WaitClosed(ctx) }

type drainingProcessor struct {
	syncProcessor
	entered, release chan struct{}
}

func (p *drainingProcessor) WaitClosed(ctx context.Context) error {
	close(p.entered)
	select {
	case <-p.release:
		return p.l.WaitClosed(ctx)
	case <-ctx.Done():
		return context.Cause(ctx)
	}
}
func TestPlanWaitsForBackendDrain(t *testing.T) {
	life, _ := processor.NewLifecycle(1)
	backend := &drainingProcessor{syncProcessor: syncProcessor{life}, entered: make(chan struct{}), release: make(chan struct{})}
	plan, e := NewPlan([]pipeline.Entry{{Class: pipeline.Script, Processor: backend}})
	if e != nil {
		t.Fatal(e)
	}
	var publisher Publisher
	publisher.Publish(plan.Generation)
	published := make(chan struct{})
	go func() { publisher.Publish(New()); close(published) }()
	<-backend.entered
	if plan.Generation.State() != Retiring {
		t.Fatal("backend still running")
	}
	select {
	case <-plan.Generation.Done():
		t.Fatal("early closed")
	default:
	}
	l, e := publisher.Bind()
	if e != nil {
		t.Fatal(e)
	}
	l.Close()
	close(backend.release)
	<-published
	if plan.Generation.State() != Closed {
		t.Fatal("not drained")
	}
	publisher.Close()
}
