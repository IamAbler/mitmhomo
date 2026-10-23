package generation

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/mitm/processing/model"
	"github.com/metacubex/mihomo/component/mitm/processing/pipeline"
	"github.com/metacubex/mihomo/component/mitm/processing/processor"
)

type bufferedProcessor struct{ *asyncProcessor }

func (p bufferedProcessor) Describe() processor.Descriptor {
	descriptor := p.asyncProcessor.Describe()
	descriptor.RequestNeeds = processor.Requirements{Body: model.FullBuffered, MaxBodyBytes: 32}
	return descriptor
}

type generationBodyReader struct {
	entered, release chan struct{}
	closes           atomic.Int32
}

func (r *generationBodyReader) Read([]byte) (int, error) {
	close(r.entered)
	<-r.release
	return 0, io.EOF
}
func (r *generationBodyReader) Close() error { r.closes.Add(1); return nil }

func generationChannelClosed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

type gatedGenerationLease struct {
	io.Closer
	entered chan struct{}
	release <-chan struct{}
	once    sync.Once
}

func (l *gatedGenerationLease) Close() error {
	l.once.Do(func() {
		close(l.entered)
		<-l.release
	})
	return l.Closer.Close()
}

func TestBodyReadPinsRetiredGenerationUntilPhysicalDrain(t *testing.T) {
	lifecycle, _ := processor.NewLifecycle(1)
	backend := &asyncProcessor{lifecycle: lifecycle, started: make(chan *processor.Invocation, 1), finish: make(chan *processor.Completion, 1)}
	resource := &closer{}
	plan, err := NewPlan([]pipeline.Entry{{Class: pipeline.Script, Processor: bufferedProcessor{backend}}}, resource)
	if err != nil {
		t.Fatal(err)
	}
	var publisher Publisher
	if err = publisher.Publish(plan.Generation); err != nil {
		t.Fatal(err)
	}
	conn, _ := publisher.Bind()
	stream, _ := conn.Transaction()
	runner, _ := plan.Runner(stream)
	reader := &generationBodyReader{entered: make(chan struct{}), release: make(chan struct{})}
	var once sync.Once
	unblock := func() { once.Do(func() { close(reader.release) }) }
	defer unblock()
	ledger, _ := model.NewLedger(-1, nil)
	broker, err := model.NewBodyBroker(context.Background(), model.BodySource{Reader: reader, Owner: model.FrameworkOwned, DeclaredLength: -1}, ledger)
	if err != nil {
		t.Fatal(err)
	}
	copy := model.NewCopyLease(ledger)
	url, _ := model.ParseURL(copy, "https://example.test/", model.MITMHTTPS)
	headers, _ := model.NewHeaderBlock(copy, nil)
	head := model.RequestHead{Method: "POST", URL: url, Authority: "example.test", Headers: headers}
	tx, err := model.NewTransaction(context.Background(), model.TransactionOptions{ID: "body-generation", Generation: plan.Generation.ID(), Connection: model.ConnectionView{ID: "conn"}, OriginalIngress: head, Request: head, RequestBody: model.NewBodySlot(broker), Ledger: ledger})
	copy.Close()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	returned := make(chan error, 1)
	go func() { _, err := runner.Run(ctx, tx, model.RequestPhase); returned <- err }()
	select {
	case <-reader.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("read not started")
	}
	publisher.Publish(New())
	conn.Close()
	stream.Close()
	cancel()
	select {
	case err = <-returned:
	case <-time.After(5 * time.Second):
		t.Fatal("logical wait blocked")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	tx.CloseLogical()
	if plan.Generation.State() != Retiring || resource.n.Load() != 0 || backend.closes.Load() != 0 || reader.closes.Load() != 0 {
		t.Fatal("retirement closed a resource used by Read")
	}
	next, err := publisher.Bind()
	if err != nil {
		t.Fatal(err)
	}
	next.Close()
	select {
	case <-broker.ExecutionDone():
		t.Fatal("early ExecutionDone")
	default:
	}
	unblock()
	wait, cancelWait := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelWait()
	if err = tx.CloseContext(wait); err != nil {
		t.Fatal(err)
	}
	if err = plan.Generation.WaitClosed(wait); err != nil {
		t.Fatal(err)
	}
	if reader.closes.Load() != 1 || resource.n.Load() != 1 || ledger.Current() != 0 {
		t.Fatal("generation/body drain did not complete exactly once")
	}
	select {
	case <-backend.started:
		t.Fatal("processor started after canceled Body preparation")
	default:
	}
	publisher.Close()
}

func TestBodyReadInvocationAndGenerationRetireRaceKeepsBothOwners(t *testing.T) {
	lifecycle, _ := processor.NewLifecycle(1)
	backend := &asyncProcessor{lifecycle: lifecycle, started: make(chan *processor.Invocation, 1), finish: make(chan *processor.Completion, 1)}
	resource := &closer{}
	plan, err := NewPlan([]pipeline.Entry{{Class: pipeline.Script, Processor: backend}}, resource)
	if err != nil {
		t.Fatal(err)
	}
	var publisher Publisher
	if err = publisher.Publish(plan.Generation); err != nil {
		t.Fatal(err)
	}
	connection, _ := publisher.Bind()
	stream, _ := connection.Transaction()
	runner, err := plan.Runner(stream)
	if err != nil {
		t.Fatal(err)
	}
	tx := transaction(t, plan.Generation.ID())
	defer tx.Close()
	reader := &generationBodyReader{entered: make(chan struct{}), release: make(chan struct{})}
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(reader.release) }) }
	defer unblock()
	ledger, _ := model.NewLedger(-1, nil)
	pinCloseEntered := make(chan struct{})
	pinCloseRelease := make(chan struct{})
	broker, err := model.NewBodyBroker(context.Background(), model.BodySource{
		Reader: reader, Owner: model.FrameworkOwned, DeclaredLength: -1,
		AcquireExecution: func() (io.Closer, error) {
			pin, pinErr := connection.Execution()
			if pinErr != nil {
				return nil, pinErr
			}
			return &gatedGenerationLease{Closer: pin, entered: pinCloseEntered, release: pinCloseRelease}, nil
		},
	}, ledger)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runReturned := make(chan error, 1)
	go func() { _, runErr := runner.Run(ctx, tx, model.RequestPhase); runReturned <- runErr }()
	invocation := <-backend.started
	completion := <-backend.finish
	bodyReturned := make(chan error, 1)
	go func() { bodyReturned <- broker.Prepare(ctx, model.FullBuffered, 32) }()
	select {
	case <-reader.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("Body operation did not enter while the Invocation was running")
	}
	if generationChannelClosed(invocation.ExecutionDone()) {
		t.Fatal("async Processor unexpectedly completed before the race")
	}

	next := New()
	barrier := make(chan struct{})
	var race sync.WaitGroup
	race.Add(4)
	go func() { defer race.Done(); <-barrier; _ = publisher.Publish(next) }()
	go func() { defer race.Done(); <-barrier; connection.Close(); stream.Close() }()
	go func() { defer race.Done(); <-barrier; cancel() }()
	go func() { defer race.Done(); <-barrier; tx.CloseLogical() }()
	close(barrier)
	race.Wait()
	select {
	case runErr := <-runReturned:
		if runErr != nil && !errors.Is(runErr, context.Canceled) {
			t.Fatal(runErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("canceled invocation did not return")
	}
	select {
	case bodyErr := <-bodyReturned:
		if !errors.Is(bodyErr, context.Canceled) {
			t.Fatal("Body logical wait did not report cancellation", bodyErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("canceled Body logical wait did not return")
	}
	if plan.Generation.State() != Retiring || resource.n.Load() != 0 || backend.closes.Load() != 0 || generationChannelClosed(invocation.ExecutionDone()) {
		t.Fatal("retirement dropped an in-flight Invocation or Body owner")
	}
	newConnection, err := publisher.Bind()
	if err != nil {
		t.Fatal("old cleanup blocked new generation admission", err)
	}
	newConnection.Close()
	broker.CloseLogical()
	// Logical close cannot substitute for the Processor's real exit.
	select {
	case <-invocation.ExecutionDone():
		t.Fatal("logical close forged ExecutionDone")
	default:
	}
	if !completion.Finish(model.Continue(), nil) {
		t.Fatal("late Processor completion failed")
	}
	select {
	case <-invocation.ExecutionDone():
	case <-time.After(5 * time.Second):
		t.Fatal("Processor owner did not exit")
	}
	if backend.closes.Load() != 0 || resource.n.Load() != 0 {
		t.Fatal("Body owner or Invocation resource was released before physical cleanup")
	}
	unblock()
	select {
	case <-pinCloseEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("Body operation did not release its Generation pin")
	}
	select {
	case <-broker.ExecutionDone():
		t.Fatal("Body ExecutionDone closed while Generation pin disposal was blocked")
	default:
	}
	if backend.closes.Load() != 0 || resource.n.Load() != 0 {
		t.Fatal("Generation cleanup ignored the blocked Body pin")
	}
	close(pinCloseRelease)
	wait, cancelWait := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelWait()
	if err = tx.CloseContext(wait); err != nil {
		t.Fatal(err)
	}
	if err = plan.Generation.WaitClosed(wait); err != nil {
		t.Fatal(err)
	}
	if backend.closes.Load() != 1 || resource.n.Load() != 1 || ledger.Current() != 0 || reader.closes.Load() != 1 {
		t.Fatal("race did not release each owner exactly once")
	}
	publisher.Close()
}

type unreadGenerationBody struct {
	entered, release chan struct{}
	closes           atomic.Int32
}

func (*unreadGenerationBody) Read([]byte) (int, error) { return 0, io.EOF }
func (r *unreadGenerationBody) Close() error {
	r.closes.Add(1)
	close(r.entered)
	<-r.release
	return nil
}
func TestUnreadBodyDisposalPinsGeneration(t *testing.T) {
	resource := &closer{}
	g := New(resource)
	g.Activate()
	connection, _ := g.Bind()
	reader := &unreadGenerationBody{entered: make(chan struct{}), release: make(chan struct{})}
	var once sync.Once
	unblock := func() { once.Do(func() { close(reader.release) }) }
	defer unblock()
	ledger, _ := model.NewLedger(-1, nil)
	broker, err := model.NewBodyBroker(context.Background(), model.BodySource{Reader: reader, Owner: model.FrameworkOwned, DeclaredLength: -1, AcquireExecution: func() (io.Closer, error) { return connection.Execution() }}, ledger)
	if err != nil {
		t.Fatal(err)
	}
	broker.CloseLogical()
	select {
	case <-reader.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("disposal did not start")
	}
	g.Retire()
	connection.Close()
	if g.State() != Retiring || resource.n.Load() != 0 || reader.closes.Load() != 1 {
		t.Fatal("unread source disposal lost its generation pin")
	}
	unblock()
	wait, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err = broker.CloseContext(wait); err != nil {
		t.Fatal(err)
	}
	if err = g.WaitClosed(wait); err != nil {
		t.Fatal(err)
	}
	if resource.n.Load() != 1 || reader.closes.Load() != 1 {
		t.Fatal("duplicate cleanup")
	}
}
