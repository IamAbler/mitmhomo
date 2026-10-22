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
