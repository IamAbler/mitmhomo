package gojaprocessor

import (
	"context"
	"fmt"

	"github.com/metacubex/mihomo/component/mitm/processing/generation"
	"github.com/metacubex/mihomo/component/mitm/processing/model"
	"github.com/metacubex/mihomo/component/mitm/processing/pipeline"
)

func ExampleNew() {
	factory, err := NewFactory(Config{
		ID: "add-request-header",
		Source: `function process(input) {
  if (input.phase !== "request") return {kind:"continue"};
  return {kind:"request_change",request:{
    headers:[{op:"set",name:"X-Processed-By",values:["goja"]}]
  }};
}`,
		Request: true,
	})
	if err != nil {
		panic(err)
	}
	backend, err := factory.Build()
	if err != nil {
		panic(err)
	}

	plan, err := generation.NewPlan([]pipeline.Entry{{
		Class:     pipeline.Script,
		Priority:  10,
		Processor: backend,
	}})
	if err != nil {
		panic(err)
	}
	publisher := &generation.Publisher{}
	if err := publisher.Publish(plan.Generation); err != nil {
		panic(err)
	}
	connection, err := publisher.Bind()
	if err != nil {
		panic(err)
	}
	runner, err := plan.Runner(connection)
	if err != nil {
		panic(err)
	}

	ledger, err := model.NewLedger(-1, nil)
	if err != nil {
		panic(err)
	}
	sourceLease := model.NewCopyLease(ledger)
	urlValue, err := model.ParseURL(sourceLease, "https://example.test/", model.MITMHTTPS)
	if err != nil {
		panic(err)
	}
	headers, err := model.NewHeaderBlock(sourceLease, []model.HeaderField{{Name: "Accept", Values: []string{"*/*"}}})
	if err != nil {
		panic(err)
	}
	request := model.RequestHead{Method: "GET", URL: urlValue, Authority: "example.test", Headers: headers}
	body, err := model.NewBodyBroker(context.Background(), model.BodySource{Owner: model.FrameworkOwned, DeclaredLength: 0}, ledger)
	if err != nil {
		panic(err)
	}
	tx, err := model.NewTransaction(context.Background(), model.TransactionOptions{
		ID: "example-transaction", Generation: plan.Generation.ID(),
		Connection:      model.ConnectionView{ID: "example-connection"},
		OriginalIngress: request, Request: request,
		RequestBody: model.NewBodySlot(body), Ledger: ledger,
	})
	_ = sourceLease.Close()
	if err != nil {
		panic(err)
	}
	report, err := runner.Run(context.Background(), tx, model.RequestPhase)
	if err != nil {
		panic(err)
	}
	input, inputLease, err := tx.Snapshot("read-example-result")
	if err != nil {
		panic(err)
	}
	values, _, err := input.Request().Headers.Values("X-Processed-By")
	if err != nil {
		panic(err)
	}
	fmt.Printf("backend=%s result=%d header=%s\n", backend.Describe().Backend, report.LastResult, values[0])
	_ = inputLease.Close()
	_ = tx.Close()
	_ = connection.Close()
	_ = publisher.Close()
	if err := plan.Generation.WaitClosed(context.Background()); err != nil {
		panic(err)
	}

	// Output: backend=goja result=2 header=goja
}
