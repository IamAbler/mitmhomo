package gojaprocessor

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/mitm/processing/model"
	"github.com/metacubex/mihomo/component/mitm/processing/pipeline"
	"github.com/metacubex/mihomo/component/mitm/processing/processor"
)

func TestGojaInputBodyBudgetBoundaryAndOverflow(t *testing.T) {
	limit := int(model.DefaultBodyBufferBytes)
	backend := newTestProcessor(t, Config{ID: "body-boundary", Source: `function process(input) { return {kind:"continue"}; }`, Request: true, RequestBody: model.FullBuffered})
	runner := newTestRunner(t, backend, pipeline.Options{})
	within := testTransaction(t, 7, bytes.Repeat([]byte{'x'}, limit))
	if _, err := runner.Run(context.Background(), within, model.RequestPhase); err != nil {
		t.Fatalf("body at the configured boundary failed: %v", err)
	}
	over := testTransaction(t, 7, bytes.Repeat([]byte{'x'}, limit+1))
	_, err := runner.Run(context.Background(), over, model.RequestPhase)
	if !processingKindIs(err, model.ProcessingErrorBodyLimitExceeded) {
		t.Fatalf("over-budget body error = %v", err)
	}
}

func TestGojaOutputBodyLimitAndInvalidResults(t *testing.T) {
	tests := []struct {
		name      string
		source    string
		wantKind  model.ProcessingErrorKind
		bodyLimit int64
		jsonLimit int
	}{
		{name: "oversize body", source: `function process(input) { return {kind:"request_change",request:{body:{encoding:"base64",data:"AQID"}}}; }`, wantKind: model.ProcessingErrorOutputLimitExceeded, bodyLimit: 2},
		{name: "oversize JSON result", source: `function process(input) { return {kind:"continue",debug:"` + strings.Repeat("x", 128) + `"}; }`, wantKind: model.ProcessingErrorOutputLimitExceeded, jsonLimit: 64},
		{name: "null", source: `function process(input) { return null; }`, wantKind: model.ProcessingErrorInvalidOutput},
		{name: "unknown kind", source: `function process(input) { return {kind:"surge_magic"}; }`, wantKind: model.ProcessingErrorInvalidOutput},
		{name: "extra field", source: `function process(input) { return {kind:"continue",debug:true}; }`, wantKind: model.ProcessingErrorInvalidOutput},
		{name: "managed header", source: `function process(input) { return {kind:"request_change",request:{headers:[{op:"set",name:"Content-Length",values:["1"]}]}}; }`, wantKind: model.ProcessingErrorInvalidOutput},
		{name: "invalid header value", source: `function process(input) { return {kind:"request_change",request:{headers:[{op:"set",name:"X-Test",values:["ok\r\nInjected: yes"]}]}}; }`, wantKind: model.ProcessingErrorInvalidOutput},
		{name: "wrong phase", source: `function process(input) { return {kind:"response_change",response:{status:201}}; }`, wantKind: model.ProcessingErrorInvalidOutput},
		{name: "bad base64", source: `function process(input) { return {kind:"request_change",request:{body:{encoding:"base64",data:"***"}}}; }`, wantKind: model.ProcessingErrorInvalidOutput},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := testConfig(test.source)
			if test.bodyLimit != 0 {
				config.MaxOutputBodyBytes = test.bodyLimit
			}
			if test.jsonLimit != 0 {
				config.MaxSerializedOutputBytes = test.jsonLimit
			}
			backend := newTestProcessor(t, config)
			tx := testTransaction(t, 7, nil)
			runner := newTestRunner(t, backend, pipeline.Options{})
			_, err := runner.Run(context.Background(), tx, model.RequestPhase)
			if !processingKindIs(err, test.wantKind) {
				t.Fatalf("error = %v; want processing kind %d", err, test.wantKind)
			}
			if tx.State() != model.Terminated {
				t.Fatal("invalid processor output did not terminate the Transaction")
			}
		})
	}
}

func TestGojaCompileAndRuntimeExceptionClassification(t *testing.T) {
	_, err := New(testConfig(`function process(input) { return {kind: }; }`))
	if !processingKindIs(err, model.ProcessingErrorCompile) {
		t.Fatalf("compile error = %v", err)
	}
	backend := newTestProcessor(t, testConfig(`function process(input) { throw new Error("script failure"); }`))
	tx := testTransaction(t, 7, nil)
	runner := newTestRunner(t, backend, pipeline.Options{})
	_, err = runner.Run(context.Background(), tx, model.RequestPhase)
	if !processingKindIs(err, model.ProcessingErrorExecution) {
		t.Fatalf("runtime exception = %v", err)
	}
}

func TestGojaGlobalStateIsIsolatedAcrossConcurrentInvocations(t *testing.T) {
	backend := newTestProcessor(t, testConfig(`var executions = 0; function process(input) { executions++; return {kind:"request_change",request:{headers:[{op:"set",name:"X-Execution",values:[String(executions)]}]}}; }`))
	runner := newTestRunner(t, backend, pipeline.Options{})
	const count = 24
	txs := make([]*model.Transaction, count)
	for i := range txs {
		txs[i] = testTransaction(t, 7, nil)
	}
	errCh := make(chan error, count)
	var workers sync.WaitGroup
	for _, tx := range txs {
		workers.Add(1)
		go func(tx *model.Transaction) {
			defer workers.Done()
			if _, err := runner.Run(context.Background(), tx, model.RequestPhase); err != nil {
				errCh <- err
				return
			}
			input, lease, err := tx.Snapshot("concurrent-check")
			if err != nil {
				errCh <- err
				return
			}
			defer lease.Close()
			values, _, err := input.Request().Headers.Values("X-Execution")
			if err != nil || len(values) != 1 || values[0] != "1" {
				errCh <- fmt.Errorf("global state leaked: %v %v", values, err)
			}
		}(tx)
	}
	workers.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
}

func TestGojaDeadlineInterruptsInfiniteLoop(t *testing.T) {
	config := testConfig(`function process(input) { while (true) {} }`)
	config.ExecutionTimeout = 25 * time.Millisecond
	backend := newTestProcessor(t, config)
	tx := testTransaction(t, 7, nil)
	runner := newTestRunner(t, backend, pipeline.Options{})
	started := time.Now()
	_, err := runner.Run(context.Background(), tx, model.RequestPhase)
	if !processingKindIs(err, model.ProcessingErrorTimeout) {
		t.Fatalf("infinite loop error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("Goja Interrupt took too long: %s", elapsed)
	}
	if tx.State() != model.Terminated || tx.Revision() != 1 || tx.Outcome() != model.ExchangeAborted {
		t.Fatal("late JavaScript output changed a terminated Transaction")
	}
}

type testCloser struct{ closes atomic.Int64 }

func (c *testCloser) Close() error { c.closes.Add(1); return nil }

type blockingTestCloser struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (c *blockingTestCloser) Close() error {
	c.once.Do(func() {
		close(c.entered)
		<-c.release
	})
	return nil
}

func TestGojaCloseAndCapacityRetainExecutionOwnership(t *testing.T) {
	config := testConfig(`function process(input) { while (true) {} }`)
	config.Capacity = 1
	backend := newTestProcessor(t, config)
	tx := testTransaction(t, 7, nil)
	input, inputLease, err := tx.Snapshot("cancel-first")
	if err != nil {
		t.Fatal(err)
	}
	blocked := &blockingTestCloser{entered: make(chan struct{}), release: make(chan struct{})}
	invocation, err := backend.Start(context.Background(), input, inputLease, blocked)
	if err != nil {
		t.Fatal(err)
	}
	secondInput, secondLease, err := tx.Snapshot("capacity-second")
	if err != nil {
		t.Fatal(err)
	}
	callerOwned := &testCloser{}
	second, err := backend.Start(context.Background(), secondInput, secondLease, callerOwned)
	if second != nil || !processingKindIs(err, model.ProcessingErrorCapacityExhausted) {
		t.Fatalf("second Start = %v, %v", second, err)
	}
	if callerOwned.closes.Load() != 0 {
		t.Fatal("failed Start took ownership of caller resources")
	}
	_ = secondLease.Close()
	_ = callerOwned.Close()
	if err := backend.Close(); err != nil {
		t.Fatal(err)
	}
	closedInput, closedLease, err := tx.Snapshot("after-close")
	if err != nil {
		t.Fatal(err)
	}
	closedResource := &testCloser{}
	closedInvocation, startErr := backend.Start(context.Background(), closedInput, closedLease, closedResource)
	if closedInvocation != nil || !processingKindIs(startErr, model.ProcessingErrorClosed) || closedResource.closes.Load() != 0 {
		t.Fatalf("closed Start = %v, %v; resource closes=%d", closedInvocation, startErr, closedResource.closes.Load())
	}
	_ = closedLease.Close()
	_ = closedResource.Close()
	wait, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, awaitErr := invocation.Await(wait)
	if !processingKindIs(awaitErr, model.ProcessingErrorClosed) {
		t.Fatalf("Close result = %v", awaitErr)
	}
	select {
	case <-blocked.entered:
	case <-wait.Done():
		t.Fatal("execution did not reach resource cleanup")
	}
	select {
	case <-invocation.ExecutionDone():
		t.Fatal("ExecutionDone closed while a transferred resource was still cleaning up")
	default:
	}
	closed := make(chan error, 1)
	go func() { closed <- backend.WaitClosed(wait) }()
	select {
	case err := <-closed:
		t.Fatalf("WaitClosed returned before resource cleanup: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(blocked.release)
	select {
	case <-invocation.ExecutionDone():
	case <-wait.Done():
		t.Fatal("ExecutionDone did not close after actual cleanup")
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
}

func TestGojaContextCancelInterruptsExecution(t *testing.T) {
	backend := newTestProcessor(t, testConfig(`function process(input) { while (true) {} }`))
	tx := testTransaction(t, 7, nil)
	input, lease, err := tx.Snapshot("context-cancel")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	invocation, err := backend.Start(ctx, input, lease)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	cancel()
	wait, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	_, err = invocation.Await(wait)
	if !processingKindIs(err, model.ProcessingErrorCanceled) {
		t.Fatalf("cancel result = %v", err)
	}
	select {
	case <-invocation.ExecutionDone():
	case <-wait.Done():
		t.Fatal("Goja execution did not exit after Context cancellation")
	}
	if err := backend.Close(); err != nil {
		t.Fatal(err)
	}
	if err := backend.WaitClosed(wait); err != nil {
		t.Fatal(err)
	}
}

func TestGojaRunnerUsesFrameworkInvocationPool(t *testing.T) {
	backend := newTestProcessor(t, testConfig(`function process(input) { return {kind:"continue"}; }`))
	pool := processor.NewInvocationPool(1)
	permit, err := pool.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	tx := testTransaction(t, 7, nil)
	runner := newTestRunner(t, backend, pipeline.Options{InvocationPool: pool})
	_, err = runner.Run(context.Background(), tx, model.RequestPhase)
	if !processingKindIs(err, model.ProcessingErrorCapacityExhausted) || pool.Rejected() != 1 {
		t.Fatalf("framework pool capacity error = %v; rejected=%d", err, pool.Rejected())
	}
	_ = permit.Close()
}

func TestGojaCompletionRacesContextCancel(t *testing.T) {
	backend := newTestProcessor(t, testConfig(`function process(input) { let n=0; while (n < 1000) n++; return {kind:"continue"}; }`))
	for i := 0; i < 20; i++ {
		tx := testTransaction(t, 7, nil)
		input, lease, err := tx.Snapshot(model.InvocationID(fmt.Sprintf("race-%d", i)))
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		invocation, err := backend.Start(ctx, input, lease)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		cancelDone := make(chan struct{})
		go func() { cancel(); close(cancelDone) }()
		wait, stop := context.WithTimeout(context.Background(), 5*time.Second)
		result, awaitErr := invocation.Await(wait)
		if awaitErr == nil {
			if result.Kind() != model.ResultContinue {
				t.Errorf("result kind = %v", result.Kind())
			}
			_ = result.Release()
		} else if !processingKindIs(awaitErr, model.ProcessingErrorCanceled) {
			t.Errorf("race error = %v", awaitErr)
		}
		select {
		case <-invocation.ExecutionDone():
		case <-wait.Done():
			t.Fatal("raced execution was not joined")
		}
		<-cancelDone
		stop()
	}
}
