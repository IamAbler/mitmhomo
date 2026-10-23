package gojaprocessor

import (
	"context"
	"errors"
	goruntime "runtime"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/mitm/processing/generation"
	"github.com/metacubex/mihomo/component/mitm/processing/model"
	"github.com/metacubex/mihomo/component/mitm/processing/pipeline"
)

func TestGojaGenerationHotUpdatePinsProgramToGeneration(t *testing.T) {
	newPlan := func(source string) *generation.Plan {
		t.Helper()
		factory, err := NewFactory(testConfig(source))
		if err != nil {
			t.Fatal(err)
		}
		backend, err := factory.Build()
		if err != nil {
			t.Fatal(err)
		}
		plan, err := generation.NewPlan([]pipeline.Entry{{Class: pipeline.Script, Processor: backend}})
		if err != nil {
			var buildErr *generation.BuildError
			if errors.As(err, &buildErr) {
				buildErr.Pending.Retire()
				_ = buildErr.Pending.WaitClosed(context.Background())
			}
			t.Fatal(err)
		}
		return plan
	}
	oldPlan := newPlan(`function process(input) { return {kind:"request_change",request:{headers:[{op:"set",name:"X-Generation",values:["old"]}]}}; }`)
	newPlanValue := newPlan(`function process(input) { return {kind:"request_change",request:{headers:[{op:"set",name:"X-Generation",values:["new"]}]}}; }`)
	publisher := &generation.Publisher{}
	if err := publisher.Publish(oldPlan.Generation); err != nil {
		t.Fatal(err)
	}
	oldConnection, err := publisher.Bind()
	if err != nil {
		t.Fatal(err)
	}
	oldRunner, err := oldPlan.Runner(oldConnection)
	if err != nil {
		t.Fatal(err)
	}
	if err := publisher.Publish(newPlanValue.Generation); err != nil {
		t.Fatal(err)
	}
	if oldPlan.Generation.State() != generation.Retiring {
		t.Fatalf("old generation state = %v", oldPlan.Generation.State())
	}
	newConnection, err := publisher.Bind()
	if err != nil {
		t.Fatal(err)
	}
	newRunner, err := newPlanValue.Runner(newConnection)
	if err != nil {
		t.Fatal(err)
	}
	runAndRead := func(runner *generation.BoundRunner, generationID model.GenerationID) string {
		t.Helper()
		tx := testTransaction(t, generationID, nil)
		if _, err := runner.Run(context.Background(), tx, model.RequestPhase); err != nil {
			t.Fatal(err)
		}
		input, lease, err := tx.Snapshot("generation-value")
		if err != nil {
			t.Fatal(err)
		}
		defer lease.Close()
		values, _, err := input.Request().Headers.Values("X-Generation")
		if err != nil || len(values) != 1 {
			t.Fatalf("generation header = %v, err = %v", values, err)
		}
		return values[0]
	}
	if got := runAndRead(newRunner, newPlanValue.Generation.ID()); got != "new" {
		t.Fatalf("new generation used script %q", got)
	}
	if got := runAndRead(oldRunner, oldPlan.Generation.ID()); got != "old" {
		t.Fatalf("retired connection lost its script: %q", got)
	}

	_ = oldConnection.Close()
	wait, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := oldPlan.Generation.WaitClosed(wait); err != nil {
		t.Fatalf("old generation did not drain: %v", err)
	}
	retiredTx := testTransaction(t, oldPlan.Generation.ID(), nil)
	if _, err := oldRunner.Run(context.Background(), retiredTx, model.RequestPhase); !errors.Is(err, model.ErrGenerationRetired) {
		t.Fatalf("closed generation accepted a new transaction: %v", err)
	}
	_ = newConnection.Close()
	_ = publisher.Close()
	if err := newPlanValue.Generation.WaitClosed(wait); err != nil {
		t.Fatalf("new generation did not close: %v", err)
	}
}

func TestProcessorFactoryDescriptorAndCompileCacheLifecycle(t *testing.T) {
	factory, err := NewFactory(Config{ID: "factory", Source: `function process(input) { return {kind:"continue"}; }`, Request: true, RequestBody: model.FullBuffered, ExecutionTimeout: 250 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	backend, err := factory.Build()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = backend.Close()
		if err := backend.WaitClosed(context.Background()); err != nil {
			t.Errorf("factory Processor did not drain: %v", err)
		}
	})
	descriptor := backend.Describe()
	if descriptor.Backend != "goja" || descriptor.ContractVersion != apiVersion || !descriptor.Request || descriptor.Response || descriptor.RequestNeeds.Body != model.FullBuffered || descriptor.RequestNeeds.ExecutionTimeout != 250*time.Millisecond {
		t.Fatalf("descriptor = %+v", descriptor)
	}
	if stats := backend.runtime.CacheStats(); stats.Entries != 1 || stats.Capacity != 1 {
		t.Fatalf("compile cache stats = %+v", stats)
	}
	if err := backend.Close(); err != nil {
		t.Fatal(err)
	}
	if err := backend.WaitClosed(context.Background()); err != nil {
		t.Fatal(err)
	}
	if stats := backend.runtime.CacheStats(); stats.Entries != 0 || stats.Capacity != 1 {
		t.Fatalf("closed cache stats = %+v", stats)
	}
}

func TestRetiredGenerationRetainsProgramUntilExecutionDrains(t *testing.T) {
	oldFactory, err := NewFactory(Config{
		ID:     "retiring-infinite",
		Source: `function process(input) { while (true) {} }`, Request: true,
		ExecutionTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	oldBackend, err := oldFactory.Build()
	if err != nil {
		t.Fatal(err)
	}
	oldPlan, err := generation.NewPlan([]pipeline.Entry{{Class: pipeline.Script, Processor: oldBackend}})
	if err != nil {
		t.Fatal(err)
	}
	newBackend, err := New(testConfig(`function process(input) { return {kind:"continue"}; }`))
	if err != nil {
		t.Fatal(err)
	}
	newPlan, err := generation.NewPlan([]pipeline.Entry{{Class: pipeline.Script, Processor: newBackend}})
	if err != nil {
		t.Fatal(err)
	}
	publisher := &generation.Publisher{}
	if err := publisher.Publish(oldPlan.Generation); err != nil {
		t.Fatal(err)
	}
	oldConnection, err := publisher.Bind()
	if err != nil {
		t.Fatal(err)
	}
	oldRunner, err := oldPlan.Runner(oldConnection)
	if err != nil {
		t.Fatal(err)
	}
	tx := testTransaction(t, oldPlan.Generation.ID(), nil)
	runResult := make(chan error, 1)
	go func() {
		_, err := oldRunner.Run(context.Background(), tx, model.RequestPhase)
		runResult <- err
	}()
	startDeadline := time.Now().Add(5 * time.Second)
	for oldBackend.lifecycle.Active() == 0 && time.Now().Before(startDeadline) {
		goruntime.Gosched()
	}
	if oldBackend.lifecycle.Active() != 1 {
		t.Fatal("old Generation did not admit the Goja Invocation")
	}
	oldProgram := oldBackend.program
	if err := publisher.Publish(newPlan.Generation); err != nil {
		t.Fatalf("publishing the new Generation waited for old JavaScript: %v", err)
	}
	if err := oldConnection.Close(); err != nil {
		t.Fatal(err)
	}
	if oldPlan.Generation.State() != generation.Retiring || oldBackend.program != oldProgram {
		t.Fatal("retirement released the old Program while its Invocation was active")
	}
	wait, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	if err := oldPlan.Generation.WaitClosed(wait); !errors.Is(err, context.DeadlineExceeded) {
		cancel()
		t.Fatalf("old Generation closed before the active script drained: %v", err)
	}
	cancel()
	tx.Terminate(context.Canceled)
	select {
	case err := <-runResult:
		if !processingKindIs(err, model.ProcessingErrorCanceled) {
			t.Fatalf("old invocation cancellation = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("old Goja execution did not exit after Transaction cancellation")
	}
	wait, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := oldPlan.Generation.WaitClosed(wait); err != nil {
		t.Fatalf("old Generation did not finish cleanup: %v", err)
	}
	if oldBackend.program != nil {
		t.Fatal("WaitClosed retained the retired Generation Program")
	}
	_ = publisher.Close()
	if err := newPlan.Generation.WaitClosed(wait); err != nil {
		t.Fatalf("new Generation did not close: %v", err)
	}
}

func TestFactoryBuildsIndependentGenerationPrograms(t *testing.T) {
	factory, err := NewFactory(testConfig(`function process(input) { return {kind:"continue"}; }`))
	if err != nil {
		t.Fatal(err)
	}
	first, err := factory.Build()
	if err != nil {
		t.Fatal(err)
	}
	second, err := factory.Build()
	if err != nil {
		t.Fatal(err)
	}
	if first.runtime == second.runtime || first.program == second.program {
		t.Fatal("Factory reused a runtime or Program across generations")
	}
	_ = first.Close()
	_ = second.Close()
	if err := first.WaitClosed(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := second.WaitClosed(context.Background()); err != nil {
		t.Fatal(err)
	}
}
