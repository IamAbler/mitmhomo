//go:build quickjs && cgo

package quickjs

import (
	contextpkg "context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func newTestContext(t *testing.T, options RuntimeOptions) (*Runtime, *Context) {
	t.Helper()
	runtime, err := NewRuntime(options)
	if err != nil {
		t.Fatal(err)
	}
	context, err := runtime.NewContext()
	if err != nil {
		_ = runtime.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := context.Close(); err != nil {
			t.Errorf("close Context: %v", err)
		}
		if err := runtime.Close(); err != nil {
			t.Errorf("close Runtime: %v", err)
		}
	})
	return runtime, context
}

func TestRuntimeContextLifecycleAndEval(t *testing.T) {
	runtime, context := newTestContext(t, RuntimeOptions{})
	if err := runtime.Close(); !errors.Is(err, ErrContextsAlive) {
		t.Fatalf("Close with a live Context = %v, want ErrContextsAlive", err)
	}
	got, err := context.Eval("String((1 + 2) * 14)")
	if err != nil || got != "42" {
		t.Fatalf("Eval = %q, %v; want 42", got, err)
	}
	got, err = context.Eval("'你好😀'")
	if err != nil || got != "你好😀" {
		t.Fatalf("UTF-8 Eval = %q, %v", got, err)
	}
	if err := context.Close(); err != nil {
		t.Fatal(err)
	}
	if err := context.Close(); err != nil {
		t.Fatalf("repeated Context.Close = %v", err)
	}
	if _, err := context.Eval("1 + 1"); !errors.Is(err, ErrClosed) {
		t.Fatalf("Eval after Context.Close = %v, want ErrClosed", err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("repeated Runtime.Close = %v", err)
	}
	if _, err := runtime.NewContext(); !errors.Is(err, ErrClosed) {
		t.Fatalf("NewContext after Runtime.Close = %v, want ErrClosed", err)
	}
}

func TestEvalExceptionAndContextReuse(t *testing.T) {
	_, context := newTestContext(t, RuntimeOptions{})
	if _, err := context.Eval(`throw new Error("boom")`); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("Eval exception = %v, want message containing boom", err)
	}
	if got, err := context.Eval("40 + 2"); err != nil || got != "42" {
		t.Fatalf("Eval after exception = %q, %v", got, err)
	}
}

func TestCompileRunAndValueOwnership(t *testing.T) {
	_, context := newTestContext(t, RuntimeOptions{})
	script, err := context.Compile("String(40 + 2)")
	if err != nil {
		t.Fatal(err)
	}
	if err := context.Close(); !errors.Is(err, ErrCompiledAlive) {
		t.Fatalf("Context.Close with compiled script = %v, want ErrCompiledAlive", err)
	}
	for i := 0; i < 2; i++ {
		if got, err := script.Eval(); err != nil || got != "42" {
			t.Fatalf("compiled Eval #%d = %q, %v", i, got, err)
		}
	}
	if err := script.Close(); err != nil {
		t.Fatal(err)
	}
	if err := script.Close(); err != nil {
		t.Fatalf("repeated CompiledScript.Close = %v", err)
	}
	if _, err := script.Eval(); !errors.Is(err, ErrClosed) {
		t.Fatalf("compiled Eval after Close = %v, want ErrClosed", err)
	}
	if _, err := context.Compile("function {"); err == nil {
		t.Fatal("Compile accepted invalid JavaScript")
	}
}

func TestMultipleRuntimeIsolation(t *testing.T) {
	first, firstContext := newTestContext(t, RuntimeOptions{})
	_, secondContext := newTestContext(t, RuntimeOptions{})
	if _, err := firstContext.Eval("globalThis.secret = 123"); err != nil {
		t.Fatal(err)
	}
	if got, err := secondContext.Eval("typeof secret"); err != nil || got != "undefined" {
		t.Fatalf("second Runtime observed first Runtime state: %q, %v", got, err)
	}
	if usage, err := first.MemoryUsage(); err != nil || usage == 0 {
		t.Fatalf("QuickJS memory usage = %d, %v", usage, err)
	}
}

func TestMemoryLimitAndRecovery(t *testing.T) {
	runtime, context := newTestContext(t, RuntimeOptions{})
	if err := runtime.SetMemoryLimit(1 << 20); err != nil {
		t.Fatal(err)
	}
	if _, err := context.Eval("String(new Array(1024).fill(7).length)"); err != nil {
		t.Fatalf("normal allocation under memory limit failed: %v", err)
	}
	_, bufferErr := context.Eval("new ArrayBuffer(8 * 1024 * 1024)")
	_, arrayErr := context.Eval("new Array(4 * 1024 * 1024).fill(1)")
	if bufferErr == nil {
		t.Fatal("large ArrayBuffer succeeded above the QuickJS memory limit")
	}
	if arrayErr == nil {
		t.Fatal("large Array succeeded above the QuickJS memory limit")
	}
	if got, err := context.Eval("6 * 7"); err != nil || got != "42" {
		t.Fatalf("Context unusable after memory exception: %q, %v", got, err)
	}
	if err := runtime.SetMemoryLimit(0); err != nil {
		t.Fatal(err)
	}
	if got, err := context.Eval("6 * 7"); err != nil || got != "42" {
		t.Fatalf("Context unusable after removing memory cap: %q, %v", got, err)
	}
}

func TestStackLimitAndRecovery(t *testing.T) {
	runtime, context := newTestContext(t, RuntimeOptions{MaxStackBytes: 64 << 10})
	if _, err := context.Eval("function recurse() { return recurse() }; recurse()"); err == nil {
		t.Fatal("deep recursion succeeded above the configured stack limit")
	}
	if got, err := context.Eval("6 * 7"); err != nil || got != "42" {
		t.Fatalf("Context unusable after stack exception: %q, %v", got, err)
	}
	if err := runtime.SetMaxStackSize(0); err != nil {
		t.Fatal(err)
	}
}

func TestInterruptInfiniteLoopAndReuse(t *testing.T) {
	_, context := newTestContext(t, RuntimeOptions{})
	ctx, cancel := contextpkg.WithTimeout(contextpkg.Background(), 40*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := context.EvalContext(ctx, "while (true) {}")
	if !errors.Is(err, contextpkg.DeadlineExceeded) {
		t.Fatalf("infinite loop result = %v, want DeadlineExceeded", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("interrupt took too long: %s", elapsed)
	}
	if got, err := context.Eval("6 * 7"); err != nil || got != "42" {
		t.Fatalf("Context unusable after interrupt: %q, %v", got, err)
	}
}

func TestRuntimeCloseDoesNotForceFreeActiveExecution(t *testing.T) {
	runtime, context := newTestContext(t, RuntimeOptions{})
	execContext, cancel := contextpkg.WithCancel(contextpkg.Background())
	defer cancel()
	evalDone := make(chan error, 1)
	go func() {
		_, err := context.EvalContext(execContext, "while (true) {}")
		evalDone <- err
	}()
	time.Sleep(10 * time.Millisecond)
	closeDone := make(chan error, 1)
	go func() {
		closeDone <- runtime.Close()
	}()
	time.Sleep(10 * time.Millisecond)
	cancel()
	if err := <-evalDone; !errors.Is(err, contextpkg.Canceled) {
		t.Fatalf("active Eval result = %v, want Canceled", err)
	}
	if err := <-closeDone; !errors.Is(err, ErrContextsAlive) {
		t.Fatalf("Runtime.Close with live Context = %v, want ErrContextsAlive", err)
	}
	if got, err := context.Eval("40 + 2"); err != nil || got != "42" {
		t.Fatalf("Runtime was not usable after refused Close: %q, %v", got, err)
	}
}

func TestPromisePendingJobQueue(t *testing.T) {
	runtime, context := newTestContext(t, RuntimeOptions{})
	if pending, err := runtime.IsJobPending(); err != nil || pending {
		t.Fatalf("initial pending status = %v, %v", pending, err)
	}
	_, err := context.Eval("globalThis.answer = 0; Promise.resolve(41).then(v => { answer = v + 1 }); 'queued'")
	if err != nil {
		t.Fatal(err)
	}
	if pending, err := runtime.IsJobPending(); err != nil || !pending {
		t.Fatalf("pending status after Promise = %v, %v", pending, err)
	}
	if ran, err := runtime.ExecutePendingJob(); err != nil || !ran {
		t.Fatalf("ExecutePendingJob = %v, %v", ran, err)
	}
	if pending, err := runtime.IsJobPending(); err != nil || pending {
		t.Fatalf("pending status after drain = %v, %v", pending, err)
	}
	if got, err := context.Eval("answer"); err != nil || got != "42" {
		t.Fatalf("Promise result = %q, %v", got, err)
	}
	if ran, err := runtime.ExecutePendingJob(); err != nil || ran {
		t.Fatalf("ExecutePendingJob on empty queue = %v, %v", ran, err)
	}
}

func TestPendingJobException(t *testing.T) {
	runtime, context := newTestContext(t, RuntimeOptions{})
	if err := context.enqueueThrowingJobForTest("native job failure"); err != nil {
		t.Fatal(err)
	}
	if pending, err := runtime.IsJobPending(); err != nil || !pending {
		t.Fatalf("pending status = %v, %v", pending, err)
	}
	if ran, err := runtime.ExecutePendingJob(); ran || err == nil || !strings.Contains(err.Error(), "native job failure") {
		t.Fatalf("ExecutePendingJob exception = (%v, %v)", ran, err)
	}
	if got, err := context.Eval("40 + 2"); err != nil || got != "42" {
		t.Fatalf("Context unusable after job exception: %q, %v", got, err)
	}
}

func TestContextCloseLeavesPendingJobOwnedByRuntime(t *testing.T) {
	runtime, context := newTestContext(t, RuntimeOptions{})
	if _, err := context.Eval("globalThis.done = 0; Promise.resolve().then(() => { done = 1 })"); err != nil {
		t.Fatal(err)
	}
	if err := context.Close(); err != nil {
		t.Fatal(err)
	}
	if pending, err := runtime.IsJobPending(); err != nil || !pending {
		t.Fatalf("pending status after Context.Close = %v, %v", pending, err)
	}
	if ran, err := runtime.ExecutePendingJob(); err != nil || !ran {
		t.Fatalf("ExecutePendingJob after Context.Close = %v, %v", ran, err)
	}
}

func TestRepeatedCreateDestroy(t *testing.T) {
	for i := 0; i < 100; i++ {
		runtime, err := NewRuntime(RuntimeOptions{})
		if err != nil {
			t.Fatalf("iteration %d NewRuntime: %v", i, err)
		}
		context, err := runtime.NewContext()
		if err != nil {
			_ = runtime.Close()
			t.Fatalf("iteration %d NewContext: %v", i, err)
		}
		if got, err := context.Eval("1 + 1"); err != nil || got != "2" {
			t.Fatalf("iteration %d Eval: %q, %v", i, got, err)
		}
		if err := context.Close(); err != nil {
			t.Fatalf("iteration %d close Context: %v", i, err)
		}
		if err := runtime.Close(); err != nil {
			t.Fatalf("iteration %d close Runtime: %v", i, err)
		}
	}
}

func TestRuntimeSerializesConcurrentCalls(t *testing.T) {
	_, context := newTestContext(t, RuntimeOptions{MaxStackBytes: 128 << 10})
	const workers = 12
	var wait sync.WaitGroup
	errorsFound := make(chan error, workers)
	for worker := 0; worker < workers; worker++ {
		wait.Add(1)
		go func(worker int) {
			defer wait.Done()
			for iteration := 0; iteration < 10; iteration++ {
				const want = "42"
				got, err := context.Eval("40 + 2")
				if err != nil {
					errorsFound <- fmt.Errorf("worker %d iteration %d: %w", worker, iteration, err)
					return
				}
				if got != want {
					errorsFound <- fmt.Errorf("got %q, want %q", got, want)
					return
				}
			}
		}(worker)
	}
	wait.Wait()
	close(errorsFound)
	for err := range errorsFound {
		t.Error(err)
	}
}
