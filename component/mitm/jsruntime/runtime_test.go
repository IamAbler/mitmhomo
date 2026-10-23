package jsruntime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func testConfig() Config {
	config := DefaultConfig()
	config.MaxConcurrent = 128
	config.ExecutionTimeout = 2 * time.Second
	return config
}

func newTestRuntime(t *testing.T, config Config) *Runtime {
	t.Helper()
	r, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r
}

func TestRunNormalInputAndOutputConversion(t *testing.T) {
	r := newTestRuntime(t, testConfig())
	input := map[string]any{"value": 40, "items": []any{"a", true}}
	got, err := r.Run(context.Background(), `({ value: input.value + 2, items: input.items })`, input)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"value": float64(42), "items": []any{"a", true}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("result = %#v, want %#v", got, want)
	}

	got, err = r.Run(context.Background(), `void 0`, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatalf("undefined result = %#v, want nil", got)
	}
}

func TestCompileSyntaxErrorAndJavaScriptThrow(t *testing.T) {
	r := newTestRuntime(t, testConfig())
	if _, err := r.Compile(`function {`); !errors.Is(err, ErrCompile) {
		t.Fatalf("syntax error = %v, want ErrCompile", err)
	}

	_, err := r.Run(context.Background(), `throw new Error("script failed")`, nil)
	if !errors.Is(err, ErrExecution) {
		t.Fatalf("throw error = %v, want ErrExecution", err)
	}
	var runtimeErr *RuntimeError
	if !errors.As(err, &runtimeErr) {
		t.Fatalf("error type = %T, want *RuntimeError", err)
	}
	if !strings.Contains(runtimeErr.Stack, "script failed") || !strings.Contains(runtimeErr.Stack, scriptName) {
		t.Fatalf("exception stack does not include message and script location: %q", runtimeErr.Stack)
	}
}

func TestPanicIsContainedAndRuntimeCanContinue(t *testing.T) {
	_, err := guardPanic(KindExecution, func() (int, error) {
		panic("injected panic")
	})
	if !errors.Is(err, ErrExecution) || !strings.Contains(err.Error(), "injected panic") {
		t.Fatalf("recovered panic = %v", err)
	}

	r := newTestRuntime(t, testConfig())
	if got, err := r.Run(context.Background(), `6 * 7`, nil); err != nil || got != float64(42) {
		t.Fatalf("runtime did not recover after panic: result=%#v err=%v", got, err)
	}
}

type panicMarshaler struct {
	called *bool
}

func (marshaler panicMarshaler) MarshalJSON() ([]byte, error) {
	*marshaler.called = true
	panic("injected input marshaler panic")
}

func TestInputCustomMarshalerIsRejectedWithoutCallingIt(t *testing.T) {
	r := newTestRuntime(t, testConfig())
	called := false
	if _, err := r.Run(context.Background(), `input`, panicMarshaler{called: &called}); !errors.Is(err, ErrInputConversion) {
		t.Fatalf("input marshaler panic error = %v, want ErrInputConversion", err)
	}
	if called {
		t.Fatal("custom MarshalJSON was called")
	}
	if got, err := r.Run(context.Background(), `42`, nil); err != nil || got != float64(42) {
		t.Fatalf("runtime did not recover after input marshaler panic: result=%#v err=%v", got, err)
	}
}

func TestResourceLimitsAndConversionErrors(t *testing.T) {
	config := testConfig()
	config.MaxSourceBytes = 16
	config.MaxInputBytes = 8
	config.MaxOutputBytes = 16
	r := newTestRuntime(t, config)

	if _, err := r.Compile(strings.Repeat("x", config.MaxSourceBytes+1)); !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("oversized source error = %v, want ErrResourceLimit", err)
	}
	if _, err := r.Run(context.Background(), `input`, map[string]any{"value": "long"}); !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("oversized input error = %v, want ErrResourceLimit", err)
	}
	if _, err := r.Run(context.Background(), `"12345678901234567890"`, nil); !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("oversized output error = %v, want ErrResourceLimit", err)
	}
	if _, err := r.Run(context.Background(), `input`, make(chan int)); !errors.Is(err, ErrInputConversion) {
		t.Fatalf("unsupported Go input error = %v, want ErrInputConversion", err)
	}
	if _, err := r.Run(context.Background(), `(function () {})`, nil); !errors.Is(err, ErrOutputConversion) {
		t.Fatalf("non-JSON result error = %v, want ErrOutputConversion", err)
	}
}

func TestRunCompiledInputDistinguishesInputBudgetFromOutputLimits(t *testing.T) {
	runtime := newTestRuntime(t, testConfig())
	input := map[string]any{"value": "long"}
	encoded, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}

	exactConfig := testConfig()
	exactConfig.MaxInputBytes = len(encoded)
	exactRuntime := newTestRuntime(t, exactConfig)
	exactProgram, err := exactRuntime.Compile("input")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := exactRuntime.RunCompiledInput(context.Background(), exactProgram, input); err != nil {
		t.Fatalf("RunCompiledInput rejected input at its exact encoded size: %v", err)
	}

	limitedConfig := testConfig()
	limitedConfig.MaxInputBytes = len(encoded) - 1
	limitedRuntime := newTestRuntime(t, limitedConfig)
	limitedProgram, err := limitedRuntime.Compile("input")
	if err != nil {
		t.Fatal(err)
	}

	_, err = limitedRuntime.RunCompiledInput(context.Background(), limitedProgram, input)
	var inputErr *RuntimeError
	if !errors.As(err, &inputErr) || inputErr.Kind != KindInputResourceLimit || !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("RunCompiledInput error = %v, want input resource limit", err)
	}

	_, err = limitedRuntime.RunCompiled(context.Background(), limitedProgram, input)
	var genericErr *RuntimeError
	if !errors.As(err, &genericErr) || genericErr.Kind != KindResourceLimit {
		t.Fatalf("RunCompiled error = %v, want existing generic resource limit", err)
	}

	depthRuntime := runtime
	depthProgram, err := depthRuntime.Compile("input")
	if err != nil {
		t.Fatal(err)
	}
	var deep any = 0
	for index := 0; index < maxJSONDepth+1; index++ {
		deep = []any{deep}
	}
	_, err = depthRuntime.RunCompiledInput(context.Background(), depthProgram, deep)
	var depthErr *RuntimeError
	if !errors.As(err, &depthErr) || depthErr.Kind != KindInputResourceLimit {
		t.Fatalf("RunCompiledInput depth error = %v, want input resource limit", err)
	}
}

func TestFreshVMPreventsGlobalStateSharing(t *testing.T) {
	r := newTestRuntime(t, testConfig())
	const source = `var counter = (typeof counter === "undefined" ? 0 : counter) + 1; input.value + counter`
	compiled, err := r.Compile(source)
	if err != nil {
		t.Fatal(err)
	}

	const workers = 100
	start := make(chan struct{})
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(value int) {
			defer wg.Done()
			<-start
			got, err := r.RunCompiled(context.Background(), compiled, map[string]int{"value": value})
			if err != nil {
				errs <- err
				return
			}
			if got != float64(value+1) {
				errs <- fmt.Errorf("value %d produced %#v", value, got)
			}
		}(i)
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func TestCompileCacheHitEvictionAndConcurrentAccess(t *testing.T) {
	config := testConfig()
	config.CompileCacheEntries = 2
	r := newTestRuntime(t, config)

	a, err := r.Compile(`1`)
	if err != nil {
		t.Fatal(err)
	}
	b, err := r.Compile(`2`)
	if err != nil {
		t.Fatal(err)
	}
	aHit, err := r.Compile(`1`)
	if err != nil {
		t.Fatal(err)
	}
	if aHit != a {
		t.Fatal("cache hit returned a different compiled program")
	}
	if len(a.ContentHash()) != 64 {
		t.Fatalf("content hash length = %d, want 64", len(a.ContentHash()))
	}
	if _, err := r.Compile(`3`); err != nil {
		t.Fatal(err)
	}
	if stats := r.CacheStats(); stats.Entries != 2 || stats.Capacity != 2 {
		t.Fatalf("cache stats after eviction = %+v", stats)
	}
	bAgain, err := r.Compile(`2`)
	if err != nil {
		t.Fatal(err)
	}
	if bAgain == b {
		t.Fatal("least recently used program was not evicted")
	}

	config.CompileCacheEntries = 4
	r = newTestRuntime(t, config)
	const workers = 100
	programs := make(chan *CompiledScript, workers)
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			program, err := r.Compile(`input.value * 2`)
			if err != nil {
				errs <- err
				return
			}
			programs <- program
		}()
	}
	wg.Wait()
	close(programs)
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	var first *CompiledScript
	for program := range programs {
		if first == nil {
			first = program
		} else if first != program {
			t.Fatal("concurrent cache miss returned distinct programs")
		}
	}
}

func TestInfiniteLoopTimesOutAndRuntimeRecovers(t *testing.T) {
	config := testConfig()
	config.ExecutionTimeout = 40 * time.Millisecond
	r := newTestRuntime(t, config)
	started := time.Now()
	if _, err := r.Run(context.Background(), `while (true) {}`, nil); !errors.Is(err, ErrTimeout) {
		t.Fatalf("infinite loop error = %v, want ErrTimeout", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("timeout took %s, want under one second", elapsed)
	}
	if got, err := r.Run(context.Background(), `20 + 22`, nil); err != nil || got != float64(42) {
		t.Fatalf("runtime did not recover after timeout: result=%#v err=%v", got, err)
	}
}

func TestContextCancelAndCancelCompletionRace(t *testing.T) {
	config := testConfig()
	config.ExecutionTimeout = time.Second
	r := newTestRuntime(t, config)
	preCanceled, preCancel := context.WithCancel(context.Background())
	preCancel()
	if _, err := r.Run(preCanceled, `42`, nil); !errors.Is(err, ErrCanceled) {
		t.Fatalf("pre-canceled context error = %v, want ErrCanceled", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := r.Run(ctx, `while (true) {}`, nil)
		result <- err
	}()
	time.Sleep(15 * time.Millisecond)
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, ErrCanceled) {
			t.Fatalf("canceled infinite loop error = %v, want ErrCanceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled script did not stop")
	}

	deadlineCtx, deadlineCancel := context.WithTimeout(context.Background(), 15*time.Millisecond)
	defer deadlineCancel()
	if _, err := r.Run(deadlineCtx, `while (true) {}`, nil); !errors.Is(err, ErrTimeout) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("context deadline error = %v, want ErrTimeout and context.DeadlineExceeded", err)
	}

	const iterations = 100
	for i := 0; i < iterations; i++ {
		raceCtx, raceCancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			_, err := r.Run(raceCtx, `var i = 0; for (; i < 500; i++) {} i`, nil)
			done <- err
		}()
		runtime.Gosched()
		raceCancel()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, ErrCanceled) {
				t.Fatalf("cancel/completion race error = %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("cancel/completion race left a running call")
		}
	}
	if got, err := r.Run(context.Background(), `42`, nil); err != nil || got != float64(42) {
		t.Fatalf("runtime did not recover after cancellation race: result=%#v err=%v", got, err)
	}
}

func TestConcurrentExecutionLimit(t *testing.T) {
	config := testConfig()
	config.MaxConcurrent = 1
	config.ExecutionTimeout = time.Second
	r := newTestRuntime(t, config)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := r.Run(ctx, `while (true) {}`, nil)
		done <- err
	}()
	deadline := time.Now().Add(time.Second)
	for r.permits.Load() == 0 && time.Now().Before(deadline) {
		runtime.Gosched()
		time.Sleep(time.Millisecond)
	}
	if r.permits.Load() != 1 {
		t.Fatal("first execution did not acquire the only permit")
	}
	if _, err := r.Run(context.Background(), `1`, nil); !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("second execution error = %v, want ErrResourceLimit", err)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, ErrCanceled) {
			t.Fatalf("first execution cancellation error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("first execution did not stop")
	}
}

func TestNoWatcherGoroutineRemainsAfterRepeatedTimeouts(t *testing.T) {
	config := testConfig()
	config.ExecutionTimeout = 5 * time.Millisecond
	r := newTestRuntime(t, config)
	baseline := runtime.NumGoroutine()
	for i := 0; i < 20; i++ {
		if _, err := r.Run(context.Background(), `for (;;) {}`, nil); !errors.Is(err, ErrTimeout) {
			t.Fatalf("iteration %d error = %v, want ErrTimeout", i, err)
		}
	}
	deadline := time.Now().Add(time.Second)
	for runtime.NumGoroutine() > baseline+2 && time.Now().Before(deadline) {
		runtime.Gosched()
		time.Sleep(5 * time.Millisecond)
	}
	if got := runtime.NumGoroutine(); got > baseline+2 {
		t.Fatalf("goroutine count after repeated timeouts = %d, baseline %d", got, baseline)
	}
}

func TestRuntimeDoesNotExposeHostServicesOrAsyncHelpers(t *testing.T) {
	r := newTestRuntime(t, testConfig())
	got, err := r.Run(context.Background(), `[typeof process, typeof require, typeof fetch, typeof setTimeout, typeof Promise].join(":")`, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != "undefined:undefined:undefined:undefined:undefined" {
		t.Fatalf("host services or async helpers were exposed: %#v", got)
	}
}

func BenchmarkRunCompiled(b *testing.B) {
	r, err := New(DefaultConfig())
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = r.Close() })
	compiled, err := r.Compile(`({ result: input.value + 1 })`)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := r.RunCompiled(context.Background(), compiled, map[string]int{"value": 41}); err != nil {
				b.Error(err)
				return
			}
		}
	})
}

func BenchmarkCompileCacheHit(b *testing.B) {
	r, err := New(DefaultConfig())
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = r.Close() })
	if _, err := r.Compile(`input.value + 1`); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := r.Compile(`input.value + 1`); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRun(b *testing.B) {
	r, err := New(DefaultConfig())
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = r.Close() })
	const source = `({ result: input.value + 1 })`
	input := map[string]int{"value": 41}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := r.Run(context.Background(), source, input); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCompileMiss(b *testing.B) {
	config := DefaultConfig()
	config.CompileCacheEntries = 0
	r, err := New(config)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = r.Close() })
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := r.Compile(`input.value + 1`); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRuntimeNewClose(b *testing.B) {
	config := DefaultConfig()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r, err := New(config)
		if err != nil {
			b.Fatal(err)
		}
		if err := r.Close(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRuntimeNew(b *testing.B) {
	config := DefaultConfig()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := New(config); err != nil {
			b.Fatal(err)
		}
	}
}
