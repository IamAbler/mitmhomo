package jsruntime

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCloseIsIdempotentAndRejectsAllOperations(t *testing.T) {
	r := newTestRuntime(t, testConfig())
	compiled, err := r.Compile(`42`)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("second Close returned %v", err)
	}
	if _, err := r.Compile(`42`); !errors.Is(err, ErrClosed) {
		t.Fatalf("Compile after Close error = %v, want ErrClosed", err)
	}
	if _, err := r.Run(context.Background(), `42`, nil); !errors.Is(err, ErrClosed) {
		t.Fatalf("Run after Close error = %v, want ErrClosed", err)
	}
	if _, err := r.RunCompiled(context.Background(), compiled, nil); !errors.Is(err, ErrClosed) {
		t.Fatalf("RunCompiled after Close error = %v, want ErrClosed", err)
	}
	if stats := r.CacheStats(); stats.Entries != 0 {
		t.Fatalf("cache after Close = %+v, want zero entries", stats)
	}
}

func TestCloseInterruptsLongRunningExecutionWithoutWaiting(t *testing.T) {
	r := newTestRuntime(t, testConfig())
	compiled, err := r.Compile(`while (true) {}`)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, runErr := r.RunCompiled(ctx, compiled, nil)
		done <- runErr
	}()

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		r.activeMu.Lock()
		active := len(r.activeVMs)
		r.activeMu.Unlock()
		if active > 0 {
			break
		}
		runtime.Gosched()
		time.Sleep(time.Millisecond)
	}
	r.activeMu.Lock()
	active := len(r.activeVMs)
	r.activeMu.Unlock()
	if active == 0 {
		t.Fatal("long-running script did not register its VM")
	}

	started := time.Now()
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("Close took %s, want a bounded prompt return", elapsed)
	}
	select {
	case err := <-done:
		if !errors.Is(err, ErrClosed) {
			t.Fatalf("running script after Close error = %v, want ErrClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not interrupt the running script")
	}
}

func TestCloseRacesWithCompileCacheHitsAndMisses(t *testing.T) {
	config := testConfig()
	config.CompileCacheEntries = 8
	r := newTestRuntime(t, config)
	if _, err := r.Compile(`input.value`); err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	var wait sync.WaitGroup
	errs := make(chan error, 40)
	for index := 0; index < 20; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			_, err := r.Compile(`input.value`)
			if err != nil && !errors.Is(err, ErrClosed) {
				errs <- err
			}
		}()
	}
	for index := 0; index < 20; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			source := strings.Repeat(" ", 64*1024) + "1 + " + string(rune('0'+index%10))
			_, err := r.Compile(source)
			if err != nil && !errors.Is(err, ErrClosed) {
				errs <- err
			}
		}(index)
	}
	close(start)
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	wait.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if stats := r.CacheStats(); stats.Entries != 0 {
		t.Fatalf("cache refilled after concurrent Close: %+v", stats)
	}
}

func TestRepeatedRuntimeCreateRunCloseHasNoGoroutineGrowth(t *testing.T) {
	baseline := runtime.NumGoroutine()
	for index := 0; index < 100; index++ {
		r := newTestRuntime(t, testConfig())
		if got, err := r.Run(context.Background(), `input.value + 1`, map[string]int{"value": index}); err != nil || got != float64(index+1) {
			t.Fatalf("iteration %d result = %#v, err=%v", index, got, err)
		}
		if err := r.Close(); err != nil {
			t.Fatalf("iteration %d Close error = %v", index, err)
		}
	}
	runtime.GC()
	deadline := time.Now().Add(time.Second)
	for runtime.NumGoroutine() > baseline+2 && time.Now().Before(deadline) {
		runtime.Gosched()
		time.Sleep(5 * time.Millisecond)
	}
	if got := runtime.NumGoroutine(); got > baseline+2 {
		t.Fatalf("goroutines after 100 create/run/close cycles = %d, baseline %d", got, baseline)
	}
}
