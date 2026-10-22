package jsruntime

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/mitm/scripthost"
)

type sessionTestHost struct {
	scheduled chan struct{}
	calls     atomic.Int32
}

func (h *sessionTestHost) Call(_ context.Context, session scripthost.Session, call HostCall) (any, error) {
	switch call.Name {
	case "$done":
		if len(call.Args) == 0 {
			session.Done(nil, false)
		} else {
			session.Done(call.Args[0], true)
		}
		return nil, nil
	case "$task":
		h.calls.Add(1)
		options := call.Args[0].(map[string]any)
		name := options["name"].(string)
		delay := time.Duration(options["delay"].(float64)) * time.Millisecond
		if h.scheduled != nil {
			select {
			case h.scheduled <- struct{}{}:
			default:
			}
		}
		return nil, session.Schedule(call.CallbackID, func(ctx context.Context) ([]any, error) {
			timer := time.NewTimer(delay)
			defer timer.Stop()
			select {
			case <-timer.C:
				return []any{name}, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		})
	default:
		return nil, fmt.Errorf("unexpected host call %q", call.Name)
	}
}

func sessionTestBindings() []Binding {
	return []Binding{{Name: "$done", CallbackArg: -1}, {Name: "$task", Async: true, CallbackArg: 1}}
}

func sessionTestOptions(host SessionHost) SessionOptions {
	return SessionOptions{Host: host, Bindings: sessionTestBindings(), Timeout: time.Second, MaxPendingTasks: 4}
}

func TestRunSessionGlobalsDoneAndVMIsolation(t *testing.T) {
	runtime := newTestRuntime(t, testConfig())
	compiled, err := runtime.Compile(`$request.count += 1; $done({count: $request.count}); $done({count: 99})`)
	if err != nil {
		t.Fatal(err)
	}
	options := sessionTestOptions(&sessionTestHost{})
	options.Globals = map[string]any{"$request": map[string]any{"count": 4}}
	got, err := runtime.RunSession(context.Background(), compiled, options)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"count": float64(5)}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("RunSession() = %#v, want %#v", got, want)
	}
	got, err = runtime.RunSession(context.Background(), compiled, options)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("second isolated RunSession() = %#v, %v; want %#v", got, err, want)
	}
}

func TestRunSessionAsyncCallbacksRunOnVMOwnerInCompletionOrder(t *testing.T) {
	runtime := newTestRuntime(t, testConfig())
	host := &sessionTestHost{}
	compiled, err := runtime.Compile(`
		var order = [];
		var count = 0;
		function finish(name) { order.push(name); count++; if (count === 2) $done({order: order.join(",")}); }
		$task({name: "slow", delay: 40}, function(error, name) { if (error) throw new Error(error); finish(name); });
		$task({name: "fast", delay: 5}, function(error, name) { if (error) throw new Error(error); finish(name); });
	`)
	if err != nil {
		t.Fatal(err)
	}
	got, err := runtime.RunSession(context.Background(), compiled, sessionTestOptions(host))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"order": "fast,slow"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("completion order = %#v, want %#v", got, want)
	}
}

func TestRunSessionWithoutDoneWaitsForTasksThenPassesThrough(t *testing.T) {
	runtime := newTestRuntime(t, testConfig())
	host := &sessionTestHost{}
	compiled, err := runtime.Compile(`$task({name: "fire", delay: 1}, function() { });`)
	if err != nil {
		t.Fatal(err)
	}
	got, err := runtime.RunSession(context.Background(), compiled, sessionTestOptions(host))
	if err != nil || got != nil {
		t.Fatalf("RunSession() = %#v, %v; want implicit passthrough", got, err)
	}
}

func TestRunSessionTaskQueueIsBounded(t *testing.T) {
	runtime := newTestRuntime(t, testConfig())
	host := &sessionTestHost{}
	compiled, err := runtime.Compile(`
		$task({name: "one", delay: 100}, function() {});
		$task({name: "two", delay: 100}, function() {});
	`)
	if err != nil {
		t.Fatal(err)
	}
	options := sessionTestOptions(host)
	options.MaxPendingTasks = 1
	if _, err := runtime.RunSession(context.Background(), compiled, options); !errors.Is(err, ErrExecution) {
		t.Fatalf("RunSession() error = %v, want task limit failure", err)
	}
	if got := host.calls.Load(); got != 2 {
		t.Fatalf("host calls = %d, want 2 calls with second rejected by queue", got)
	}
}

func TestSessionCloseSerializesTaskRegistration(t *testing.T) {
	for iteration := 0; iteration < 64; iteration++ {
		ctx, cancel := context.WithCancel(context.Background())
		session := newSession(ctx, cancel, 1)
		start := make(chan struct{})
		finished := make(chan error, 1)
		scheduleResult := make(chan error, 1)
		go func() {
			<-start
			scheduleResult <- session.Schedule(1, func(taskCtx context.Context) ([]any, error) {
				<-taskCtx.Done()
				finished <- context.Cause(taskCtx)
				return nil, context.Cause(taskCtx)
			})
		}()
		closeResult := make(chan struct{})
		go func() {
			<-start
			session.Close()
			close(closeResult)
		}()
		close(start)
		scheduleErr := <-scheduleResult
		<-closeResult
		if scheduleErr == nil {
			select {
			case err := <-finished:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("iteration %d scheduled task context error = %v, want context.Canceled", iteration, err)
				}
			case <-time.After(time.Second):
				t.Fatalf("iteration %d accepted task did not stop after Session.Close", iteration)
			}
		} else if !errors.Is(scheduleErr, ErrSessionDone) && !errors.Is(scheduleErr, context.Canceled) {
			t.Fatalf("iteration %d Schedule error = %v, want closed or canceled", iteration, scheduleErr)
		}
		if err := session.Schedule(2, func(context.Context) ([]any, error) {
			t.Errorf("iteration %d started work after Session.Close", iteration)
			return nil, nil
		}); !errors.Is(err, ErrSessionDone) {
			t.Fatalf("iteration %d Schedule after Close error = %v, want ErrSessionDone", iteration, err)
		}
		session.Close()
	}
}

func TestRunSessionTimeoutAndRuntimeCloseCancelWorkers(t *testing.T) {
	t.Run("timeout", func(t *testing.T) {
		runtime := newTestRuntime(t, testConfig())
		host := &sessionTestHost{scheduled: make(chan struct{}, 1)}
		compiled, err := runtime.Compile(`$task({name: "wait", delay: 5000}, function() { $done({callback: "must-not-run-after-close"}); });`)
		if err != nil {
			t.Fatal(err)
		}
		options := sessionTestOptions(host)
		options.Timeout = 30 * time.Millisecond
		_, err = runtime.RunSession(context.Background(), compiled, options)
		if !errors.Is(err, ErrTimeout) {
			t.Fatalf("RunSession() error = %v, want ErrTimeout", err)
		}
	})

	t.Run("runtime close", func(t *testing.T) {
		config := testConfig()
		runtime, err := New(config)
		if err != nil {
			t.Fatal(err)
		}
		host := &sessionTestHost{scheduled: make(chan struct{}, 1)}
		compiled, err := runtime.Compile(`$task({name: "wait", delay: 5000}, function() {});`)
		if err != nil {
			t.Fatal(err)
		}
		result := make(chan error, 1)
		go func() {
			_, runErr := runtime.RunSession(context.Background(), compiled, sessionTestOptions(host))
			result <- runErr
		}()
		select {
		case <-host.scheduled:
		case <-time.After(time.Second):
			t.Fatal("host task was not scheduled")
		}
		if err := runtime.Close(); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-result:
			if !errors.Is(err, ErrClosed) {
				t.Fatalf("RunSession() error = %v, want ErrClosed", err)
			}
		case <-time.After(time.Second):
			t.Fatal("Runtime.Close did not stop the session")
		}
	})
}

func TestRunSessionRejectsPromiseAndInvalidOptions(t *testing.T) {
	runtime := newTestRuntime(t, testConfig())
	compiled, err := runtime.Compile(`Promise.resolve(1)`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.RunSession(context.Background(), compiled, SessionOptions{}); !errors.Is(err, ErrExecution) {
		t.Fatalf("Promise execution error = %v, want ErrExecution", err)
	}
	if _, err := runtime.RunSession(context.Background(), compiled, SessionOptions{Timeout: 31 * time.Second}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("invalid timeout error = %v, want ErrInvalidConfig", err)
	}
}

func TestRunSessionConcurrentVMsAreIsolated(t *testing.T) {
	runtime := newTestRuntime(t, testConfig())
	compiled, err := runtime.Compile(`var state = 0; state++; $done({state: state, input: input.value});`)
	if err != nil {
		t.Fatal(err)
	}
	// Session input is supplied as engine-owned globals, including any
	// application value that needs to survive a JS/Go boundary.
	options := SessionOptions{
		Globals:  map[string]any{"input": map[string]any{"value": "isolated"}},
		Bindings: []Binding{{Name: "$done", CallbackArg: -1}},
		Host:     &simpleDoneHost{},
		Timeout:  time.Second,
	}
	const workers = 12
	var wait sync.WaitGroup
	errCh := make(chan error, workers)
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			got, err := runtime.RunSession(context.Background(), compiled, options)
			if err != nil {
				errCh <- err
				return
			}
			want := map[string]any{"state": float64(1), "input": "isolated"}
			if !reflect.DeepEqual(got, want) {
				errCh <- fmt.Errorf("session result %#v != %#v", got, want)
			}
		}()
	}
	wait.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
}

type simpleDoneHost struct{}

func (simpleDoneHost) Call(_ context.Context, session scripthost.Session, call HostCall) (any, error) {
	if call.Name != "$done" {
		return nil, fmt.Errorf("unexpected host call %q", call.Name)
	}
	if len(call.Args) == 0 {
		session.Done(nil, false)
	} else {
		session.Done(call.Args[0], true)
	}
	return nil, nil
}
