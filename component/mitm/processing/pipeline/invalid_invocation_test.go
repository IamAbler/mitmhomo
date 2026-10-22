package pipeline

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/mitm/processing/model"
	"github.com/metacubex/mihomo/component/mitm/processing/processor"
)

// This gate represents a backend that has made its final Input access, but
// whose execution cleanup has not returned. It must never hold up Cancel.
type cleanupGate struct {
	entered, exit chan struct{}
	count         countCloser
}

func (g *cleanupGate) Close() error { g.count.Close(); close(g.entered); <-g.exit; return nil }

func receiveInvalid[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(5 * time.Second):
		t.Fatal("invalid Invocation path did not return independently of execution")
		var zero T
		return zero
	}
}

func TestInvalidInvocationLifecycle(t *testing.T) {
	for _, mode := range []string{"cancel-first", "finish-first", "race", "parent-canceled", "close-race", "blocked-cleanup", "released-output"} {
		t.Run(mode, func(t *testing.T) {
			tx, _, _ := newTransaction(t, "invalid-"+mode, "")
			outputLedger, err := model.NewLedger(-1, nil)
			if err != nil {
				t.Fatal(err)
			}
			output := mustRequestChange(t, outputLedger, model.RequestPatch{Method: model.Optional[string]{Present: true, Value: "PATCH"}})
			generation, admission := &countCloser{}, &countCloser{}
			gate := &cleanupGate{entered: make(chan struct{}), exit: make(chan struct{})}
			var openGate sync.Once
			defer openGate.Do(func() { close(gate.exit) })
			type handle struct {
				inv        *processor.Invocation
				completion *processor.Completion
				input      model.Input
			}
			started := make(chan handle, 1)
			returnStart := make(chan struct{})
			finished := make(chan struct{})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			fake := newFake(t, "invalid", processor.Requirements{}, func(inv *processor.Invocation, c *processor.Completion, input model.Input) {
				started <- handle{inv, c, input}
				<-returnStart
			})
			fake.mutateKey = func(k model.InvocationKey) model.InvocationKey { k.Invocation = "wrong"; return k }
			runner, err := NewRunner([]Entry{{Class: Rewrite, Processor: fake, AllowFailOpen: true, FailOpenSafe: func(error) bool { return true }}}, Options{
				AcquireGeneration: func(context.Context, model.GenerationID) (io.Closer, error) { return generation, nil },
				AcquireExecution: func(context.Context, processor.Descriptor, model.InvocationKey) ([]io.Closer, error) {
					if mode == "blocked-cleanup" {
						return []io.Closer{admission, gate}, nil
					}
					return []io.Closer{admission}, nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { _, err := runner.Run(ctx, tx, model.RequestPhase); done <- err }()
			h := receiveInvalid(t, started)
			finishNow := func() {
				if !h.completion.Finish(output, nil) {
					t.Error("first Finish rejected")
				}
				close(finished)
			}
			switch mode {
			case "finish-first":
				finishNow()
			case "released-output":
				_ = output.Release()
				finishNow()
			case "blocked-cleanup":
				go finishNow()
				receiveInvalid(t, gate.entered)
			case "parent-canceled":
				cancel()
			}
			var racers sync.WaitGroup
			if mode == "race" {
				racers.Add(1)
				go func() { defer racers.Done(); <-returnStart; finishNow() }()
			}
			if mode == "close-race" {
				racers.Add(1)
				go func() {
					defer racers.Done()
					<-returnStart
					if err := runner.Close(); err != nil {
						t.Error(err)
					}
				}()
			}
			close(returnStart)
			runErr := receiveInvalid(t, done)
			h.inv.Cancel(model.ErrInvalid)
			h.inv.Cancel(model.ErrInvalid)
			if !channelClosed(h.inv.LogicalDone()) {
				t.Fatal("Cancel did not synchronously fix logical latch")
			}
			// A second observation is legal; it must be immediate even if cleanup blocks.
			observed := make(chan struct{}, 1)
			go func() { _, _ = h.inv.Await(context.Background()); observed <- struct{}{} }()
			receiveInvalid(t, observed)
			if mode == "race" {
				receiveInvalid(t, finished)
			}
			completed := mode == "finish-first" || mode == "released-output" || mode == "race"
			if !completed {
				if runErr == nil || tx.Revision() != 1 || generation.closes.Load() != 0 || admission.closes.Load() != 0 || fake.lifecycle.Active() != 1 || !channelOpen(h.inv.ExecutionDone()) {
					t.Fatal("logical failure committed or released execution ownership")
				}
				if value(t, h.input, "X-Test") != "original" {
					t.Fatal("Input lease released before execution exit")
				}
				if mode == "blocked-cleanup" {
					openGate.Do(func() { close(gate.exit) })
					receiveInvalid(t, finished)
				} else {
					finishNow()
				}
			}
			racers.Wait()
			if runErr != nil && tx.Revision() != 1 || runErr == nil && tx.Revision() != 2 {
				t.Fatalf("foreign result changed revision: err=%v revision=%d", runErr, tx.Revision())
			}
			if outputLedger.Current() != 0 || generation.closes.Load() != 1 || admission.closes.Load() != 1 || fake.lifecycle.Active() != 0 || !channelClosed(h.inv.ExecutionDone()) {
				t.Fatalf("execution/output ownership leaked: output=%d generation=%d admission=%d active=%d", outputLedger.Current(), generation.closes.Load(), admission.closes.Load(), fake.lifecycle.Active())
			}
			if mode == "blocked-cleanup" && gate.count.closes.Load() != 1 {
				t.Fatal("cleanup closer called more than once")
			}
			// Finish-first may safely fail open; the foreign PATCH must never commit.
			input, lease, err := tx.Snapshot("inspect")
			if err == nil {
				if input.Request().Method != "POST" {
					t.Error("foreign result committed")
				}
				_ = lease.Close()
			}
			if err := runner.Close(); err != nil {
				t.Fatal(err)
			}
			drain, cancelDrain := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancelDrain()
			if err := runner.WaitClosed(drain); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestInvalidInvocationCleanupFailureCannotFailOpen(t *testing.T) {
	tx, _, _ := newTransaction(t, "invalid-cleanup", "")
	resource := &failingCloser{err: errors.New("cleanup failed")}
	fake := newFake(t, "invalid-cleanup", processor.Requirements{}, nil)
	fake.mutateKey = func(k model.InvocationKey) model.InvocationKey { k.Invocation = "wrong"; return k }
	runner, _ := NewRunner([]Entry{{Class: Rewrite, Processor: fake, AllowFailOpen: true, FailOpenSafe: func(error) bool { return true }}}, Options{AcquireExecution: func(context.Context, processor.Descriptor, model.InvocationKey) ([]io.Closer, error) {
		return []io.Closer{resource}, nil
	}})
	_, err := runner.Run(context.Background(), tx, model.RequestPhase)
	if !errors.Is(err, errExecutionResourceCleanup) || tx.State() != model.Terminated || tx.Revision() != 1 || resource.closes.Load() != 1 {
		t.Fatalf("cleanup failure allowed recovery: %v", err)
	}
}

// Returning nil,nil violates Start's contract, but without starting execution
// the caller still owns all supplied resources and can safely reclaim them.
type nilInvocationProcessor struct{ *fakeProcessor }

func (p nilInvocationProcessor) Start(context.Context, model.Input, ...io.Closer) (*processor.Invocation, error) {
	return nil, nil
}

func TestInvalidInvocationBeforeOwnershipTransfer(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		name := "nil-invocation"
		if canceled {
			name = "already-canceled"
		}
		t.Run(name, func(t *testing.T) {
			tx, _, _ := newTransaction(t, name, "")
			generation := &countCloser{}
			fake := newFake(t, name, processor.Requirements{}, nil)
			runner, _ := NewRunner([]Entry{{Class: Rewrite, Processor: nilInvocationProcessor{fake}}}, Options{AcquireGeneration: func(context.Context, model.GenerationID) (io.Closer, error) { return generation, nil }})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if canceled {
				cancel()
			}
			_, err := runner.Run(ctx, tx, model.RequestPhase)
			want := int64(1)
			if canceled {
				want = 0
			}
			if err == nil || generation.closes.Load() != want || tx.Revision() != 1 || fake.lifecycle.Active() != 0 {
				t.Fatalf("pre-transfer failure ownership: err=%v closes=%d", err, generation.closes.Load())
			}
		})
	}
}
