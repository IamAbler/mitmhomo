package processor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/mitm/processing/model"
)

func testKey(n int) model.InvocationKey {
	return model.InvocationKey{TransactionID: fmt.Sprintf("tx-%d", n), Generation: 7, Phase: model.RequestPhase, Revision: 1, Invocation: model.InvocationID(fmt.Sprintf("inv-%d", n))}
}

type fakeProcessor struct {
	lifecycle   *Lifecycle
	descriptor  Descriptor
	onStart     func(*Invocation, *Completion, model.Input)
	mu          sync.Mutex
	completions map[*Invocation]*Completion
}

func newFakeProcessor(t testing.TB, capacity int, onStart func(*Invocation, *Completion, model.Input)) *fakeProcessor {
	t.Helper()
	lifecycle, err := NewProcessorLifecycle("fake", capacity)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeProcessor{
		lifecycle:   lifecycle,
		descriptor:  Descriptor{ID: "fake", Backend: "test", ContractVersion: 1, Request: true, Response: true},
		onStart:     onStart,
		completions: make(map[*Invocation]*Completion),
	}
}

func (p *fakeProcessor) Describe() Descriptor { return p.descriptor.Clone() }
func (p *fakeProcessor) Start(ctx context.Context, input model.Input, resources ...io.Closer) (*Invocation, error) {
	invocation, completion, err := p.lifecycle.BeginWithResources(ctx, input.Key(), resources...)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	p.completions[invocation] = completion
	p.mu.Unlock()
	if p.onStart != nil {
		p.onStart(invocation, completion, input)
	}
	return invocation, nil
}
func (p *fakeProcessor) Close() error                         { return p.lifecycle.Close() }
func (p *fakeProcessor) WaitClosed(ctx context.Context) error { return p.lifecycle.WaitClosed(ctx) }
func (p *fakeProcessor) completion(invocation *Invocation) *Completion {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.completions[invocation]
}

func testInput(t testing.TB, id string) (model.Input, *model.CopyLease, *model.Transaction, func()) {
	t.Helper()
	ledger, err := model.NewLedger(-1, nil)
	if err != nil {
		t.Fatal(err)
	}
	sourceLease := model.NewCopyLease(ledger)
	url, err := model.ParseURL(sourceLease, "https://example.test/path", model.MITMHTTPS)
	if err != nil {
		t.Fatal(err)
	}
	headers, err := model.NewHeaderBlock(sourceLease, []model.HeaderField{{Name: "X-Test", Values: []string{"one"}}})
	if err != nil {
		t.Fatal(err)
	}
	trailers, err := model.NewTrailerView(model.TrailerUnavailable, model.HeaderBlock{}, model.HeaderBlock{})
	if err != nil {
		t.Fatal(err)
	}
	request := model.RequestHead{Method: "GET", URL: url, Authority: "example.test", Headers: headers, Trailers: trailers}
	tx, err := model.NewTransaction(context.Background(), model.TransactionOptions{
		ID:              id,
		Generation:      7,
		Connection:      model.ConnectionView{ID: "conn-" + id},
		OriginalIngress: request,
		Request:         request,
		Ledger:          ledger,
	})
	sourceLease.Close()
	if err != nil {
		t.Fatal(err)
	}
	input, lease, err := tx.Snapshot(model.InvocationID("invoke-" + id))
	if err != nil {
		tx.Close()
		t.Fatal(err)
	}
	cleanup := func() {
		_ = lease.Close()
		_ = tx.Close()
	}
	return input, lease, tx, cleanup
}

func waitClosed(t testing.TB, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("channel did not close")
	}
}

func isOpen(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return false
	default:
		return true
	}
}

func TestFakeProcessorInterfaceAndDescriptor(t *testing.T) {
	input, inputLease, _, cleanup := testInput(t, "fake-interface")
	defer cleanup()
	processor := newFakeProcessor(t, 2, func(invocation *Invocation, completion *Completion, got model.Input) {
		if got.Key() != input.Key() {
			t.Errorf("input key changed: %+v", got.Key())
		}
		if !completion.Finish(model.Continue(), nil) {
			t.Error("synchronous fake completion was rejected")
		}
	})
	descriptor := processor.Describe()
	descriptor.ID = "caller-mutation"
	if err := processor.Describe().Validate(); err != nil || processor.Describe().ID != "fake" {
		t.Fatalf("descriptor exposed mutable configuration: %v", err)
	}
	invocation, err := processor.Start(context.Background(), input, inputLease)
	if err != nil || invocation == nil {
		t.Fatalf("successful Start contract failed: invocation=%v err=%v", invocation, err)
	}
	result, err := invocation.Await(context.Background())
	if err != nil || result.Kind() != model.ResultContinue {
		t.Fatalf("synchronous result failed: %v %v", result.Kind(), err)
	}
	waitClosed(t, invocation.ExecutionDone())
	_ = processor.Close()
	if err := processor.WaitClosed(context.Background()); err != nil {
		t.Fatal(err)
	}
	callerOwned := &countCloser{}
	failed, err := processor.Start(context.Background(), input, callerOwned)
	if failed != nil || err == nil || !errors.Is(err, model.ErrorSentinel(model.ProcessingErrorClosed)) {
		t.Fatalf("Start after Close must return nil,error: invocation=%v err=%v", failed, err)
	}
	if callerOwned.count.Load() != 0 {
		t.Fatal("failed Start closed a resource that remained caller-owned")
	}
	_ = callerOwned.Close()
	if callerOwned.count.Load() != 1 {
		t.Fatal("caller could not release a resource after failed Start")
	}
	if err := (Descriptor{ID: "bad"}).Validate(); err == nil {
		t.Fatal("invalid Descriptor accepted")
	}
}

func TestStartRegistersResourcesBeforeBackendCanFinish(t *testing.T) {
	input, _, _, cleanup := testInput(t, "finish-before-start-return")
	defer cleanup()
	resource := &countCloser{}
	processor := newFakeProcessor(t, 1, func(_ *Invocation, completion *Completion, _ model.Input) {
		if !completion.Finish(model.Continue(), nil) {
			t.Error("synchronous backend Finish was rejected")
		}
	})
	invocation, err := processor.Start(context.Background(), input, resource)
	if err != nil || invocation == nil {
		t.Fatalf("Start failed: invocation=%v err=%v", invocation, err)
	}
	if isOpen(invocation.ExecutionDone()) || resource.count.Load() != 1 {
		t.Fatal("backend completed before Start returned without releasing its pre-registered resource")
	}
	result, err := invocation.Await(context.Background())
	if err != nil || result.Kind() != model.ResultContinue {
		t.Fatalf("synchronous result unavailable after Start: kind=%d err=%v", result.Kind(), err)
	}
	if err := processor.Close(); err != nil {
		t.Fatal(err)
	}
	if err := processor.WaitClosed(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestProcessorConcurrentCallsKeepInvocationStateIsolated(t *testing.T) {
	firstInput, _, _, firstCleanup := testInput(t, "parallel-first")
	defer firstCleanup()
	secondInput, _, _, secondCleanup := testInput(t, "parallel-second")
	defer secondCleanup()
	processor := newFakeProcessor(t, 2, nil)
	type startResult struct {
		invocation *Invocation
		err        error
	}
	start := make(chan struct{})
	started := make(chan startResult, 2)
	go func() {
		<-start
		invocation, err := processor.Start(context.Background(), firstInput)
		started <- startResult{invocation, err}
	}()
	go func() {
		<-start
		invocation, err := processor.Start(context.Background(), secondInput)
		started <- startResult{invocation, err}
	}()
	close(start)
	firstStart, secondStart := <-started, <-started
	if firstStart.err != nil || secondStart.err != nil {
		t.Fatalf("concurrent Start failed: %v / %v", firstStart.err, secondStart.err)
	}
	var first, second *Invocation
	for _, outcome := range []startResult{firstStart, secondStart} {
		switch outcome.invocation.Key().TransactionID {
		case "parallel-first":
			first = outcome.invocation
		case "parallel-second":
			second = outcome.invocation
		default:
			t.Fatalf("unexpected transaction id: %s", outcome.invocation.Key().TransactionID)
		}
	}
	if first.Key().TransactionID == second.Key().TransactionID || first.Key().Invocation == second.Key().Invocation {
		t.Fatal("simultaneous calls shared identity")
	}
	firstResult, err := model.Reject("first_policy", mustLedger(t))
	if err != nil {
		t.Fatal(err)
	}
	secondResult, err := model.Abort("second_reason", mustLedger(t))
	if err != nil {
		t.Fatal(err)
	}
	if !processor.completion(second).Finish(secondResult, nil) || !processor.completion(first).Finish(firstResult, nil) {
		t.Fatal("one of the concurrent Completion slots rejected Finish")
	}
	firstDone, firstErr := first.Await(context.Background())
	secondDone, secondErr := second.Await(context.Background())
	if firstErr != nil || firstDone.Kind() != model.ResultReject || secondErr != nil || secondDone.Kind() != model.ResultAbort {
		t.Fatalf("invocations crossed results: first=(%d,%v) second=(%d,%v)", firstDone.Kind(), firstErr, secondDone.Kind(), secondErr)
	}
	firstCode, ok, err := firstDone.RejectCode()
	if err != nil || !ok || firstCode != "first_policy" {
		t.Fatal("first payload crossed invocation boundary", err)
	}
	secondReason, ok, err := secondDone.AbortReason()
	if err != nil || !ok || secondReason != "second_reason" {
		t.Fatal("second payload crossed invocation boundary", err)
	}
	_ = firstDone.Release()
	_ = secondDone.Release()
	_ = processor.Close()
	if err := processor.WaitClosed(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func mustLedger(t testing.TB) *model.Ledger {
	t.Helper()
	ledger, err := model.NewLedger(-1, nil)
	if err != nil {
		t.Fatal(err)
	}
	return ledger
}

func TestInvocationAsyncFinishAndSeparateExecutionDone(t *testing.T) {
	invocation, completion := NewInvocation(context.Background(), testKey(1))
	finish := make(chan struct{})
	go func() {
		<-finish
		completion.Finish(model.Continue(), nil)
	}()
	awaited := make(chan struct {
		result model.DoneResult
		err    error
	}, 1)
	go func() {
		result, err := invocation.Await(context.Background())
		awaited <- struct {
			result model.DoneResult
			err    error
		}{result, err}
	}()
	if !isOpen(invocation.ExecutionDone()) || !isOpen(invocation.LogicalDone()) {
		t.Fatal("invocation completed before backend finish")
	}
	close(finish)
	got := <-awaited
	if got.err != nil || got.result.Kind() != model.ResultContinue {
		t.Fatalf("async await failed: kind=%d err=%v", got.result.Kind(), got.err)
	}
	waitClosed(t, invocation.ExecutionDone())
}

func TestInvocationErrorsInvalidOutputAndMutualExclusion(t *testing.T) {
	t.Run("execution error", func(t *testing.T) {
		invocation, completion := NewInvocation(context.Background(), testKey(2))
		cause := errors.New("backend failed")
		if !completion.Finish(model.DoneResult{}, cause) {
			t.Fatal("first Finish rejected")
		}
		result, err := invocation.Await(context.Background())
		var processing *model.ProcessingError
		if result.Kind() != model.ResultInvalid || !errors.Is(err, cause) || !errors.As(err, &processing) || processing.Kind != model.ProcessingErrorExecution || processing.Origin != model.ProcessingOriginProcessor {
			t.Fatalf("execution error was not classified: result=%d err=%#v", result.Kind(), err)
		}
	})
	t.Run("invalid zero result", func(t *testing.T) {
		invocation, completion := NewInvocation(context.Background(), testKey(3))
		completion.Finish(model.DoneResult{}, nil)
		result, err := invocation.Await(context.Background())
		if result.Kind() != model.ResultInvalid || !errors.Is(err, model.ErrorSentinel(model.ProcessingErrorInvalidOutput)) {
			t.Fatalf("zero Result committed: kind=%d err=%v", result.Kind(), err)
		}
	})
	t.Run("result and error conflict", func(t *testing.T) {
		ledger, _ := model.NewLedger(-1, nil)
		result, err := model.Reject("policy", ledger)
		if err != nil {
			t.Fatal(err)
		}
		invocation, completion := NewInvocation(context.Background(), testKey(4))
		completion.Finish(result, errors.New("also failed"))
		got, finishErr := invocation.Await(context.Background())
		if got.Kind() != model.ResultInvalid || !errors.Is(finishErr, model.ErrorSentinel(model.ProcessingErrorInvalidOutput)) {
			t.Fatalf("result+error conflict not rejected: kind=%d err=%v", got.Kind(), finishErr)
		}
	})
	t.Run("wrong phase", func(t *testing.T) {
		ledger, _ := model.NewLedger(-1, nil)
		result, err := model.ChangeResponse(model.ResponsePatch{Status: model.Optional[int]{Present: true, Value: 201}}, ledger, 0)
		if err != nil {
			t.Fatal(err)
		}
		invocation, completion := NewInvocation(context.Background(), testKey(5))
		completion.Finish(result, nil)
		got, finishErr := invocation.Await(context.Background())
		if got.Kind() != model.ResultInvalid || !errors.Is(finishErr, model.ErrorSentinel(model.ProcessingErrorInvalidOutput)) {
			t.Fatalf("wrong phase result committed: kind=%d err=%v", got.Kind(), finishErr)
		}
	})
}

func TestAwaitTimeoutAndParentCancellationOrigins(t *testing.T) {
	t.Run("Await context is processor timeout", func(t *testing.T) {
		invocation, completion := NewInvocation(context.Background(), testKey(6))
		wait, cancel := context.WithTimeout(context.Background(), 15*time.Millisecond)
		defer cancel()
		result, err := invocation.Await(wait)
		var processing *model.ProcessingError
		if result.Kind() != model.ResultInvalid || !errors.As(err, &processing) || processing.Kind != model.ProcessingErrorTimeout || processing.Origin != model.ProcessingOriginProcessor {
			t.Fatalf("Await timeout source lost: result=%d err=%#v", result.Kind(), err)
		}
		select {
		case <-invocation.Context().Done():
		case <-time.After(time.Second):
			t.Fatal("Await cancellation did not propagate to execution context")
		}
		if !isOpen(invocation.ExecutionDone()) {
			t.Fatal("Await timeout claimed execution had exited")
		}
		completion.Finish(model.Continue(), nil)
		waitClosed(t, invocation.ExecutionDone())
	})
	t.Run("parent context is request timeout", func(t *testing.T) {
		parent, cancel := context.WithCancelCause(context.Background())
		invocation, completion := NewInvocation(parent, testKey(7))
		cancel(context.DeadlineExceeded)
		result, err := invocation.Await(context.Background())
		var processing *model.ProcessingError
		if result.Kind() != model.ResultInvalid || !errors.As(err, &processing) || processing.Kind != model.ProcessingErrorTimeout || processing.Origin != model.ProcessingOriginRequest {
			t.Fatalf("parent timeout source lost: result=%d err=%#v", result.Kind(), err)
		}
		completion.Finish(model.Continue(), nil)
		waitClosed(t, invocation.ExecutionDone())
	})
	t.Run("parent cancellation is distinct", func(t *testing.T) {
		parent, cancel := context.WithCancel(context.Background())
		invocation, completion := NewInvocation(parent, testKey(8))
		cancel()
		_, err := invocation.Await(context.Background())
		var processing *model.ProcessingError
		if !errors.As(err, &processing) || processing.Kind != model.ProcessingErrorCanceled || processing.Origin != model.ProcessingOriginRequest {
			t.Fatalf("parent cancellation source lost: %#v", err)
		}
		completion.Finish(model.Continue(), nil)
	})
}

func TestInvocationLateFinishAndDuplicateFinishReleaseResultBudgetOnce(t *testing.T) {
	ledger, err := model.NewLedger(-1, nil)
	if err != nil {
		t.Fatal(err)
	}
	result, err := model.ChangeRequest(model.RequestPatch{Method: model.Optional[string]{Present: true, Value: "PATCH"}}, ledger, 0)
	if err != nil {
		t.Fatal(err)
	}
	charged := ledger.Current()
	if charged == 0 {
		t.Fatal("result payload not charged")
	}
	invocation, completion := NewInvocation(context.Background(), testKey(9))
	invocation.Cancel(errors.New("transaction moved on"))
	if _, err := invocation.Await(context.Background()); err == nil {
		t.Fatal("canceled invocation returned success")
	}
	if !isOpen(invocation.ExecutionDone()) || ledger.Current() != charged {
		t.Fatal("logical cancel released a live result/execution allocation")
	}
	if !completion.Finish(result, nil) {
		t.Fatal("late Finish must still release real execution resources")
	}
	waitClosed(t, invocation.ExecutionDone())
	if ledger.Current() != 0 {
		t.Fatalf("late output result leaked budget: %d", ledger.Current())
	}
	if completion.Finish(result, nil) {
		t.Fatal("duplicate Finish accepted")
	}
}

type countCloser struct{ count atomic.Int32 }

func (c *countCloser) Close() error { c.count.Add(1); return nil }

type trackedPermit struct{ active atomic.Bool }

func (p *trackedPermit) Close() error { p.active.Store(false); return nil }

type gatedCloser struct {
	entered chan struct{}
	release chan struct{}
	err     error
	count   atomic.Int32
}

func (c *gatedCloser) Close() error {
	c.count.Add(1)
	close(c.entered)
	<-c.release
	return c.err
}

type observedContext struct {
	context.Context
	done     chan struct{}
	observed chan struct{}
	once     sync.Once
}

func newObservedContext() *observedContext {
	return &observedContext{Context: context.Background(), done: make(chan struct{}), observed: make(chan struct{})}
}

func (c *observedContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.observed) })
	return c.done
}

func TestCopyLeaseAndAdmissionRemainUntilExecutionDone(t *testing.T) {
	ledger, err := model.NewLedger(-1, nil)
	if err != nil {
		t.Fatal(err)
	}
	inputLease := model.NewCopyLease(ledger)
	if _, err := model.ParseURL(inputLease, "https://example.test/lease", model.MITMHTTPS); err != nil {
		t.Fatal(err)
	}
	initialBudget := ledger.Current()
	if initialBudget == 0 {
		t.Fatal("test input did not acquire a CopyLease")
	}
	resource := &countCloser{}
	taskPermit := &trackedPermit{}
	taskPermit.active.Store(true)
	lifecycle, err := NewLifecycle(1)
	if err != nil {
		t.Fatal(err)
	}
	invocation, completion, err := lifecycle.BeginWithResources(context.Background(), testKey(10), inputLease, resource)
	if err != nil {
		t.Fatal(err)
	}
	invocation.Cancel(errors.New("await ended"))
	waitClosed(t, invocation.LogicalDone())
	if ledger.Current() != initialBudget || resource.count.Load() != 0 || lifecycle.Active() != 1 {
		t.Fatal("logical cancel released execution lease or admission early")
	}
	// A fake backend still uses its private input copy after the waiter has
	// canceled; the lease remains open until its actual Finish.
	if _, err := model.ParseURL(inputLease, "https://example.test/still-live", model.MITMHTTPS); err != nil {
		t.Fatalf("CopyLease closed before execution exit: %v", err)
	}
	if ledger.Current() <= initialBudget {
		t.Fatal("continued execution did not retain its CopyLease allocation")
	}
	if _, _, err := lifecycle.Begin(context.Background(), testKey(11)); !errors.Is(err, model.ErrorSentinel(model.ProcessingErrorResourceLimit)) {
		t.Fatalf("cancel returned execution admission: %v", err)
	}
	rejectedLease := &countCloser{}
	if _, _, err := lifecycle.BeginWithResources(context.Background(), testKey(111), rejectedLease); !errors.Is(err, model.ErrorSentinel(model.ProcessingErrorResourceLimit)) {
		t.Fatalf("resource-full Start did not fail: %v", err)
	}
	if rejectedLease.count.Load() != 0 {
		t.Fatal("failed Start took ownership of the caller's lease")
	}
	if !completion.Finish(model.Continue(), nil) {
		t.Fatal("Finish rejected")
	}
	waitClosed(t, invocation.ExecutionDone())
	if !taskPermit.active.Load() {
		t.Fatal("independent HTTP task permit released with Invocation")
	}
	if ledger.Current() != 0 || resource.count.Load() != 1 || lifecycle.Active() != 0 {
		t.Fatalf("execution release mismatch: budget=%d close=%d active=%d", ledger.Current(), resource.count.Load(), lifecycle.Active())
	}
	next, nextCompletion, err := lifecycle.Begin(context.Background(), testKey(12))
	if err != nil || next == nil || nextCompletion == nil {
		t.Fatalf("admission did not return after execution exit: %v", err)
	}
	_ = taskPermit.Close()
	if taskPermit.active.Load() {
		t.Fatal("independent task permit did not release when its task ended")
	}
	_ = lifecycle.Close()
	nextCompletion.Finish(model.Continue(), nil)
	if err := lifecycle.WaitClosed(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestResourcesAreRegisteredBeforeExecutionAndReleasedExactlyOnce(t *testing.T) {
	resources := []*countCloser{{}, {}}
	closers := make([]io.Closer, len(resources))
	for i := range resources {
		closers[i] = resources[i]
	}
	invocation, completion, err := NewInvocationWithResources(context.Background(), testKey(13), closers...)
	if err != nil {
		t.Fatal(err)
	}
	invocation.Cancel(errors.New("request no longer waits"))
	waitClosed(t, invocation.LogicalDone())
	for _, resource := range resources {
		if resource.count.Load() != 0 {
			t.Fatal("logical cancellation released a pre-registered execution resource")
		}
	}
	if !completion.Finish(model.Continue(), nil) {
		t.Fatal("Finish rejected")
	}
	waitClosed(t, invocation.ExecutionDone())
	for i, resource := range resources {
		if resource.count.Load() != 1 {
			t.Fatalf("resource %d released %d times", i, resource.count.Load())
		}
	}
}

func TestExecutionResourceCountIsBoundedAndFailureRetainsOwnership(t *testing.T) {
	tooMany := make([]io.Closer, maxExecutionResources+1)
	for i := range tooMany {
		tooMany[i] = &countCloser{}
	}
	if invocation, completion, err := NewInvocationWithResources(context.Background(), testKey(14), tooMany...); invocation != nil || completion != nil || !errors.Is(err, model.ErrorSentinel(model.ProcessingErrorResourceLimit)) {
		t.Fatalf("unbounded execution resource list accepted: invocation=%v completion=%v err=%v", invocation, completion, err)
	}
	for i, resource := range tooMany {
		if resource.(*countCloser).count.Load() != 0 {
			t.Fatalf("failed registration closed caller-owned resource %d", i)
		}
	}

	resources := make([]io.Closer, maxExecutionResources)
	for i := range resources {
		resources[i] = &countCloser{}
	}
	invocation, completion, err := NewInvocationWithResources(context.Background(), testKey(15), resources...)
	if err != nil {
		t.Fatal(err)
	}
	if !completion.Finish(model.Continue(), nil) {
		t.Fatal("Finish rejected")
	}
	waitClosed(t, invocation.ExecutionDone())
	for i, resource := range resources {
		if got := resource.(*countCloser).count.Load(); got != 1 {
			t.Fatalf("resource %d released %d times", i, got)
		}
	}
}

func TestFinishPublishesNormalResultOnlyAfterBlockingCleanup(t *testing.T) {
	closeErr := errors.New("resource close failed")
	resource := &gatedCloser{entered: make(chan struct{}), release: make(chan struct{}), err: closeErr}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(resource.release) }) }
	defer release()
	lifecycle, err := NewLifecycle(1)
	if err != nil {
		t.Fatal(err)
	}
	invocation, completion, err := lifecycle.BeginWithResources(context.Background(), testKey(16), resource)
	if err != nil {
		t.Fatal(err)
	}
	finished := make(chan bool, 1)
	finishExited := make(chan struct{})
	go func() {
		defer close(finishExited)
		finished <- completion.Finish(model.Continue(), nil)
	}()
	waitClosed(t, resource.entered)

	awaitCtx := newObservedContext()
	type awaitResult struct {
		result model.DoneResult
		err    error
	}
	awaited := make(chan awaitResult, 1)
	awaitExited := make(chan struct{})
	go func() {
		defer close(awaitExited)
		result, err := invocation.Await(awaitCtx)
		awaited <- awaitResult{result: result, err: err}
	}()
	t.Cleanup(func() {
		release()
		waitClosed(t, finishExited)
		waitClosed(t, awaitExited)
	})
	waitClosed(t, awaitCtx.observed)
	if !isOpen(invocation.LogicalDone()) || !isOpen(invocation.ExecutionDone()) || lifecycle.Active() != 1 {
		t.Fatal("Finish published completion or released admission while a resource Closer was blocked")
	}
	select {
	case <-awaited:
		t.Fatal("Await returned a normal result before synchronous resource cleanup completed")
	default:
	}

	release()
	if !<-finished {
		t.Fatal("first Finish was rejected")
	}
	got := <-awaited
	if got.result.Kind() != model.ResultInvalid || !errors.Is(got.err, closeErr) {
		t.Fatalf("cleanup failure was not returned as the execution result: kind=%d err=%v", got.result.Kind(), got.err)
	}
	if resource.count.Load() != 1 || !errors.Is(invocation.CleanupError(), closeErr) {
		t.Fatalf("cleanup failure/count mismatch: closes=%d cleanup=%v", resource.count.Load(), invocation.CleanupError())
	}
	waitClosed(t, invocation.ExecutionDone())
	if lifecycle.Active() != 0 {
		t.Fatal("execution admission remained occupied after cleanup completed")
	}
	_ = lifecycle.Close()
	if err := lifecycle.WaitClosed(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestCancelAndWaitClosedRemainIndependentOfBlockingCleanup(t *testing.T) {
	cancelCause := errors.New("owner canceled")
	closeErr := errors.New("late resource close failure")
	resource := &gatedCloser{entered: make(chan struct{}), release: make(chan struct{}), err: closeErr}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(resource.release) }) }
	defer release()
	lifecycle, err := NewLifecycle(1)
	if err != nil {
		t.Fatal(err)
	}
	invocation, completion, err := lifecycle.BeginWithResources(context.Background(), testKey(17), resource)
	if err != nil {
		t.Fatal(err)
	}
	finished := make(chan bool, 1)
	finishExited := make(chan struct{})
	go func() {
		defer close(finishExited)
		finished <- completion.Finish(model.Continue(), nil)
	}()
	waitClosed(t, resource.entered)

	awaitCtx := newObservedContext()
	type awaitResult struct {
		result model.DoneResult
		err    error
	}
	awaited := make(chan awaitResult, 1)
	awaitExited := make(chan struct{})
	go func() {
		defer close(awaitExited)
		result, err := invocation.Await(awaitCtx)
		awaited <- awaitResult{result: result, err: err}
	}()
	t.Cleanup(func() {
		release()
		waitClosed(t, finishExited)
		waitClosed(t, awaitExited)
	})
	waitClosed(t, awaitCtx.observed)
	invocation.Cancel(cancelCause)
	got := <-awaited
	if got.result.Kind() != model.ResultInvalid || !errors.Is(got.err, cancelCause) {
		t.Fatalf("Cancel did not determine the logical result during cleanup: kind=%d err=%v", got.result.Kind(), got.err)
	}
	if isOpen(invocation.ExecutionDone()) == false || lifecycle.Active() != 1 {
		t.Fatal("logical cancellation closed ExecutionDone or returned execution admission early")
	}
	_ = lifecycle.Close()
	waitCtx, cancelWait := context.WithTimeout(context.Background(), 50*time.Millisecond)
	waitErr := lifecycle.WaitClosed(waitCtx)
	cancelWait()
	var processing *model.ProcessingError
	if !errors.As(waitErr, &processing) || processing.Kind != model.ProcessingErrorTimeout {
		t.Fatalf("WaitClosed did not honor its context while cleanup was blocked: %v", waitErr)
	}
	if isOpen(invocation.ExecutionDone()) == false || resource.count.Load() != 1 {
		t.Fatal("blocked cleanup was incorrectly treated as completed")
	}

	release()
	if !<-finished {
		t.Fatal("first Finish was rejected")
	}
	waitClosed(t, invocation.ExecutionDone())
	if resource.count.Load() != 1 || !errors.Is(invocation.CleanupError(), closeErr) {
		t.Fatalf("late cleanup failure was swallowed or resource was double-closed: closes=%d cleanup=%v", resource.count.Load(), invocation.CleanupError())
	}
	if err := lifecycle.WaitClosed(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestTwoFinishCallsRaceAndReleaseLosingPayload(t *testing.T) {
	for round := 0; round < 30; round++ {
		ledger, err := model.NewLedger(-1, nil)
		if err != nil {
			t.Fatal(err)
		}
		first, err := model.Reject("first", ledger)
		if err != nil {
			t.Fatal(err)
		}
		second, err := model.Reject("second", ledger)
		if err != nil {
			t.Fatal(err)
		}
		invocation, completion := NewInvocation(context.Background(), testKey(200+round))
		start := make(chan struct{})
		accepted := make(chan bool, 2)
		var workers sync.WaitGroup
		workers.Add(2)
		go func() { defer workers.Done(); <-start; accepted <- completion.Finish(first, nil) }()
		go func() { defer workers.Done(); <-start; accepted <- completion.Finish(second, nil) }()
		close(start)
		workers.Wait()
		one, two := <-accepted, <-accepted
		if one == two {
			t.Fatalf("round %d expected exactly one Finish winner", round)
		}
		result, err := invocation.Await(context.Background())
		if err != nil || result.Kind() != model.ResultReject {
			t.Fatalf("round %d lost winner result: kind=%d err=%v", round, result.Kind(), err)
		}
		if ledger.Current() == 0 {
			t.Fatalf("round %d released delivered output before owner decision", round)
		}
		if err := result.Release(); err != nil {
			t.Fatal(err)
		}
		waitClosed(t, invocation.ExecutionDone())
		if ledger.Current() != 0 {
			t.Fatalf("round %d leaked winner/loser result bytes: %d", round, ledger.Current())
		}
	}
}

func TestCloseDoesNotWaitAndWaitClosedHonorsContext(t *testing.T) {
	gate := make(chan struct{})
	var gateOnce sync.Once
	releaseGate := func() { gateOnce.Do(func() { close(gate) }) }
	finished := make(chan struct{})
	workerStarted := make(chan struct{})
	resource := &countCloser{}
	processor := newFakeProcessor(t, 1, func(_ *Invocation, completion *Completion, _ model.Input) {
		go func() {
			defer close(finished)
			<-gate
			completion.Finish(model.Continue(), nil)
		}()
		close(workerStarted)
	})
	t.Cleanup(func() {
		releaseGate()
		select {
		case <-workerStarted:
			waitClosed(t, finished)
		default:
		}
	})
	input, _, _, cleanup := testInput(t, "close-does-not-wait")
	defer cleanup()
	invocation, err := processor.Start(context.Background(), input, resource)
	if err != nil {
		t.Fatal(err)
	}
	closed := make(chan struct{})
	go func() { _ = processor.Close(); close(closed) }()
	waitClosed(t, closed)
	if _, err := invocation.Await(context.Background()); err == nil {
		t.Fatal("Close did not cancel invocation")
	}
	waitContext, cancel := context.WithTimeout(context.Background(), 15*time.Millisecond)
	err = processor.WaitClosed(waitContext)
	cancel()
	var processing *model.ProcessingError
	if !errors.As(err, &processing) || processing.Kind != model.ProcessingErrorTimeout {
		t.Fatalf("WaitClosed ignored its deadline: %#v", err)
	}
	if isOpen(invocation.ExecutionDone()) == false || resource.count.Load() != 0 {
		t.Fatal("Processor.Close released a pre-registered resource before backend Finish")
	}
	releaseGate()
	waitClosed(t, finished)
	waitClosed(t, invocation.ExecutionDone())
	if resource.count.Load() != 1 {
		t.Fatalf("resource close count after Finish = %d, want 1", resource.count.Load())
	}
	if err := processor.WaitClosed(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestWaitClosedRequiresClose(t *testing.T) {
	processor := newFakeProcessor(t, 1, nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := processor.WaitClosed(ctx)
	if err == nil || !errors.Is(err, model.ErrorSentinel(model.ProcessingErrorInvalidInput)) {
		t.Fatalf("WaitClosed before Close was ambiguous: %v", err)
	}
}

func TestFinishCancelCloseCompetitionRepeated(t *testing.T) {
	for round := 0; round < 40; round++ {
		parent, cancelParent := context.WithCancelCause(context.Background())
		invocation, completion := NewInvocation(parent, testKey(100+round))
		waitCtx, cancelWait := context.WithCancel(context.Background())
		start := make(chan struct{})
		var workers sync.WaitGroup
		workers.Add(5)
		go func() { defer workers.Done(); <-start; completion.Finish(model.Continue(), nil) }()
		go func() { defer workers.Done(); <-start; invocation.Cancel(errors.New("processor canceled")) }()
		go func() { defer workers.Done(); <-start; _ = invocation.Close() }()
		go func() { defer workers.Done(); <-start; cancelParent(context.DeadlineExceeded) }()
		awaited := make(chan error, 1)
		go func() { defer workers.Done(); <-start; _, err := invocation.Await(waitCtx); awaited <- err }()
		close(start)
		cancelWait()
		workers.Wait()
		if err := <-awaited; err == nil && invocation.resultKindForTest() != model.ResultContinue {
			t.Fatalf("round %d returned no error without a normal result", round)
		}
		waitClosed(t, invocation.ExecutionDone())
	}
}

func (i *Invocation) resultKindForTest() model.ResultKind {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.result.Kind()
}

func TestStartCloseLinearizationRepeated(t *testing.T) {
	for round := 0; round < 40; round++ {
		processor := newFakeProcessor(t, 1, nil)
		input, _, _, cleanup := testInput(t, fmt.Sprintf("start-close-%d", round))
		resource := &countCloser{}
		start := make(chan struct{})
		var invocation *Invocation
		var startErr error
		started := make(chan struct{})
		go func() {
			<-start
			invocation, startErr = processor.Start(context.Background(), input, resource)
			close(started)
		}()
		closed := make(chan struct{})
		go func() { <-start; _ = processor.Close(); close(closed) }()
		close(start)
		waitClosed(t, started)
		waitClosed(t, closed)
		if startErr == nil {
			if invocation == nil {
				t.Fatal("Start returned success with nil Invocation")
			}
			completion := processor.completion(invocation)
			if completion == nil || !completion.Finish(model.DoneResult{}, nil) {
				cleanup()
				t.Fatal("successful racing Start lost its Completion")
			}
			waitClosed(t, invocation.ExecutionDone())
			if resource.count.Load() != 1 {
				cleanup()
				t.Fatalf("successful Start did not transfer its resource exactly once: %d", resource.count.Load())
			}
		} else if invocation != nil {
			cleanup()
			t.Fatal("failed Start returned a non-nil Invocation")
		}
		if startErr != nil && !errors.Is(startErr, model.ErrorSentinel(model.ProcessingErrorClosed)) {
			cleanup()
			t.Fatalf("Start/Close returned unexpected failure: %v", startErr)
		}
		if startErr != nil {
			if resource.count.Load() != 0 {
				cleanup()
				t.Fatal("failed racing Start closed caller-owned resource")
			}
			_ = resource.Close()
			if resource.count.Load() != 1 {
				cleanup()
				t.Fatal("caller could not release resource after failed racing Start")
			}
		}
		if err := processor.WaitClosed(context.Background()); err != nil {
			cleanup()
			t.Fatal(err)
		}
		cleanup()
	}
}
