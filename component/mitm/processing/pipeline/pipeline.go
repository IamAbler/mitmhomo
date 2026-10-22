// Package pipeline runs ordered, engine-independent HTTP processors over
// immutable model.Input snapshots. It has no protocol, VM, CGO, or IPC
// dependencies; only Transaction's owner methods can publish mutations.
package pipeline

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/metacubex/mihomo/component/mitm/processing/model"
	"github.com/metacubex/mihomo/component/mitm/processing/processor"
)

type Class uint8

const (
	InternalHook Class = iota + 1
	Script
	Rewrite
)

type ErrorProfile uint8

const (
	StrictProfile ErrorProfile = iota
	LegacyProfile
)

// Metadata contains only immutable HTTP metadata. It deliberately excludes
// BodyView bytes so selection cannot cause Body reads or retain network data.
type Metadata struct {
	Key         model.InvocationKey
	Connection  model.ConnectionView
	Route       model.RouteView
	Origin      model.ResponseOrigin
	Request     model.RequestHead
	Response    model.ResponseHead
	HasResponse bool
	Body        model.BodyInfo
}

type Matcher func(Metadata) bool

// Entry configures one independently selected Processor. Lower numeric
// Priority runs first within InternalHook, Script, or Rewrite. A Script group
// executes only its first matching entry; Rewrite entries are incremental.
//
// FailOpenSafe is an explicit proof hook for legacy fallback or AllowFailOpen.
// It is evaluated only after execution has exited (or Start failed before
// ownership transfer). Return false when a failure followed irreversible I/O.
// Without this hook the Runner fails closed.
type Entry struct {
	Class         Class
	Priority      int
	Processor     processor.Processor
	Match         Matcher
	Profile       ErrorProfile
	AllowFailOpen bool
	FailOpenSafe  func(error) bool
}

type GenerationLease func(context.Context, model.GenerationID) (io.Closer, error)
type ExecutionResources func(context.Context, processor.Descriptor, model.InvocationKey) ([]io.Closer, error)

type Options struct {
	AcquireGeneration GenerationLease
	AcquireExecution  ExecutionResources
}

type Runner struct {
	entries []Entry
	options Options
}

type Outcome uint8

const (
	ContinueUpstream Outcome = iota + 1
	ResponseComplete
	SyntheticReady
	Rejected
	Aborted
	SkippedSyntheticResponse
)

type Recovery struct {
	ProcessorID string
	Kind        model.ProcessingErrorKind
	Err         error
}

type Report struct {
	Phase       model.Phase
	Outcome     Outcome
	LastResult  model.ResultKind
	ProcessorID string
	Revision    model.Revision
	Stopped     bool
	Recoveries  []Recovery
}

var invocationSequence atomic.Uint64

var errExecutionResourceCleanup = errors.New("execution resource cleanup failed")

func NewRunner(entries []Entry, options Options) (*Runner, error) {
	copyEntries := append([]Entry(nil), entries...)
	for _, entry := range copyEntries {
		// Legacy fallback is enabled only when the integration supplies a
		// per-entry guard that can reject fallback after irreversible I/O.
		if entry.Processor == nil || entry.Class < InternalHook || entry.Class > Rewrite || entry.Profile > LegacyProfile || entry.Profile == LegacyProfile && entry.FailOpenSafe == nil {
			return nil, model.ErrInvalid
		}
	}
	sort.SliceStable(copyEntries, func(i, j int) bool {
		if copyEntries[i].Class != copyEntries[j].Class {
			return copyEntries[i].Class < copyEntries[j].Class
		}
		return copyEntries[i].Priority < copyEntries[j].Priority
	})
	return &Runner{entries: copyEntries, options: options}, nil
}

// Run executes exactly one phase. It holds a Transaction phase permit for the
// complete run, so a second Runner cannot overlap processors for that
// Transaction. A request that reaches the end claims the single main upstream
// transition but performs no network I/O.
func (r *Runner) Run(ctx context.Context, tx *model.Transaction, phase model.Phase) (Report, error) {
	report := Report{Phase: phase}
	if r == nil || tx == nil || phase != model.RequestPhase && phase != model.ResponsePhase {
		return report, model.NewProcessingError(model.ProcessingErrorInvalidInput, model.ProcessingOriginProtocol, phase, "", "", model.ErrInvalid)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if phase == model.ResponsePhase && tx.Outcome() == model.ExchangeSynthetic {
		report.Outcome = SkippedSyntheticResponse
		report.Revision = tx.Revision()
		return report, nil
	}
	permit, skipped, err := tx.AcquirePipelinePhase(ctx, phase)
	if err != nil {
		failure := classify(err, phase, "", "", model.ProcessingOriginRequest)
		if kind := processingKind(failure); kind == model.ProcessingErrorCanceled || kind == model.ProcessingErrorTimeout {
			tx.Terminate(failure)
		}
		return report, failure
	}
	if skipped {
		report.Outcome = SkippedSyntheticResponse
		report.Revision = tx.Revision()
		return report, nil
	}
	defer permit.Release()
	// Observe cancellation and an existing BodyBroker fault without consuming
	// the real source. FullBuffered still waits until after metadata selection.
	if err := tx.PrepareBody(model.None, 0); err != nil {
		return r.terminate(tx, report, classifyBody(err, phase, "", ""))
	}

	for _, class := range []Class{InternalHook, Script, Rewrite} {
		matchedScript := false
		for _, entry := range r.entries {
			if entry.Class != class {
				continue
			}
			invocationID := nextInvocationID()
			descriptor := entry.Processor.Describe()
			if err := descriptor.Validate(); err != nil {
				return r.terminate(tx, report, classify(err, phase, descriptor.ID, invocationID, model.ProcessingOriginProcessor))
			}
			if !supportsPhase(descriptor, phase) {
				continue
			}
			input, inputLease, err := tx.Snapshot(invocationID)
			if err != nil {
				return r.terminate(tx, report, classify(err, phase, descriptor.ID, invocationID, model.ProcessingOriginRequest))
			}
			matched := entry.Match == nil || entry.Match(metadata(input))
			if !matched {
				_ = inputLease.Close()
				continue
			}
			if class == Script {
				matchedScript = true
			}

			result, input, inputLease, started, executionDone, err := r.invoke(ctx, tx, entry, descriptor, input, inputLease)
			if err != nil {
				if inputLease != nil {
					_ = inputLease.Close()
				}
				if r.canFailOpen(entry, err, started, executionDone) {
					report.Recoveries = append(report.Recoveries, Recovery{ProcessorID: descriptor.ID, Kind: processingKind(err), Err: err})
					if class == Script && matchedScript {
						break
					}
					continue
				}
				return r.terminate(tx, report, err)
			}
			// Invocation.Finish owns and releases Input CopyLease at the real
			// execution boundary. It is non-nil here only for a local synchronous
			// setup path that has not transferred ownership.
			if inputLease != nil {
				_ = inputLease.Close()
			}
			if !result.Valid() || result.ValidateForInput(input) != nil {
				_ = result.Release()
				failure := model.NewProcessingError(model.ProcessingErrorInvalidOutput, model.ProcessingOriginProcessor, phase, descriptor.ID, input.Key().Invocation, model.ErrInvalid)
				if r.canFailOpen(entry, failure, true, true) {
					report.Recoveries = append(report.Recoveries, Recovery{ProcessorID: descriptor.ID, Kind: model.ProcessingErrorInvalidOutput, Err: failure})
					if class == Script && matchedScript {
						break
					}
					continue
				}
				return r.terminate(tx, report, failure)
			}
			kind := result.Kind()
			if _, err := tx.Commit(input, result); err != nil {
				_ = result.Release()
				failure := classify(err, phase, descriptor.ID, input.Key().Invocation, model.ProcessingOriginProtocol)
				// A stale/foreign key is not a recoverable Processor entry error.
				return r.terminate(tx, report, failure)
			}
			_ = result.Release()
			report.LastResult = kind
			report.ProcessorID = descriptor.ID
			report.Revision = tx.Revision()
			switch kind {
			case model.ResultRespond:
				report.Outcome = SyntheticReady
				return report, nil
			case model.ResultReject:
				report.Outcome = Rejected
				tx.Terminate(errors.New("processing rejected"))
				return report, nil
			case model.ResultAbort:
				report.Outcome = Aborted
				tx.Terminate(errors.New("processing aborted"))
				return report, nil
			case model.ResultStopPhase:
				report.Stopped = true
				break
			}
			if kind == model.ResultStopPhase {
				break
			}
			if class == Script && matchedScript {
				break
			}
		}
		if report.Stopped {
			break
		}
	}

	if phase == model.RequestPhase {
		input, lease, err := tx.Snapshot(nextInvocationID())
		if err != nil {
			return r.terminate(tx, report, classify(err, phase, "", "", model.ProcessingOriginRequest))
		}
		revision, claimErr := tx.ClaimMainUpstream(input)
		_ = lease.Close()
		if claimErr != nil {
			return r.terminate(tx, report, classify(claimErr, phase, "", input.Key().Invocation, model.ProcessingOriginProtocol))
		}
		report.Outcome = ContinueUpstream
		report.Revision = revision
	} else {
		report.Outcome = ResponseComplete
		report.Revision = tx.Revision()
	}
	return report, nil
}

func (r *Runner) invoke(ctx context.Context, tx *model.Transaction, entry Entry, descriptor processor.Descriptor, input model.Input, inputLease *model.CopyLease) (model.DoneResult, model.Input, *model.CopyLease, bool, bool, error) {
	key := input.Key()
	if ctx.Err() != nil {
		_ = inputLease.Close()
		return model.DoneResult{}, input, nil, false, true, classify(context.Cause(ctx), key.Phase, descriptor.ID, key.Invocation, model.ProcessingOriginRequest)
	}
	if tx.Context().Err() != nil {
		_ = inputLease.Close()
		return model.DoneResult{}, input, nil, false, true, classify(tx.CancellationCause(), key.Phase, descriptor.ID, key.Invocation, model.ProcessingOriginRequest)
	}
	requirements := descriptor.RequestNeeds
	if key.Phase == model.ResponsePhase {
		requirements = descriptor.ResponseNeeds
	}
	if err := tx.PrepareBody(requirements.Body, requirements.MaxBodyBytes); err != nil {
		_ = inputLease.Close()
		return model.DoneResult{}, input, nil, false, true, classifyBody(err, key.Phase, descriptor.ID, key.Invocation)
	}
	if requirements.Body == model.FullBuffered {
		_ = inputLease.Close()
		var err error
		input, inputLease, err = tx.Snapshot(key.Invocation)
		if err != nil {
			return model.DoneResult{}, input, nil, false, true, classifyBody(err, key.Phase, descriptor.ID, key.Invocation)
		}
		key = input.Key()
	}
	if ctx.Err() != nil || tx.Context().Err() != nil {
		_ = inputLease.Close()
		cause := context.Cause(ctx)
		if tx.Context().Err() != nil {
			cause = tx.CancellationCause()
		}
		return model.DoneResult{}, input, nil, false, true, classify(cause, key.Phase, descriptor.ID, key.Invocation, model.ProcessingOriginRequest)
	}

	resources := []io.Closer{&onceCloser{inner: inputLease}}
	prepareResource := func(resource io.Closer) {
		if resource != nil {
			resources = append(resources, &onceCloser{inner: resource})
		}
	}
	if r.options.AcquireGeneration != nil {
		generation, err := r.options.AcquireGeneration(ctx, key.Generation)
		if err != nil {
			cleanupErr := closeResources(resources)
			return model.DoneResult{}, input, nil, false, cleanupErr == nil, classify(joinCleanup(err, cleanupErr), key.Phase, descriptor.ID, key.Invocation, model.ProcessingOriginConnection)
		}
		if generation == nil {
			cleanupErr := closeResources(resources)
			cause := joinCleanup(model.ErrInvalid, cleanupErr)
			return model.DoneResult{}, input, nil, false, cleanupErr == nil, model.NewProcessingError(model.ProcessingErrorInvalidInput, model.ProcessingOriginConnection, key.Phase, descriptor.ID, key.Invocation, cause)
		}
		prepareResource(generation)
	}
	if r.options.AcquireExecution != nil {
		extra, err := r.options.AcquireExecution(ctx, descriptor, key)
		for _, resource := range extra {
			prepareResource(resource)
		}
		if err != nil {
			cleanupErr := closeResources(resources)
			return model.DoneResult{}, input, nil, false, cleanupErr == nil, classify(joinCleanup(err, cleanupErr), key.Phase, descriptor.ID, key.Invocation, model.ProcessingOriginProcessor)
		}
	}
	if ctx.Err() != nil || tx.Context().Err() != nil {
		cleanupErr := closeResources(resources)
		cause := context.Cause(ctx)
		if tx.Context().Err() != nil {
			cause = tx.CancellationCause()
		}
		return model.DoneResult{}, input, nil, false, cleanupErr == nil, classify(joinCleanup(cause, cleanupErr), key.Phase, descriptor.ID, key.Invocation, model.ProcessingOriginRequest)
	}
	// Invocation releases resources in slice order. Pass the reverse of
	// acquisition order so task/admission resources close first, followed by
	// the generation pin and finally the Input CopyLease.
	closers := make([]io.Closer, len(resources))
	for i := range resources {
		closers[len(resources)-1-i] = resources[i]
	}
	invocation, startErr := entry.Processor.Start(tx.Context(), input, closers...)
	if startErr != nil {
		cleanupErr := closeResources(resources)
		if invocation != nil {
			invocation.Cancel(startErr)
		}
		return model.DoneResult{}, input, nil, true, cleanupErr == nil && (invocation == nil || channelClosed(invocation.ExecutionDone())), classify(joinCleanup(startErr, cleanupErr), key.Phase, descriptor.ID, key.Invocation, model.ProcessingOriginProcessor)
	}
	if invocation == nil {
		cleanupErr := closeResources(resources)
		return model.DoneResult{}, input, nil, true, cleanupErr == nil, model.NewProcessingError(model.ProcessingErrorExecution, model.ProcessingOriginProcessor, key.Phase, descriptor.ID, key.Invocation, joinCleanup(model.ErrInvalid, cleanupErr))
	}
	if invocation.Key() != key {
		invocation.Cancel(model.ErrInvalid)
		lateResult, _ := invocation.Await(context.Background())
		_ = lateResult.Release()
		return model.DoneResult{}, input, nil, true, channelClosed(invocation.ExecutionDone()), model.NewProcessingError(model.ProcessingErrorInvalidOutput, model.ProcessingOriginProcessor, key.Phase, descriptor.ID, key.Invocation, model.ErrInvalid)
	}

	awaitCtx := ctx
	cancel := func() {}
	if requirements.TotalTimeout > 0 {
		awaitCtx, cancel = context.WithTimeout(ctx, requirements.TotalTimeout)
	}
	result, awaitErr := invocation.Await(awaitCtx)
	cancel()
	if awaitErr != nil {
		_ = result.Release()
		cleanupErr := invocation.CleanupError()
		return model.DoneResult{}, input, nil, true, channelClosed(invocation.ExecutionDone()), classify(joinCleanup(awaitErr, cleanupErr), key.Phase, descriptor.ID, key.Invocation, model.ProcessingOriginProcessor)
	}
	if ctx.Err() != nil || tx.Context().Err() != nil {
		_ = result.Release()
		cause := context.Cause(ctx)
		if tx.Context().Err() != nil {
			cause = tx.CancellationCause()
		}
		return model.DoneResult{}, input, nil, true, channelClosed(invocation.ExecutionDone()), classify(cause, key.Phase, descriptor.ID, key.Invocation, model.ProcessingOriginRequest)
	}
	return result, input, nil, true, channelClosed(invocation.ExecutionDone()), nil
}

func (r *Runner) canFailOpen(entry Entry, err error, started, executionDone bool) bool {
	if (!entry.AllowFailOpen && entry.Profile != LegacyProfile) || !executionDone || errors.Is(err, errExecutionResourceCleanup) {
		return false
	}
	kind := processingKind(err)
	if kind != model.ProcessingErrorCompile && kind != model.ProcessingErrorExecution && kind != model.ProcessingErrorInvalidOutput && kind != model.ProcessingErrorResourceLimit && kind != model.ProcessingErrorTimeout {
		return false
	}
	if entry.FailOpenSafe == nil {
		return !started
	}
	return entry.FailOpenSafe(err)
}

func joinCleanup(cause, cleanupErr error) error {
	if cleanupErr == nil {
		return cause
	}
	return errors.Join(cause, errExecutionResourceCleanup, cleanupErr)
}

func (r *Runner) terminate(tx *model.Transaction, report Report, err error) (Report, error) {
	if err != nil {
		tx.Terminate(err)
	}
	report.Revision = tx.Revision()
	return report, err
}

func supportsPhase(descriptor processor.Descriptor, phase model.Phase) bool {
	if phase == model.RequestPhase {
		return descriptor.Request
	}
	return descriptor.Response
}

func metadata(input model.Input) Metadata {
	response, hasResponse := input.Response()
	return Metadata{Key: input.Key(), Connection: input.Connection(), Route: input.Route(), Origin: input.Origin(), Request: input.Request(), Response: response, HasResponse: hasResponse, Body: input.Body().Info()}
}

func nextInvocationID() model.InvocationID {
	return model.InvocationID(fmt.Sprintf("pipeline-%d", invocationSequence.Add(1)))
}

func channelClosed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

type onceCloser struct {
	sync.Once
	inner io.Closer
	err   error
}

func (c *onceCloser) Close() error {
	if c == nil {
		return nil
	}
	c.Do(func() {
		if c.inner != nil {
			c.err = c.inner.Close()
		}
	})
	return c.err
}

func closeResources(resources []io.Closer) error {
	var result error
	for i := len(resources) - 1; i >= 0; i-- {
		if resources[i] != nil {
			result = errors.Join(result, resources[i].Close())
		}
	}
	return result
}

func classifyBody(err error, phase model.Phase, processorID string, invocationID model.InvocationID) error {
	kind := model.ProcessingErrorBodyRead
	if errors.Is(err, model.ErrResourceLimit) || errors.Is(err, model.ErrBodyLimit) {
		kind = model.ProcessingErrorResourceLimit
	} else if errors.Is(err, context.DeadlineExceeded) {
		kind = model.ProcessingErrorTimeout
	} else if errors.Is(err, context.Canceled) {
		kind = model.ProcessingErrorCanceled
	} else if errors.Is(err, model.ErrBodyClaimed) || errors.Is(err, model.ErrReleased) || errors.Is(err, model.ErrInvalid) || errors.Is(err, model.ErrClosed) {
		kind = model.ProcessingErrorProtocol
	}
	return model.NewProcessingError(kind, model.ProcessingOriginRequest, phase, processorID, invocationID, err)
}

func classify(err error, phase model.Phase, processorID string, invocationID model.InvocationID, origin model.ProcessingErrorOrigin) error {
	if err == nil {
		return nil
	}
	var existing *model.ProcessingError
	if errors.As(err, &existing) {
		if errors.Is(err, errExecutionResourceCleanup) {
			return model.NewProcessingError(existing.Kind, existing.Origin, existing.Phase, existing.ProcessorID, existing.InvocationID, err)
		}
		return existing
	}
	kind := model.ProcessingErrorExecution
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		kind = model.ProcessingErrorTimeout
	case errors.Is(err, context.Canceled):
		kind = model.ProcessingErrorCanceled
	case errors.Is(err, model.ErrResourceLimit), errors.Is(err, model.ErrBodyLimit):
		kind = model.ProcessingErrorResourceLimit
	case errors.Is(err, model.ErrClosed):
		kind = model.ProcessingErrorClosed
	case errors.Is(err, model.ErrStaleRevision), errors.Is(err, model.ErrInvalid):
		kind = model.ProcessingErrorProtocol
	}
	return model.NewProcessingError(kind, origin, phase, processorID, invocationID, err)
}

func processingKind(err error) model.ProcessingErrorKind {
	var processingError *model.ProcessingError
	if errors.As(err, &processingError) {
		return processingError.Kind
	}
	return classify(err, model.PhaseInvalid, "", "", model.ProcessingOriginProcessor).(*model.ProcessingError).Kind
}

// Close requests cancellation of every configured Processor. It is idempotent
// by the Processor contract and does not wait for active execution to drain.
func (r *Runner) Close() error {
	if r == nil {
		return nil
	}
	var result error
	for _, entry := range r.entries {
		result = errors.Join(result, entry.Processor.Close())
	}
	return result
}

// WaitClosed uses each Processor's lifecycle drain rather than treating one
// invocation's ExecutionDone as proof the Processor has fully drained.
func (r *Runner) WaitClosed(ctx context.Context) error {
	if r == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	var result error
	for _, entry := range r.entries {
		result = errors.Join(result, entry.Processor.WaitClosed(ctx))
	}
	return result
}
