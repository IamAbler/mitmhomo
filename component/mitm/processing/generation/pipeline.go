package generation

import (
	"context"
	"errors"
	"io"

	"github.com/metacubex/mihomo/component/mitm/processing/model"
	"github.com/metacubex/mihomo/component/mitm/processing/pipeline"
	"github.com/metacubex/mihomo/component/mitm/processing/processor"
)

// Plan owns a fixed processor configuration. The caller transfers processor
// ownership even on validation failure. No runtime/backend initialization is
// deferred until after publication by this constructor.
type Plan struct {
	Generation *Generation
	entries    []pipeline.Entry
}

type executionPin struct{ *Lease }

func (p *executionPin) FinalizeExecution() { _ = p.Close() }

// Processor.Close only requests shutdown. Generation completion also requires
// explicit drain, including backend-owned workers beyond invocation admission.
type planResources struct{ runner *pipeline.Runner }

func (p planResources) Close() error {
	return errors.Join(p.runner.Close(), p.runner.WaitClosed(context.Background()))
}

func retiredProcessingError(phase model.Phase, cause error) error {
	return model.NewProcessingError(model.ProcessingErrorGenerationRetired, model.ProcessingOriginConnection, phase, "", "", errors.Join(model.ErrGenerationRetired, cause))
}

// BuildError retains exclusive ownership of ALL partial resources. Returning
// it never calls a potentially blocking Close. The receiver must arrange
// cleanup of Pending (or attach a pre-reserved cleanup owner), then WaitClosed.
type BuildError struct {
	Cause   error
	Pending *Generation
}

func (e *BuildError) Error() string { return e.Cause.Error() }
func (e *BuildError) Unwrap() error { return e.Cause }

type partialProcessors struct{ processors []processor.Processor }

func (p partialProcessors) Close() error {
	var err error
	for _, backend := range p.processors {
		err = errors.Join(err, backend.Close())
	}
	for _, backend := range p.processors {
		err = errors.Join(err, backend.WaitClosed(context.Background()))
	}
	return err
}
func FailedBuild(cause error, entries []pipeline.Entry, resources ...io.Closer) *BuildError {
	partial := partialProcessors{}
	for _, entry := range entries {
		if entry.Processor != nil {
			partial.processors = append(partial.processors, entry.Processor)
		}
	}
	owned := append(append([]io.Closer(nil), resources...), partial)
	return &BuildError{Cause: cause, Pending: New(owned...)}
}

func NewPlan(entries []pipeline.Entry, resources ...io.Closer) (*Plan, error) {
	copied := append([]pipeline.Entry(nil), entries...)
	runner, err := pipeline.NewRunner(copied, pipeline.Options{})
	if err != nil {
		return nil, FailedBuild(err, copied, resources...)
	}
	resources = append(append([]io.Closer(nil), resources...), planResources{runner})
	g := New(resources...)
	for _, entry := range copied {
		if err = entry.Processor.Describe().Validate(); err != nil {
			return nil, &BuildError{Cause: err, Pending: g}
		}
	}
	return &Plan{Generation: g, entries: copied}, nil
}

// Runner is scoped to an open connection/transaction capability. Its execution
// pin is registered by M4.7 before Processor.Start and transferred to Invocation
// on success. Retiring generations continue admission through the parent.
// BoundRunner exposes execution, never ownership of the Plan's processors.
type BoundRunner struct {
	entries []pipeline.Entry
	parent  *Lease
}

func (r *BoundRunner) GenerationID() model.GenerationID { return r.parent.ID() }

func (r *BoundRunner) Run(ctx context.Context, tx *model.Transaction, phase model.Phase) (pipeline.Report, error) {
	if tx == nil {
		return pipeline.Report{}, model.ErrInvalid
	}
	if tx.GenerationID() != r.parent.ID() {
		return pipeline.Report{}, retiredProcessingError(phase, ErrUnavailable)
	}
	lease, err := r.parent.Transaction()
	if err != nil {
		return pipeline.Report{}, retiredProcessingError(phase, err)
	}
	defer lease.Close()
	runner, err := pipeline.NewRunner(r.entries, pipeline.Options{AcquireGeneration: func(ctx context.Context, id model.GenerationID) (io.Closer, error) {
		if err := ctx.Err(); err != nil {
			return nil, context.Cause(ctx)
		}
		if id != lease.ID() {
			return nil, ErrUnavailable
		}
		lease, err := lease.Execution()
		if err != nil {
			return nil, errors.Join(model.ErrGenerationRetired, err)
		}
		return &executionPin{lease}, nil
	}})
	if err != nil {
		return pipeline.Report{}, err
	}
	return runner.Run(ctx, tx, phase)
}

func (p *Plan) Runner(parent *Lease) (*BoundRunner, error) {
	if parent == nil || parent.g != p.Generation {
		return nil, ErrUnavailable
	}
	return &BoundRunner{entries: p.entries, parent: parent}, nil
}
