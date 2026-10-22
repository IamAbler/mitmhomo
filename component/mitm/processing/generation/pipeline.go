package generation

import (
	"context"
	"errors"
	"io"

	"github.com/metacubex/mihomo/component/mitm/processing/model"
	"github.com/metacubex/mihomo/component/mitm/processing/pipeline"
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

func NewPlan(entries []pipeline.Entry, resources ...io.Closer) (*Plan, error) {
	copied := append([]pipeline.Entry(nil), entries...)
	runner, err := pipeline.NewRunner(copied, pipeline.Options{})
	if err != nil {
		for _, e := range copied {
			if e.Processor != nil {
				err = errors.Join(err, e.Processor.Close())
			}
		}
		g := New(resources...)
		err = errors.Join(err, g.Close())
		return nil, err
	}
	resources = append(append([]io.Closer(nil), resources...), runner)
	g := New(resources...)
	for _, entry := range copied {
		if err = entry.Processor.Describe().Validate(); err != nil {
			return nil, errors.Join(err, g.Close())
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
		return pipeline.Report{}, ErrUnavailable
	}
	lease, err := r.parent.Transaction()
	if err != nil {
		return pipeline.Report{}, err
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
			return nil, err
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
