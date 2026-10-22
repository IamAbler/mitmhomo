package generation

import (
	"context"
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
				_ = e.Processor.Close()
			}
		}
		g := New(resources...)
		g.Close()
		return nil, err
	}
	resources = append(append([]io.Closer(nil), resources...), runner)
	g := New(resources...)
	for _, entry := range copied {
		if err = entry.Processor.Describe().Validate(); err != nil {
			g.Close()
			return nil, err
		}
	}
	return &Plan{Generation: g, entries: copied}, nil
}

// Runner is scoped to an open connection/transaction capability. Its execution
// pin is registered by M4.7 before Processor.Start and transferred to Invocation
// on success. Retiring generations continue admission through the parent.
// Callers must not Close this borrowed runner; Plan owns processor cleanup.
func (p *Plan) Runner(parent *Lease) (*pipeline.Runner, error) {
	if parent == nil || parent.g != p.Generation {
		return nil, ErrUnavailable
	}
	return pipeline.NewRunner(p.entries, pipeline.Options{AcquireGeneration: func(ctx context.Context, id model.GenerationID) (io.Closer, error) {
		if err := ctx.Err(); err != nil {
			return nil, context.Cause(ctx)
		}
		if id != p.Generation.ID() {
			return nil, ErrUnavailable
		}
		lease, err := parent.Execution()
		if err != nil {
			return nil, err
		}
		return &executionPin{lease}, nil
	}})
}
