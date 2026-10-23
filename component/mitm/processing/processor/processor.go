// Package processor defines the engine-independent HTTP processing execution
// contract. It has no dependency on Goja, network adapters, or the MITM handler.
//
// The owner retains the model.Input CopyLease and other execution resources
// while calling Start. Start registers them before backend execution can begin;
// on success their ownership transfers to the Invocation, while on failure
// ownership remains with the caller. Finish releases them after backend cleanup
// and its final Input access. Logical cancellation never releases them. A
// successful output DoneResult keeps its own payload budget until the receiver
// commits or discards it and calls DoneResult.Release. Independent HTTP tasks
// must keep their own task permit until those tasks actually exit. This package
// never commits into a Transaction: its owner must recheck the Input key,
// revision, and parent Context before applying a returned result.
package processor

import (
	"context"
	"io"
	"strings"
	"time"

	"github.com/metacubex/mihomo/component/mitm/processing/model"
)

type Requirements struct {
	Body model.BodyNeed
	// MaxBodyBytes caps a complete FullBuffered body. It must be zero for None.
	MaxBodyBytes int64
	// MaxOutputBytes caps the immutable DoneResult allocation. Zero uses the
	// owning Transaction's bounded default.
	MaxOutputBytes int64
	// TotalTimeout is the whole invocation wait budget; zero inherits the parent.
	TotalTimeout time.Duration
	// ExecutionTimeout is the backend's execution budget, separate from TotalTimeout.
	ExecutionTimeout time.Duration
}

// Descriptor contains immutable scalar configuration only. Describe must return
// a value snapshot and may not expose backend-owned mutable state.
type Descriptor struct {
	ID              string
	Backend         string
	ContractVersion uint32
	Request         bool
	Response        bool
	RequestNeeds    Requirements
	ResponseNeeds   Requirements
}

// Clone returns an independent value. Descriptor deliberately contains no
// maps, slices, backend objects, or mutable configuration references.
func (d Descriptor) Clone() Descriptor {
	d.ID = strings.Clone(d.ID)
	d.Backend = strings.Clone(d.Backend)
	return d
}

func validRequirements(r Requirements) bool {
	if r.Body != model.None && r.Body != model.FullBuffered || r.MaxBodyBytes < 0 || r.MaxOutputBytes < 0 || r.TotalTimeout < 0 || r.ExecutionTimeout < 0 {
		return false
	}
	return r.Body == model.FullBuffered || r.MaxBodyBytes == 0
}

func emptyRequirements(r Requirements) bool {
	return r == (Requirements{})
}

func (d Descriptor) Validate() error {
	if d.ID == "" || d.Backend == "" || d.ContractVersion == 0 || !d.Request && !d.Response || !validRequirements(d.RequestNeeds) || !validRequirements(d.ResponseNeeds) {
		return model.NewProcessingError(model.ProcessingErrorInvalidConfiguration, model.ProcessingOriginProcessor, model.PhaseInvalid, d.ID, "", model.ErrInvalid)
	}
	if !d.Request && !emptyRequirements(d.RequestNeeds) || !d.Response && !emptyRequirements(d.ResponseNeeds) {
		return model.NewProcessingError(model.ProcessingErrorInvalidInput, model.ProcessingOriginProcessor, model.PhaseInvalid, d.ID, "", model.ErrInvalid)
	}
	return nil
}

// Processor is normally scoped to one immutable configuration generation. Start
// must perform bounded admission/registration only: it cannot synchronously
// wait for network, JavaScript, IPC, or compilation. It must register resources
// before it starts backend execution, so even a backend that finishes before
// Start returns cannot outlive an unowned Input lease. On failure Start returns
// nil,error and retains no resource; on success it returns a non-nil Invocation
// and transfers all resources, even if that Invocation is already complete.
// Implementations must finish fallible preparation before BeginWithResources
// succeeds. After ownership transfers, setup or execution failures are delivered
// through Completion.Finish and Start must return the Invocation successfully.
// Implementations must use bounded execution admission and keep simultaneous
// invocation state independent. Close is idempotent and requests cancellation
// without draining execution. WaitClosed is the explicit context-bounded drain
// operation.
type Processor interface {
	Describe() Descriptor
	Start(context.Context, model.Input, ...io.Closer) (*Invocation, error)
	Close() error
	WaitClosed(context.Context) error
}

// ExecutionFinalizer is an optional generation ownership barrier. Close is
// used by the caller on Start failure; after successful transfer Finish calls
// FinalizeExecution only after ExecutionDone and admission bookkeeping. It
// must be idempotent. Input and ordinary execution resources retain their
// existing pre-ExecutionDone cleanup contract.
type ExecutionFinalizer interface {
	io.Closer
	FinalizeExecution()
}
