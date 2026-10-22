// Package scripthost defines the engine-neutral contract between script
// runtimes and host APIs. It depends only on the Go standard library.
package scripthost

import "context"

// Binding describes a host function made available to a script. CallbackArg
// is -1 for synchronous functions and the zero-based callback argument index
// for asynchronous functions.
type Binding struct {
	Name        string
	Async       bool
	CallbackArg int
}

// HostCall contains JSON-compatible arguments. CallbackID is opaque to the
// host and identifies the runtime-owned callback for asynchronous calls.
type HostCall struct {
	Name       string
	Args       []any
	CallbackID uint64
}

// Session exposes only lifecycle and bounded task scheduling to host code.
// It does not expose a VM or engine-specific value.
type Session interface {
	Done(value any, hasValue bool) bool
	IsDone() bool
	Schedule(callbackID uint64, work func(context.Context) ([]any, error)) error
}

// Host implements the functions described by Binding for one script session.
type Host interface {
	Call(context.Context, Session, HostCall) (any, error)
}
