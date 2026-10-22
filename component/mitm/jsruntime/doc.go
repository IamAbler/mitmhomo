// Package jsruntime provides a Goja-backed JavaScript execution runtime for
// MITM scripting features. It has no HTTP transport or proxy dependencies.
//
// Each execution gets a new Goja VM. The only input exposed to JavaScript is a
// JSON-decoded value named input; the result is converted back through JSON.
// No Go objects or host services are installed in the VM.
//
// Source, input JSON, output JSON, execution concurrency, and JavaScript
// execution time have separate configured limits. Input is size-estimated
// before encoding, is limited to 128 nesting levels, and rejects caller types
// with custom JSON or text encoders. JSON parsing, script execution, and result
// stringification run under the same deadline. The stringifier replacer stops
// when its conservative serialized-size budget is exceeded; output decoding
// runs only after that check.
//
// Compile has a source byte limit but no deadline because Goja exposes no
// cancellable compiler API. Goja's interrupt also cannot preempt a native Go
// operation already in progress. The output-size replacer is a native Go
// callback; each call is bounded by MaxOutputBytes, but a single string export
// or accounting callback can overrun the deadline until that bounded call
// returns. Input encoding and output decoding are ordinary Go operations
// bounded by their byte and nesting limits.
//
// Goja does not provide a hard process-memory limit. Scripts can allocate
// intermediate values, including values returned by toJSON, before the output
// replacer can reject them. Goja VM allocations and JSON temporary buffers also
// have peaks beyond the payload limits. Source, payload, and concurrency
// limits reduce resource use but do not create a hard memory sandbox; arbitrary
// untrusted scripts require process-level isolation for that guarantee.
//
// New creates no VM or worker. The Goja package has static package-init lookup
// tables, but this package creates no Runtime, compile cache map, or goroutine
// until the corresponding API is used. Runtime.Close rejects new calls,
// interrupts active VMs, and clears the internal compile cache without waiting
// for executions or an in-progress compile to finish. CompiledScript values
// are opaque and valid only on the Runtime that created them; external
// references retained by callers remain the caller's responsibility.
package jsruntime
