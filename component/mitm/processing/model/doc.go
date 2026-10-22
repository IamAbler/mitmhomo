// Package model provides standalone HTTP transaction values and body ownership.
// It is not connected to the MITM handler and contains no processor, engine,
// pipeline, native routing, or background goroutine implementation.
//
// A Transaction has one owner. Inputs are detached copies with independent
// CopyLeases. Only the execution owner receives the lease; an Input cannot close
// its lease or the Transaction. Closing a Transaction never releases an Input's
// charges. The execution owner must close its lease only after all consumers,
// including users of returned byte/header copies, have stopped using them.
// Go cannot revoke a slice or string already returned to a caller.
//
// BodyBroker serializes preparation, streaming, replacement and Close per body.
// Close waits for an in-flight Read: arbitrary readers cannot safely be forced
// to stop, and no goroutine is launched to pretend cancellation drained them.
// Context cancellation is checked around reads; a blocked read must itself honor
// cancellation, a protocol deadline, or an externally managed interruption.
// ServerOwned sources remain the server's disposal and final Close responsibility.
// TransportOwned sources must represent one response stream, not its H2 socket.
//
// Budgets account explicitly reserved framework bytes and conservative copy
// overhead, not allocator-exact heap sizes, engine heaps, or process RSS. There
// are no global budgets or production default caps in this package.
package model
