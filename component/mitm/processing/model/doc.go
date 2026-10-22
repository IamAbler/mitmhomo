// Package model provides standalone HTTP transaction values and body ownership.
// It is not connected to the MITM handler and contains no processor, engine,
// pipeline, or native routing implementation.
//
// A Transaction has one owner. Inputs are detached copies with independent
// CopyLeases. Only the execution owner receives the lease; an Input cannot close
// its lease or the Transaction. Closing a Transaction never releases an Input's
// charges. The execution owner must close its lease only after all consumers,
// including users of returned byte/header copies, have stopped using them.
// Go cannot revoke a slice or string already returned to a caller.
//
// BodyBroker serializes preparation, streaming, replacement and Close per body.
// Close waits for physical drain; CloseLogical and CloseContext bound the logical
// caller. Source acceptance reserves one of 64 global Body execution owners;
// there is at most one operation per source, including blocked Read/Close.
// A cancelable stream also has one cancellation watcher, joined before its
// owner capacity is released. There is no unbounded queue or cleanup fan-out.
// Cancellation does not release buffers, generation pins or capacity early.
// Only a certified Interrupt capability may interrupt I/O concurrently.
// Streaming Read still borrows its caller's buffer until it returns, runs on
// that caller outside state locks, and requires protocol interruption to exit.
// ServerOwned sources remain the server's disposal and final Close responsibility.
// TransportOwned sources must represent one response stream, not its H2 socket.
//
// Budgets account explicitly reserved framework bytes and conservative copy
// overhead, not allocator-exact heap sizes, engine heaps, or process RSS. There
// is no global byte budget. The Body owner cap bounds retained operations, not RSS.
package model
