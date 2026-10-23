package model

import (
	"context"
	"errors"
	"io"
)

var (
	ErrBodyBusy           = errors.New("body operation in progress")
	ErrBodyCapacity       = errors.New("body execution ownership capacity exhausted")
	bodyAlreadyDone       = func() <-chan struct{} { ch := make(chan struct{}); close(ch); return ch }()
	defaultBodyExecutions = NewBodyExecutionPool(defaultBodyExecutionCapacity)
)

const defaultBodyExecutionCapacity int64 = 256

// BodyExecutionPool bounds live source owners, including idle sources and
// canceled I/O. It uses the existing Ledger reservation/release mechanism.
// Reservation at source acceptance guarantees a drain slot even for Close.
// A custom pool adds a restriction; it cannot bypass the default global cap.
type BodyExecutionPool struct{ ledger *Ledger }

func NewBodyExecutionPool(capacity int64) *BodyExecutionPool {
	if capacity <= 0 {
		panic("invalid body execution capacity")
	}
	ledger, _ := NewLedger(capacity, nil)
	return &BodyExecutionPool{ledger}
}
func (p *BodyExecutionPool) Occupied() int64 { return p.ledger.Current() }
func errorsJoinBodyCapacity(err error) error {
	return errors.Join(ErrBodyCapacity, ErrCapacityExhausted, err)
}

type bodyReservation struct{ *Reservation }

func (r bodyReservation) Close() error { r.Release(); return nil }
func closeBodyResources(resources []io.Closer) error {
	var err error
	for i := len(resources) - 1; i >= 0; i-- {
		if resources[i] != nil {
			if closeErr := resources[i].Close(); closeErr != nil {
				err = errors.Join(err, ErrCleanupFailure, closeErr)
			}
		}
	}
	return err
}

// bodyAcceptance calls publish while holding the Transaction's state lock,
// after checking its original revision and cancellation state. It never does I/O.
type bodyAcceptance func(publish func() error) error

type bodyOperation struct {
	logical, done            chan struct{}
	work                     bodyData
	ctx                      context.Context
	err                      error
	count                    int
	setupError               error
	canceled                 error
	logicalClosed            bool
	temporary                []io.Closer
	stream, reading          bool
	info                     BodyInfo
	stopWatcher, watcherExit chan struct{}
}

func (b *BodyBroker) LogicalDone() <-chan struct{} {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.last == nil {
		return bodyAlreadyDone
	}
	return b.last.logical
}
func (b *BodyBroker) ExecutionDone() <-chan struct{} {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.last == nil {
		return bodyAlreadyDone
	}
	return b.last.done
}

func (b *BodyBroker) cancelOperation(op *bodyOperation, cause error) {
	b.cancelOperationWithInterrupt(op, cause, true)
}

func (b *BodyBroker) cancelOperationWithInterrupt(op *bodyOperation, cause error, interruptRead bool) {
	b.mu.Lock()
	if b.operation != op || op.logicalClosed {
		b.mu.Unlock()
		return
	}
	if b.ctx.Err() != nil {
		cause = context.Cause(b.ctx)
	} else if b.ownerContext.Err() != nil {
		cause = context.Cause(b.ownerContext)
	} else if op.ctx.Err() != nil {
		cause = context.Cause(op.ctx)
	}
	op.canceled = cause
	op.err = cause
	op.logicalClosed = true
	close(op.logical)
	var interrupt func()
	if interruptRead {
		interrupt = b.interrupt
	}
	b.mu.Unlock()
	// Only an explicitly certified, nonblocking adapter capability is called.
	if interrupt != nil {
		interrupt()
	}
}

func (b *BodyBroker) CancelRead(cause error) {
	if cause == nil {
		cause = context.Canceled
	}
	b.mu.Lock()
	op := b.operation
	b.mu.Unlock()
	if op != nil {
		b.cancelOperation(op, cause)
	}
}

func (b *BodyBroker) run(ctx context.Context, accept bodyAcceptance, resources []io.Closer, execute func(*bodyData) (int, error)) (int, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		b.mu.Lock()
		if b.closing || b.state == Released {
			b.mu.Unlock()
			closeBodyResources(resources)
			return 0, ErrReleased
		}
		if b.operation != nil {
			prior := b.operation
			if prior.stream {
				b.mu.Unlock()
				closeBodyResources(resources)
				return 0, ErrBodyClaimed
			}
			b.mu.Unlock()
			select {
			case <-prior.done:
				continue
			case <-ctx.Done():
				closeBodyResources(resources)
				return 0, context.Cause(ctx)
			case <-b.ctx.Done():
				closeBodyResources(resources)
				return 0, context.Cause(b.ctx)
			case <-b.ownerContext.Done():
				closeBodyResources(resources)
				return 0, context.Cause(b.ownerContext)
			}
		}
		if b.state == Faulted {
			err := b.fault
			b.mu.Unlock()
			closeBodyResources(resources)
			return 0, err
		}
		// The optional capability pins this Body's immutable Generation. Keep
		// one lifetime pin; later prepares release their duplicate at real exit.
		if len(resources) > 1 {
			b.mu.Unlock()
			closeBodyResources(resources)
			return 0, ErrInvalid
		}
		if len(resources) > 0 && len(b.tickets) == 0 {
			ticket, err := defaultBodyExecutions.ledger.Reserve(1)
			if err != nil {
				b.mu.Unlock()
				closeBodyResources(resources)
				return 0, errorsJoinBodyCapacity(err)
			}
			b.tickets = append(b.tickets, ticket)
		}
		op := &bodyOperation{logical: make(chan struct{}), done: make(chan struct{}), work: b.bodyData, ctx: ctx}
		for _, resource := range resources {
			if _, ok := resource.(bodyReservation); ok || len(b.held) > 0 {
				op.temporary = append(op.temporary, resource)
			} else {
				b.held = append(b.held, resource)
			}
		}
		b.operation = op
		b.last = op
		b.bodyData = bodyData{ctx: b.ctx, ledger: b.ledger, owner: op.work.owner, declared: op.work.declared, state: Reading, claimed: op.work.claimed}
		acquire := b.acquireExecution
		b.acquireExecution = nil // Exactly one lifetime pin for an adapter-owned source.
		b.mu.Unlock()
		acquireErr := b.acquirePin(acquire)
		task := func() {
			var n int
			err := acquireErr
			if err == nil {
				n, err = execute(&op.work)
			} else {
				err = op.work.fail(err)
			}
			b.finishOperation(op, accept, n, err)
		}
		// Buffered operation launch: a source already owns a global
		// capacity ticket, and operation registration permits one worker per source.
		// No queue or auxiliary cancellation/cleanup worker is created for it.
		if len(b.tickets) == 0 {
			task()
		} else {
			go task()
		}
		for {
			select {
			case <-op.logical:
				b.mu.Lock()
				n, err := op.count, op.err
				b.mu.Unlock()
				return n, err
			case <-ctx.Done():
				b.cancelOperation(op, context.Cause(ctx))
			case <-b.ctx.Done():
				b.cancelOperation(op, context.Cause(b.ctx))
			case <-b.ownerContext.Done():
				b.cancelOperation(op, context.Cause(b.ownerContext))
			}
		}
	}
}

func (b *BodyBroker) finishOperation(op *bodyOperation, accept bodyAcceptance, n int, err error) {
	kept := false
	var rejection error
	publish := func() error {
		b.mu.Lock()
		defer b.mu.Unlock()
		switch {
		case b.closing:
			rejection = ErrReleased
		case op.canceled != nil:
			rejection = op.canceled
		case op.ctx.Err() != nil:
			rejection = context.Cause(op.ctx)
		case b.ctx.Err() != nil:
			rejection = context.Cause(b.ctx)
		case b.ownerContext.Err() != nil:
			rejection = context.Cause(b.ownerContext)
		default:
			b.bodyData = op.work
			kept = true
		}
		return rejection
	}
	if accept != nil {
		if acceptanceErr := accept(publish); acceptanceErr != nil {
			rejection = acceptanceErr
		}
	} else {
		_ = publish()
	}
	if !kept {
		if rejection == nil {
			rejection = ErrClosed
		}
		err = errors.Join(rejection, op.work.close())
	}
	if cleanupErr := closeBodyResources(op.temporary); cleanupErr != nil {
		err = errors.Join(err, cleanupErr)
	}
	op.temporary = nil
	if op.stopWatcher != nil {
		close(op.stopWatcher)
		<-op.watcherExit
	}
	for {
		b.mu.Lock()
		// CloseLogical may win after acceptance but before physical completion.
		if kept && b.closing {
			b.bodyData = bodyData{ctx: b.ctx, ledger: b.ledger, owner: op.work.owner, declared: op.work.declared, state: Released}
			b.mu.Unlock()
			err = errors.Join(err, op.work.close())
			kept = false
			continue
		}
		terminal := !kept || b.state == Faulted || b.closing
		if terminal && !kept {
			b.bodyData = bodyData{ctx: b.ctx, ledger: b.ledger, owner: op.work.owner, declared: op.work.declared, state: Faulted, fault: err, serverDisposal: op.work.serverDisposal}
		}
		if terminal {
			held, tickets := b.held, b.tickets
			b.held = nil
			b.tickets = nil
			b.mu.Unlock()
			cleanupErr := closeBodyResources(held)
			for _, ticket := range tickets {
				ticket.Release()
			}
			b.mu.Lock()
			b.closeErr = errors.Join(b.closeErr, op.work.closeErr, cleanupErr, op.setupError)
		}
		if b.closing {
			b.state = Released
			close(b.closed)
		}
		b.operation = nil
		op.work = bodyData{} // No retained source/buffer aliases after physical exit.
		op.count = n
		if !op.logicalClosed {
			op.err = err
			op.logicalClosed = true
			close(op.logical)
		}
		close(op.done)
		b.mu.Unlock()
		return
	}
}

// CloseLogical revokes admission immediately. Actual resource ownership stays
// with the operation until Read AND source disposal have returned. It never
// calls an arbitrary Reader.Close under a state lock or on the logical caller.
func (b *BodyBroker) CloseLogical() {
	if b == nil {
		return
	}
	b.mu.Lock()
	if b.closing {
		b.mu.Unlock()
		return
	}
	b.closing = true
	if op := b.operation; op != nil {
		drain := op.stream && !op.reading
		interruptRead := !drain
		if drain {
			op.reading = true
		}
		b.mu.Unlock()
		b.cancelOperationWithInterrupt(op, ErrReleased, interruptRead)
		if drain {
			b.dispatchBodyClose(op)
		}
		return
	}
	// No external source or generation release: finish without launching work.
	if b.source == nil && len(b.held) == 0 {
		b.dropBuffer()
		b.state = Released
		for _, ticket := range b.tickets {
			ticket.Release()
		}
		b.tickets = nil
		close(b.closed)
		b.mu.Unlock()
		return
	}
	op := &bodyOperation{logical: make(chan struct{}), done: make(chan struct{}), ctx: context.Background(), work: b.bodyData}
	op.logicalClosed = true
	close(op.logical)
	b.operation = op
	b.last = op
	b.bodyData = bodyData{ctx: b.ctx, ledger: b.ledger, state: Released, owner: op.work.owner, declared: op.work.declared}
	acquire := b.acquireExecution
	b.acquireExecution = nil
	b.mu.Unlock()
	op.setupError = b.acquirePin(acquire)
	// The source's reserved owner also covers a blocked destructor.
	b.dispatchBodyClose(op)
}
func (b *BodyBroker) dispatchBodyClose(op *bodyOperation) {
	go func() { err := errors.Join(op.setupError, op.work.close()); b.finishOperation(op, nil, 0, err) }()
}

// Streaming Read borrows its caller's buffer, so cancellation can only ask an
// explicit adapter to interrupt it. This watcher is bounded by the same source
// owner and is joined before its capacity can be reused. It never reads Body.
func (b *BodyBroker) startStreamCancellation(op *bodyOperation) {
	b.mu.Lock()
	if b.operation != op || b.closing || op.ctx.Done() == nil && b.ctx.Done() == nil && b.ownerContext.Done() == nil {
		b.mu.Unlock()
		return
	}
	op.stopWatcher = make(chan struct{})
	op.watcherExit = make(chan struct{})
	b.mu.Unlock()
	go func() {
		defer close(op.watcherExit)
		select {
		case <-op.stopWatcher:
			return
		case <-op.ctx.Done():
		case <-b.ctx.Done():
		case <-b.ownerContext.Done():
		}
		b.CloseLogical()
	}()
}
func (b *BodyBroker) CloseContext(ctx context.Context) error {
	if b == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	b.CloseLogical()
	select {
	case <-b.closed:
		b.mu.Lock()
		err := b.closeErr
		b.mu.Unlock()
		return err
	case <-ctx.Done():
		return context.Cause(ctx)
	}
}
func (b *BodyBroker) Close() error { return b.CloseContext(context.Background()) }

// The adapter capability must only register an existing generation lease;
// it must not initialize a backend or perform I/O. It runs outside state locks.
func (b *BodyBroker) acquirePin(acquire func() (io.Closer, error)) error {
	if acquire == nil {
		return nil
	}
	lease, err := acquire()
	if lease != nil {
		b.mu.Lock()
		b.held = append(b.held, lease)
		b.mu.Unlock()
	}
	if lease == nil && err == nil {
		return ErrInvalid
	}
	return err
}
