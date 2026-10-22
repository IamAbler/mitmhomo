package model

import (
	"context"
	"io"
)

// A stream retains one operation and its channels for the whole borrow. Reads
// use their caller's slice synchronously outside state locks, with zero per-read
// allocations. Concurrent Read is rejected; Close never waits on the read flag.
func (b *BodyBroker) takeStream(ctx context.Context) (io.ReadCloser, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	b.mu.Lock()
	if b.closing {
		b.mu.Unlock()
		return nil, ErrReleased
	}
	if b.claimed {
		b.mu.Unlock()
		return nil, ErrBodyClaimed
	}
	if b.operation != nil {
		b.mu.Unlock()
		return nil, ErrBodyBusy
	}
	if b.state == Faulted {
		err := b.fault
		b.mu.Unlock()
		return nil, err
	}
	if err := b.bodyData.contextErr(ctx); err != nil {
		b.mu.Unlock()
		return nil, err
	}
	if b.state == Unavailable {
		b.mu.Unlock()
		return nil, ErrBodyUnavailable
	}
	b.claimed = true
	op := &bodyOperation{logical: make(chan struct{}), done: make(chan struct{}), ctx: ctx, work: b.bodyData, stream: true}
	op.info = op.work.infoLocked()
	b.operation = op
	b.last = op
	b.bodyData = bodyData{ctx: b.ctx, ledger: b.ledger, owner: op.work.owner, declared: op.work.declared, state: op.work.state, claimed: true}
	acquire := b.acquireExecution
	b.acquireExecution = nil
	// Reserve exclusive setup until a concurrent Close can elect stream drain.
	op.reading = true
	b.mu.Unlock()
	var err error
	if acquire != nil {
		lease, acquireErr := acquire()
		err = acquireErr
		if lease == nil && err == nil {
			err = ErrInvalid
		}
		if lease != nil {
			b.mu.Lock()
			b.held = append(b.held, lease)
			b.mu.Unlock()
		}
	}
	b.mu.Lock()
	closing := b.closing
	if err == nil && !closing {
		op.reading = false
	}
	b.mu.Unlock()
	if err != nil || closing {
		if err == nil {
			err = ErrReleased
		}
		b.cancelOperation(op, err)
		b.dispatchBodyClose(op)
		return nil, err
	}
	b.startStreamCancellation(op)
	return &bodyStream{b, op}, nil
}

func (b *BodyBroker) readStream(op *bodyOperation, p []byte) (int, error) {
	b.mu.Lock()
	if b.closing || b.operation != op {
		b.mu.Unlock()
		return 0, ErrReleased
	}
	if op.reading {
		b.mu.Unlock()
		return 0, ErrBodyBusy
	}
	op.reading = true
	b.mu.Unlock()
	n, err := op.work.read(op.ctx, p)
	b.mu.Lock()
	// Keep the read flag until the closing owner is settled, so Close cannot
	// start a second drain concurrently with this final access to bodyData.
	canceled := b.closing || op.canceled != nil || op.ctx.Err() != nil || b.ownerContext.Err() != nil || b.ctx.Err() != nil
	if canceled || err != nil && err != io.EOF {
		b.mu.Unlock()
		if canceled {
			if op.ctx.Err() != nil {
				err = context.Cause(op.ctx)
			} else if b.ownerContext.Err() != nil {
				err = context.Cause(b.ownerContext)
			} else if b.ctx.Err() != nil {
				err = context.Cause(b.ctx)
			} else {
				err = ErrReleased
			}
		}
		b.finishOperation(op, nil, n, err)
		return n, err
	}
	op.reading = false
	op.info = op.work.infoLocked()
	b.mu.Unlock()
	return n, err
}
