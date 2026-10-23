package model

import (
	"context"
	"errors"
	"io"
	"math"
)

// bodyData is exclusively owned by the registered operation during I/O.
// It is detached from BodyBroker while any Reader or Closer can access it.
type bodyData struct {
	ctx                          context.Context
	ownerContext                 context.Context
	ledger                       *Ledger
	source                       io.ReadCloser
	owner                        OwnerKind
	declared, consumed           int64
	state                        BodyState
	claimed, eof, serverDisposal bool
	data                         []byte
	position                     int
	charge                       *Reservation
	fault, closeErr              error
}

func (b *bodyData) infoLocked() BodyInfo {
	length := b.declared
	if b.state == FullBufferedState || b.state == Replaced {
		length = int64(len(b.data))
	}
	return BodyInfo{b.state, b.owner, length, b.claimed, b.serverDisposal}
}
func (b *bodyData) contextErr(ctx context.Context) error {
	if b.ownerContext != nil && b.ownerContext.Err() != nil {
		return context.Cause(b.ownerContext)
	}
	if err := b.ctx.Err(); err != nil {
		return context.Cause(b.ctx)
	}
	if ctx != nil && ctx.Err() != nil {
		return context.Cause(ctx)
	}
	return nil
}

func (b *bodyData) disposeSource() error {
	if b.source == nil {
		return b.closeErr
	}
	source := b.source
	b.source = nil
	if b.owner == ServerOwned {
		// Caller/server retains the original source and must dispose any unread
		// upload. This broker may neither drain nor close it behind its back.
		b.serverDisposal = !b.eof
	} else {
		if err := source.Close(); err != nil {
			b.closeErr = errors.Join(b.closeErr, errors.Join(ErrCleanupFailure, err))
		}
	}
	return b.closeErr
}
func (b *bodyData) dropBuffer() {
	b.data = nil
	b.position = 0
	b.charge.Release()
	b.charge = nil
}
func (b *bodyData) fail(err error) error {
	b.state = Faulted
	b.fault = errors.Join(err, b.disposeSource())
	b.dropBuffer()
	return b.fault
}

// readSource is called only by the detached operation owner, without state locks.
// Cancellation is cooperative:
// checking around Read cannot interrupt an arbitrary Read that never returns.
func (b *bodyData) readSource(ctx context.Context, p []byte) (int, error) {
	if err := b.contextErr(ctx); err != nil {
		return 0, err
	}
	n, err := b.source.Read(p)
	if n < 0 || n > len(p) {
		return 0, ErrInvalid
	}
	if int64(n) > math.MaxInt64-b.consumed {
		return 0, ErrInvalid
	}
	b.consumed += int64(n)
	if cause := b.contextErr(ctx); cause != nil {
		return n, cause
	}
	if b.declared >= 0 && b.consumed > b.declared {
		return n, io.ErrUnexpectedEOF
	}
	if err == io.EOF {
		if b.declared >= 0 && b.consumed < b.declared {
			return n, io.ErrUnexpectedEOF
		}
		b.eof = true
	}
	return n, err
}

// Prepare(None) performs no allocation or source read. FullBuffered attempts at
// most limit+1 total source bytes, preserving an oversize prefix for TakeStream.
// A larger subsequent limit continues the same source, never reads it again.
func (b *bodyData) prepare(ctx context.Context, need BodyNeed, limit int64) error {
	if b.state == Released {
		return ErrReleased
	}
	if b.state == Faulted {
		return b.fault
	}
	if err := b.contextErr(ctx); err != nil {
		return b.fail(err)
	}
	if need == None {
		return nil
	}
	if need != FullBuffered || limit < 0 || limit >= int64(int(^uint(0)>>1)) {
		return ErrInvalid
	}
	if b.claimed {
		return ErrBodyClaimed
	}
	if b.state == Unavailable {
		return ErrBodyUnavailable
	}
	if b.state == FullBufferedState || b.state == Replaced {
		if int64(len(b.data)) > limit {
			return ErrBodyLimit
		}
		return nil
	}
	if int64(len(b.data)) > limit {
		return ErrBodyLimit
	}
	n, err := copyCharge(limit + 1)
	if err != nil {
		return err
	}
	charge, err := b.ledger.Reserve(n)
	if err != nil {
		return err
	}
	buffer := make([]byte, int(limit+1))
	used := copy(buffer, b.data)
	oldCharge := b.charge
	b.data = nil
	b.charge = nil
	oldCharge.Release() // old prefix has now been copied, not borrowed.
	zeroReads := 0
	for used < len(buffer) && !b.eof {
		count, readErr := b.readSource(ctx, buffer[used:])
		used += count
		if readErr != nil && readErr != io.EOF {
			charge.Release()
			return b.fail(readErr)
		}
		if count == 0 && readErr == nil {
			zeroReads++
			if zeroReads >= 100 {
				charge.Release()
				return b.fail(io.ErrNoProgress)
			}
		} else {
			zeroReads = 0
		}
	}
	b.data = buffer[:used]
	b.charge = charge
	if int64(used) > limit {
		b.state = PrefixReplay
		return ErrBodyLimit
	}
	b.state = FullBufferedState
	if err := b.disposeSource(); err != nil {
		return b.fail(err)
	}
	return nil
}

// Replace copies before disposing the previous source. A claimed stream cannot
// be replaced. On a source Close error the broker is Faulted, not rolled back.
func (b *bodyData) replace(ctx context.Context, data []byte) error {
	if b.state == Released {
		return ErrReleased
	}
	if b.state == Faulted {
		return b.fault
	}
	if b.claimed {
		return ErrBodyClaimed
	}
	if err := b.contextErr(ctx); err != nil {
		return b.fail(err)
	}
	n, err := copyCharge(int64(len(data)))
	if err != nil {
		return err
	}
	charge, err := b.ledger.Reserve(n)
	if err != nil {
		return err
	}
	copyData := append([]byte(nil), data...)
	if err := b.disposeSource(); err != nil {
		charge.Release()
		return b.fail(err)
	}
	b.dropBuffer()
	b.data = copyData
	b.charge = charge
	b.state = Replaced
	return nil
}

func (b *bodyData) read(ctx context.Context, p []byte) (int, error) {
	if b.state == Released {
		return 0, ErrReleased
	}
	if b.state == Faulted {
		return 0, b.fault
	}
	if err := b.contextErr(ctx); err != nil {
		return 0, b.fail(err)
	}
	if len(p) == 0 {
		return 0, nil
	}
	if b.position < len(b.data) {
		n := copy(p, b.data[b.position:])
		b.position += n
		return n, nil
	}
	if b.state == FullBufferedState || b.state == Replaced || b.eof {
		return 0, io.EOF
	}
	n, err := b.readSource(ctx, p)
	if err != nil && err != io.EOF {
		return n, b.fail(err)
	}
	return n, err
}

func (b *bodyData) close() error {
	if b == nil {
		return nil
	}
	if b.state != Released {
		b.disposeSource()
		b.dropBuffer()
		b.state = Released
	}
	return b.closeErr
}

func (b *bodyData) snapshot(lease *CopyLease) (BodyView, error) {
	if b.state == Released {
		return BodyView{}, ErrReleased
	}
	if b.state == Faulted {
		return BodyView{}, b.fault
	}
	view := BodyView{info: b.infoLocked(), lease: lease}
	if b.state != FullBufferedState && b.state != Replaced {
		return view, nil
	}
	n, err := copyCharge(int64(len(b.data)))
	if err != nil {
		return BodyView{}, err
	}
	err = lease.allocate(n, func() error { view.data = append([]byte(nil), b.data...); return nil })
	return view, err
}
