package model

import (
	"context"
	"errors"
	"io"
	"math"
	"sync"
)

type BodyNeed uint8

const (
	None BodyNeed = iota
	FullBuffered
)

type BodyState uint8

const (
	Unavailable BodyState = iota
	UnreadStream
	PrefixReplay
	FullBufferedState
	Replaced
	Faulted
	Released
)

type OwnerKind uint8

const (
	ServerOwned OwnerKind = iota + 1
	TransportOwned
	FrameworkOwned
)

type BodySource struct {
	Reader         io.ReadCloser
	Owner          OwnerKind
	DeclaredLength int64 // -1 unknown; otherwise checked at EOF and on excess.
}
type BodyInfo struct {
	State   BodyState
	Owner   OwnerKind
	Length  int64
	Claimed bool
	// NeedsServerDisposal reports an unread upload, not final Close ownership.
	// A ServerOwned source must still be closed by its server when this is false.
	NeedsServerDisposal bool
}

// BodySlot is an owner-only reference, never included in Input.
type BodySlot struct{ broker *BodyBroker }

func NewBodySlot(broker *BodyBroker) BodySlot { return BodySlot{broker} }
func (s BodySlot) Broker() *BodyBroker        { return s.broker }
func (s BodySlot) Close() error {
	if s.broker == nil {
		return nil
	}
	return s.broker.Close()
}

// BodyBroker has no background worker. mu serializes every access to the real
// reader, including Close. A blocking non-cooperative reader also delays Close.
type BodyBroker struct {
	mu                           sync.Mutex
	ctx                          context.Context
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

func NewBodyBroker(ctx context.Context, source BodySource, ledger *Ledger) (*BodyBroker, error) {
	if ledger == nil || source.Owner < ServerOwned || source.Owner > FrameworkOwned || source.DeclaredLength < -1 {
		return nil, ErrInvalid
	}
	if ctx == nil {
		ctx = context.Background()
	}
	b := &BodyBroker{ctx: ctx, ledger: ledger, source: source.Reader, owner: source.Owner, declared: source.DeclaredLength, state: UnreadStream}
	if source.Reader == nil {
		b.state = Unavailable
		if source.DeclaredLength > 0 {
			return nil, ErrInvalid
		}
	}
	return b, nil
}

func (b *BodyBroker) Info() BodyInfo { b.mu.Lock(); defer b.mu.Unlock(); return b.infoLocked() }
func (b *BodyBroker) infoLocked() BodyInfo {
	length := b.declared
	if b.state == FullBufferedState || b.state == Replaced {
		length = int64(len(b.data))
	}
	return BodyInfo{b.state, b.owner, length, b.claimed, b.serverDisposal}
}
func (b *BodyBroker) contextErr(ctx context.Context) error {
	if err := b.ctx.Err(); err != nil {
		return context.Cause(b.ctx)
	}
	if ctx != nil && ctx.Err() != nil {
		return context.Cause(ctx)
	}
	return nil
}

func (b *BodyBroker) disposeSource() error {
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
		b.closeErr = errors.Join(b.closeErr, source.Close())
	}
	return b.closeErr
}
func (b *BodyBroker) dropBuffer() {
	b.data = nil
	b.position = 0
	b.charge.Release()
	b.charge = nil
}
func (b *BodyBroker) fail(err error) error {
	b.state = Faulted
	b.fault = errors.Join(err, b.disposeSource())
	b.dropBuffer()
	return b.fault
}

// readSource is called under the per-body lock only. Cancellation is cooperative:
// checking around Read cannot interrupt an arbitrary Read that never returns.
func (b *BodyBroker) readSource(ctx context.Context, p []byte) (int, error) {
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
func (b *BodyBroker) Prepare(ctx context.Context, need BodyNeed, limit int64) error {
	b.mu.Lock()
	defer b.mu.Unlock()
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
func (b *BodyBroker) Replace(ctx context.Context, data []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
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

// TakeStream grants exactly one consumer. The returned wrapper exposes neither
// the source nor a connection. Its Close delegates to the broker's owner policy.
func (b *BodyBroker) TakeStream(ctx context.Context) (io.ReadCloser, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.state == Released {
		return nil, ErrReleased
	}
	if b.state == Faulted {
		return nil, b.fault
	}
	if b.claimed {
		return nil, ErrBodyClaimed
	}
	if err := b.contextErr(ctx); err != nil {
		return nil, b.fail(err)
	}
	if b.state == Unavailable {
		return nil, ErrBodyUnavailable
	}
	b.claimed = true
	return &bodyStream{broker: b, ctx: ctx}, nil
}

type bodyStream struct {
	broker *BodyBroker
	ctx    context.Context
}

func (s *bodyStream) Close() error { return s.broker.Close() }
func (s *bodyStream) Read(p []byte) (int, error) {
	b := s.broker
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.state == Released {
		return 0, ErrReleased
	}
	if b.state == Faulted {
		return 0, b.fault
	}
	if err := b.contextErr(s.ctx); err != nil {
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
	n, err := b.readSource(s.ctx, p)
	if err != nil && err != io.EOF {
		return n, b.fail(err)
	}
	return n, err
}

func (b *BodyBroker) Close() error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.state != Released {
		b.disposeSource()
		b.dropBuffer()
		b.state = Released
	}
	return b.closeErr
}

// BodyView is a detached value. Streaming/prefix views contain no source and
// cannot return partial bytes as a complete body. Its lease belongs to execution.
type BodyView struct {
	info  BodyInfo
	data  []byte
	lease *CopyLease
}

func (v BodyView) Info() BodyInfo { return v.info }
func (v BodyView) BytesCopy() ([]byte, error) {
	if v.info.State != FullBufferedState && v.info.State != Replaced {
		return nil, ErrBodyUnavailable
	}
	n, err := copyCharge(int64(len(v.data)))
	if err != nil {
		return nil, err
	}
	var out []byte
	err = v.lease.allocate(n, func() error { out = append([]byte(nil), v.data...); return nil })
	if err != nil {
		return nil, err
	}
	return out, err
}

func (b *BodyBroker) Snapshot(lease *CopyLease) (BodyView, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
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
