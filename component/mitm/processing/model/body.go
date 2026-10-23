package model

import (
	"context"
	"io"
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
	Reading
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
	// Interrupt must be concurrency-safe, nonblocking, and specific to this source.
	// It is an explicit adapter capability, never inferred from io.Closer.
	Interrupt func()
	// Executions optionally adds a smaller owner limit; the global limit still applies.
	Executions *BodyExecutionPool
	// AcquireExecution must register an existing Generation lease without I/O.
	// The pin covers Read and source disposal, including an unread Body's Close.
	AcquireExecution func() (io.Closer, error)
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
func (s BodySlot) CloseLogical() {
	if s.broker != nil {
		s.broker.CloseLogical()
	}
}
func (s BodySlot) CloseContext(ctx context.Context) error {
	if s.broker == nil {
		return nil
	}
	return s.broker.CloseContext(ctx)
}
func (s BodySlot) ExecutionDone() <-chan struct{} {
	if s.broker == nil {
		return bodyAlreadyDone
	}
	return s.broker.ExecutionDone()
}

// BodyBroker keeps only state transitions under mu. I/O owns detached bodyData.
// Close remains a physical drain; CloseContext/CloseLogical bound logical waits.
type BodyBroker struct {
	mu           sync.Mutex
	ctx          context.Context
	ownerContext context.Context
	ledger       *Ledger
	bodyData
	operation        *bodyOperation
	last             *bodyOperation
	closing          bool
	closed           chan struct{}
	closeErr         error
	tickets          []*Reservation
	held             []io.Closer
	interrupt        func()
	acquireExecution func() (io.Closer, error)
}

func NewBodyBroker(ctx context.Context, source BodySource, ledger *Ledger) (*BodyBroker, error) {
	if ledger == nil || source.Owner < ServerOwned || source.Owner > FrameworkOwned || source.DeclaredLength < -1 {
		return nil, ErrInvalid
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if source.Reader == nil && source.DeclaredLength > 0 {
		return nil, ErrInvalid
	}
	b := &BodyBroker{ctx: ctx, ownerContext: ctx, ledger: ledger, closed: make(chan struct{}), interrupt: source.Interrupt, acquireExecution: source.AcquireExecution}
	b.bodyData = bodyData{ctx: ctx, ledger: ledger, source: source.Reader, owner: source.Owner, declared: source.DeclaredLength, state: UnreadStream}
	if source.Reader == nil {
		b.state = Unavailable
	}
	// A live source reserves its bounded drain owner before being accepted. This
	// includes idle sources, so even Close cannot require an unbounded new worker.
	if source.Reader != nil || source.AcquireExecution != nil {
		pools := []*BodyExecutionPool{defaultBodyExecutions}
		if source.Executions != nil && source.Executions != defaultBodyExecutions {
			pools = append(pools, source.Executions)
		}
		for _, pool := range pools {
			ticket, err := pool.ledger.Reserve(1)
			if err != nil {
				for _, held := range b.tickets {
					held.Release()
				}
				return nil, errorsJoinBodyCapacity(err)
			}
			b.tickets = append(b.tickets, ticket)
		}
	}
	return b, nil
}

func (b *BodyBroker) attachContext(ctx context.Context) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.ownerContext = ctx
	b.bodyData.ownerContext = ctx
}

// attachLedger transfers a fresh broker's byte accounting into its owning
// Transaction. It is only valid before any read, buffer, or replacement exists.
func (b *BodyBroker) attachLedger(ledger *Ledger) error {
	if b == nil || ledger == nil {
		return ErrInvalid
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.operation != nil || b.bodyData.charge != nil || len(b.bodyData.data) != 0 || b.bodyData.state != UnreadStream && b.bodyData.state != Unavailable {
		return ErrBodyBusy
	}
	b.ledger = ledger
	b.bodyData.ledger = ledger
	return nil
}

func (b *BodyBroker) Info() BodyInfo {
	b.mu.Lock()
	defer b.mu.Unlock()
	if op := b.operation; op != nil && op.stream {
		info := op.info
		if op.reading {
			info.State = Reading
		}
		return info
	}
	return b.bodyData.infoLocked()
}

func (b *BodyBroker) Prepare(ctx context.Context, need BodyNeed, limit int64) error {
	return b.prepare(ctx, need, limit, nil, nil)
}

func (b *BodyBroker) prepare(ctx context.Context, need BodyNeed, limit int64, accept bodyAcceptance, resources []io.Closer) error {
	if ctx == nil {
		ctx = context.Background()
	}
	b.mu.Lock()
	// Preserve the no-read/no-allocation fast path. Cancellation that needs source
	// disposal goes through the admitted owner instead of calling Close here.
	if need == None && b.operation == nil && b.ctx.Err() == nil && b.ownerContext.Err() == nil && ctx.Err() == nil && !b.closing && b.state != Faulted {
		b.mu.Unlock()
		closeBodyResources(resources)
		return nil
	}
	b.mu.Unlock()
	_, err := b.run(ctx, accept, resources, func(work *bodyData) (int, error) { return 0, work.prepare(ctx, need, limit) })
	return err
}

func (b *BodyBroker) Replace(ctx context.Context, data []byte) error {
	return b.replace(ctx, data, nil)
}
func (b *BodyBroker) replace(ctx context.Context, data []byte, accept bodyAcceptance) error {
	// The worker must never borrow the caller's slice after logical return.
	n, err := copyCharge(int64(len(data)))
	if err != nil {
		return err
	}
	ticket, err := b.ledger.Reserve(n)
	if err != nil {
		return err
	}
	owned := append([]byte(nil), data...)
	var operationErr error
	acceptReplacement := func(publish func() error) error {
		if operationErr != nil || accept == nil {
			return publish()
		}
		return accept(publish)
	}
	_, err = b.run(ctx, acceptReplacement, []io.Closer{bodyReservation{ticket}}, func(work *bodyData) (int, error) {
		operationErr = work.replace(ctx, owned)
		return 0, operationErr
	})
	return err
}

func (b *BodyBroker) TakeStream(ctx context.Context) (io.ReadCloser, error) {
	return b.takeStream(ctx)
}

type bodyStream struct {
	broker    *BodyBroker
	operation *bodyOperation
}

func (s *bodyStream) Close() error               { return s.broker.Close() }
func (s *bodyStream) Read(p []byte) (int, error) { return s.broker.readStream(s.operation, p) }

func (b *BodyBroker) Snapshot(lease *CopyLease) (BodyView, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closing {
		return BodyView{}, ErrReleased
	}
	if b.operation != nil {
		if op := b.operation; op.stream && !op.reading {
			return op.work.snapshot(lease)
		}
		return BodyView{}, ErrBodyBusy
	}
	return b.bodyData.snapshot(lease)
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
