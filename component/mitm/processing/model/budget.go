package model

import (
	"errors"
	"math"
	"sync"
	"sync/atomic"
)

var (
	ErrInvalid         = errors.New("invalid model value")
	ErrResourceLimit   = errors.New("model resource limit exceeded")
	ErrReleased        = errors.New("model resource released")
	ErrBodyUnavailable = errors.New("complete body unavailable")
	ErrBodyLimit       = errors.New("body buffering limit exceeded")
	ErrBodyClaimed     = errors.New("body stream already claimed")
	ErrStaleRevision   = errors.New("stale transaction revision")
	ErrClosed          = errors.New("transaction closed")
)

// Budget is concurrent reservation accounting. -1 means unlimited; zero means
// no charged allocation. Limits must be chosen explicitly by the caller.
type Budget struct {
	limit   int64
	current atomic.Int64
	peak    atomic.Int64
}

func NewBudget(limit int64) (*Budget, error) {
	if limit < -1 {
		return nil, ErrInvalid
	}
	return &Budget{limit: limit}, nil
}

func (b *Budget) Current() int64 { return b.current.Load() }
func (b *Budget) Peak() int64    { return b.peak.Load() }
func (b *Budget) Limit() int64   { return b.limit }

func (b *Budget) reserve(n int64) error {
	if b == nil || n < 0 {
		return ErrInvalid
	}
	for {
		old := b.current.Load()
		if n > math.MaxInt64-old || b.limit >= 0 && n > b.limit-old {
			return ErrResourceLimit
		}
		if b.current.CompareAndSwap(old, old+n) {
			for peak := b.peak.Load(); old+n > peak; peak = b.peak.Load() {
				if b.peak.CompareAndSwap(peak, old+n) {
					break
				}
			}
			return nil
		}
	}
}

// Ledger pairs a transaction-local budget with an optional shared budget.
// A failed two-budget reservation rolls back the first reservation. Peak can
// include that transient admission attempt; Current has no residual charge.
type Ledger struct{ local, shared *Budget }

func NewLedger(limit int64, shared *Budget) (*Ledger, error) {
	local, err := NewBudget(limit)
	if err != nil {
		return nil, err
	}
	return &Ledger{local: local, shared: shared}, nil
}
func (l *Ledger) Current() int64 { return l.local.Current() }
func (l *Ledger) Peak() int64    { return l.local.Peak() }

// Reservation is a single-use release capability. Copies of this pointer share
// the same release guard. It must not be copied by value after first use.
type Reservation struct {
	local, shared *Budget
	bytes         int64
	released      atomic.Bool
}

func (l *Ledger) Reserve(n int64) (*Reservation, error) {
	if l == nil || l.local == nil || n < 0 {
		return nil, ErrInvalid
	}
	if l.shared != nil {
		if err := l.shared.reserve(n); err != nil {
			return nil, err
		}
	}
	if err := l.local.reserve(n); err != nil {
		if l.shared != nil {
			l.shared.current.Add(-n)
		}
		return nil, err
	}
	return &Reservation{local: l.local, shared: l.shared, bytes: n}, nil
}

func (r *Reservation) Release() bool {
	if r == nil || !r.released.CompareAndSwap(false, true) {
		return false
	}
	if r.local != nil {
		r.local.current.Add(-r.bytes)
	}
	if r.shared != nil {
		r.shared.current.Add(-r.bytes)
	}
	return true
}

// CopyLease owns detached input/candidate/checkpoint allocations. Close seals
// new allocations. Outstanding read pins defer release until their copies finish.
// It does not cancel consumers: the execution owner must join them before Close.
type CopyLease struct {
	mu      sync.Mutex
	ledger  *Ledger
	closed  bool
	pins    int
	charges []*Reservation
}

func NewCopyLease(ledger *Ledger) *CopyLease { return &CopyLease{ledger: ledger} }

func (s *CopyLease) pin() (func(), error) {
	if s == nil || s.ledger == nil {
		return nil, ErrInvalid
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, ErrReleased
	}
	s.pins++
	s.mu.Unlock()
	return func() {
		s.mu.Lock()
		s.pins--
		if s.closed && s.pins == 0 {
			s.releaseLocked()
		}
		s.mu.Unlock()
	}, nil
}

// allocate reserves before build. build must not do I/O or call this lease.
func (s *CopyLease) allocate(n int64, build func() error) error {
	unpin, err := s.pin()
	if err != nil {
		return err
	}
	defer unpin()
	charge, err := s.ledger.Reserve(n)
	if err != nil {
		return err
	}
	if err := build(); err != nil {
		charge.Release()
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		charge.Release()
		return ErrReleased
	}
	s.charges = append(s.charges, charge)
	return nil
}

func (s *CopyLease) releaseLocked() {
	for _, r := range s.charges {
		r.Release()
	}
	s.charges = nil
}

func (s *CopyLease) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	s.closed = true
	if s.pins == 0 {
		s.releaseLocked()
	}
	s.mu.Unlock()
	return nil
}

func copyCharge(n int64) (int64, error) {
	// Include conservative metadata/lease-entry overhead, even for empty copies.
	if n < 0 || n > math.MaxInt64-128 {
		return 0, ErrResourceLimit
	}
	return n + 128, nil
}
