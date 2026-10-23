package model

import (
	"errors"
	"math"
	"sync"
	"testing"
)

func testLedger(t testing.TB, limit int64) *Ledger {
	t.Helper()
	l, err := NewLedger(limit, nil)
	if err != nil {
		t.Fatal(err)
	}
	return l
}
func testLease(t testing.TB, l *Ledger) *CopyLease {
	t.Helper()
	s := NewCopyLease(l)
	t.Cleanup(func() { s.Close() })
	return s
}
func TestBudgetRollbackLimitsAndOverflow(t *testing.T) {
	shared, _ := NewBudget(10)
	l, _ := NewLedger(5, shared)
	r, err := l.Reserve(5)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int64{1, 6, math.MaxInt64} {
		if _, err := l.Reserve(n); !errors.Is(err, ErrResourceLimit) {
			t.Fatalf("Reserve(%d)=%v", n, err)
		}
		if l.Current() != 5 || shared.Current() != 5 {
			t.Fatal("partial reservation survived failure")
		}
	}
	if !r.Release() || r.Release() || l.Current() != 0 || shared.Current() != 0 {
		t.Fatal("release not idempotent")
	}
	if l.Peak() != 5 || shared.Peak() < 5 {
		t.Fatal("peak accounting")
	}
	if _, err := l.Reserve(-1); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	zero := testLedger(t, 0)
	if _, err := zero.Reserve(1); !errors.Is(err, ErrResourceLimit) {
		t.Fatal(err)
	}
	unlimited := testLedger(t, -1)
	large, err := unlimited.Reserve(math.MaxInt64)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unlimited.Reserve(1); !errors.Is(err, ErrResourceLimit) {
		t.Fatal(err)
	}
	large.Release()
	if _, err := NewBudget(-2); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
}

func TestConcurrentBudgetReserveAndDuplicateRelease(t *testing.T) {
	shared, _ := NewBudget(100)
	l, _ := NewLedger(100, shared)
	var wg sync.WaitGroup
	for worker := 0; worker < 16; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				r, err := l.Reserve(1)
				if err != nil {
					t.Error(err)
					return
				}
				var releases sync.WaitGroup
				releases.Add(2)
				go func() { defer releases.Done(); r.Release() }()
				go func() { defer releases.Done(); r.Release() }()
				releases.Wait()
			}
		}()
	}
	wg.Wait()
	if l.Current() != 0 || shared.Current() != 0 || l.Peak() > 100 || shared.Peak() > 100 {
		t.Fatal("invalid concurrent accounting")
	}
}

func TestCopyLeaseCloseWaitsForAllocationPin(t *testing.T) {
	l := testLedger(t, 1000)
	s := NewCopyLease(l)
	if err := s.allocate(100, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	started, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() { done <- s.allocate(200, func() error { close(started); <-release; return nil }) }()
	<-started
	s.Close()
	if l.Current() != 300 {
		t.Fatalf("premature release: %d", l.Current())
	}
	close(release)
	if err := <-done; !errors.Is(err, ErrReleased) {
		t.Fatal(err)
	}
	if l.Current() != 0 {
		t.Fatal("pin leaked")
	}
	if err := s.allocate(1, func() error { t.Error("closed lease allocated"); return nil }); !errors.Is(err, ErrReleased) {
		t.Fatal(err)
	}
}

func TestDefaultTransactionAndFrameworkBudgetsAreSeparateAndBounded(t *testing.T) {
	if DefaultTransactionBudgetBytes != 16<<20 || DefaultFrameworkBudgetBytes != 64<<20 || DefaultBodyBufferBytes != 1<<20 || DefaultProcessorOutputBytes != 1<<20 {
		t.Fatal("default resource policy changed unexpectedly")
	}
	if current := defaultFrameworkBudget.Current(); current != 0 {
		t.Fatalf("framework byte budget leaked before test: %d", current)
	}
	ledgers := make([]*Ledger, 4)
	reservations := make([]*Reservation, 4)
	for i := range ledgers {
		base := testLedger(t, -1)
		ledger, err := newTransactionLedger(base, DefaultTransactionBudgetBytes)
		if err != nil {
			t.Fatal(err)
		}
		ledgers[i] = ledger
		reservations[i], err = ledger.Reserve(DefaultTransactionBudgetBytes)
		if err != nil {
			t.Fatalf("transaction %d could not reserve its exact local limit: %v", i, err)
		}
	}
	if got := defaultFrameworkBudget.Current(); got != DefaultFrameworkBudgetBytes {
		t.Fatalf("framework cap not shared across transactions: %d", got)
	}
	if _, err := ledgers[0].Reserve(1); !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("transaction-local limit was bypassed: %v", err)
	}
	base := testLedger(t, -1)
	fifth, err := newTransactionLedger(base, DefaultTransactionBudgetBytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fifth.Reserve(1); !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("framework aggregate cap was bypassed: %v", err)
	}
	if fifth.Current() != 0 || base.Current() != 0 {
		t.Fatal("failed multi-budget admission left a partial reservation")
	}
	for _, reservation := range reservations {
		if !reservation.Release() || reservation.Release() {
			t.Fatal("reservation release was not single-use")
		}
	}
	if got := defaultFrameworkBudget.Current(); got != 0 {
		t.Fatalf("framework budget did not recover: %d", got)
	}
}
