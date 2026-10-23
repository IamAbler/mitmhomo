package processor

import (
	"context"
	"errors"
	"testing"

	"github.com/metacubex/mihomo/component/mitm/processing/model"
)

func TestInvocationPoolRejectsAndRecoversWithoutWaiting(t *testing.T) {
	pool := NewInvocationPool(1)
	first, err := pool.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if pool.Occupied() != 1 || pool.Capacity() != 1 {
		t.Fatal("admission did not occupy its independent invocation slot")
	}
	if _, err := pool.Acquire(context.Background()); !errors.Is(err, model.ErrCapacityExhausted) || pool.Rejected() != 1 {
		t.Fatalf("full pool did not reject immediately: err=%v rejected=%d", err, pool.Rejected())
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil || pool.Occupied() != 0 {
		t.Fatalf("permit release was not idempotent: err=%v occupied=%d", err, pool.Occupied())
	}
	recovered, err := pool.Acquire(context.Background())
	if err != nil {
		t.Fatalf("capacity was not restored: %v", err)
	}
	_ = recovered.Close()
}
