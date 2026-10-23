//go:build !quickjs || !cgo

package quickjs

import (
	"errors"
	"testing"
)

func TestUnavailableBuildIsExplicit(t *testing.T) {
	if _, err := NewRuntime(RuntimeOptions{}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("NewRuntime error = %v, want ErrUnavailable", err)
	}
}
