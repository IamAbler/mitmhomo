package gojaprocessor

import (
	"encoding/json"
	"testing"
)

func TestBoundedJSONSizeMatchesRuntimeEncoding(t *testing.T) {
	value := map[string]any{
		"text":  "quotes \" & < \u2028",
		"array": []any{int64(3), true, nil, map[string]any{"body": "AP8="}},
	}
	size, err := boundedJSONSize(value, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if size != len(encoded) {
		t.Fatalf("preflight size %d differs from encoded size %d (%s)", size, len(encoded), encoded)
	}
	if _, err := boundedJSONSize(value, size-1); err == nil {
		t.Fatal("preflight accepted an undersized input limit")
	}
}
