package jsruntime

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestInputPreflightBoundsDepthArraysStringsAndCustomEncoders(t *testing.T) {
	config := testConfig()
	config.MaxInputBytes = 64
	r := newTestRuntime(t, config)

	var nested any
	for i := 0; i < maxJSONDepth+2; i++ {
		nested = []any{nested}
	}
	if _, err := r.Run(context.Background(), `input`, nested); !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("deep input error = %v, want ErrResourceLimit", err)
	}
	if _, err := r.Run(context.Background(), `input`, []string{strings.Repeat("x", 128)}); !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("large string input error = %v, want ErrResourceLimit", err)
	}
	if _, err := r.Run(context.Background(), `input`, make([]int, 1000)); !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("large array input error = %v, want ErrResourceLimit", err)
	}

	called := false
	custom := customJSONEncoder{called: &called}
	if _, err := r.Run(context.Background(), `input`, custom); !errors.Is(err, ErrInputConversion) {
		t.Fatalf("custom encoder error = %v, want ErrInputConversion", err)
	}
	if called {
		t.Fatal("custom MarshalJSON ran before the input limit check")
	}
}

func TestInputPreflightPreservesStandardJSONShapes(t *testing.T) {
	type taggedInput struct {
		Name  string `json:"name,omitempty"`
		Count int    `json:"count,string"`
	}
	r := newTestRuntime(t, testConfig())

	got, err := r.Run(context.Background(), `input.count === "7" ? input.name : "bad"`, taggedInput{Name: "ok", Count: 7})
	if err != nil || got != "ok" {
		t.Fatalf("tagged struct result = %#v, err=%v", got, err)
	}
	got, err = r.Run(context.Background(), `input["1"]`, map[int]string{1: "one"})
	if err != nil || got != "one" {
		t.Fatalf("integer-key map result = %#v, err=%v", got, err)
	}
	got, err = r.Run(context.Background(), `input`, []byte("hi"))
	if err != nil || got != "aGk=" {
		t.Fatalf("byte-slice result = %#v, err=%v", got, err)
	}
}

func TestOutputLimitRejectsLargeStringAndArrayBeforeStringifyCompletes(t *testing.T) {
	config := testConfig()
	config.MaxOutputBytes = 64
	r := newTestRuntime(t, config)

	for _, source := range []string{
		`"x".repeat(4 * 1024 * 1024)`,
		`new String("x".repeat(4 * 1024 * 1024))`,
		`({ ["x".repeat(4 * 1024 * 1024)]: 1 })`,
		`new Array(100000).fill("value")`,
	} {
		if _, err := r.Run(context.Background(), source, nil); !errors.Is(err, ErrResourceLimit) {
			t.Errorf("source %q output error = %v, want ErrResourceLimit", source, err)
		}
	}
}

func TestOutputLimitAccountsForEscapingAndAllowsWithinLimit(t *testing.T) {
	config := testConfig()
	config.MaxOutputBytes = 16
	r := newTestRuntime(t, config)
	got, err := r.Run(context.Background(), `"<ok>"`, nil)
	if err != nil || got != "<ok>" {
		t.Fatalf("escaped result = %#v, err=%v", got, err)
	}

	config.MaxOutputBytes = 5 // JSON representation of the string "abc" is five bytes.
	r = newTestRuntime(t, config)
	if got, err = r.Run(context.Background(), `"abc"`, nil); err != nil || got != "abc" {
		t.Fatalf("at-limit result = %#v, err=%v", got, err)
	}

	config.MaxOutputBytes = len([]byte(`"😀"`))
	r = newTestRuntime(t, config)
	if got, err = r.Run(context.Background(), `"😀"`, nil); err != nil || got != "😀" {
		t.Fatalf("UTF-16 pair at-limit result = %#v, err=%v", got, err)
	}

	const emojiKeyJSON = `{"😀":1}`
	config.MaxOutputBytes = len([]byte(emojiKeyJSON)) + 1 // Output preflight reserves one comma byte.
	r = newTestRuntime(t, config)
	if got, err = r.Run(context.Background(), `({["😀"]: 1})`, nil); err != nil || !reflect.DeepEqual(got, map[string]any{"😀": float64(1)}) {
		t.Fatalf("UTF-16 pair key at-limit result = %#v, err=%v", got, err)
	}

	config.MaxOutputBytes = 8 // JSON.stringify escapes an unpaired surrogate as six bytes.
	r = newTestRuntime(t, config)
	if got, err = r.Run(context.Background(), `"\uD800"`, nil); err != nil || got != "\uFFFD" {
		t.Fatalf("unpaired surrogate result = %#v, err=%v", got, err)
	}
}

func TestTimeoutAndNormalCompletionCompetition(t *testing.T) {
	config := testConfig()
	config.ExecutionTimeout = 2 * time.Millisecond
	r := newTestRuntime(t, config)
	source := `var i = 0; while (i < 3000) i++; i`
	for attempt := 0; attempt < 40; attempt++ {
		_, err := r.Run(context.Background(), source, nil)
		if err != nil && !errors.Is(err, ErrTimeout) {
			t.Fatalf("attempt %d error = %v, want success or timeout", attempt, err)
		}
	}
}

func TestJavaScriptExceptionAndTimeoutCompetition(t *testing.T) {
	config := testConfig()
	config.ExecutionTimeout = time.Millisecond
	r := newTestRuntime(t, config)
	source := `var i = 0; while (i < 10000) i++; throw new Error("finished")`
	for attempt := 0; attempt < 20; attempt++ {
		_, err := r.Run(context.Background(), source, nil)
		if !errors.Is(err, ErrExecution) && !errors.Is(err, ErrTimeout) {
			t.Fatalf("attempt %d error = %v, want execution error or timeout", attempt, err)
		}
	}
}

func TestForeignCompiledProgramsAreRejected(t *testing.T) {
	first := newTestRuntime(t, testConfig())
	second := newTestRuntime(t, testConfig())
	compiled, err := first.Compile(`42`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := second.RunCompiled(context.Background(), compiled, nil); !errors.Is(err, ErrInvalidProgram) {
		t.Fatalf("foreign compiled program error = %v, want ErrInvalidProgram", err)
	}
	if got, err := first.RunCompiled(context.Background(), compiled, nil); err != nil || got != float64(42) {
		t.Fatalf("own compiled program result = %#v, err=%v", got, err)
	}
}

func TestCompilationRejectsOversizedSourceBeforeHashOrCompile(t *testing.T) {
	config := testConfig()
	config.MaxSourceBytes = 32
	r := newTestRuntime(t, config)
	if _, err := r.Compile(strings.Repeat(" ", 33)); !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("oversized source error = %v, want ErrResourceLimit", err)
	}
	if _, err := r.Run(context.Background(), fmt.Sprintf("%q", strings.Repeat("x", 40)), nil); !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("oversized source through Run error = %v, want ErrResourceLimit", err)
	}
}

type customJSONEncoder struct {
	called *bool
}

func (encoder customJSONEncoder) MarshalJSON() ([]byte, error) {
	*encoder.called = true
	return []byte(`null`), nil
}
