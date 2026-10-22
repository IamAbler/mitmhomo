package httphook

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

var benchmarkHookResult RequestResult

func BenchmarkHTTPHookUnconfigured(b *testing.B) {
	var snapshot *Snapshot
	request, _ := http.NewRequest(http.MethodGet, "https://example.test/", nil)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if snapshot != nil {
			benchmarkHookResult, _ = snapshot.ApplyRequest(context.Background(), request)
		}
	}
}

func BenchmarkHTTPHookUnmatched(b *testing.B) {
	snapshot, err := Compile(Config{Enable: true, Rules: []Rule{{Name: "never", Phase: RequestPhase, Match: Match{Path: "/match"}, Source: `null`}}})
	if err != nil {
		b.Fatal(err)
	}
	defer snapshot.Close()
	request, _ := http.NewRequest(http.MethodGet, "https://example.test/miss", nil)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchmarkHookResult, err = snapshot.ApplyRequest(context.Background(), request)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHTTPHookMatchedPassthrough(b *testing.B) {
	snapshot, err := Compile(Config{Enable: true, Rules: []Rule{{Name: "pass", Phase: RequestPhase, Source: `null`}}})
	if err != nil {
		b.Fatal(err)
	}
	defer snapshot.Close()
	request, _ := http.NewRequest(http.MethodPost, "https://example.test/match", strings.NewReader("small request body"))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		request.Body = io.NopCloser(strings.NewReader("small request body"))
		benchmarkHookResult, err = snapshot.ApplyRequest(context.Background(), request)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHTTPHookMatchedMutation(b *testing.B) {
	snapshot, err := Compile(Config{Enable: true, Rules: []Rule{{
		Name: "mutate", Phase: RequestPhase, Source: `({headers: Object.assign({}, input.headers, {"X-Hook": ["yes"]}), body: input.body + "!"})`,
	}}})
	if err != nil {
		b.Fatal(err)
	}
	defer snapshot.Close()
	request, _ := http.NewRequest(http.MethodPost, "https://example.test/match", strings.NewReader("small request body"))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		request.Body = io.NopCloser(strings.NewReader("small request body"))
		benchmarkHookResult, err = snapshot.ApplyRequest(context.Background(), request)
		if err != nil {
			b.Fatal(err)
		}
	}
}
