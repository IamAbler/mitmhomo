package processor

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/metacubex/mihomo/component/mitm/processing/model"
)

func BenchmarkInvocationNormalCompletion(b *testing.B) {
	b.ReportAllocs()
	key := testKey(1)
	for n := 0; n < b.N; n++ {
		invocation, completion := NewInvocation(context.Background(), key)
		if !completion.Finish(model.Continue(), nil) {
			b.Fatal("Finish rejected")
		}
		if _, err := invocation.Await(context.Background()); err != nil {
			b.Fatal(err)
		}
		<-invocation.ExecutionDone()
	}
}

func BenchmarkInvocationCancel(b *testing.B) {
	b.ReportAllocs()
	key := testKey(2)
	for n := 0; n < b.N; n++ {
		invocation, completion := NewInvocation(context.Background(), key)
		invocation.Cancel(errors.New("benchmark cancel"))
		if _, err := invocation.Await(context.Background()); err == nil {
			b.Fatal("cancel returned success")
		}
		completion.Finish(model.Continue(), nil)
		<-invocation.ExecutionDone()
	}
}

func BenchmarkCompletionCompetition(b *testing.B) {
	b.ReportAllocs()
	key := testKey(3)
	for n := 0; n < b.N; n++ {
		invocation, completion := NewInvocation(context.Background(), key)
		start := make(chan struct{})
		var workers sync.WaitGroup
		workers.Add(2)
		go func() { defer workers.Done(); <-start; completion.Finish(model.Continue(), nil) }()
		go func() { defer workers.Done(); <-start; invocation.Cancel(context.Canceled) }()
		close(start)
		workers.Wait()
		<-invocation.ExecutionDone()
	}
}

func BenchmarkDoneResultConstruct(b *testing.B) {
	b.ReportAllocs()
	for n := 0; n < b.N; n++ {
		result := model.Continue()
		if !result.Valid() {
			b.Fatal("Continue invalid")
		}
	}
}

func BenchmarkRequestPatchCopy(b *testing.B) {
	ledger, err := model.NewLedger(-1, nil)
	if err != nil {
		b.Fatal(err)
	}
	sourceLease := model.NewCopyLease(ledger)
	u, err := model.ParseURL(sourceLease, "https://example.test/a%2Fb?x=1&x=2", model.MITMHTTPS)
	if err != nil {
		b.Fatal(err)
	}
	patch := model.RequestPatch{
		Method:  model.Optional[string]{Present: true, Value: "PATCH"},
		URL:     model.Optional[model.URLValue]{Present: true, Value: u},
		Headers: []model.HeaderEdit{{Kind: model.HeaderSet, Name: "X-Bench", Values: []string{"one", "two"}}},
		Body:    model.BodyEdit{Kind: model.BodyReplace, Bytes: make([]byte, 1024)},
	}
	b.SetBytes(1024)
	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		result, err := model.ChangeRequest(patch, ledger, 1024)
		if err != nil {
			b.Fatal(err)
		}
		if err := result.Release(); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	_ = sourceLease.Close()
}

func BenchmarkSyntheticResponseConstruct(b *testing.B) {
	ledger, err := model.NewLedger(-1, nil)
	if err != nil {
		b.Fatal(err)
	}
	inputLease := model.NewCopyLease(ledger)
	headers, err := model.NewHeaderBlock(inputLease, []model.HeaderField{{Name: "Content-Type", Values: []string{"text/plain"}}})
	if err != nil {
		b.Fatal(err)
	}
	trailers, err := model.NewTrailerView(model.TrailerComplete, model.HeaderBlock{}, model.HeaderBlock{})
	if err != nil {
		b.Fatal(err)
	}
	body := make([]byte, 128)
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		response, err := model.NewSyntheticResponse(200, headers, body, trailers, ledger, int64(len(body)))
		if err != nil {
			b.Fatal(err)
		}
		if err := response.Release(); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	_ = inputLease.Close()
}
