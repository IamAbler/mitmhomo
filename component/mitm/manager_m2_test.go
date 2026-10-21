package mitm

import (
	"context"
	"net/url"
	"sync"
	"testing"

	"github.com/metacubex/mihomo/component/mitm/rewrite"
)

func TestM2ConcurrentSnapshotPublication(t *testing.T) {
	build := func(method string) *rewrite.Snapshot {
		s, err := rewrite.Compile(rewrite.Config{Enable: true, Rules: []rewrite.Rule{{Name: "method", Request: &rewrite.RequestAction{Method: method}}}})
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	first, second := build("POST"), build("PATCH")
	manager := NewManager(Config{Rewrite: first})
	pinned := manager.ConfigSnapshot()
	target, _ := url.Parse("https://a.example/")
	request := rewrite.RequestView{URL: *target, Method: "GET"}
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		for i := 0; i < 500; i++ {
			manager.Update(Config{Rewrite: first})
			manager.Update(Config{Rewrite: second})
		}
	}()
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for j := 0; j < 500; j++ {
				snapshot := manager.ConfigSnapshot()
				result, err := snapshot.Rewrite.ApplyRequest(context.Background(), request)
				if err != nil || (result.Request.Method != "POST" && result.Request.Method != "PATCH") {
					t.Error("mixed published snapshot")
					return
				}
				old, err := pinned.Rewrite.ApplyRequest(context.Background(), request)
				if err != nil || old.Request.Method != "POST" {
					t.Error("pinned snapshot mutated")
					return
				}
			}
		}()
	}
	workers.Wait()
}
