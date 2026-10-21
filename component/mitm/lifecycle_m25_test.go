package mitm

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/metacubex/mihomo/component/mitm/rewrite"
	"github.com/stretchr/testify/require"
)

// Actual TLS connection shutdown races with publication; old phases stay pinned.
func TestM25ReloadAndConnectionCloseRace(t *testing.T) {
	old := compileM2Rules(t, rewrite.Rule{Name: "old", Response: &rewrite.ResponseAction{Body: &rewrite.BodyReplacement{Replace: "old"}}})
	next := compileM2Rules(t, rewrite.Rule{Name: "new", Response: &rewrite.ResponseAction{Body: &rewrite.BodyReplacement{Replace: "new"}}})
	h := newM2HTTPHarness(t, "localhost", old, func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "origin") })
	for round := 0; round < 12; round++ {
		config := h.manager.ConfigSnapshot()
		config.Rewrite = old
		h.manager.Update(config)
		client, done := h.startTCPClient(t)
		response := sendM2Request(t, client, bufio.NewReader(client), "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n", "GET")
		require.Equal(t, "old", readM2ResponseBody(t, response))
		var worker sync.WaitGroup
		worker.Add(1)
		go func() {
			defer worker.Done()
			for i := 0; i < 100; i++ {
				config.Rewrite = next
				h.manager.Update(config)
				config.Rewrite = old
				h.manager.Update(config)
			}
		}()
		finishM2Dispatch(t, client, done)
		worker.Wait()
	}
}

func TestM25LiveTLSMemory(t *testing.T) {
	h := newM2HTTPHarness(t, "localhost", nil, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})
	runtime.GC()
	var before, active, after runtime.MemStats
	runtime.ReadMemStats(&before)
	clients := make([]*tls.Conn, 16)
	done := make([]<-chan dispatchResult, len(clients))
	for i := range clients {
		clients[i], done[i] = h.startTCPClient(t)
		response := sendM2Request(t, clients[i], bufio.NewReader(clients[i]), "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n", "GET")
		require.Equal(t, "ok", readM2ResponseBody(t, response))
	}
	runtime.GC()
	runtime.ReadMemStats(&active)
	for i := range clients {
		finishM2Dispatch(t, clients[i], done[i])
		clients[i] = nil
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	t.Logf("16 live TLS Keep-Alive connections: heap delta active=%d closed=%d bytes", int64(active.HeapAlloc)-int64(before.HeapAlloc), int64(after.HeapAlloc)-int64(before.HeapAlloc))
}

// This is a bounded retention experiment, not a long-duration load test. Each
// reload owns a distinct 1 MiB payload; only the current snapshot should survive.
func TestM25SnapshotRetention(t *testing.T) {
	manager := NewManager(Config{})
	publish := func(version int) {
		pipeline := compileM2Rules(t, rewrite.Rule{Name: fmt.Sprint(version), Response: &rewrite.ResponseAction{Body: &rewrite.BodyReplacement{Replace: strings.Repeat(fmt.Sprint(version%10), 1<<20)}}})
		manager.Update(Config{Rewrite: pipeline})
	}
	publish(0)
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for i := 1; i <= 64; i++ {
		publish(i)
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	runtime.KeepAlive(manager)
	growth := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	t.Logf("64 reloads x 1 MiB: retained heap growth %d bytes", growth)
	// Leave room for unrelated runtime activity while detecting retained generations.
	require.Less(t, growth, int64(16<<20))
}
