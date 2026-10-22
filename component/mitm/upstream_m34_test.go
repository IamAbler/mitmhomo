package mitm

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/mitm/rewrite"
	"github.com/stretchr/testify/require"
)

// Barrier assertions prove simultaneous streams, not sequential keep-alive.
// RemoteAddr identifies the accepted TLS socket independently of native dials.
func TestM34ConcurrentReuse(t *testing.T) {
	for _, n := range []int{10, 20, 50, 100} {
		t.Run(strconv.Itoa(n), func(t *testing.T) {
			entered := make(chan struct{}, n)
			release := make(chan struct{})
			var releaseOnce sync.Once
			defer releaseOnce.Do(func() { close(release) })
			var mu sync.Mutex
			sockets := map[string]int{}
			var active, peak atomic.Int32
			pipeline, err := rewrite.Compile(rewrite.Config{Enable: true, Rules: []rewrite.Rule{{Name: "header", Request: &rewrite.RequestAction{Headers: rewrite.HeaderAction{Set: map[string]string{"X-Rewritten": "yes"}}}}}})
			require.NoError(t, err)
			h := newProtocolHarness(t, nil, "localhost", 443, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer active.Add(-1)
				a := active.Add(1)
				for old := peak.Load(); a > old; old = peak.Load() {
					if peak.CompareAndSwap(old, a) {
						break
					}
				}
				mu.Lock()
				sockets[r.RemoteAddr]++
				mu.Unlock()
				if r.ProtoMajor != 2 || r.TLS.NegotiatedProtocol != "h2" || r.Header.Get("X-Rewritten") != "yes" {
					t.Error("wire protocol/rewrite mismatch")
				}
				b, e := io.ReadAll(r.Body)
				if e != nil {
					t.Error(e)
					return
				}
				if r.Method == "POST" && (string(b) != "upload" || r.Trailer.Get("X-Up") != "done") {
					t.Error("upload/trailer mismatch")
				}
				entered <- struct{}{}
				select {
				case <-release:
				case <-r.Context().Done():
					return
				}
				// Different sizes and release order without serializing transport.
				i, _ := strconv.Atoi(r.URL.Query().Get("i"))
				time.Sleep(time.Duration(n-i) * time.Microsecond)
				w.Header().Set("Trailer", "X-Down")
				io.WriteString(w, strings.Repeat("r", 1+i*997))
				w.Header().Set("X-Down", "done")
			}), false, true, true, []string{"h2"}, func(c *Config) {
				c.Rewrite = pipeline
				c.RequestTimeout = 15 * time.Second
				c.IdleTimeout = 15 * time.Second
			})
			results := make(chan error, n)
			start := time.Now()
			for i := 0; i < n; i++ {
				go func(i int) {
					method := "GET"
					if i%2 == 1 {
						method = "POST"
					}
					req, _ := http.NewRequest(method, fmt.Sprintf("https://localhost/?i=%d", i), strings.NewReader("upload"))
					if method == "POST" {
						req.ContentLength = -1
						req.Trailer = http.Header{"X-Up": {"done"}}
					}
					res, e := h.client.RoundTrip(req)
					if e == nil {
						var b []byte
						b, e = io.ReadAll(res.Body)
						res.Body.Close()
						if e == nil && (len(b) != 1+i*997 || res.Trailer.Get("X-Down") != "done") {
							e = fmt.Errorf("response %d length/trailer mismatch", i)
						}
					}
					results <- e
				}(i)
			}
			for i := 0; i < n; i++ {
				select {
				case <-entered:
				case <-time.After(10 * time.Second):
					t.Fatal("streams did not concurrently reach upstream")
				}
			}
			require.EqualValues(t, 1, h.accepted.Load(), "actual upstream TCP accepts")
			require.EqualValues(t, 1, h.dials.Load(), "native route selected once")
			require.EqualValues(t, n, peak.Load())
			mu.Lock()
			require.Len(t, sockets, 1)
			for _, count := range sockets {
				require.Equal(t, n, count)
			}
			mu.Unlock()
			releaseOnce.Do(func() { close(release) })
			for i := 0; i < n; i++ {
				require.NoError(t, <-results)
			}
			t.Logf("requests=%d TCP/TLS=%d max_active=%d duration=%s", n, h.accepted.Load(), peak.Load(), time.Since(start))
		})
	}
}

// A response streams while its request is still uploading; another stream
// finishes before that upload is released. No connection-wide I/O lock.
func TestM34FullDuplexAndUnreadBody(t *testing.T) {
	upload := make(chan struct{})
	defer close(upload)
	h := newProtocolHarness(t, nil, "localhost", 443, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/duplex" {
			w.WriteHeader(200)
			io.WriteString(w, "early")
			w.(http.Flusher).Flush()
			b, e := io.ReadAll(r.Body)
			if e != nil || string(b) != "late" {
				t.Error("upload interrupted", e)
			}
			io.WriteString(w, "final")
			return
		}
		if r.URL.Path == "/unread" {
			for i := 0; i < 256; i++ {
				if _, e := io.WriteString(w, strings.Repeat("z", 16384)); e != nil {
					return
				}
			}
			return
		}
		io.WriteString(w, "sibling")
	}), false, true, true, []string{"h2"})
	reader, writer := io.Pipe()
	req, _ := http.NewRequest("POST", "https://localhost/duplex", reader)
	go func() { <-upload; io.WriteString(writer, "late"); writer.Close() }()
	res, err := h.client.RoundTrip(req)
	require.NoError(t, err)
	b := make([]byte, 5)
	_, err = io.ReadFull(res.Body, b)
	require.NoError(t, err)
	require.Equal(t, "early", string(b))
	sibling := h2Request(t, h, "GET", "/sibling", "")
	require.Equal(t, "sibling", readM2ResponseBody(t, sibling))
	// Complete upload before checking body and leave the deferred close harmless.
	upload <- struct{}{}
	require.Equal(t, "final", readM2ResponseBody(t, res))
	unread := h2Request(t, h, "GET", "/unread", "")
	require.NoError(t, unread.Body.Close())
	sibling = h2Request(t, h, "GET", "/sibling", "")
	require.Equal(t, "sibling", readM2ResponseBody(t, sibling))
	require.EqualValues(t, 1, h.accepted.Load())
}

func TestM34SnapshotMultipleStreams(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]int{}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		mu.Lock()
		seen[r.URL.Path]++
		mu.Unlock()
		w.Header().Set("X-Echo", r.Header.Get("X-Step"))
		io.WriteString(w, "origin")
	})
	old := newProtocolHarness(t, nil, "localhost", 443, handler, false, true, true, []string{"h2"}, func(c *Config) { c.Rewrite = m24Pipeline(t, "old") })
	run := func(h *h2Harness, want string) {
		results := make(chan string, 10)
		for i := 0; i < 10; i++ {
			go func() {
				req, _ := http.NewRequestWithContext(context.Background(), "POST", "https://localhost/start", nil)
				res, e := h.client.RoundTrip(req)
				if e != nil {
					results <- e.Error()
					return
				}
				b, e := io.ReadAll(res.Body)
				res.Body.Close()
				if e != nil {
					results <- e.Error()
					return
				}
				results <- string(b)
			}()
		}
		for i := 0; i < 10; i++ {
			require.Equal(t, "response-"+want, <-results)
		}
	}
	run(old, "old")
	cfg := old.manager.ConfigSnapshot()
	cfg.Rewrite = m24Pipeline(t, "new")
	old.manager.Update(cfg)
	run(old, "old")
	fresh := newProtocolHarness(t, old.manager, "localhost", 443, handler, false, true, true, []string{"h2"})
	run(fresh, "new")
	require.EqualValues(t, 1, old.accepted.Load())
	require.EqualValues(t, 1, fresh.accepted.Load())
	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, map[string]int{"/final/old": 20, "/final/new": 10}, seen)
}
