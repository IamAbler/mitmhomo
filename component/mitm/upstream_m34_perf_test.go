package mitm

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/stretchr/testify/require"
)

// Same native transport/TLS origin and 100-request, 20-worker workload, with
// either M3.3's nil manager or M3.4's manager. This is a local transport fixture,
// not production end-to-end throughput or process-isolated RSS attribution.
func TestM34TransportComparison(t *testing.T) {
	for _, shared := range []bool{false, true} {
		t.Run(fmt.Sprintf("shared=%v", shared), func(t *testing.T) {
			cert, roots := makeTestUpstreamCertificate(t)
			var accepts, peak, active atomic.Int32
			var mu sync.Mutex
			perConn := map[string]int{}
			maxPerConn := 0
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				a := active.Add(1)
				defer active.Add(-1)
				for old := peak.Load(); a > old; old = peak.Load() {
					if peak.CompareAndSwap(old, a) {
						break
					}
				}
				mu.Lock()
				perConn[r.RemoteAddr]++
				if perConn[r.RemoteAddr] > maxPerConn {
					maxPerConn = perConn[r.RemoteAddr]
				}
				mu.Unlock()
				defer func() { mu.Lock(); perConn[r.RemoteAddr]--; mu.Unlock() }()
				io.Copy(io.Discard, r.Body)
				time.Sleep(2 * time.Millisecond)
				io.WriteString(w, strings.Repeat("x", 32768))
			}))
			server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
			server.EnableHTTP2 = true
			server.Config.ConnState = func(_ net.Conn, s http.ConnState) {
				if s == http.StateNew {
					accepts.Add(1)
				}
			}
			server.StartTLS()
			defer server.Close()
			var pool *upstreamManager
			if shared {
				pool = newUpstreamManager(context.Background(), time.Second)
				defer pool.Close()
			}
			rt := &nativeRoundTripper{pool: pool, target: &C.Metadata{NetWork: C.TCP, Host: "localhost", DstPort: 443}, tlsConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12, NextProtos: []string{"h2"}}, handshakeTimeout: time.Second, requestTimeout: 5 * time.Second, idleTimeout: time.Second, dial: m34Dial(func(*C.Metadata) string { return server.Listener.Addr().String() })}
			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			baseG := runtime.NumGoroutine()
			peakG := baseG
			peakHeap := before.HeapAlloc
			stop, done := make(chan struct{}), make(chan struct{})
			go func() {
				defer close(done)
				timer := time.NewTicker(time.Millisecond)
				defer timer.Stop()
				for {
					select {
					case <-stop:
						return
					case <-timer.C:
						var m runtime.MemStats
						runtime.ReadMemStats(&m)
						if m.HeapAlloc > peakHeap {
							peakHeap = m.HeapAlloc
						}
						if g := runtime.NumGoroutine(); g > peakG {
							peakG = g
						}
					}
				}
			}()
			jobs := make(chan int, 100)
			results := make(chan error, 100)
			start := time.Now()
			for worker := 0; worker < 20; worker++ {
				go func() {
					for i := range jobs {
						method := "GET"
						if i%2 == 1 {
							method = "POST"
						}
						req, _ := http.NewRequest(method, "https://localhost/", strings.NewReader(strings.Repeat("u", 16384)))
						res, e := rt.RoundTrip(req)
						if e == nil {
							var n int64
							n, e = io.Copy(io.Discard, res.Body)
							res.Body.Close()
							if e == nil && n != 32768 {
								e = fmt.Errorf("truncated response")
							}
						}
						results <- e
					}
				}()
			}
			for i := 0; i < 100; i++ {
				jobs <- i
			}
			close(jobs)
			for i := 0; i < 100; i++ {
				require.NoError(t, <-results)
			}
			elapsed := time.Since(start)
			close(stop)
			<-done
			runtime.ReadMemStats(&after)
			if shared {
				require.EqualValues(t, 1, accepts.Load())
				require.Greater(t, maxPerConn, 1)
			} else {
				require.EqualValues(t, 100, accepts.Load())
				require.Equal(t, 1, maxPerConn)
			}
			t.Logf("requests=100 workers=20 TCP_TLS=%d max_streams_per_TCP=%d max_active=%d elapsed=%s requests_per_second=%.2f total_alloc_bytes=%d sampled_heap_peak_bytes=%d heap_start_bytes=%d goroutines_start=%d sampled_goroutines_peak=%d", accepts.Load(), maxPerConn, peak.Load(), elapsed, 100/elapsed.Seconds(), after.TotalAlloc-before.TotalAlloc, peakHeap, before.HeapAlloc, baseG, peakG)
		})
	}
}
