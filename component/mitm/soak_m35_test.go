package mitm

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/mitm/rewrite"
	C "github.com/metacubex/mihomo/constant"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
)

// Opt-in, repeatable lifecycle soak. No per-cycle Cleanup closures or retained
// subtests: those would measure the test runner's growing fixture list.
// Run MITM_SOAK_DURATION=5m go test ./component/mitm -run '^TestM35Soak$' -v -timeout=7m.
func TestM35Soak(t *testing.T) {
	configured := os.Getenv("MITM_SOAK_DURATION")
	if configured == "" {
		t.Skip("opt-in: set MITM_SOAK_DURATION, e.g. 5m")
	}
	duration, err := time.ParseDuration(configured)
	require.NoError(t, err)
	require.GreaterOrEqual(t, duration, time.Second)
	cert, upRoots := makeTestUpstreamCertificate(t)
	authority, clientRoots := makeTestAuthority(t)
	var accepted, handshakes, upActive, streamActive, peakStreams, requests, downActive atomic.Int64
	cancelEntered, cancelDone := make(chan struct{}, 8), make(chan struct{}, 8)
	payload := strings.Repeat("d", 32768)
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, 2, r.ProtoMajor)
		a := streamActive.Add(1)
		defer streamActive.Add(-1)
		for old := peakStreams.Load(); a > old; old = peakStreams.Load() {
			if peakStreams.CompareAndSwap(old, a) {
				break
			}
		}
		requests.Add(1)
		if r.URL.Path == "/cancel" {
			cancelEntered <- struct{}{}
			<-r.Context().Done()
			cancelDone <- struct{}{}
			return
		}
		if _, err := io.Copy(io.Discard, r.Body); !assert.NoError(t, err) {
			http.Error(w, "upload failed", 500)
			return
		}
		w.Header().Set("X-Epoch", r.Header.Get("X-Epoch"))
		io.WriteString(w, payload)
	}))
	upstream.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) { handshakes.Add(1); return nil, nil }}
	upstream.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			accepted.Add(1)
			upActive.Add(1)
		}
		if s == http.StateClosed {
			upActive.Add(-1)
		}
	}
	upstream.EnableHTTP2 = true
	upstream.StartTLS()
	defer upstream.Close()
	cfg := Config{Enabled: true, Domains: []string{"localhost"}, Ports: []uint16{443}, CA: authority, upstreamRootCAs: upRoots, HandshakeTimeout: 3 * time.Second, RequestTimeout: 5 * time.Second, IdleTimeout: time.Second}
	manager := NewManager(cfg)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			raw, e := listener.Accept()
			if e != nil {
				return
			}
			wg.Add(1)
			downActive.Add(1)
			go func() {
				defer wg.Done()
				defer downActive.Add(-1)
				defer raw.Close()
				manager.Dispatch(ctx, N.NewBufferedConn(raw), &C.Metadata{NetWork: C.TCP, Host: "localhost", DstPort: 443}, nil, m34Dial(func(*C.Metadata) string { return upstream.Listener.Addr().String() }))
			}()
		}
	}()
	defer func() {
		listener.Close()
		cancel()
		done := make(chan struct{})
		go func() { <-acceptDone; wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("soak downstream handlers retained after cancellation")
		}
	}()
	fdCount := func() int {
		if runtime.GOOS != "linux" {
			return -1
		}
		files, e := os.ReadDir("/proc/self/fd")
		if e != nil {
			return -1
		}
		return len(files)
	}
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	baselineG, baselineFD := runtime.NumGoroutine(), fdCount()
	startHeap, startAlloc := mem.HeapAlloc, mem.TotalAlloc
	peakHeap, peakG, peakFD := mem.HeapAlloc, baselineG, baselineFD
	start, nextSample := time.Now(), time.Now().Add(5*time.Second)
	cycles, goaways := 0, 0
	var drained []m35ResourcePoint
	sample := func(phase string) {
		runtime.ReadMemStats(&mem)
		g, fd := runtime.NumGoroutine(), fdCount()
		if phase == "drained" || phase == "steady" {
			drained = append(drained, m35ResourcePoint{seconds: time.Since(start).Seconds(), heap: float64(mem.HeapAlloc), objects: float64(mem.HeapObjects)})
		}
		if mem.HeapAlloc > peakHeap {
			peakHeap = mem.HeapAlloc
		}
		if g > peakG {
			peakG = g
		}
		if fd > peakFD {
			peakFD = fd
		}
		t.Logf("resource phase=%s elapsed=%s cycles=%d requests=%d tcp=%d tls=%d up_active=%d streams_active=%d goroutines=%d heap=%d heap_objects=%d num_gc=%d fd=%d", phase, time.Since(start).Round(time.Millisecond), cycles, requests.Load(), accepted.Load(), handshakes.Load(), upActive.Load(), streamActive.Load(), g, mem.HeapAlloc, mem.HeapObjects, mem.NumGC, fd)
	}
	for time.Since(start) < duration {
		func() {
			cycleCtx, cancelCycle := context.WithTimeout(ctx, 10*time.Second)
			defer cancelCycle()
			epoch := strconv.Itoa(cycles)
			cfg.Rewrite = compileM2Rules(t, rewrite.Rule{Name: "epoch", Request: &rewrite.RequestAction{Headers: rewrite.HeaderAction{Set: map[string]string{"X-Epoch": epoch}}}})
			manager.Update(cfg)
			raw, e := (&net.Dialer{}).DialContext(cycleCtx, "tcp", listener.Addr().String())
			require.NoError(t, e)
			defer raw.Close()
			require.NoError(t, raw.SetDeadline(time.Now().Add(3*time.Second)))
			secure := tls.Client(raw, &tls.Config{RootCAs: clientRoots, ServerName: "localhost", NextProtos: []string{"h2"}, MinVersion: tls.VersionTLS12})
			require.NoError(t, secure.HandshakeContext(cycleCtx))
			cc, e := (&http2.Transport{StrictMaxConcurrentStreams: true}).NewClientConn(secure)
			require.NoError(t, e)
			defer func() { raw.Close(); cc.Close() }()
			require.NoError(t, raw.SetDeadline(time.Time{}))
			send := func(n int) {
				batch := newM35Batch(cycleCtx, n, 5*time.Second, func() { raw.Close() })
				defer batch.Close(t)
				for i := 0; i < n; i++ {
					batch.Go(func(requestCtx context.Context) error {
						req, _ := http.NewRequestWithContext(requestCtx, "POST", "https://localhost/", strings.NewReader(strings.Repeat("u", 16384)))
						res, e := cc.RoundTrip(req)
						if e == nil {
							var n int64
							n, e = io.Copy(io.Discard, res.Body)
							res.Body.Close()
							if e == nil && (n != 32768 || res.Header.Get("X-Epoch") != epoch) {
								e = fmt.Errorf("response/snapshot mismatch")
							}
						}
						return e
					})
				}
				for _, err := range batch.Wait(t) {
					require.NoError(t, err)
				}
			}
			send(20)
			canceledBatch := newM35Batch(cycleCtx, 8, 5*time.Second, func() { raw.Close() })
			defer canceledBatch.Close(t)
			cancels := make([]context.CancelFunc, 8)
			for i := range cancels {
				requestCtx, stop := context.WithCancel(canceledBatch.ctx)
				cancels[i] = stop
				defer stop()
				canceledBatch.Go(func(context.Context) error {
					req, _ := http.NewRequestWithContext(requestCtx, "POST", "https://localhost/cancel", nil)
					res, e := cc.RoundTrip(req)
					if res != nil {
						res.Body.Close()
					}
					return e
				})
			}
			canceledBatch.Await(t, cancelEntered, 8, 3*time.Second)
			sample("active-cancel")
			for _, stop := range cancels {
				stop()
			}
			for _, err := range canceledBatch.Wait(t) {
				require.ErrorIs(t, err, context.Canceled)
			}
			canceledBatch.Await(t, cancelDone, 8, 3*time.Second)
			// The old downstream keeps its snapshot after an internal manager reload.
			cfg.Rewrite = compileM2Rules(t, rewrite.Rule{Name: "new", Request: &rewrite.RequestAction{Headers: rewrite.HeaderAction{Set: map[string]string{"X-Epoch": "next"}}}})
			manager.Update(cfg)
			send(1)
			require.EqualValues(t, cycles+1, accepted.Load(), "one TCP per downstream lifecycle, including after cancellation")
			raw.Close()
			cc.Close()
			require.Eventually(t, func() bool { return upActive.Load() == 0 && streamActive.Load() == 0 && downActive.Load() == 0 }, 3*time.Second, time.Millisecond)
			cycles++
			if cycles%50 == 0 {
				m34GoAwayDrainAndNoReplay(t)
				goaways++
			}
			if time.Now().After(nextSample) {
				sample("drained")
				nextSample = time.Now().Add(5 * time.Second)
			}
		}()
		// Explicit low duty cycle makes repeated create/cancel/close the workload,
		// rather than claiming an unconstrained throughput benchmark.
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
	require.Eventually(t, func() bool { return runtime.NumGoroutine() <= baselineG+8 }, 3*time.Second, 10*time.Millisecond)
	if baselineFD >= 0 {
		require.LessOrEqual(t, fdCount(), baselineFD+2)
	}
	for i := 0; i < 5; i++ {
		require.Zero(t, upActive.Load())
		require.Zero(t, streamActive.Load())
		require.Zero(t, downActive.Load())
		require.LessOrEqual(t, runtime.NumGoroutine(), baselineG+8)
		if baselineFD >= 0 {
			require.LessOrEqual(t, fdCount(), baselineFD+2)
		}
		sample("steady")
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			t.Fatal(ctx.Err())
		}
	}
	sample("final-drained")
	if len(drained) >= 3 {
		// Omit the initial warm-up sample; report regressions, not a GC-sensitive
		// pass threshold for heap. FD/goroutine/connection invariants remain strict.
		points := drained[1:]
		t.Logf("SOAK_TREND drained_samples=%d heap_bytes_per_second=%.2f heap_objects_per_second=%.2f first_heap=%.0f last_heap=%.0f explicit_GC=0", len(points), m35ResourceSlope(points, false), m35ResourceSlope(points, true), points[0].heap, points[len(points)-1].heap)
	}
	require.Equal(t, accepted.Load(), handshakes.Load())
	t.Logf("SOAK_SUMMARY duration=%s cycles=%d requests=%d concurrency=20 cancel_streams_per_cycle=8 tcp_tls=%d peak_streams=%d goaway_rounds=%d goaway_extra_tcp=%d goroutines_start=%d goroutines_end=%d sampled_goroutines_peak=%d heap_start=%d heap_end=%d sampled_heap_peak=%d total_alloc_delta=%d fd_start=%d fd_end=%d sampled_fd_peak=%d explicit_GC=0", time.Since(start).Round(time.Millisecond), cycles, requests.Load(), accepted.Load(), peakStreams.Load(), goaways, goaways*2, baselineG, runtime.NumGoroutine(), peakG, startHeap, mem.HeapAlloc, peakHeap, mem.TotalAlloc-startAlloc, baselineFD, fdCount(), peakFD)
}

type m35ResourcePoint struct{ seconds, heap, objects float64 }

func m35ResourceSlope(points []m35ResourcePoint, objects bool) float64 {
	var timeMean, valueMean float64
	for _, point := range points {
		timeMean += point.seconds
		if objects {
			valueMean += point.objects
		} else {
			valueMean += point.heap
		}
	}
	timeMean /= float64(len(points))
	valueMean /= float64(len(points))
	var numerator, denominator float64
	for _, point := range points {
		value := point.heap
		if objects {
			value = point.objects
		}
		delta := point.seconds - timeMean
		numerator += delta * (value - valueMean)
		denominator += delta * delta
	}
	if denominator == 0 {
		return 0
	}
	return numerator / denominator
}
