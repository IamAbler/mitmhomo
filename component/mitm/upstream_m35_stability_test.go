package mitm

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestM35MoreThan100Requests(t *testing.T) {
	const total = 160
	entered, release := make(chan struct{}, total), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	var active, peak, completed atomic.Int32
	h := newProtocolHarness(t, nil, "localhost", 443, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a := active.Add(1)
		defer active.Add(-1)
		for old := peak.Load(); a > old; old = peak.Load() {
			if peak.CompareAndSwap(old, a) {
				break
			}
		}
		entered <- struct{}{}
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		io.WriteString(w, "ok")
		completed.Add(1)
	}), false, true, true, []string{"h2"}, func(c *Config) { c.RequestTimeout = 15 * time.Second; c.IdleTimeout = 15 * time.Second })
	batch := newM35Batch(context.Background(), total, 20*time.Second, func() { h.raw.Close() })
	defer batch.Close(t)
	for i := 0; i < total; i++ {
		batch.Go(func(ctx context.Context) error {
			req, _ := http.NewRequestWithContext(ctx, "GET", "https://localhost/batch", nil)
			res, e := h.client.RoundTrip(req)
			if e == nil {
				var b []byte
				b, e = io.ReadAll(res.Body)
				res.Body.Close()
				if string(b) != "ok" {
					e = fmt.Errorf("bad body: %q", b)
				}
			}
			return e
		})
	}
	// Downstream advertises MAX_CONCURRENT_STREAMS=100. The remaining 60 calls
	// must queue, not redial, fail or get serialized one at a time.
	batch.Await(t, entered, 100, 10*time.Second)
	require.EqualValues(t, 1, h.accepted.Load())
	require.EqualValues(t, 100, peak.Load())
	once.Do(func() { close(release) })
	for _, err := range batch.Wait(t) {
		require.NoError(t, err)
	}
	require.EqualValues(t, total, completed.Load())
	require.EqualValues(t, 1, h.dials.Load())
	require.EqualValues(t, 1, h.accepted.Load())
	require.LessOrEqual(t, peak.Load(), int32(100))
	t.Logf("offered_concurrent=160 negotiated_downstream_limit=100 peak_streams=%d upstream_TCP_TLS=%d", peak.Load(), h.accepted.Load())
}

func TestM35StreamTimeoutAndMassCancel(t *testing.T) {
	entered := make(chan struct{}, 20)
	upstreamCanceled := make(chan struct{}, 16)
	release := make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	h := newProtocolHarness(t, nil, "localhost", 443, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/timeout" {
			<-r.Context().Done()
			return
		}
		entered <- struct{}{}
		if r.URL.Path == "/cancel" {
			<-r.Context().Done()
			upstreamCanceled <- struct{}{}
			return
		}
		select {
		case <-release:
			io.WriteString(w, "ok")
		case <-r.Context().Done():
		}
	}), false, true, true, []string{"h2"}, func(c *Config) { c.RequestTimeout = 2 * time.Second })
	res := h2Request(t, h, "POST", "/timeout", "once")
	require.Equal(t, 504, res.StatusCode)
	res.Body.Close()
	batch := newM35Batch(context.Background(), 20, 10*time.Second, func() { h.raw.Close() })
	defer batch.Close(t)
	cancels := make([]context.CancelFunc, 16)
	send := func(ctx context.Context, path string) error {
		req, _ := http.NewRequestWithContext(ctx, "POST", "https://localhost"+path, nil)
		res, e := h.client.RoundTrip(req)
		if res != nil {
			b, readErr := io.ReadAll(res.Body)
			res.Body.Close()
			if e == nil {
				e = readErr
			}
			if e == nil && string(b) != "ok" {
				e = fmt.Errorf("bad survivor %q", b)
			}
		}
		return e
	}
	for i := range cancels {
		ctx, cancel := context.WithCancel(batch.ctx)
		cancels[i] = cancel
		defer cancel()
		batch.Go(func(context.Context) error { return send(ctx, "/cancel") })
	}
	for i := 0; i < 4; i++ {
		batch.Go(func(ctx context.Context) error { return send(ctx, "/survive") })
	}
	batch.Await(t, entered, 20, 3*time.Second)
	for _, cancel := range cancels {
		cancel()
	}
	batch.Await(t, upstreamCanceled, 16, 3*time.Second)
	once.Do(func() { close(release) })
	failed, succeeded := 0, 0
	for _, err := range batch.Wait(t) {
		if err != nil {
			require.ErrorIs(t, err, context.Canceled)
			failed++
		} else {
			succeeded++
		}
	}
	require.Equal(t, 16, failed)
	require.Equal(t, 4, succeeded)
	res = h2Request(t, h, "GET", "/after", "")
	require.Equal(t, "ok", readM2ResponseBody(t, res))
	require.EqualValues(t, 1, h.accepted.Load(), "timeout/reset must preserve sibling TCP")
}

func TestM35DownstreamDisconnectActiveStreams(t *testing.T) {
	entered, canceled := make(chan struct{}, 8), make(chan struct{}, 8)
	h := newProtocolHarness(t, nil, "localhost", 443, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		<-r.Context().Done()
		canceled <- struct{}{}
	}), false, true, true, []string{"h2"})
	batch := newM35Batch(context.Background(), 8, 10*time.Second, func() { h.raw.Close() })
	defer batch.Close(t)
	for i := 0; i < 8; i++ {
		batch.Go(func(ctx context.Context) error {
			req, _ := http.NewRequestWithContext(ctx, "POST", "https://localhost/", nil)
			res, e := h.client.RoundTrip(req)
			if res != nil {
				res.Body.Close()
			}
			return e
		})
	}
	batch.Await(t, entered, 8, 3*time.Second)
	require.NoError(t, h.client.Close())
	for _, err := range batch.Wait(t) {
		require.Error(t, err)
	}
	batch.Await(t, canceled, 8, 3*time.Second)
	require.Eventually(t, func() bool { return h.active.Load() == 0 }, time.Second, time.Millisecond)
	require.EqualValues(t, 1, h.accepted.Load())
}
