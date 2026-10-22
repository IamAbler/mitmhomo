package mitm

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
)

func m34Transport(t *testing.T, idle time.Duration, handler http.Handler, max uint32) (*nativeRoundTripper, *atomic.Int32, *atomic.Int32) {
	t.Helper()
	cert, roots := makeTestUpstreamCertificate(t)
	accepts, active := new(atomic.Int32), new(atomic.Int32)
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	server.EnableHTTP2 = true
	require.NoError(t, http2.ConfigureServer(server.Config, &http2.Server{MaxConcurrentStreams: max}))
	server.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			accepts.Add(1)
			active.Add(1)
		}
		if s == http.StateClosed {
			active.Add(-1)
		}
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	pool := newUpstreamManager(context.Background(), idle)
	t.Cleanup(pool.Close)
	rt := &nativeRoundTripper{pool: pool, target: &C.Metadata{NetWork: C.TCP, Host: "localhost", DstPort: 443}, tlsConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12, NextProtos: []string{"h2"}}, handshakeTimeout: time.Second, requestTimeout: 3 * time.Second, idleTimeout: idle, dial: m34Dial(func(*C.Metadata) string { return server.Listener.Addr().String() })}
	return rt, accepts, active
}

func m34TransportRequest(rt *nativeRoundTripper, ctx context.Context) error {
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://localhost/", nil)
	res, err := rt.RoundTrip(req)
	if err != nil {
		return err
	}
	_, err = io.Copy(io.Discard, res.Body)
	res.Body.Close()
	return err
}

func TestM34ServerConcurrencyLimit(t *testing.T) {
	var active, peak atomic.Int32
	rt, accepts, _ := m34Transport(t, time.Second, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a := active.Add(1)
		defer active.Add(-1)
		for old := peak.Load(); a > old; old = peak.Load() {
			if peak.CompareAndSwap(old, a) {
				break
			}
		}
		time.Sleep(time.Millisecond)
		io.WriteString(w, "ok")
	}), 3)
	// Warm up to receive peer SETTINGS before the concurrency wave.
	require.NoError(t, m34TransportRequest(rt, context.Background()))
	results := make(chan error, 50)
	for i := 0; i < 50; i++ {
		go func() { results <- m34TransportRequest(rt, context.Background()) }()
	}
	for i := 0; i < 50; i++ {
		require.NoError(t, <-results)
	}
	require.EqualValues(t, 1, accepts.Load())
	require.LessOrEqual(t, peak.Load(), int32(3))
	require.Greater(t, peak.Load(), int32(1))
}

func TestM34ManagerIdleAndRepeatedClose(t *testing.T) {
	rt, accepts, active := m34Transport(t, 30*time.Millisecond, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }), 100)
	require.NoError(t, m34TransportRequest(rt, context.Background()))
	require.Eventually(t, func() bool {
		rt.pool.mu.Lock()
		defer rt.pool.mu.Unlock()
		return active.Load() == 0 && len(rt.pool.all) == 0 && len(rt.pool.current) == 0
	}, time.Second, 5*time.Millisecond)
	require.NoError(t, m34TransportRequest(rt, context.Background()))
	require.EqualValues(t, 2, accepts.Load())
	rt.pool.Close()
	require.Eventually(t, func() bool { return active.Load() == 0 }, time.Second, 5*time.Millisecond)
	baseline := runtime.NumGoroutine()
	for i := 0; i < 20; i++ {
		rt.pool = newUpstreamManager(context.Background(), time.Second)
		for j := 0; j < 3; j++ {
			require.NoError(t, m34TransportRequest(rt, context.Background()))
		}
		rt.pool.Close()
		require.Eventually(t, func() bool { return active.Load() == 0 }, time.Second, time.Millisecond)
		rt.pool.mu.Lock()
		require.Empty(t, rt.pool.all)
		require.Empty(t, rt.pool.current)
		require.Empty(t, rt.pool.pending)
		rt.pool.mu.Unlock()
	}
	require.Eventually(t, func() bool { return runtime.NumGoroutine() <= baseline+4 }, 2*time.Second, 10*time.Millisecond, "per-manager goroutines retained after 20 lifecycles")
	t.Logf("cycles=20 upstream_accepts=%d active_after=0 goroutines_baseline=%d goroutines_after=%d", accepts.Load(), baseline, runtime.NumGoroutine())
}

func TestM34CanceledDialWaiter(t *testing.T) {
	rt, accepts, _ := m34Transport(t, time.Second, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }), 100)
	original := rt.dial
	entered := make(chan struct{})
	var calls atomic.Int32
	rt.dial = func(ctx context.Context, m *C.Metadata, h NativeTLSHandshake) (net.Conn, error) {
		if calls.Add(1) == 1 {
			close(entered)
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return original(ctx, m, h)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first, second := make(chan error, 1), make(chan error, 1)
	go func() { first <- m34TransportRequest(rt, ctx) }()
	<-entered
	go func() { second <- m34TransportRequest(rt, context.Background()) }()
	cancel()
	require.ErrorIs(t, <-first, context.Canceled)
	require.NoError(t, <-second)
	require.EqualValues(t, 2, calls.Load())
	require.EqualValues(t, 1, accepts.Load())
}

type m34PrefaceConn struct {
	net.Conn
	armed   atomic.Bool
	once    sync.Once
	started chan struct{}
}

func (c *m34PrefaceConn) Write(p []byte) (int, error) {
	if c.armed.Load() {
		c.once.Do(func() { close(c.started) })
	}
	return c.Conn.Write(p)
}

func TestM34CloseDuringPreface(t *testing.T) {
	testM34CloseInitialization(t, true)
}

func TestM34CloseBeforePreface(t *testing.T) {
	testM34CloseInitialization(t, false)
}

func testM34CloseInitialization(t *testing.T, during bool) {
	cert, roots := makeTestUpstreamCertificate(t)
	server, client := net.Pipe()
	observed := &m34PrefaceConn{Conn: client, started: make(chan struct{})}
	verified := make(chan struct{})
	handshaken, release, serverDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(serverDone)
		defer server.Close()
		secure := tls.Server(server, &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2"}})
		if secure.Handshake() == nil {
			close(handshaken)
			<-release
		}
	}()
	defer func() { close(release); <-serverDone }()
	pool := newUpstreamManager(context.Background(), time.Second)
	defer pool.Close()
	rt := &nativeRoundTripper{pool: pool, target: &C.Metadata{NetWork: C.TCP, Host: "localhost", DstPort: 443}, tlsConfig: &tls.Config{RootCAs: roots, NextProtos: []string{"h2"}}, handshakeTimeout: time.Second, requestTimeout: time.Second, idleTimeout: time.Second, dial: func(ctx context.Context, _ *C.Metadata, h NativeTLSHandshake) (net.Conn, error) {
		secure, e := h(ctx, observed)
		if e != nil {
			client.Close()
		} else {
			close(verified)
			if !during {
				<-ctx.Done()
			}
		}
		observed.armed.Store(true)
		return secure, e
	}}
	result := make(chan error, 1)
	go func() { result <- m34TransportRequest(rt, context.Background()) }()
	select {
	case <-handshaken:
	case <-time.After(time.Second):
		t.Fatal("TLS did not complete")
	}
	ready := verified
	if during {
		ready = observed.started
	}
	select {
	case <-ready:
	case <-time.After(time.Second):
		t.Fatal("ClientConn did not begin preface write")
	}
	closed := make(chan struct{})
	go func() { pool.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("manager close blocked on preface")
	}
	require.Error(t, <-result)
}

func TestM34SecurityPartitionAndOwner(t *testing.T) {
	var handled atomic.Int32
	rt, accepts, _ := m34Transport(t, time.Second, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handled.Add(1); io.WriteString(w, "ok") }), 100)
	require.NoError(t, m34TransportRequest(rt, context.Background()))
	trusted := rt.tlsConfig
	rt.tlsConfig = trusted.Clone()
	rt.tlsConfig.RootCAs = x509.NewCertPool()
	require.Error(t, m34TransportRequest(rt, context.Background()), "new untrusted security policy cannot borrow established trusted TLS")
	require.EqualValues(t, 1, handled.Load())
	require.EqualValues(t, 2, accepts.Load())
	rt.tlsConfig = trusted
	require.NoError(t, m34TransportRequest(rt, context.Background()))
	require.EqualValues(t, 2, accepts.Load(), "original security partition remains reusable")
	old := rt.pool
	rt.pool = newUpstreamManager(context.Background(), time.Second)
	defer rt.pool.Close()
	require.NoError(t, m34TransportRequest(rt, context.Background()))
	require.EqualValues(t, 3, accepts.Load(), "different downstream owner cannot reuse another owner's socket")
	old.Close()
}
