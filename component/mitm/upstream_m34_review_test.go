package mitm

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/stretchr/testify/require"
)

// Done is first consulted by acquire's pending select for these requests.
// This acknowledges an actual waiter, rather than guessing scheduling with Sleep.
type m34ObservedWait struct {
	context.Context
	waiting chan struct{}
	once    sync.Once
}

func (c *m34ObservedWait) Done() <-chan struct{} {
	c.once.Do(func() { close(c.waiting) })
	return c.Context.Done()
}

func m34Await(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatal("barrier timed out")
	}
}
func m34Result(t *testing.T, ch <-chan error) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(3 * time.Second):
		t.Fatal("request did not finish")
		return nil
	}
}
func m34EmptyPool(t *testing.T, m *upstreamManager) {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	require.Empty(t, m.current, "rejected initialization must not leave current")
	require.Empty(t, m.all, "rejected initialization must not need prune")
	require.Empty(t, m.pending, "pending must finish after cleanup")
}

func m34OnlyPending(t *testing.T, m *upstreamManager) {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	require.Empty(t, m.current)
	require.Empty(t, m.all)
	require.Len(t, m.pending, 1)
}

// Real TCP/TLS origins remain open for the successful request after each fault.
// No pool scan or idle expiration is allowed between failure and empty assertions.
func TestM34ReviewInitializationFailures(t *testing.T) {
	for _, stage := range []string{"tcp", "tls", "h2-preface"} {
		t.Run(stage, func(t *testing.T) {
			rt, accepts, active := m34Transport(t, time.Minute, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }), 100)
			original := rt.dial
			var first sync.Once
			rt.dial = func(ctx context.Context, m *C.Metadata, h NativeTLSHandshake) (net.Conn, error) {
				fail := false
				first.Do(func() { fail = true })
				if !fail {
					return original(ctx, m, h)
				}
				if stage == "tcp" {
					return nil, errors.New("injected TCP dial failure")
				}
				return original(ctx, m, func(ctx context.Context, raw net.Conn) (net.Conn, error) {
					if stage == "tls" {
						raw.Close()
						return h(ctx, raw)
					}
					// Arm only after verified TLS, so NewClientConn fails.
					fault := &m34ReviewWriteFault{Conn: raw}
					secure, err := h(ctx, fault)
					fault.armed.Store(err == nil)
					return secure, err
				})
			}
			require.Error(t, m34TransportRequest(rt, context.Background()))
			m34EmptyPool(t, rt.pool)
			require.Eventually(t, func() bool { return active.Load() == 0 }, time.Second, time.Millisecond)
			require.NoError(t, m34TransportRequest(rt, context.Background()), "next request must create a healthy connection")
			want := int32(2)
			if stage == "tcp" {
				want = 1
			}
			require.Equal(t, want, accepts.Load())
			rt.pool.Close()
			require.Eventually(t, func() bool { return active.Load() == 0 }, time.Second, time.Millisecond)
			m34EmptyPool(t, rt.pool)
		})
	}
}

type m34ReviewWriteFault struct {
	net.Conn
	armed atomic.Bool
}

func (c *m34ReviewWriteFault) Write(p []byte) (int, error) {
	if c.armed.Load() {
		return 0, errors.New("injected HTTP/2 preface write failure")
	}
	return c.Conn.Write(p)
}

// Exercise publish directly with real initialized ClientConns. SetDoNotReuse
// and Close provide deterministic states, including x/net's closed-first-use
// CanTakeNewRequest exception; no fake ClientConn or production test hook.
func TestM34ReviewRejectUnusableClientConn(t *testing.T) {
	for _, state := range []string{"do-not-reuse", "closed-unused"} {
		t.Run(state, func(t *testing.T) {
			rt, _, active := m34Transport(t, time.Minute, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }), 100)
			secure, err := rt.dialTLS(context.Background(), "localhost")
			require.NoError(t, err)
			cc, err := rt.h2Transport().NewClientConn(secure)
			require.NoError(t, err)
			defer func() { secure.NetConn().Close(); cc.Close() }()
			if state == "closed-unused" {
				secure.NetConn().Close()
				cc.Close()
				require.True(t, cc.State().Closed)
				require.True(t, cc.CanTakeNewRequest(), "x/net deliberately allows reporting initial errors")
			} else {
				cc.SetDoNotReuse()
				require.False(t, cc.CanTakeNewRequest())
			}
			key := upstreamTarget{scheme: "https", host: "localhost", port: 443, serverName: "localhost", security: rt.tlsConfig}
			e := &upstreamEntry{identity: identityForUpstream(key, rt.pool, 1, secure), cc: cc, secure: secure}
			require.Error(t, rt.pool.publish(context.Background(), e))
			m34EmptyPool(t, rt.pool)
			// Creator retains cleanup ownership on rejection, just as acquire does.
			secure.NetConn().Close()
			cc.Close()
			require.Eventually(t, func() bool { return active.Load() == 0 }, time.Second, time.Millisecond)
			require.NoError(t, m34TransportRequest(rt, context.Background()))
		})
	}
}

// A Native Connection wrapper supplies a barrier after NewClientConn succeeds,
// during identity capture, before publish. It does not alter transport state.
type m34PublicationGate struct {
	net.Conn
	reached   chan struct{}
	release   chan struct{}
	once      sync.Once
	closed    atomic.Int32
	closeOnce sync.Once
	closeErr  error
}

func (c *m34PublicationGate) Chains() C.Chain {
	c.once.Do(func() { close(c.reached); <-c.release })
	return C.Chain{"test-route"}
}
func (c *m34PublicationGate) ProviderChains() C.Chain       { return nil }
func (c *m34PublicationGate) AppendToChains(C.ProxyAdapter) {}
func (c *m34PublicationGate) RemoteDestination() string     { return "" }
func (c *m34PublicationGate) Close() error {
	// Native Tracker cleanup is idempotent even when the HTTP/2 reader
	// also closes the socket after observing shutdown.
	c.closeOnce.Do(func() { c.closed.Add(1); c.closeErr = c.Conn.Close() })
	return c.closeErr
}

func TestM34ReviewCancelBeforePublication(t *testing.T) {
	for _, closePool := range []bool{false, true} {
		t.Run(map[bool]string{false: "request-cancel", true: "pool-close"}[closePool], func(t *testing.T) {
			rt, _, active := m34Transport(t, time.Minute, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }), 100)
			original := rt.dial
			gate := &m34PublicationGate{reached: make(chan struct{}), release: make(chan struct{})}
			var once sync.Once
			rt.dial = func(ctx context.Context, m *C.Metadata, h NativeTLSHandshake) (net.Conn, error) {
				first := false
				once.Do(func() { first = true })
				if !first {
					return original(ctx, m, h)
				}
				return original(ctx, m, func(ctx context.Context, raw net.Conn) (net.Conn, error) { gate.Conn = raw; return h(ctx, gate) })
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan error, 1)
			go func() { result <- m34TransportRequest(rt, ctx) }()
			m34Await(t, gate.reached)
			m34OnlyPending(t, rt.pool)
			if closePool {
				rt.pool.cancel()
				m34Await(t, rt.pool.ctx.Done())
			} else {
				cancel()
			}
			close(gate.release)
			err := m34Result(t, result)
			require.Error(t, err)
			if !closePool {
				require.ErrorIs(t, err, context.Canceled)
			} else {
				rt.pool.Close()
			}
			m34EmptyPool(t, rt.pool)
			require.Eventually(t, func() bool { return active.Load() == 0 }, time.Second, time.Millisecond)
			require.EqualValues(t, 1, gate.closed.Load(), "unpublished socket has one cleanup owner")
			if closePool {
				rt.pool = newUpstreamManager(context.Background(), time.Minute)
				defer rt.pool.Close()
			}
			require.NoError(t, m34TransportRequest(rt, context.Background()))
		})
	}
}

func TestM34ReviewTLSWaiterCancellation(t *testing.T) {
	for _, cancelOwner := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancel-some-waiters", true: "cancel-creator"}[cancelOwner], func(t *testing.T) {
			rt, accepts, active := m34Transport(t, time.Minute, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }), 100)
			original := rt.dial
			entered, release := make(chan struct{}), make(chan struct{})
			var calls atomic.Int32
			rt.dial = func(ctx context.Context, m *C.Metadata, h NativeTLSHandshake) (net.Conn, error) {
				n := calls.Add(1)
				if n != 1 {
					return original(ctx, m, h)
				}
				return original(ctx, m, func(ctx context.Context, raw net.Conn) (net.Conn, error) {
					return h(ctx, &m34HandshakeReadGate{Conn: raw, ctx: ctx, entered: entered, release: release})
				})
			}
			ownerCtx, cancel := context.WithCancel(context.Background())
			defer cancel()
			owner := make(chan error, 1)
			go func() { owner <- m34TransportRequest(rt, ownerCtx) }()
			m34Await(t, entered)
			results := make([]chan error, 8)
			cancels := make([]context.CancelFunc, 8)
			for i := range results {
				ctx, stop := context.WithCancel(context.Background())
				cancels[i] = stop
				defer stop()
				wait := &m34ObservedWait{Context: ctx, waiting: make(chan struct{})}
				results[i] = make(chan error, 1)
				result := results[i]
				go func() { result <- m34TransportRequest(rt, wait) }()
				m34Await(t, wait.waiting)
			}
			for i := 0; i < 3; i++ {
				cancels[i]()
				require.ErrorIs(t, m34Result(t, results[i]), context.Canceled)
			}
			require.EqualValues(t, 1, calls.Load(), "waiting streams must not create parallel dials")
			if cancelOwner {
				cancel()
				require.ErrorIs(t, m34Result(t, owner), context.Canceled)
			} else {
				close(release)
				require.NoError(t, m34Result(t, owner))
			}
			for i := 3; i < 8; i++ {
				require.NoError(t, m34Result(t, results[i]))
			}
			want := int32(1)
			if cancelOwner {
				want = 2
			}
			require.Equal(t, want, calls.Load())
			require.Equal(t, want, accepts.Load())
			rt.pool.Close()
			m34EmptyPool(t, rt.pool)
			require.Eventually(t, func() bool { return active.Load() == 0 }, time.Second, time.Millisecond)
		})
	}
}

var _ C.Connection = (*m34PublicationGate)(nil)

func TestM34ReviewH2WaiterCancellation(t *testing.T) {
	for _, closePool := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancel-all", true: "downstream-close"}[closePool], func(t *testing.T) {
			rt, accepts, active := m34Transport(t, time.Minute, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }), 100)
			cert, _ := makeTestUpstreamCertificate(t)
			rt.tlsConfig.RootCAs = rt.tlsConfig.RootCAs.Clone()
			rt.tlsConfig.RootCAs.AddCert(cert.Leaf)
			server, client := net.Pipe()
			observed := &m34PrefaceConn{Conn: client, started: make(chan struct{})}
			releaseServer, serverDone := make(chan struct{}), make(chan struct{})
			go func() {
				defer close(serverDone)
				defer server.Close()
				secure := tls.Server(server, &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2"}})
				if secure.Handshake() == nil {
					<-releaseServer
				}
			}()
			defer func() { close(releaseServer); <-serverDone }()
			original := rt.dial
			var calls atomic.Int32
			rt.dial = func(ctx context.Context, m *C.Metadata, h NativeTLSHandshake) (net.Conn, error) {
				if calls.Add(1) != 1 {
					return original(ctx, m, h)
				}
				secure, err := h(ctx, observed)
				if err != nil {
					observed.Close()
				} else {
					observed.armed.Store(true)
				}
				return secure, err
			}
			ownerCtx, cancel := context.WithCancel(context.Background())
			defer cancel()
			owner := make(chan error, 1)
			go func() { owner <- m34TransportRequest(rt, ownerCtx) }()
			m34Await(t, observed.started)
			results := make([]chan error, 8)
			cancels := make([]context.CancelFunc, 8)
			for i := range results {
				ctx, stop := context.WithCancel(context.Background())
				cancels[i] = stop
				defer stop()
				wait := &m34ObservedWait{Context: ctx, waiting: make(chan struct{})}
				results[i] = make(chan error, 1)
				result := results[i]
				go func() { result <- m34TransportRequest(rt, wait) }()
				m34Await(t, wait.waiting)
			}
			require.EqualValues(t, 1, calls.Load())
			if closePool {
				rt.pool.cancel()
			} else {
				// Every waiter must exit while the creator is still in the blocked preface.
				for _, stop := range cancels {
					stop()
				}
				for _, result := range results {
					require.ErrorIs(t, m34Result(t, result), context.Canceled)
				}
				m34OnlyPending(t, rt.pool)
				cancel()
			}
			require.Error(t, m34Result(t, owner))
			if closePool {
				for _, result := range results {
					require.Error(t, m34Result(t, result))
				}
				rt.pool.Close()
			}
			m34EmptyPool(t, rt.pool)
			// The Native socket is actually closed, not only removed from maps.
			var one [1]byte
			_, err := client.Read(one[:])
			require.Error(t, err)
			if closePool {
				rt.pool = newUpstreamManager(context.Background(), time.Minute)
				defer rt.pool.Close()
			}
			require.NoError(t, m34TransportRequest(rt, context.Background()))
			require.EqualValues(t, 2, calls.Load())
			require.EqualValues(t, 1, accepts.Load())
			rt.pool.Close()
			require.Eventually(t, func() bool { return active.Load() == 0 }, time.Second, time.Millisecond)
		})
	}
}

// TLS has written ClientHello when it first reads the server handshake.
type m34HandshakeReadGate struct {
	net.Conn
	ctx              context.Context
	entered, release chan struct{}
	once             sync.Once
}

func (c *m34HandshakeReadGate) Read(p []byte) (int, error) {
	var err error
	c.once.Do(func() {
		close(c.entered)
		select {
		case <-c.release:
		case <-c.ctx.Done():
		}
		err = c.ctx.Err()
	})
	if err != nil {
		return 0, err
	}
	return c.Conn.Read(p)
}
