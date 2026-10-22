package mitm

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/mitm/rewrite"
	C "github.com/metacubex/mihomo/constant"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
)

type h2Harness struct {
	client  *http2.ClientConn
	wire    http.RoundTripper
	manager *Manager
	streams atomic.Int32
	dials   atomic.Int32
	active  atomic.Int32
	done    chan dispatchResult
}

// Both sides use real TCP + verified TLS. The client uses one explicit
// ClientConn so a successful second request cannot hide a redial.
func newH2Harness(t *testing.T, upstreamHandler http.Handler, failDial, trust bool, options ...func(*Config)) *h2Harness {
	return newH2HarnessWithManager(t, nil, upstreamHandler, failDial, trust, options...)
}

func newH2HarnessWithManager(t *testing.T, manager *Manager, upstreamHandler http.Handler, failDial, trust bool, options ...func(*Config)) *h2Harness {
	return newH2HarnessTarget(t, manager, "localhost", 443, upstreamHandler, failDial, trust, options...)
}

func newH2HarnessTarget(t *testing.T, manager *Manager, targetHost string, targetPort uint16, upstreamHandler http.Handler, failDial, trust bool, options ...func(*Config)) *h2Harness {
	return newProtocolHarness(t, manager, targetHost, targetPort, upstreamHandler, failDial, trust, true, []string{"http/1.1"}, options...)
}

func newProtocolHarness(t *testing.T, manager *Manager, targetHost string, targetPort uint16, upstreamHandler http.Handler, failDial, trust, downstreamH2 bool, protocols []string, options ...func(*Config)) *h2Harness {
	t.Helper()
	h := &h2Harness{done: make(chan dispatchResult, 1)}
	cert, roots := makeTestUpstreamCertificateFor(t, targetHost)
	upstream := httptest.NewUnstartedServer(upstreamHandler)
	upstream.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: protocols}
	upstream.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			h.active.Add(1)
		}
		if state == http.StateClosed {
			h.active.Add(-1)
		}
	}
	upstream.EnableHTTP2 = true
	upstream.StartTLS()
	t.Cleanup(upstream.Close)
	authority, clientRoots := makeTestAuthority(t)
	cfg := Config{Enabled: true, Ports: []uint16{443}, Domains: []string{"localhost"}, CA: authority,
		HandshakeTimeout: time.Second, RequestTimeout: 3 * time.Second, IdleTimeout: 3 * time.Second, ReadHeaderTimeout: time.Second,
		RequestHook: func(r *http.Request) error {
			if (r.ProtoMajor == 2) != downstreamH2 || r.TLS == nil || downstreamH2 && r.TLS.NegotiatedProtocol != "h2" {
				return errors.New("unexpected downstream TLS HTTP protocol")
			}
			h.streams.Add(1)
			return nil
		},
	}
	if trust {
		cfg.upstreamRootCAs = roots
	}
	for _, option := range options {
		option(&cfg)
	}
	h.manager = NewManager(cfg)
	if manager != nil {
		h.manager = manager
		clientRoots.AddCert(manager.ConfigSnapshot().CA.leaf)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		raw, err := listener.Accept()
		if err != nil {
			h.done <- dispatchResult{err: err}
			return
		}
		defer raw.Close()
		outcome, err := h.manager.Dispatch(ctx, N.NewBufferedConn(raw), &C.Metadata{NetWork: C.TCP, Type: C.TUNNEL, Host: "localhost", DstPort: 443}, nil,
			func(ctx context.Context, metadata *C.Metadata, handshake NativeTLSHandshake) (net.Conn, error) {
				h.dials.Add(1)
				if failDial {
					return nil, errors.New("test native dial failure")
				}
				if metadata.Host != targetHost || metadata.DstPort != targetPort {
					return nil, errors.New("wrong native target")
				}
				conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", upstream.Listener.Addr().String())
				if err != nil {
					return nil, err
				}
				secure, err := handshake(ctx, conn)
				if err != nil {
					_ = conn.Close()
				}
				return secure, err
			})
		h.done <- dispatchResult{outcome: outcome, err: err}
	}()
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
	require.NoError(t, err)
	clientProtocols := []string{"http/1.1"}
	if downstreamH2 {
		clientProtocols = []string{"h2", "http/1.1"}
	}
	secure := tls.Client(raw, &tls.Config{RootCAs: clientRoots, ServerName: "localhost", NextProtos: clientProtocols, MinVersion: tls.VersionTLS12})
	handshakeCtx, stop := context.WithTimeout(ctx, 3*time.Second)
	err = secure.HandshakeContext(handshakeCtx)
	stop()
	require.NoError(t, err)
	if downstreamH2 {
		require.Equal(t, "h2", secure.ConnectionState().NegotiatedProtocol)
		h.client, err = (&http2.Transport{}).NewClientConn(secure)
		require.NoError(t, err)
		h.wire = h.client
	} else {
		h.wire = &http.Transport{TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}, DialTLSContext: func(context.Context, string, string) (net.Conn, error) { return secure, nil }}
	}
	t.Cleanup(func() {
		if h.client != nil {
			_ = h.client.Close()
		} else {
			h.wire.(*http.Transport).CloseIdleConnections()
			_ = secure.Close()
		}
		defer cancel()
		select {
		case result := <-h.done:
			require.Equal(t, DispatchIntercepted, result.outcome)
		case <-time.After(5 * time.Second):
			cancel()
			t.Error("H2 dispatcher leaked")
		}
		require.Eventually(t, func() bool { return h.active.Load() == 0 }, 3*time.Second, 10*time.Millisecond, "upstream connections leaked")
	})
	return h
}

func h2Request(t *testing.T, h *h2Harness, method, path, body string) *http.Response {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	r, err := http.NewRequestWithContext(ctx, method, "https://localhost"+path, strings.NewReader(body))
	require.NoError(t, err)
	r.Header.Set("X-Client", "h2")
	response, err := h.client.RoundTrip(r)
	require.NoError(t, err)
	require.Equal(t, 2, response.ProtoMajor)
	return response
}

func TestM31HTTP2TLSGetPostAndHeaders(t *testing.T) {
	h := newH2Harness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 1 || r.ProtoMinor != 1 {
			t.Error("upstream must be HTTP/1.1")
		}
		require.Equal(t, "h2", r.Header.Get("X-Client"))
		require.Equal(t, "http/1.1", r.TLS.NegotiatedProtocol)
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		w.Header().Set("X-Upstream", "h1")
		_, _ = fmt.Fprintf(w, "%s %s %s", r.Method, r.URL.Path, body)
	}), false, true)
	for _, tc := range []struct{ method, path, body string }{{"GET", "/get", ""}, {"POST", "/post", "payload"}} {
		response := h2Request(t, h, tc.method, tc.path, tc.body)
		require.Equal(t, 200, response.StatusCode)
		require.Equal(t, "h1", response.Header.Get("X-Upstream"))
		data, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		require.NoError(t, response.Body.Close())
		require.Equal(t, tc.method+" "+tc.path+" "+tc.body, string(data))
	}
	require.EqualValues(t, 2, h.streams.Load())
	require.EqualValues(t, 2, h.dials.Load())
}

func TestM31HTTP2ConcurrentStreamsAndCancellation(t *testing.T) {
	entered := make(chan struct{}, 2)
	canceled := make(chan struct{})
	release := make(chan struct{})
	h := newH2Harness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		if r.URL.Path == "/cancel" {
			<-r.Context().Done()
			close(canceled)
			return
		}
		select {
		case <-release:
			_, _ = io.WriteString(w, "survivor")
		case <-r.Context().Done():
		}
	}), false, true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, "GET", "https://localhost/cancel", nil)
	require.NoError(t, err)
	failed := make(chan error, 1)
	go func() {
		response, err := h.client.RoundTrip(request)
		if response != nil {
			_ = response.Body.Close()
		}
		failed <- err
	}()
	success := make(chan string, 1)
	go func() {
		req, _ := http.NewRequest("GET", "https://localhost/survive", nil)
		response, err := h.client.RoundTrip(req)
		if err != nil {
			success <- err.Error()
			return
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil {
			success <- err.Error()
			return
		}
		success <- string(body)
	}()
	for i := 0; i < 2; i++ {
		select {
		case <-entered:
		case <-time.After(3 * time.Second):
			t.Fatal("streams did not overlap")
		}
	}
	cancel()
	select {
	case err := <-failed:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(3 * time.Second):
		t.Fatal("client cancellation stuck")
	}
	select {
	case <-canceled:
	case <-time.After(3 * time.Second):
		t.Fatal("native upstream not canceled")
	}
	close(release)
	select {
	case body := <-success:
		require.Equal(t, "survivor", body)
	case <-time.After(3 * time.Second):
		t.Fatal("sibling stream canceled")
	}
	response := h2Request(t, h, "GET", "/again", "")
	data, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())
	require.Equal(t, "survivor", string(data))
	require.EqualValues(t, 3, h.streams.Load())
}

func TestM31HTTP2UpstreamFailures(t *testing.T) {
	for _, failDial := range []bool{true, false} {
		t.Run(fmt.Sprintf("dialFailure=%v", failDial), func(t *testing.T) {
			h := newH2Harness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("failed upstream must not receive request") }), failDial, false)
			response := h2Request(t, h, "GET", "/", "")
			require.Equal(t, http.StatusBadGateway, response.StatusCode)
			_, err := io.Copy(io.Discard, response.Body)
			require.NoError(t, err)
			require.NoError(t, response.Body.Close())
		})
	}
}

// Existing rewrite engine works through the shared handler. This is a smoke
// check, not the full M3.2 protocol/terminal semantics matrix.
func TestM31HTTP2SharedPipelineAndConnectionSnapshot(t *testing.T) {
	h := newH2Harness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.Equal(t, "PATCH", r.Method)
		require.Equal(t, "/final/old", r.URL.Path)
		require.Equal(t, "request-old", string(body))
		w.Header().Set("X-Echo", r.Header.Get("X-Step"))
		_, _ = io.WriteString(w, "origin")
	}), false, true, func(cfg *Config) { cfg.Rewrite = m24Pipeline(t, "old") })
	cfg := h.manager.ConfigSnapshot()
	cfg.Rewrite = m24Pipeline(t, "new")
	h.manager.Update(cfg)
	for i := 0; i < 2; i++ {
		response := h2Request(t, h, "POST", "/start", "original")
		require.Equal(t, 202, response.StatusCode)
		require.Equal(t, "old", response.Header.Get("X-Response-Step"))
		require.Equal(t, "response-old", readM2ResponseBody(t, response))
	}
}

func TestM31HTTP2TerminalUploadKeepsSiblingConnection(t *testing.T) {
	pipeline := compileM2Rules(t, rewrite.Rule{Name: "local", Match: rewrite.Match{Path: "/local"}, LocalResponse: &rewrite.LocalResponse{Status: 200, Body: "local-body"}})
	h := newH2Harness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "upstream") }), false, true, func(cfg *Config) { cfg.Rewrite = pipeline })
	// The upload remains open: terminal response must not wait for its EOF or
	// set a connection-wide deadline. A subsequent stream must still work.
	reader, writer := io.Pipe()
	defer writer.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", "https://localhost/local", reader)
	require.NoError(t, err)
	response, err := h.client.RoundTrip(req)
	require.NoError(t, err)
	require.Equal(t, "local-body", readM2ResponseBody(t, response))
	require.Zero(t, h.dials.Load())
	response = h2Request(t, h, "GET", "/normal", "")
	require.Equal(t, "upstream", readM2ResponseBody(t, response))
	require.EqualValues(t, 1, h.dials.Load())
}
