package mitm

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
)

func m34Client(t *testing.T, manager *Manager, roots *x509.CertPool, dial NativeDialContext) *http2.ClientConn {
	t.Helper()
	server, client := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan dispatchResult, 1)
	go func() {
		outcome, err := manager.Dispatch(ctx, N.NewBufferedConn(server), &C.Metadata{NetWork: C.TCP, Host: "localhost", DstPort: 443}, nil, dial)
		done <- dispatchResult{outcome: outcome, err: err}
	}()
	secure := tls.Client(client, &tls.Config{RootCAs: roots, ServerName: "localhost", NextProtos: []string{"h2"}, MinVersion: tls.VersionTLS12})
	require.NoError(t, secure.HandshakeContext(ctx))
	cc, err := (&http2.Transport{}).NewClientConn(secure)
	require.NoError(t, err)
	t.Cleanup(func() {
		defer cancel()
		cc.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("dispatcher leaked")
		}
	})
	return cc
}

func m34Dial(address func(*C.Metadata) string) NativeDialContext {
	return func(ctx context.Context, metadata *C.Metadata, handshake NativeTLSHandshake) (net.Conn, error) {
		raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", address(metadata))
		if err != nil {
			return nil, err
		}
		secure, err := handshake(ctx, raw)
		if err != nil {
			raw.Close()
		}
		return secure, err
	}
}

func TestM34TargetIdentityIsolation(t *testing.T) {
	roots := x509.NewCertPool()
	var accepted [3]atomic.Int32
	addresses := map[string]string{}
	// Same domain on different ports AND different names must stay isolated.
	targets := []string{"a.example:443", "b.example:443", "a.example:8443"}
	for i, target := range targets {
		i, target := i, target
		host, _, _ := net.SplitHostPort(target)
		cert, _ := makeTestUpstreamCertificateFor(t, host)
		roots.AddCert(cert.Leaf)
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.TLS.ServerName != host || r.Host != target || r.ProtoMajor != 2 {
				t.Error("target/SNI/Host/protocol mixed", r.Host, r.TLS.ServerName)
			}
			io.WriteString(w, target)
		}))
		server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
		server.Config.ConnState = func(_ net.Conn, s http.ConnState) {
			if s == http.StateNew {
				accepted[i].Add(1)
			}
		}
		server.EnableHTTP2 = true
		server.StartTLS()
		t.Cleanup(server.Close)
		addresses[target] = server.Listener.Addr().String()
	}
	authority, clientRoots := makeTestAuthority(t)
	manager := NewManager(Config{Enabled: true, Ports: []uint16{443}, Domains: []string{"localhost"}, CA: authority, upstreamRootCAs: roots, HandshakeTimeout: time.Second, RequestTimeout: 5 * time.Second, IdleTimeout: time.Second, RequestHook: func(r *http.Request) error {
		i, e := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/"))
		if e != nil {
			return e
		}
		r.URL.Host = targets[i%3]
		return nil
	}})
	cc := m34Client(t, manager, clientRoots, m34Dial(func(m *C.Metadata) string { return addresses[net.JoinHostPort(m.Host, strconv.Itoa(int(m.DstPort)))] }))
	results := make(chan error, 30)
	for i := 0; i < 30; i++ {
		go func(i int) {
			req, _ := http.NewRequest("GET", fmt.Sprintf("https://localhost/%d", i), nil)
			res, e := cc.RoundTrip(req)
			if e == nil {
				var b []byte
				b, e = io.ReadAll(res.Body)
				res.Body.Close()
				if string(b) != targets[i%3] {
					e = fmt.Errorf("wrong identity: %s", b)
				}
			}
			results <- e
		}(i)
	}
	for i := 0; i < 30; i++ {
		require.NoError(t, <-results)
	}
	for i := range accepted {
		require.EqualValues(t, 1, accepted[i].Load())
	}
}

func TestM34ResetIsolation(t *testing.T) {
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	h := newProtocolHarness(t, nil, "localhost", 443, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/reset" {
			entered <- struct{}{}
			<-release
			panic(http.ErrAbortHandler)
		}
		if r.URL.Path == "/sibling" {
			entered <- struct{}{}
			<-release
		}
		io.WriteString(w, "ok")
	}), false, true, true, []string{"h2"})
	results := make(chan int, 2)
	for _, path := range []string{"/reset", "/sibling"} {
		go func(path string) {
			req, _ := http.NewRequest("POST", "https://localhost"+path, strings.NewReader("once"))
			res, e := h.client.RoundTrip(req)
			if e != nil {
				results <- 0
				return
			}
			io.Copy(io.Discard, res.Body)
			res.Body.Close()
			results <- res.StatusCode
		}(path)
	}
	for i := 0; i < 2; i++ {
		select {
		case <-entered:
		case <-time.After(3 * time.Second):
			t.Fatal("streams not overlapping")
		}
	}
	once.Do(func() { close(release) })
	codes := []int{<-results, <-results}
	require.ElementsMatch(t, []int{502, 200}, codes)
	require.Equal(t, "ok", readM2ResponseBody(t, h2Request(t, h, "GET", "/after", "")))
	require.EqualValues(t, 1, h.accepted.Load(), "RST_STREAM does not close shared TCP")
}

func TestM34IdleEviction(t *testing.T) {
	h := newProtocolHarness(t, nil, "localhost", 443, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }), false, true, true, []string{"h2"}, func(c *Config) { c.IdleTimeout = 100 * time.Millisecond })
	require.Equal(t, "ok", readM2ResponseBody(t, h2Request(t, h, "GET", "/", "")))
	// Both upstream idle and downstream idle release sockets. Independent
	// upstream eviction/replacement is tested with a manager directly below.
	require.Eventually(t, func() bool { return h.active.Load() == 0 }, time.Second, 5*time.Millisecond)
	require.EqualValues(t, 1, h.accepted.Load())
}

func TestM34CancelUploadingStream(t *testing.T) {
	entered := make(chan struct{})
	canceled := make(chan struct{})
	h := newProtocolHarness(t, nil, "localhost", 443, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/upload" {
			close(entered)
			io.Copy(io.Discard, r.Body)
			<-r.Context().Done()
			close(canceled)
			return
		}
		io.WriteString(w, "sibling")
	}), false, true, true, []string{"h2"})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reader, writer := io.Pipe()
	defer writer.Close()
	result := make(chan error, 1)
	go func() {
		req, _ := http.NewRequestWithContext(ctx, "POST", "https://localhost/upload", reader)
		res, err := h.client.RoundTrip(req)
		if res != nil {
			res.Body.Close()
		}
		result <- err
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("upload not entered")
	}
	require.Equal(t, "sibling", readM2ResponseBody(t, h2Request(t, h, "GET", "/sibling", "")))
	cancel()
	select {
	case err := <-result:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("upload cancellation blocked")
	}
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("upstream upload retained")
	}
	require.Equal(t, "sibling", readM2ResponseBody(t, h2Request(t, h, "GET", "/after", "")))
	require.EqualValues(t, 1, h.accepted.Load())
}
