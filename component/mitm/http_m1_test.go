package mitm

import (
	"bufio"
	"container/list"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	mihomoCA "github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/sniffer"
	C "github.com/metacubex/mihomo/constant"
	"github.com/stretchr/testify/require"
)

func makeTestAuthority(t testing.TB) (*CertificateAuthority, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "M1 test root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		SubjectKeyId:          []byte{1, 2, 3, 4},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	certificate := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	return &CertificateAuthority{
		certificate: certificate,
		leaf:        leaf,
		signer:      key,
		cache:       make(map[string]*list.Element),
		lru:         list.New(),
	}, roots
}

func makeTestUpstreamCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	return makeTestUpstreamCertificateFor(t, "localhost")
}

func makeTestUpstreamCertificateFor(t *testing.T, serverName string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: serverName},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{serverName},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	certificate, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	)
	require.NoError(t, err)
	certificate.Leaf, err = x509.ParseCertificate(der)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(certificate.Leaf)
	return certificate, roots
}

func newMITMDispatchHarness(t *testing.T, trustUpstream bool, nextProtos []string) (*tls.Conn, <-chan dispatchResult, *atomic.Int32, *Manager) {
	t.Helper()
	var upstreamRequests atomic.Int32
	upstreamCertificate, _ := makeTestUpstreamCertificate(t)
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamRequests.Add(1)
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		_, _ = fmt.Fprintf(w, "%s %s %s", r.Method, r.URL.Path, body)
	}))
	upstream.TLS = &tls.Config{Certificates: []tls.Certificate{upstreamCertificate}}
	upstream.StartTLS()
	t.Cleanup(upstream.Close)
	upstreamAddress := upstream.Listener.Addr().String()

	ca, clientRoots := makeTestAuthority(t)
	if trustUpstream {
		mihomoCA.ResetCertificate()
		require.NoError(t, mihomoCA.AddCertificate(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstreamCertificate.Certificate[0]}))))
		t.Cleanup(mihomoCA.ResetCertificate)
	}
	manager := NewManager(Config{
		Enabled:           true,
		Ports:             []uint16{443},
		Domains:           []string{"localhost"},
		CA:                ca,
		HandshakeTimeout:  3 * time.Second,
		ReadHeaderTimeout: 3 * time.Second,
		RequestTimeout:    3 * time.Second,
		IdleTimeout:       3 * time.Second,
	})
	serverRaw, clientRaw := net.Pipe()
	buffered := N.NewBufferedConn(serverRaw)
	dispatchDone := make(chan dispatchResult, 1)
	dialCount := &atomic.Int32{}
	go func() {
		outcome, err := manager.Dispatch(context.Background(), buffered, &C.Metadata{
			NetWork: C.TCP,
			Type:    C.TUNNEL,
			Host:    "localhost",
			DstPort: 443,
		}, nil, func(ctx context.Context, metadata *C.Metadata, handshake NativeTLSHandshake) (net.Conn, error) {
			dialCount.Add(1)
			require.Equal(t, "localhost", metadata.Host)
			require.Equal(t, uint16(443), metadata.DstPort)
			conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", upstreamAddress)
			if err != nil {
				return nil, err
			}
			secureConn, err := handshake(ctx, conn)
			if err != nil {
				_ = conn.Close()
			}
			return secureConn, err
		})
		dispatchDone <- dispatchResult{outcome: outcome, err: err}
	}()
	client := tls.Client(clientRaw, &tls.Config{
		RootCAs:    clientRoots,
		ServerName: "localhost",
		NextProtos: nextProtos,
	})
	_ = client.SetDeadline(time.Now().Add(10 * time.Second))
	if err := client.Handshake(); err != nil {
		_ = client.Close()
		_ = serverRaw.Close()
		t.Fatalf("MITM TLS client handshake: %v", err)
	}
	if len(nextProtos) == 0 {
		require.Empty(t, client.ConnectionState().NegotiatedProtocol)
	} else {
		require.Equal(t, "http/1.1", client.ConnectionState().NegotiatedProtocol)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client, dispatchDone, dialCount, manager
}

type dispatchResult struct {
	outcome DispatchOutcome
	err     error
}

func sendHTTPOverTLS(t *testing.T, client *tls.Conn, method, path, body string) *http.Response {
	t.Helper()
	request := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: localhost\r\n", method, path)
	if body != "" {
		request += fmt.Sprintf("Content-Length: %d\r\n", len(body))
	}
	request += "\r\n" + body
	_, err := io.WriteString(client, request)
	require.NoError(t, err)
	response, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: method})
	require.NoError(t, err)
	return response
}

func TestM1DispatchHTTP11GetPostKeepAliveAndVerifiedUpstream(t *testing.T) {
	client, dispatchDone, dialCount, _ := newMITMDispatchHarness(t, true, []string{"http/1.1"})
	reader := bufio.NewReader(client)
	for _, test := range []struct {
		method string
		path   string
		body   string
		want   string
	}{
		{method: http.MethodGet, path: "/get", want: "GET /get "},
		{method: http.MethodPost, path: "/post", body: "payload", want: "POST /post payload"},
	} {
		request := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: localhost\r\n", test.method, test.path)
		if test.body != "" {
			request += fmt.Sprintf("Content-Length: %d\r\n", len(test.body))
		}
		request += "\r\n" + test.body
		_, err := io.WriteString(client, request)
		require.NoError(t, err)
		response, err := http.ReadResponse(reader, &http.Request{Method: test.method})
		require.NoError(t, err)
		body, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		require.NoError(t, response.Body.Close())
		require.Equal(t, http.StatusOK, response.StatusCode)
		require.Equal(t, test.want, string(body))
	}
	require.EqualValues(t, 2, dialCount.Load(), "each request must resolve the current native proxy policy without reusing a potentially stale route")
	_ = client.Close()
	select {
	case result := <-dispatchDone:
		require.Equal(t, DispatchIntercepted, result.outcome)
		require.NoError(t, result.err)
	case <-time.After(5 * time.Second):
		t.Fatal("MITM HTTP connection did not shut down after the client closed")
	}
}

func TestM1ConcurrentClientConnections(t *testing.T) {
	upstreamCertificate, upstreamRoots := makeTestUpstreamCertificate(t)
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.URL.Path)
	}))
	upstream.TLS = &tls.Config{Certificates: []tls.Certificate{upstreamCertificate}}
	upstream.StartTLS()
	defer upstream.Close()
	upstreamAddress := upstream.Listener.Addr().String()
	ca, clientRoots := makeTestAuthority(t)
	manager := NewManager(Config{
		Enabled:           true,
		Ports:             []uint16{443},
		Domains:           []string{"localhost"},
		CA:                ca,
		HandshakeTimeout:  3 * time.Second,
		ReadHeaderTimeout: 3 * time.Second,
		RequestTimeout:    3 * time.Second,
		IdleTimeout:       3 * time.Second,
		upstreamRootCAs:   upstreamRoots,
	})
	var dialCount atomic.Int32
	const clients = 8
	var wg sync.WaitGroup
	for i := 0; i < clients; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			serverRaw, clientRaw := net.Pipe()
			result := make(chan dispatchResult, 1)
			go func() {
				outcome, err := manager.Dispatch(context.Background(), N.NewBufferedConn(serverRaw), &C.Metadata{
					NetWork: C.TCP,
					Type:    C.TUNNEL,
					Host:    "localhost",
					DstPort: 443,
				}, nil, func(ctx context.Context, metadata *C.Metadata, handshake NativeTLSHandshake) (net.Conn, error) {
					dialCount.Add(1)
					require.Equal(t, "localhost", metadata.Host)
					conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", upstreamAddress)
					if err != nil {
						return nil, err
					}
					secureConn, err := handshake(ctx, conn)
					if err != nil {
						_ = conn.Close()
					}
					return secureConn, err
				})
				result <- dispatchResult{outcome: outcome, err: err}
			}()
			client := tls.Client(clientRaw, &tls.Config{RootCAs: clientRoots, ServerName: "localhost", NextProtos: []string{"http/1.1"}})
			_ = client.SetDeadline(time.Now().Add(10 * time.Second))
			if err := client.Handshake(); err != nil {
				t.Errorf("client %d handshake failed: %v", id, err)
				_ = client.Close()
				return
			}
			_, err := fmt.Fprintf(client, "GET /%d HTTP/1.1\r\nHost: localhost\r\n\r\n", id)
			if err != nil {
				t.Errorf("client %d request failed: %v", id, err)
				_ = client.Close()
				return
			}
			response, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: http.MethodGet})
			if err != nil {
				t.Errorf("client %d response failed: %v", id, err)
				_ = client.Close()
				return
			}
			body, err := io.ReadAll(response.Body)
			if err != nil || response.StatusCode != http.StatusOK || string(body) != fmt.Sprintf("/%d", id) {
				t.Errorf("client %d got status=%d body=%q err=%v", id, response.StatusCode, body, err)
			}
			_ = response.Body.Close()
			_ = client.Close()
			select {
			case dispatch := <-result:
				if dispatch.outcome != DispatchIntercepted || dispatch.err != nil {
					t.Errorf("client %d Dispatch result: outcome=%v err=%v", id, dispatch.outcome, dispatch.err)
				}
			case <-time.After(5 * time.Second):
				t.Errorf("client %d connection did not clean up", id)
			}
		}(i)
	}
	wg.Wait()
	require.EqualValues(t, clients, dialCount.Load(), "each client connection must route independently")
}

func TestM1DispatchRejectsAuthorityUpgradeAndUntrustedUpstream(t *testing.T) {
	t.Run("upgrade refused without upstream dial", func(t *testing.T) {
		ca, clientRoots := makeTestAuthority(t)
		manager := NewManager(Config{Enabled: true, Ports: []uint16{443}, Domains: []string{"localhost"}, CA: ca})
		serverRaw, clientRaw := net.Pipe()
		buffered := N.NewBufferedConn(serverRaw)
		result := make(chan dispatchResult, 1)
		var dialCount atomic.Int32
		go func() {
			outcome, err := manager.Dispatch(context.Background(), buffered, &C.Metadata{NetWork: C.TCP, Type: C.TUNNEL, Host: "localhost", DstPort: 443}, nil, func(context.Context, *C.Metadata, NativeTLSHandshake) (net.Conn, error) {
				dialCount.Add(1)
				return nil, fmt.Errorf("unexpected upstream dial")
			})
			result <- dispatchResult{outcome: outcome, err: err}
		}()
		client := tls.Client(clientRaw, &tls.Config{RootCAs: clientRoots, ServerName: "localhost", NextProtos: []string{"http/1.1"}})
		require.NoError(t, client.Handshake())
		_, err := io.WriteString(client, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
		require.NoError(t, err)
		response, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: http.MethodGet})
		require.NoError(t, err)
		require.Equal(t, http.StatusNotImplemented, response.StatusCode)
		require.NoError(t, response.Body.Close())
		require.Zero(t, dialCount.Load())
		_ = client.Close()
		select {
		case dispatch := <-result:
			require.Equal(t, DispatchIntercepted, dispatch.outcome)
			require.NoError(t, dispatch.err)
		case <-time.After(5 * time.Second):
			t.Fatal("upgrade refusal did not release connection")
		}
	})

	t.Run("untrusted upstream certificate returns 502", func(t *testing.T) {
		client, dispatchDone, dialCount, _ := newMITMDispatchHarness(t, false, []string{"http/1.1"})
		response := sendHTTPOverTLS(t, client, http.MethodGet, "/", "")
		_, err := io.Copy(io.Discard, response.Body)
		require.NoError(t, err)
		require.NoError(t, response.Body.Close())
		require.Equal(t, http.StatusBadGateway, response.StatusCode)
		require.EqualValues(t, 1, dialCount.Load())
		_ = client.Close()
		select {
		case result := <-dispatchDone:
			require.Equal(t, DispatchIntercepted, result.outcome)
			require.NoError(t, result.err)
		case <-time.After(5 * time.Second):
			t.Fatal("failed upstream TLS verification did not release connection")
		}
	})
}

func TestM1DispatchRejectsMisdirectedRequestAndUnknownALPN(t *testing.T) {
	t.Run("authority mismatch returns 421", func(t *testing.T) {
		ca, clientRoots := makeTestAuthority(t)
		manager := NewManager(Config{Enabled: true, Ports: []uint16{443}, Domains: []string{"localhost"}, CA: ca})
		serverRaw, clientRaw := net.Pipe()
		result := make(chan dispatchResult, 1)
		var dialCount atomic.Int32
		go func() {
			outcome, err := manager.Dispatch(context.Background(), N.NewBufferedConn(serverRaw), &C.Metadata{NetWork: C.TCP, Type: C.TUNNEL, Host: "localhost", DstPort: 443}, nil, func(context.Context, *C.Metadata, NativeTLSHandshake) (net.Conn, error) {
				dialCount.Add(1)
				return nil, errors.New("unexpected dial")
			})
			result <- dispatchResult{outcome: outcome, err: err}
		}()
		client := tls.Client(clientRaw, &tls.Config{RootCAs: clientRoots, ServerName: "localhost", NextProtos: []string{"http/1.1"}})
		require.NoError(t, client.Handshake())
		_, err := io.WriteString(client, "GET / HTTP/1.1\r\nHost: other.example\r\n\r\n")
		require.NoError(t, err)
		response, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: http.MethodGet})
		require.NoError(t, err)
		require.Equal(t, http.StatusMisdirectedRequest, response.StatusCode)
		_ = response.Body.Close()
		require.Zero(t, dialCount.Load())
		_ = client.Close()
		dispatch := <-result
		require.Equal(t, DispatchIntercepted, dispatch.outcome)
		require.NoError(t, dispatch.err)
	})

	t.Run("unmatched ALPN is closed", func(t *testing.T) {
		ca, roots := makeTestAuthority(t)
		manager := NewManager(Config{Enabled: true, Ports: []uint16{443}, Domains: []string{"localhost"}, CA: ca})
		serverRaw, clientRaw := net.Pipe()
		result := make(chan dispatchResult, 1)
		go func() {
			outcome, err := manager.Dispatch(context.Background(), N.NewBufferedConn(serverRaw), &C.Metadata{NetWork: C.TCP, Type: C.TUNNEL, Host: "localhost", DstPort: 443}, nil, func(context.Context, *C.Metadata, NativeTLSHandshake) (net.Conn, error) { return nil, nil })
			result <- dispatchResult{outcome: outcome, err: err}
		}()
		client := tls.Client(clientRaw, &tls.Config{RootCAs: roots, ServerName: "localhost", NextProtos: []string{"unsupported-protocol"}})
		require.Error(t, client.Handshake(), "no common ALPN must be rejected during TLS negotiation")
		_ = client.Close()
		dispatch := <-result
		require.Equal(t, DispatchFailed, dispatch.outcome)
		require.ErrorContains(t, dispatch.err, "MITM client TLS handshake")
	})
}

type blockingTLSWriteConn struct {
	net.Conn
	writeStarted chan struct{}
	closed       chan struct{}
	writeOnce    sync.Once
	closeOnce    sync.Once
}

func (conn *blockingTLSWriteConn) Write([]byte) (int, error) {
	conn.writeOnce.Do(func() { close(conn.writeStarted) })
	<-conn.closed
	return 0, net.ErrClosed
}

func (conn *blockingTLSWriteConn) Close() error {
	conn.closeOnce.Do(func() { close(conn.closed) })
	return conn.Conn.Close()
}

func TestM1DispatchMatchedMetadataPreparationFailureIsTerminal(t *testing.T) {
	ca, roots := makeTestAuthority(t)
	manager := NewManager(Config{Enabled: true, Ports: []uint16{443}, Domains: []string{"localhost"}, CA: ca})
	serverRaw, clientRaw := net.Pipe()
	result := make(chan dispatchResult, 1)
	prepareErr := errors.New("metadata preparation failed")
	var dialCalls atomic.Int32
	go func() {
		outcome, err := manager.Dispatch(context.Background(), N.NewBufferedConn(serverRaw), &C.Metadata{NetWork: C.TCP, Type: C.TUNNEL, Host: "localhost", DstPort: 443}, func(*sniffer.TLSClientHelloInfo) (*C.Metadata, error) {
			return nil, prepareErr
		}, func(context.Context, *C.Metadata, NativeTLSHandshake) (net.Conn, error) {
			dialCalls.Add(1)
			return nil, errors.New("unexpected dial")
		})
		result <- dispatchResult{outcome: outcome, err: err}
	}()
	client := tls.Client(clientRaw, &tls.Config{RootCAs: roots, ServerName: "localhost", NextProtos: []string{"http/1.1"}})
	handshakeResult := make(chan error, 1)
	go func() { handshakeResult <- client.Handshake() }()
	select {
	case dispatch := <-result:
		require.Equal(t, DispatchFailed, dispatch.outcome)
		require.ErrorIs(t, dispatch.err, prepareErr)
	case <-time.After(3 * time.Second):
		t.Fatal("matched metadata preparation failure did not terminate Dispatch")
	}
	require.Error(t, <-handshakeResult, "a matched preparation failure must close the connection, not resume native relay")
	require.Zero(t, dialCalls.Load())
	_ = client.Close()
}

func TestM1DispatchAcceptsHTTP11WithoutALPNAndRejectsHTTP2Preface(t *testing.T) {
	t.Run("HTTP/1.1 without ALPN", func(t *testing.T) {
		client, dispatchDone, _, _ := newMITMDispatchHarness(t, true, nil)
		require.Empty(t, client.ConnectionState().NegotiatedProtocol)
		response := sendHTTPOverTLS(t, client, http.MethodGet, "/no-alpn", "")
		body, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		require.NoError(t, response.Body.Close())
		require.Equal(t, http.StatusOK, response.StatusCode)
		require.Equal(t, "GET /no-alpn ", string(body))
		_ = client.Close()
		result := <-dispatchDone
		require.Equal(t, DispatchIntercepted, result.outcome)
		require.NoError(t, result.err)
	})

	t.Run("HTTP/2 preface without ALPN is rejected", func(t *testing.T) {
		client, dispatchDone, dialCount, _ := newMITMDispatchHarness(t, true, nil)
		_, err := io.WriteString(client, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
		require.NoError(t, err)
		response, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: "PRI"})
		require.NoError(t, err)
		require.GreaterOrEqual(t, response.StatusCode, http.StatusBadRequest)
		_ = response.Body.Close()
		require.Zero(t, dialCount.Load(), "an unsupported protocol preface must not reach an upstream")
		_ = client.Close()
		result := <-dispatchDone
		require.Equal(t, DispatchIntercepted, result.outcome)
		require.NoError(t, result.err)
	})
}

func TestM1DispatchContextCancellationDuringHandshake(t *testing.T) {
	ca, roots := makeTestAuthority(t)
	manager := NewManager(Config{Enabled: true, Ports: []uint16{443}, Domains: []string{"localhost"}, CA: ca, HandshakeTimeout: time.Second})
	serverRaw, clientRaw := net.Pipe()
	blockedConn := &blockingTLSWriteConn{Conn: serverRaw, writeStarted: make(chan struct{}), closed: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan dispatchResult, 1)
	go func() {
		outcome, err := manager.Dispatch(ctx, N.NewBufferedConn(blockedConn), &C.Metadata{NetWork: C.TCP, Type: C.TUNNEL, Host: "localhost", DstPort: 443}, nil, func(context.Context, *C.Metadata, NativeTLSHandshake) (net.Conn, error) { return nil, nil })
		result <- dispatchResult{outcome: outcome, err: err}
	}()
	client := tls.Client(clientRaw, &tls.Config{RootCAs: roots, ServerName: "localhost", NextProtos: []string{"http/1.1"}})
	clientHandshake := make(chan error, 1)
	go func() { clientHandshake <- client.Handshake() }()
	select {
	case <-blockedConn.writeStarted:
	case <-time.After(3 * time.Second):
		t.Fatal("server TLS handshake did not reach its blocked write")
	}
	cancel()
	select {
	case dispatch := <-result:
		require.Equal(t, DispatchFailed, dispatch.outcome)
		require.ErrorIs(t, dispatch.err, context.Canceled)
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled TLS handshake did not return")
	}
	require.Error(t, <-clientHandshake)
	_ = client.Close()
}

func TestM1DispatchContextCancellationClosesIdleTLSConnection(t *testing.T) {
	ca, roots := makeTestAuthority(t)
	manager := NewManager(Config{
		Enabled:           true,
		Ports:             []uint16{443},
		Domains:           []string{"localhost"},
		CA:                ca,
		HandshakeTimeout:  time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		RequestTimeout:    5 * time.Second,
		IdleTimeout:       5 * time.Second,
	})
	serverRaw, clientRaw := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	dialCount := new(atomic.Int32)
	dispatchDone := make(chan dispatchResult, 1)
	go func() {
		outcome, err := manager.Dispatch(ctx, N.NewBufferedConn(serverRaw), &C.Metadata{NetWork: C.TCP, Type: C.TUNNEL, Host: "localhost", DstPort: 443}, nil, func(context.Context, *C.Metadata, NativeTLSHandshake) (net.Conn, error) {
			dialCount.Add(1)
			return nil, errors.New("an idle TLS connection must not dial upstream")
		})
		dispatchDone <- dispatchResult{outcome: outcome, err: err}
	}()
	client := tls.Client(clientRaw, &tls.Config{RootCAs: roots, ServerName: "localhost", NextProtos: []string{"http/1.1"}})
	_ = client.SetDeadline(time.Now().Add(4 * time.Second))
	require.NoError(t, client.Handshake())
	cancel()
	select {
	case result := <-dispatchDone:
		require.Equal(t, DispatchFailed, result.outcome)
		require.ErrorIs(t, result.err, context.Canceled)
	case <-time.After(2 * time.Second):
		t.Fatal("cancellation did not release an idle MITM TLS connection")
	}
	require.Zero(t, dialCount.Load())
	var payload [1]byte
	_, err := client.Read(payload[:])
	require.Error(t, err, "the client-side TLS connection must be closed after Dispatcher cancellation")
	_ = client.Close()
}

func TestM1DispatchContextCancellationDuringUpstreamRequest(t *testing.T) {
	ca, roots := makeTestAuthority(t)
	manager := NewManager(Config{Enabled: true, Ports: []uint16{443}, Domains: []string{"localhost"}, CA: ca, HandshakeTimeout: 5 * time.Second})
	serverRaw, clientRaw := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dialStarted := make(chan struct{})
	dialCanceled := make(chan error, 1)
	result := make(chan dispatchResult, 1)
	go func() {
		outcome, err := manager.Dispatch(ctx, N.NewBufferedConn(serverRaw), &C.Metadata{NetWork: C.TCP, Type: C.TUNNEL, Host: "localhost", DstPort: 443}, nil, func(ctx context.Context, _ *C.Metadata, _ NativeTLSHandshake) (net.Conn, error) {
			close(dialStarted)
			<-ctx.Done()
			dialCanceled <- ctx.Err()
			return nil, ctx.Err()
		})
		result <- dispatchResult{outcome: outcome, err: err}
	}()
	client := tls.Client(clientRaw, &tls.Config{RootCAs: roots, ServerName: "localhost", NextProtos: []string{"http/1.1"}})
	require.NoError(t, client.Handshake())
	_, err := io.WriteString(client, "GET /cancel HTTP/1.1\r\nHost: localhost\r\n\r\n")
	require.NoError(t, err)
	select {
	case <-dialStarted:
	case <-time.After(3 * time.Second):
		t.Fatal("request did not reach the native dial callback")
	}
	cancel()
	select {
	case err := <-dialCanceled:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(3 * time.Second):
		t.Fatal("request cancellation did not reach the native dial callback")
	}
	select {
	case dispatch := <-result:
		require.Equal(t, DispatchFailed, dispatch.outcome)
		require.ErrorIs(t, dispatch.err, context.Canceled)
	case <-time.After(3 * time.Second):
		t.Fatal("cancelled HTTP request did not release the server lifecycle")
	}
	_ = client.Close()
}

func TestM1DispatchKeepsActiveSnapshotAcrossConfigReload(t *testing.T) {
	client, dispatchDone, _, manager := newMITMDispatchHarness(t, true, []string{"http/1.1"})
	manager.Update(Config{Enabled: false})
	require.False(t, manager.ConfigSnapshot().Enabled)
	response := sendHTTPOverTLS(t, client, http.MethodGet, "/snapshot", "")
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())
	require.Equal(t, http.StatusOK, response.StatusCode)
	require.Equal(t, "GET /snapshot ", string(body))
	_ = client.Close()
	result := <-dispatchDone
	require.Equal(t, DispatchIntercepted, result.outcome)
	require.NoError(t, result.err)
}

func TestSingleConnListenerCloseDoesNotCloseAcceptedConnection(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()
	listener := &singleConnListener{conn: serverConn}
	accepted, err := listener.Accept()
	require.NoError(t, err)
	require.Same(t, serverConn, accepted)
	require.NoError(t, listener.Close())
	require.NoError(t, listener.Close())
	_, err = listener.Accept()
	require.ErrorIs(t, err, net.ErrClosed)

	writeDone := make(chan error, 1)
	go func() {
		_, err := accepted.Write([]byte("still-open"))
		writeDone <- err
	}()
	got := make([]byte, len("still-open"))
	_, err = io.ReadFull(clientConn, got)
	require.NoError(t, err)
	require.Equal(t, "still-open", string(got))
	require.NoError(t, <-writeDone)
}

func TestValidateClientRequestAuthority(t *testing.T) {
	request, err := http.NewRequest(http.MethodGet, "/path", nil)
	require.NoError(t, err)
	request.Host = "localhost"
	target, err := validateClientRequest(request, "localhost", 443)
	require.NoError(t, err)
	require.Equal(t, "https://localhost:443/path", target.String())

	request.Host = "other.example"
	_, err = validateClientRequest(request, "localhost", 443)
	require.Error(t, err)
	request.Host = "localhost:8443"
	_, err = validateClientRequest(request, "localhost", 443)
	require.Error(t, err)
	_, err = metadataForURL(&C.Metadata{NetWork: C.TCP, Type: C.TUNNEL, Host: "localhost", DstPort: 443}, target, "localhost")
	require.NoError(t, err)
	_, err = metadataForURL(&C.Metadata{NetWork: C.TCP, Type: C.TUNNEL, Host: "localhost", DstPort: 443}, &url.URL{Scheme: "http", Host: "localhost"}, "localhost")
	require.Error(t, err)
}
