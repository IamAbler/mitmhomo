package mitm

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/sniffer"
	C "github.com/metacubex/mihomo/constant"
	"github.com/stretchr/testify/require"
)

type readCountConn struct {
	net.Conn
	reads atomic.Int32
}

func (c *readCountConn) Read(p []byte) (int, error) {
	c.reads.Add(1)
	return c.Conn.Read(p)
}

type chunkReadConn struct {
	net.Conn
	chunk int
	reads atomic.Int32
}

func (c *chunkReadConn) Read(p []byte) (int, error) {
	if len(p) > c.chunk {
		p = p[:c.chunk]
	}
	c.reads.Add(1)
	return c.Conn.Read(p)
}

type bytesConn struct {
	data []byte
}

func (c *bytesConn) Read(p []byte) (int, error) {
	if len(c.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, c.data)
	c.data = c.data[n:]
	return n, nil
}
func (*bytesConn) Write(p []byte) (int, error)      { return len(p), nil }
func (*bytesConn) Close() error                     { return nil }
func (*bytesConn) LocalAddr() net.Addr              { return testAddr("local") }
func (*bytesConn) RemoteAddr() net.Addr             { return testAddr("remote") }
func (*bytesConn) SetDeadline(time.Time) error      { return nil }
func (*bytesConn) SetReadDeadline(time.Time) error  { return nil }
func (*bytesConn) SetWriteDeadline(time.Time) error { return nil }

type testAddr string

func (a testAddr) Network() string { return "test" }
func (a testAddr) String() string  { return string(a) }

func testClientHelloRecord(serverName string) []byte {
	var extensions []byte
	if serverName != "" {
		name := []byte(serverName)
		list := append([]byte{0, byte(3 + len(name)), 0, byte(len(name))}, name...)
		extension := []byte{0, 0, byte(len(list) >> 8), byte(len(list))}
		extensions = append(extension, list...)
	}
	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0, 0, 2, 0x13, 0x01, 1, 0)
	body = binary.BigEndian.AppendUint16(body, uint16(len(extensions)))
	body = append(body, extensions...)
	handshake := []byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	handshake = append(handshake, body...)
	record := []byte{0x16, 0x03, 0x03, byte(len(handshake) >> 8), byte(len(handshake))}
	return append(record, handshake...)
}

func testCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"localhost"},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	certificate, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	require.NoError(t, err)
	certificate.Leaf = leaf
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	return certificate, roots
}

func TestInspectClientHelloGatesWithoutReading(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	counted := &readCountConn{Conn: left}
	conn := N.NewBufferedConn(counted)

	manager := NewManager(Config{Enabled: false, Ports: []uint16{443}})
	_, inspected, err := manager.InspectClientHello(conn, 443, time.Second)
	require.NoError(t, err)
	require.False(t, inspected)
	require.Zero(t, counted.reads.Load(), "disabled MITM must not peek the TCP stream")

	manager.Update(Config{Enabled: true, Ports: []uint16{8443}})
	_, inspected, err = manager.InspectClientHello(conn, 443, time.Second)
	require.NoError(t, err)
	require.False(t, inspected)
	require.Zero(t, counted.reads.Load(), "ports outside the configured set must not be inspected")
}

func TestInspectPreservesClientHelloForTLSServer(t *testing.T) {
	certificate, roots := testCertificate(t)
	serverRaw, clientRaw := net.Pipe()
	t.Cleanup(func() {
		_ = clientRaw.Close()
		_ = serverRaw.Close()
	})
	segmented := &chunkReadConn{Conn: serverRaw, chunk: 23}
	buffered := N.NewBufferedConn(segmented)
	manager := NewManager(Config{Enabled: true, Ports: []uint16{443}, Domains: []string{"localhost"}})

	client := tls.Client(clientRaw, &tls.Config{
		RootCAs:    roots,
		ServerName: "localhost",
		NextProtos: []string{"http/1.1"},
	})
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	clientHandshake := make(chan error, 1)
	go func() { clientHandshake <- client.Handshake() }()

	info, inspected, err := manager.InspectClientHello(buffered, 443, time.Second)
	require.NoError(t, err)
	require.True(t, inspected)
	require.Equal(t, "localhost", info.ServerName)
	require.False(t, info.HasECH)
	require.Greater(t, segmented.reads.Load(), int32(1), "test connection must split the ClientHello across reads")
	require.Greater(t, buffered.Buffered(), 0, "Peek must leave the ClientHello buffered")

	server := tls.Server(buffered, &tls.Config{Certificates: []tls.Certificate{certificate}, NextProtos: []string{"http/1.1"}})
	require.NoError(t, server.Handshake())
	require.NoError(t, <-clientHandshake)
	require.Equal(t, "http/1.1", server.ConnectionState().NegotiatedProtocol)
	_ = clientRaw.Close()
	_ = serverRaw.Close()
}

func TestInspectClientHelloErrors(t *testing.T) {
	manager := NewManager(Config{Enabled: true, Ports: []uint16{443}})
	tests := []struct {
		name string
		data []byte
	}{
		{name: "no SNI", data: testClientHelloRecord("")},
		{name: "non TLS", data: []byte("GET / HTTP/1.1\r\n")},
		{name: "abnormal record length", data: []byte{0x16, 0x03, 0x03, 0xff, 0xff}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			conn := N.NewBufferedConn(&bytesConn{data: append([]byte(nil), test.data...)})
			_, inspected, err := manager.InspectClientHello(conn, 443, time.Second)
			require.True(t, inspected)
			require.Error(t, err)
			remaining, readErr := io.ReadAll(conn)
			require.NoError(t, readErr)
			require.Equal(t, test.data, remaining, "inspection errors must preserve bytes for the original TCP path")
		})
	}

	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	conn := N.NewBufferedConn(left)
	start := time.Now()
	_, inspected, err := manager.InspectClientHello(conn, 443, 25*time.Millisecond)
	require.True(t, inspected)
	require.Error(t, err)
	require.Less(t, time.Since(start), time.Second)
}

func TestCanInterceptRequiresMatchingConfiguredSNI(t *testing.T) {
	manager := NewManager(Config{Enabled: true, Ports: []uint16{443}, Domains: []string{"allowed.example"}})
	hello := &sniffer.TLSClientHelloInfo{ServerName: "allowed.example"}
	metadata := &C.Metadata{Host: "allowed.example", DstPort: 443}
	require.True(t, manager.CanIntercept(metadata, hello))

	original := *metadata
	require.False(t, manager.CanIntercept(&C.Metadata{}, hello), "invalid metadata must not be made routable by the MITM decision")
	require.False(t, manager.CanIntercept(&C.Metadata{Host: "original.example", DstPort: 443}, hello), "SNI mismatch must pass through")
	require.True(t, manager.CanIntercept(&C.Metadata{DstIP: netip.MustParseAddr("192.0.2.10"), DstPort: 443}, hello), "IP targets can derive the origin from SNI")
	require.False(t, manager.CanIntercept(&C.Metadata{Host: "allowed.example", DstPort: 8443}, hello), "non-target ports must remain on the original path")
	require.False(t, manager.CanIntercept(metadata, &sniffer.TLSClientHelloInfo{ServerName: hello.ServerName, HasECH: true}), "ECH must fail closed to the original path")
	require.Equal(t, original, *metadata, "eligibility checks must not rewrite inbound metadata")
}

func TestDispatchConfigurationUsesOneReloadSnapshot(t *testing.T) {
	manager := NewManager(Config{Enabled: true, Ports: []uint16{443}, Domains: []string{"first.example"}})
	snapshot := manager.loadSnapshot()
	manager.Update(Config{Enabled: true, Ports: []uint16{8443}, Domains: []string{"second.example"}})
	metadata := &C.Metadata{Host: "first.example", DstPort: 443}
	hello := &sniffer.TLSClientHelloInfo{ServerName: "first.example"}
	require.True(t, canIntercept(snapshot, metadata, hello), "an active Dispatch must finish against the snapshot it started with")
	require.False(t, manager.CanIntercept(metadata, hello), "new connections must use the reloaded snapshot")
}

func TestManagerSnapshotsAreImmutableAndConcurrent(t *testing.T) {
	ports := []uint16{443}
	domains := []string{"one.example"}
	manager := NewManager(Config{Enabled: true, Ports: ports, Domains: domains})
	ports[0] = 8443
	domains[0] = "mutated.example"
	require.True(t, manager.ShouldInspect(443))
	require.False(t, manager.ShouldInspect(8443))

	snapshot := manager.ConfigSnapshot()
	snapshot.Ports[0] = 9443
	snapshot.Domains[0] = "mutated.snapshot"
	require.True(t, manager.ShouldInspect(443))
	require.Equal(t, "one.example", manager.ConfigSnapshot().Domains[0])

	var wg sync.WaitGroup
	for reader := 0; reader < 8; reader++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				_ = manager.ShouldInspect(uint16(443 + (i % 2)))
				current := manager.ConfigSnapshot()
				if len(current.Ports) > 0 {
					current.Ports[0] = 1
				}
				_ = manager.CanIntercept(&C.Metadata{Host: "one.example", DstPort: 443}, &sniffer.TLSClientHelloInfo{ServerName: "one.example"})
			}
		}()
	}
	for i := 0; i < 200; i++ {
		config := Config{Enabled: i%2 == 0, Ports: []uint16{uint16(443 + (i % 2))}, Domains: []string{fmt.Sprintf("host-%d.example", i)}}
		manager.Update(config)
		config.Ports[0] = 1
		config.Domains[0] = "mutated.example"
	}
	wg.Wait()
}

type oneConnListener struct {
	conn net.Conn
	used bool
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	if l.used {
		return nil, net.ErrClosed
	}
	l.used = true
	return l.conn, nil
}
func (*oneConnListener) Close() error   { return nil }
func (*oneConnListener) Addr() net.Addr { return testAddr("prototype") }

func startTLSHTTP1Server(t *testing.T, certificate tls.Certificate, handler http.Handler, states chan<- http.ConnState) (*tls.Conn, <-chan error) {
	t.Helper()
	serverRaw, clientRaw := net.Pipe()
	serverDone := make(chan error, 1)
	go func() {
		serverConn := tls.Server(serverRaw, &tls.Config{Certificates: []tls.Certificate{certificate}, NextProtos: []string{"http/1.1"}})
		if err := serverConn.Handshake(); err != nil {
			_ = serverConn.Close()
			serverDone <- err
			return
		}
		if serverConn.ConnectionState().NegotiatedProtocol != "http/1.1" {
			_ = serverConn.Close()
			serverDone <- errors.New("HTTP/1.1 ALPN was not negotiated")
			return
		}
		server := &http.Server{Handler: handler, ConnState: func(_ net.Conn, state http.ConnState) {
			if states != nil {
				select {
				case states <- state:
				default:
				}
			}
		}}
		serverDone <- server.Serve(&oneConnListener{conn: serverConn})
	}()
	client := tls.Client(clientRaw, &tls.Config{RootCAs: testRootsForCertificate(t, certificate), ServerName: "localhost", NextProtos: []string{"h2", "http/1.1"}})
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	if err := client.Handshake(); err != nil {
		_ = clientRaw.Close()
		t.Fatalf("client TLS handshake: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client, serverDone
}

func testRootsForCertificate(t *testing.T, certificate tls.Certificate) *x509.CertPool {
	t.Helper()
	leaf := certificate.Leaf
	if leaf == nil {
		var err error
		leaf, err = x509.ParseCertificate(certificate.Certificate[0])
		require.NoError(t, err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	return roots
}

func writeRequestReadResponse(t *testing.T, conn *tls.Conn, reader *bufio.Reader, request string) *http.Response {
	t.Helper()
	_, err := fmt.Fprint(conn, request)
	require.NoError(t, err)
	response, err := http.ReadResponse(reader, &http.Request{Method: "GET"})
	require.NoError(t, err)
	return response
}

func TestTLSHTTP11KeepAliveAndVerifiedUpstream(t *testing.T) {
	var upstreamRequests atomic.Int32
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamRequests.Add(1)
		_, _ = fmt.Fprintf(w, "%s %s", r.Proto, r.URL.Path)
	}))
	defer upstream.Close()
	upstreamCert := upstream.TLS.Certificates[0]
	upstreamRoots := testRootsForCertificate(t, upstreamCert)
	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{RootCAs: upstreamRoots, ServerName: "example.com"},
		ForceAttemptHTTP2: false,
	}
	t.Cleanup(transport.CloseIdleConnections)
	require.False(t, transport.TLSClientConfig.InsecureSkipVerify, "upstream certificate verification must remain enabled")

	upstreamURL, err := url.Parse(upstream.URL)
	require.NoError(t, err)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect || r.Header.Get("Upgrade") != "" || strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") {
			http.Error(w, "protocol upgrade is unsupported", http.StatusNotImplemented)
			return
		}
		target := *r.URL
		target.Scheme = "https"
		target.Host = upstreamURL.Host
		request := r.Clone(r.Context())
		request.URL = &target
		request.RequestURI = ""
		request.Host = target.Host
		request.Header.Del("Connection")
		response, err := transport.RoundTrip(request)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer response.Body.Close()
		for key, values := range response.Header {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
		w.WriteHeader(response.StatusCode)
		_, _ = io.Copy(w, response.Body)
	})

	certificate, _ := testCertificate(t)
	states := make(chan http.ConnState, 8)
	client, _ := startTLSHTTP1Server(t, certificate, handler, states)
	require.Equal(t, "http/1.1", client.ConnectionState().NegotiatedProtocol)
	reader := bufio.NewReader(client)

	for _, path := range []string{"/one", "/two"} {
		response := writeRequestReadResponse(t, client, reader, "GET "+path+" HTTP/1.1\r\nHost: localhost\r\n\r\n")
		body, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		require.NoError(t, response.Body.Close())
		require.Equal(t, http.StatusOK, response.StatusCode)
		require.Equal(t, "HTTP/1.1 "+path, string(body))
	}

	upgrade := writeRequestReadResponse(t, client, reader, "GET /upgrade HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
	upgradeBody, err := io.ReadAll(upgrade.Body)
	require.NoError(t, err)
	require.NoError(t, upgrade.Body.Close())
	require.Equal(t, http.StatusNotImplemented, upgrade.StatusCode)
	require.Contains(t, string(upgradeBody), "protocol upgrade is unsupported")
	require.EqualValues(t, 2, upstreamRequests.Load(), "upgrade requests must not reach the upstream")
	_ = client.Close()

	deadline := time.After(2 * time.Second)
	closed := false
	for !closed {
		select {
		case state := <-states:
			closed = state == http.StateClosed
		case <-deadline:
			t.Fatal("HTTP server did not release the client connection")
		}
	}
}

func TestTLSHTTPPrototypeRejectsUnnegotiatedProtocol(t *testing.T) {
	certificate, roots := testCertificate(t)
	serverRaw, clientRaw := net.Pipe()
	defer serverRaw.Close()
	defer clientRaw.Close()
	_ = serverRaw.SetDeadline(time.Now().Add(2 * time.Second))
	_ = clientRaw.SetDeadline(time.Now().Add(2 * time.Second))
	serverDone := make(chan error, 1)
	go func() {
		server := tls.Server(serverRaw, &tls.Config{Certificates: []tls.Certificate{certificate}, NextProtos: []string{"http/1.1"}})
		if err := server.Handshake(); err != nil {
			serverDone <- err
			return
		}
		if server.ConnectionState().NegotiatedProtocol != "http/1.1" {
			_ = server.Close()
			serverDone <- errors.New("HTTP/1.1 ALPN was not negotiated")
			return
		}
		serverDone <- errors.New("unsupported protocol was incorrectly served")
	}()
	client := tls.Client(clientRaw, &tls.Config{RootCAs: roots, ServerName: "localhost", NextProtos: []string{"h2"}})
	handshakeErr := client.Handshake()
	if handshakeErr == nil {
		require.Empty(t, client.ConnectionState().NegotiatedProtocol)
		_ = client.SetReadDeadline(time.Now().Add(time.Second))
		_, err := client.Read(make([]byte, 1))
		require.Error(t, err, "server must close an unnegotiated application protocol")
	}
	serverErr := <-serverDone
	require.Error(t, serverErr, "unsupported application protocol must never reach the HTTP/1.1 server")
}
