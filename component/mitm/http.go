package mitm

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/sniffer"
	C "github.com/metacubex/mihomo/constant"
	domainname "github.com/metacubex/sing/common/metadata"
)

// NativeTLSHandshake completes the upstream TLS handshake on a connection
// selected by Mihomo. Tunnel can run this inside its native retry path when
// the selected proxy requires its first write to initiate an EarlyConn.
type NativeTLSHandshake func(context.Context, net.Conn) (net.Conn, error)

// NativeDialContext opens an upstream TLS connection through Mihomo's native
// rule, proxy selection, retry, and tracking path. It owns the connection and
// must close it if the supplied TLS handshake callback fails.
type NativeDialContext func(context.Context, *C.Metadata, NativeTLSHandshake) (net.Conn, error)

// DispatchOutcome distinguishes an untouched connection from one accepted by
// the MITM and from a matched connection that failed and must be closed.
type DispatchOutcome uint8

const (
	DispatchUnmatched DispatchOutcome = iota
	DispatchIntercepted
	DispatchFailed
)

// MetadataPreparer creates the validated origin Metadata used by the HTTP
// server. Tunnel uses this to preserve Fake-IP pre-handle failure semantics.
type MetadataPreparer func(*sniffer.TLSClientHelloInfo) (*C.Metadata, error)

// RequestHook is the internal M2 extension point. M1 leaves it nil and forwards
// the validated request unchanged.
type RequestHook func(*http.Request) error

// ResponseHook is the internal M2 extension point. M1 leaves it nil.
type ResponseHook func(*http.Response) error

// Dispatch inspects a configured port and serves a matching ClientHello.
// DispatchUnmatched leaves the connection untouched so the original TCP path
// can continue. DispatchFailed means the SNI matched but the connection could
// not be prepared or served; callers must not resume native ciphertext relay.
func (m *Manager) Dispatch(ctx context.Context, conn *N.BufferedConn, metadata *C.Metadata, prepare MetadataPreparer, dial NativeDialContext) (outcome DispatchOutcome, err error) {
	snapshot := m.loadSnapshot()
	if snapshot == nil || !snapshot.config.Enabled || metadata == nil || !portAllowed(snapshot, metadata.DstPort) {
		return DispatchUnmatched, nil
	}
	timeout := snapshot.config.ClientHelloTimeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	hello, inspected, err := inspectClientHello(conn, timeout)
	if !inspected || err != nil {
		return DispatchUnmatched, nil
	}
	if !canIntercept(snapshot, metadata, hello) {
		return DispatchUnmatched, nil
	}
	origin := metadata
	if prepare != nil {
		origin, err = prepare(hello)
		if err != nil {
			return failedDispatch(conn, fmt.Errorf("prepare MITM origin Metadata: %w", err))
		}
	}
	if err := m.serveTLSConnection(ctx, conn, origin, hello, dial, snapshot); err != nil {
		return failedDispatch(conn, err)
	}
	return DispatchIntercepted, nil
}

func failedDispatch(conn net.Conn, err error) (DispatchOutcome, error) {
	if conn != nil {
		_ = conn.Close()
	}
	return DispatchFailed, err
}

func (m *Manager) serveTLSConnection(ctx context.Context, conn net.Conn, metadata *C.Metadata, hello *sniffer.TLSClientHelloInfo, dial NativeDialContext, snapshot *configSnapshot) error {
	if conn == nil || metadata == nil || hello == nil {
		return errors.New("incomplete MITM connection state")
	}
	if dial == nil {
		return errors.New("native outbound dialer is unavailable")
	}
	if snapshot.config.CA == nil {
		return errors.New("MITM CA manager is unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	handshakeTimeout := positiveDuration(snapshot.config.HandshakeTimeout, 10*time.Second)
	if err := conn.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		return fmt.Errorf("set MITM TLS handshake deadline: %w", err)
	}
	certificate, err := snapshot.config.CA.serverCertificate(hello.ServerName)
	if err != nil {
		return err
	}
	tlsConn := tls.Server(conn, &tls.Config{
		Certificates: []tls.Certificate{certificate},
		NextProtos:   []string{"http/1.1"},
		MinVersion:   tls.VersionTLS12,
	})
	handshakeCtx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	err = tlsConn.HandshakeContext(handshakeCtx)
	cancel()
	if err != nil {
		_ = tlsConn.Close()
		return fmt.Errorf("MITM client TLS handshake: %w", err)
	}
	if protocol := tlsConn.ConnectionState().NegotiatedProtocol; protocol != "" && protocol != "http/1.1" {
		_ = tlsConn.Close()
		return fmt.Errorf("unsupported negotiated protocol %q", protocol)
	}
	if err := tlsConn.SetDeadline(time.Time{}); err != nil {
		_ = tlsConn.Close()
		return fmt.Errorf("clear MITM TLS handshake deadline: %w", err)
	}
	defer tlsConn.Close()
	stopCloseOnContext := closeOnContextDone(ctx, func() { _ = conn.Close() })
	defer stopCloseOnContext()

	requestTimeout := positiveDuration(snapshot.config.RequestTimeout, 120*time.Second)
	idleTimeout := positiveDuration(snapshot.config.IdleTimeout, 60*time.Second)
	headerTimeout := positiveDuration(snapshot.config.ReadHeaderTimeout, 10*time.Second)
	handshakeTimeout = positiveDuration(snapshot.config.HandshakeTimeout, 10*time.Second)
	upstreamRoots := snapshot.config.upstreamRootCAs
	if upstreamRoots == nil {
		upstreamRoots = ca.GetCertPool()
	}
	upstreamTLSConfig := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: upstreamRoots}
	originHost := normalizeDomain(metadata.Host)
	if originHost == "" {
		originHost = normalizeDomain(hello.ServerName)
	}
	originPort := metadata.DstPort
	if originPort == 0 {
		return errors.New("MITM origin port is missing")
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 1 || r.ProtoMinor != 1 {
			rejectRequest(w, r, http.StatusHTTPVersionNotSupported, "HTTP/1.1 is required")
			return
		}
		if r.Method == http.MethodConnect || hasUpgrade(r) {
			rejectRequest(w, r, http.StatusNotImplemented, "CONNECT and protocol upgrades are unsupported")
			return
		}
		urlTarget, err := validateClientRequest(r, hello.ServerName, originPort)
		if err != nil {
			rejectRequest(w, r, http.StatusMisdirectedRequest, "request authority does not match the TLS origin")
			return
		}
		request := r.Clone(r.Context())
		request.URL = urlTarget
		request.RequestURI = ""
		if snapshot.config.RequestHook != nil {
			if err := snapshot.config.RequestHook(request); err != nil {
				rejectRequest(w, r, http.StatusBadRequest, "request rejected")
				return
			}
		}
		targetMetadata, err := metadataForURL(metadata, request.URL, originHost)
		if err != nil {
			rejectRequest(w, r, http.StatusBadRequest, "invalid upstream target")
			return
		}
		requestCtx, cancel := context.WithTimeout(request.Context(), requestTimeout)
		defer cancel()
		request = request.WithContext(requestCtx)
		proxy := &httputil.ReverseProxy{
			Transport: &nativeRoundTripper{
				target:           targetMetadata,
				dial:             dial,
				tlsConfig:        upstreamTLSConfig,
				handshakeTimeout: handshakeTimeout,
				requestTimeout:   requestTimeout,
				idleTimeout:      idleTimeout,
			},
			Rewrite: func(*httputil.ProxyRequest) {},
			ModifyResponse: func(response *http.Response) error {
				if snapshot.config.ResponseHook != nil {
					return snapshot.config.ResponseHook(response)
				}
				return nil
			},
			ErrorHandler: func(w http.ResponseWriter, r *http.Request, roundTripErr error) {
				if r.Context().Err() != nil {
					return
				}
				status := http.StatusBadGateway
				if errors.Is(roundTripErr, context.DeadlineExceeded) {
					status = http.StatusGatewayTimeout
				}
				http.Error(w, "upstream request failed", status)
			},
		}
		proxy.ServeHTTP(w, request)
	})
	server := &http.Server{
		Handler:           handler,
		ReadTimeout:       requestTimeout,
		ReadHeaderTimeout: headerTimeout,
		WriteTimeout:      requestTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    1 << 20,
		BaseContext: func(net.Listener) context.Context {
			return ctx
		},
	}
	closed := make(chan struct{})
	var closeOnce sync.Once
	server.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateClosed || state == http.StateHijacked {
			closeOnce.Do(func() { close(closed) })
		}
	}
	serveErr := server.Serve(&singleConnListener{conn: tlsConn})
	if serveErr != nil && !errors.Is(serveErr, net.ErrClosed) && !errors.Is(serveErr, http.ErrServerClosed) {
		_ = conn.Close()
		return fmt.Errorf("serve MITM HTTP/1.1 connection: %w", serveErr)
	}
	select {
	case <-closed:
		return ctx.Err()
	case <-ctx.Done():
		_ = conn.Close()
		return ctx.Err()
	}
}

func closeOnContextDone(ctx context.Context, closeConn func()) func() {
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		select {
		case <-ctx.Done():
			closeConn()
		case <-stop:
		}
	}()
	return func() {
		close(stop)
		<-done
	}
}

func validateClientRequest(request *http.Request, serverName string, originPort uint16) (*url.URL, error) {
	if request.URL == nil || request.URL.Opaque != "" || request.URL.User != nil {
		return nil, errors.New("malformed HTTP request target")
	}
	if request.URL.Scheme != "" && !strings.EqualFold(request.URL.Scheme, "https") {
		return nil, errors.New("TLS request used a non-HTTPS absolute target")
	}
	if request.URL.Host != "" {
		if request.URL.User != nil {
			return nil, errors.New("userinfo is not permitted in request authority")
		}
		if request.Host != "" {
			urlHost, urlPort, err := parseAuthority(request.URL.Host, originPort)
			if err != nil {
				return nil, err
			}
			headerHost, headerPort, err := parseAuthority(request.Host, originPort)
			if err != nil || normalizeDomain(urlHost) != normalizeDomain(headerHost) || urlPort != headerPort {
				return nil, errors.New("absolute request target and Host header differ")
			}
		}
	}
	authority := request.Host
	if authority == "" {
		authority = request.URL.Host
	}
	host, port, err := parseAuthority(authority, originPort)
	if err != nil {
		return nil, err
	}
	if normalizeDomain(host) != normalizeDomain(serverName) || port != originPort {
		return nil, errors.New("request authority differs from TLS origin")
	}
	urlTarget := *request.URL
	urlTarget.Scheme = "https"
	urlTarget.Host = net.JoinHostPort(host, strconv.Itoa(int(port)))
	return &urlTarget, nil
}

func parseAuthority(authority string, defaultPort uint16) (string, uint16, error) {
	if authority == "" || strings.ContainsAny(authority, "/?#\\") {
		return "", 0, errors.New("invalid HTTP authority")
	}
	parsed, err := url.Parse("//" + authority)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Path != "" {
		return "", 0, errors.New("invalid HTTP authority")
	}
	host := strings.TrimSuffix(strings.TrimSpace(parsed.Hostname()), ".")
	if host == "" {
		return "", 0, errors.New("HTTP authority has no hostname")
	}
	if _, err := netip.ParseAddr(host); err != nil && !domainname.IsDomainName(host) {
		return "", 0, errors.New("HTTP authority has an invalid hostname")
	}
	port := defaultPort
	if portString := parsed.Port(); portString != "" {
		parsedPort, err := strconv.ParseUint(portString, 10, 16)
		if err != nil || parsedPort == 0 {
			return "", 0, errors.New("HTTP authority has an invalid port")
		}
		port = uint16(parsedPort)
	}
	if strings.HasSuffix(authority, ":") {
		return "", 0, errors.New("HTTP authority has an empty port")
	}
	return host, port, nil
}

func metadataForURL(base *C.Metadata, target *url.URL, originalHost string) (*C.Metadata, error) {
	if base == nil || target == nil || !strings.EqualFold(target.Scheme, "https") {
		return nil, errors.New("upstream target must use HTTPS")
	}
	host, port, err := parseAuthority(target.Host, 443)
	if err != nil {
		return nil, err
	}
	metadata := base.Clone()
	if ip, err := netip.ParseAddr(host); err == nil {
		metadata.Host = ""
		metadata.DstIP = ip.Unmap()
	} else {
		metadata.Host = host
		if normalizeDomain(host) != normalizeDomain(originalHost) {
			metadata.DstIP = netip.Addr{}
			metadata.DNSMode = C.DNSNormal
			metadata.RawDstAddr = nil
			metadata.DstGeoIP = nil
			metadata.DstIPASN = ""
		}
	}
	metadata.DstPort = port
	metadata.SniffHost = ""
	metadata.RemoteDst = ""
	if !metadata.Valid() {
		return nil, errors.New("upstream Metadata is invalid")
	}
	return metadata, nil
}

func hasUpgrade(request *http.Request) bool {
	if request.Header.Get("Upgrade") != "" {
		return true
	}
	for _, token := range strings.Split(request.Header.Get("Connection"), ",") {
		if strings.EqualFold(strings.TrimSpace(token), "upgrade") {
			return true
		}
	}
	return false
}

func rejectRequest(w http.ResponseWriter, request *http.Request, status int, message string) {
	w.Header().Set("Connection", "close")
	request.Close = true
	http.Error(w, message, status)
}

func positiveDuration(value, fallback time.Duration) time.Duration {
	if value > 0 {
		return value
	}
	return fallback
}

type singleConnListener struct {
	mu       sync.Mutex
	conn     net.Conn
	accepted bool
	closed   bool
}

func (listener *singleConnListener) Accept() (net.Conn, error) {
	listener.mu.Lock()
	defer listener.mu.Unlock()
	if listener.closed {
		return nil, net.ErrClosed
	}
	if listener.accepted {
		return nil, net.ErrClosed
	}
	listener.accepted = true
	return listener.conn, nil
}

func (listener *singleConnListener) Close() error {
	listener.mu.Lock()
	listener.closed = true
	listener.mu.Unlock()
	return nil
}

// nativeRoundTripper gives each HTTP request its own upstream Transport. The
// Transport may detach its dial context from the request so that a late dial
// can populate its connection pool. M1 disables upstream connection reuse, so
// capture the exact request context and target in this RoundTripper instead of
// relying on Transport to preserve request Context values for DialTLSContext.
type nativeRoundTripper struct {
	target           *C.Metadata
	dial             NativeDialContext
	tlsConfig        *tls.Config
	handshakeTimeout time.Duration
	requestTimeout   time.Duration
	idleTimeout      time.Duration
}

func (roundTripper *nativeRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	if roundTripper.target == nil || roundTripper.dial == nil {
		return nil, errors.New("native outbound target or dialer is unavailable")
	}
	requestCtx := request.Context()
	target := roundTripper.target.Clone()
	tlsConfig := roundTripper.tlsConfig
	transport := &http.Transport{
		Proxy:                 nil,
		TLSClientConfig:       tlsConfig,
		DisableKeepAlives:     true,
		ForceAttemptHTTP2:     false,
		TLSNextProto:          map[string]func(string, *tls.Conn) http.RoundTripper{},
		TLSHandshakeTimeout:   roundTripper.handshakeTimeout,
		ResponseHeaderTimeout: roundTripper.requestTimeout,
		IdleConnTimeout:       roundTripper.idleTimeout,
		DialTLSContext: func(_ context.Context, _, address string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return nil, fmt.Errorf("parse upstream TLS address %q: %w", address, err)
			}
			serverTLSConfig := tlsConfig.Clone()
			if serverTLSConfig.ServerName == "" {
				serverTLSConfig.ServerName = strings.Trim(host, "[]")
			}
			handshakeCtx, cancel := context.WithTimeout(requestCtx, roundTripper.handshakeTimeout)
			defer cancel()
			handshake := func(ctx context.Context, conn net.Conn) (net.Conn, error) {
				tlsConn := tls.Client(conn, serverTLSConfig.Clone())
				if err := tlsConn.HandshakeContext(ctx); err != nil {
					return nil, err
				}
				return tlsConn, nil
			}
			return roundTripper.dial(handshakeCtx, target.Clone(), handshake)
		},
	}
	defer transport.CloseIdleConnections()
	return transport.RoundTrip(request)
}

func (listener *singleConnListener) Addr() net.Addr {
	if listener.conn == nil {
		return &net.TCPAddr{}
	}
	return listener.conn.LocalAddr()
}

var _ net.Listener = (*singleConnListener)(nil)
