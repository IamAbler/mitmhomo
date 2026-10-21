package mitm

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
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
	"github.com/metacubex/mihomo/component/mitm/rewrite"
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
		timeoutCtx, stopTimeout := context.WithTimeout(r.Context(), requestTimeout)
		requestCtx, cancel := context.WithCancelCause(timeoutCtx)
		defer stopTimeout()
		defer cancel(context.Canceled)
		initialURL := *urlTarget
		request := r.Clone(requestCtx)
		request.URL = urlTarget
		request.RequestURI = ""
		var discardedBody *requestBodyDiscard
		if snapshot.config.RequestHook != nil {
			if err := snapshot.config.RequestHook(request); err != nil {
				rejectRequest(w, r, http.StatusBadRequest, "request rejected")
				return
			}
		}
		if request.URL == nil {
			rejectRequest(w, r, http.StatusBadRequest, "invalid rewritten request target")
			return
		}
		if pipeline := snapshot.config.Rewrite; pipeline != nil && pipeline.HasRequestRules() {
			result, err := pipeline.ApplyRequest(request.Context(), rewrite.RequestView{
				Method:  request.Method,
				URL:     *request.URL,
				Headers: requestHeaders(request.Header, request.Host),
			})
			if err != nil {
				if request.Context().Err() != nil {
					return
				}
				rejectRequest(w, r, http.StatusInternalServerError, "request rewrite failed")
				return
			}
			if result.Terminal != nil {
				discardedBody, forceClose := startRequestBodyDiscard(w, r, cancel)
				terminalWriter := w
				if discardedBody != nil {
					defer discardedBody.stop(w)
					terminalWriter = &requestBodyDiscardResponseWriter{ResponseWriter: w, discard: discardedBody}
				}
				writeTerminalResponse(terminalWriter, request, result.Terminal, forceClose)
				return
			}
			if err := applyRequestResult(request, result); err != nil {
				rejectRequest(w, r, http.StatusBadRequest, "invalid rewritten request")
				return
			}
			if result.Body != nil {
				discardedBody, _ = startRequestBodyDiscard(w, r, cancel)
				if discardedBody != nil {
					defer discardedBody.stop(w)
				}
			}
		}
		urlAuthorityChanged := !strings.EqualFold(initialURL.Scheme, request.URL.Scheme) || !sameURLAuthority(initialURL.Host, request.URL.Host)
		if err := normalizeRequestURL(request); err != nil {
			rejectRequest(w, r, http.StatusBadRequest, "invalid rewritten request target")
			return
		}
		if urlAuthorityChanged {
			// The final HTTPS URL is authoritative for HTTP Host and upstream SNI.
			// Host is not a configurable rewrite header because it is represented
			// separately by net/http.Request.Host.
			request.Host = request.URL.Host
		}
		targetMetadata, err := metadataForURL(metadata, request.URL, originHost)
		if err != nil {
			rejectRequest(w, r, http.StatusBadRequest, "invalid upstream target")
			return
		}
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
					if err := snapshot.config.ResponseHook(response); err != nil {
						return err
					}
				}
				return applyResponseRewrite(request.Context(), rewrite.RequestView{
					Method:  request.Method,
					URL:     *request.URL,
					Headers: requestHeaders(request.Header, request.Host),
				}, response, snapshot.config.Rewrite, snapshot.config.ResponseHook != nil, r.Method)
			},
			ErrorHandler: func(w http.ResponseWriter, proxyRequest *http.Request, roundTripErr error) {
				requestErr := proxyRequest.Context().Err()
				requestCause := context.Cause(proxyRequest.Context())
				requestTimedOut := errors.Is(roundTripErr, context.DeadlineExceeded) || errors.Is(requestErr, context.DeadlineExceeded) || errors.Is(requestCause, context.DeadlineExceeded)
				if errors.Is(requestErr, context.Canceled) && !requestTimedOut && discardedBody != nil {
					// The HTTP server can cancel the request Context as soon as a
					// timed-out Body.Read fails. Wait for that reader's result before
					// classifying the cancellation, so a body read timeout is not
					// mistaken for a disconnected client and turned into an empty 200.
					requestTimedOut = isTimeoutError(discardedBody.resultAfterDone().err)
				}
				if errors.Is(requestErr, context.Canceled) && !requestTimedOut {
					return
				}
				status := http.StatusBadGateway
				if requestTimedOut {
					status = http.StatusGatewayTimeout
				}
				http.Error(w, "upstream request failed", status)
			},
		}
		proxyWriter := w
		if discardedBody != nil {
			proxyWriter = &requestBodyDiscardResponseWriter{ResponseWriter: w, discard: discardedBody}
		}
		proxy.ServeHTTP(proxyWriter, request)
	})
	server := &http.Server{
		Handler:           handler,
		ReadTimeout:       requestTimeout,
		ReadHeaderTimeout: headerTimeout,
		// Keep a short write window after the per-request Context expires so
		// the ErrorHandler can return the resulting 504 to a connected client.
		WriteTimeout:   requestTimeout + time.Second,
		IdleTimeout:    idleTimeout,
		MaxHeaderBytes: 1 << 20,
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

func requestHeaders(headers http.Header, host string) rewrite.HeaderMap {
	result := make(rewrite.HeaderMap, len(headers)+1)
	for name, values := range headers {
		result[name] = values
	}
	if host != "" {
		result["Host"] = []string{host}
	}
	return result
}

func applyRequestResult(request *http.Request, result rewrite.RequestResult) error {
	if request == nil || result.Terminal != nil {
		return errors.New("invalid non-terminal request rewrite result")
	}
	oldContentType := append([]string(nil), request.Header.Values("Content-Type")...)
	request.Method = result.Request.Method
	target := result.Request.URL
	request.URL = &target
	request.RequestURI = ""
	request.Header = http.Header(result.Request.Headers)
	request.Header.Del("Host")
	if result.Body == nil {
		return nil
	}

	// The request clone shares the server's inbound Body, but the HTTP server
	// owns its disposal. Closing it here can synchronously wait for a partial
	// upload; the handler coordinates a bounded discard before responding, and
	// the server performs the single final Close after the handler returns.
	body := result.Body.Replace
	request.Body = replacementReader(body)
	request.GetBody = func() (io.ReadCloser, error) { return replacementReader(body), nil }
	request.ContentLength = int64(len(body))
	request.TransferEncoding = nil
	request.Trailer = nil
	for _, name := range []string{
		"Content-Length", "Transfer-Encoding", "Trailer", "Expect", "Content-Encoding",
		"Content-MD5", "Digest", "Content-Range",
	} {
		request.Header.Del(name)
	}
	if result.Body.ContentType != "" {
		request.Header.Set("Content-Type", result.Body.ContentType)
	} else if equalHeaderValues(oldContentType, request.Header.Values("Content-Type")) {
		// Keep a Content-Type deliberately changed by a later Header action, but
		// discard the incoming type when it would describe the replaced body.
		request.Header.Del("Content-Type")
	}
	return nil
}

func equalHeaderValues(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func replacementReader(body string) io.ReadCloser {
	if body == "" {
		return http.NoBody
	}
	return io.NopCloser(strings.NewReader(body))
}

func writeTerminalResponse(w http.ResponseWriter, request *http.Request, terminal *rewrite.TerminalResponse, forceClose bool) {
	if terminal == nil {
		return
	}
	if terminal.StatusCode < http.StatusOK || terminal.StatusCode > 599 || terminal.StatusCode == http.StatusSwitchingProtocols || terminal.Decision != rewrite.RedirectResponse && terminal.Decision != rewrite.LocalResponseDecision {
		writeInvalidTerminalResponse(w, forceClose)
		return
	}
	if terminal.Decision == rewrite.RedirectResponse {
		switch terminal.StatusCode {
		case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		default:
			writeInvalidTerminalResponse(w, forceClose)
			return
		}
		if terminal.Body != "" {
			writeInvalidTerminalResponse(w, forceClose)
			return
		}
	}
	if (terminal.StatusCode == http.StatusNoContent || terminal.StatusCode == http.StatusResetContent || terminal.StatusCode == http.StatusNotModified) && terminal.Body != "" {
		writeInvalidTerminalResponse(w, forceClose)
		return
	}
	connectionFields := connectionNominatedHeaders(terminal.Headers)
	prepared := make(http.Header, len(terminal.Headers))
	for name, values := range terminal.Headers {
		if !validTerminalHeaderName(name) {
			writeInvalidTerminalResponse(w, forceClose)
			return
		}
		if terminalHeaderIsManaged(name) || terminalHeaderIsHopByHop(name) || connectionFields[strings.ToLower(name)] {
			continue
		}
		for _, value := range values {
			if !validTerminalHeaderValue(value) || strings.EqualFold(name, "Location") && terminal.Decision == rewrite.RedirectResponse && !validRedirectLocation(value) {
				writeInvalidTerminalResponse(w, forceClose)
				return
			}
			prepared.Add(name, value)
		}
	}
	if terminal.Decision == rewrite.RedirectResponse {
		locations := prepared.Values("Location")
		if len(locations) != 1 || !validRedirectLocation(locations[0]) {
			writeInvalidTerminalResponse(w, forceClose)
			return
		}
	}
	header := w.Header()
	for name := range header {
		header.Del(name)
	}
	for name, values := range prepared {
		header[name] = append([]string(nil), values...)
	}
	bodylessStatus := terminal.StatusCode == http.StatusNoContent || terminal.StatusCode == http.StatusResetContent || terminal.StatusCode == http.StatusNotModified
	if terminal.StatusCode == http.StatusResetContent {
		header.Set("Content-Length", "0")
	} else if terminal.StatusCode != http.StatusNoContent && terminal.StatusCode != http.StatusNotModified {
		// The adapter owns the wire length. This also describes the selected
		// representation for HEAD while the body itself remains suppressed.
		header.Set("Content-Length", strconv.Itoa(len(terminal.Body)))
		if terminal.Body != "" && header.Get("Content-Type") == "" {
			header.Set("Content-Type", "text/plain; charset=utf-8")
		}
	}
	if forceClose {
		header.Set("Connection", "close")
	}
	w.WriteHeader(terminal.StatusCode)
	if request != nil && request.Method != http.MethodHead && !bodylessStatus && terminal.Body != "" {
		_, _ = io.WriteString(w, terminal.Body)
	}
}

type requestBodyDiscardResult struct {
	complete bool
	err      error
}

type requestBodyDiscard struct {
	done            chan struct{}
	mu              sync.Mutex
	result          requestBodyDiscardResult
	reusable        bool
	request         *http.Request
	responseStarted bool
}

func startRequestBodyDiscard(w http.ResponseWriter, request *http.Request, cancel context.CancelCauseFunc) (*requestBodyDiscard, bool) {
	if request == nil || request.Body == nil || request.Body == http.NoBody || request.ContentLength == 0 {
		return nil, false
	}
	const maxReusableDiscardBytes = 64 << 10
	if request.Header.Get("Expect") != "" {
		// Do not trigger a 100-continue exchange solely to discard a body that
		// the upstream does not need. Close this HTTP/1 connection after reply.
		request.Close = true
		w.Header().Set("Connection", "close")
		_ = http.NewResponseController(w).SetReadDeadline(time.Now())
		return nil, true
	}
	reusable := request.ContentLength > 0 && request.ContentLength <= maxReusableDiscardBytes && request.Header.Get("Expect") == ""
	if !reusable {
		request.Close = true
		w.Header().Set("Connection", "close")
	}
	limit := int64(maxReusableDiscardBytes + 1)
	if reusable {
		// Read one byte beyond the declared size so the server Body observes EOF
		// and may safely reuse this HTTP/1 connection.
		limit = request.ContentLength + 1
	}
	discard := &requestBodyDiscard{done: make(chan struct{}), reusable: reusable, request: request}
	go func() {
		_, err := io.CopyN(io.Discard, request.Body, limit)
		result := requestBodyDiscardResult{complete: errors.Is(err, io.EOF), err: err}
		discard.mu.Lock()
		if err != nil && !errors.Is(err, io.EOF) && !discard.responseStarted {
			// A failed bounded read before the response begins means the client
			// disconnected or its upload timed out. Cancel active upstream work.
			cause := error(context.Canceled)
			if isTimeoutError(err) {
				cause = context.DeadlineExceeded
			}
			cancel(cause)
		}
		discard.result = result
		close(discard.done)
		discard.mu.Unlock()
	}()
	return discard, !reusable
}

func (discard *requestBodyDiscard) wait(ctx context.Context) (requestBodyDiscardResult, error) {
	select {
	case <-discard.done:
		discard.mu.Lock()
		defer discard.mu.Unlock()
		if discard.result.err != nil && !errors.Is(discard.result.err, io.EOF) {
			return discard.result, discard.result.err
		}
		return discard.result, nil
	case <-ctx.Done():
		return requestBodyDiscardResult{}, ctx.Err()
	}
}

func (discard *requestBodyDiscard) resultAfterDone() requestBodyDiscardResult {
	<-discard.done
	discard.mu.Lock()
	defer discard.mu.Unlock()
	return discard.result
}

func isTimeoutError(err error) bool {
	var networkError net.Error
	return errors.As(err, &networkError) && networkError.Timeout()
}

func (discard *requestBodyDiscard) forceClose(w http.ResponseWriter) {
	discard.request.Close = true
	w.Header().Set("Connection", "close")
	_ = http.NewResponseController(w).SetReadDeadline(time.Now())
}

func (discard *requestBodyDiscard) beforeResponseWrite(w http.ResponseWriter) {
	discard.mu.Lock()
	discard.responseStarted = true
	select {
	case <-discard.done:
		if discard.reusable && discard.result.complete && (discard.result.err == nil || errors.Is(discard.result.err, io.EOF)) {
			discard.mu.Unlock()
			return
		}
	default:
	}
	discard.mu.Unlock()
	discard.forceClose(w)
	<-discard.done
}

func (discard *requestBodyDiscard) stop(w http.ResponseWriter) {
	select {
	case <-discard.done:
		result, _ := discard.wait(context.Background())
		if result.err != nil && !errors.Is(result.err, io.EOF) {
			discard.mu.Lock()
			discard.responseStarted = true
			discard.mu.Unlock()
			discard.request.Close = true
			w.Header().Set("Connection", "close")
		}
	default:
		discard.mu.Lock()
		discard.responseStarted = true
		discard.mu.Unlock()
		discard.forceClose(w)
		<-discard.done
	}
}

type requestBodyDiscardResponseWriter struct {
	http.ResponseWriter
	discard *requestBodyDiscard
}

func (writer *requestBodyDiscardResponseWriter) Unwrap() http.ResponseWriter {
	return writer.ResponseWriter
}

func (writer *requestBodyDiscardResponseWriter) WriteHeader(statusCode int) {
	writer.discard.beforeResponseWrite(writer.ResponseWriter)
	writer.ResponseWriter.WriteHeader(statusCode)
}

func (writer *requestBodyDiscardResponseWriter) Write(body []byte) (int, error) {
	writer.discard.beforeResponseWrite(writer.ResponseWriter)
	return writer.ResponseWriter.Write(body)
}

func (writer *requestBodyDiscardResponseWriter) Flush() {
	_ = writer.FlushError()
}

func (writer *requestBodyDiscardResponseWriter) FlushError() error {
	writer.discard.beforeResponseWrite(writer.ResponseWriter)
	return http.NewResponseController(writer.ResponseWriter).Flush()
}

func connectionNominatedHeaders(headers rewrite.HeaderMap) map[string]bool {
	var result map[string]bool
	for name, values := range headers {
		if !strings.EqualFold(name, "Connection") {
			continue
		}
		for _, value := range values {
			for _, field := range strings.Split(value, ",") {
				field = strings.TrimSpace(field)
				if field == "" {
					continue
				}
				if result == nil {
					result = make(map[string]bool)
				}
				result[strings.ToLower(field)] = true
			}
		}
	}
	return result
}

func terminalHeaderIsManaged(name string) bool {
	switch strings.ToLower(name) {
	case "host", "content-length", "transfer-encoding", "trailer":
		return true
	default:
		return false
	}
}

func terminalHeaderIsHopByHop(name string) bool {
	switch strings.ToLower(name) {
	case "connection", "keep-alive", "proxy-connection", "proxy-authenticate", "proxy-authorization", "proxy-authentication-info", "te", "upgrade":
		return true
	default:
		return false
	}
}

func validTerminalHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c))) {
			return false
		}
	}
	return true
}

func validTerminalHeaderValue(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] == 127 || value[i] < 32 && value[i] != '\t' {
			return false
		}
	}
	return true
}

func validRedirectLocation(raw string) bool {
	if raw == "" || !validTerminalHeaderValue(raw) || strings.ContainsAny(raw, " \t\\") {
		return false
	}
	target, err := url.Parse(raw)
	if err != nil || target.User != nil || target.Opaque != "" {
		return false
	}
	if _, err := url.QueryUnescape(target.RawQuery); err != nil {
		return false
	}
	if target.IsAbs() {
		if !strings.EqualFold(target.Scheme, "https") || target.Host == "" {
			return false
		}
		_, _, err := parseAuthority(target.Host, 443)
		return err == nil
	}
	return target.Host == "" && !strings.HasPrefix(raw, "//")
}

func writeInvalidTerminalResponse(w http.ResponseWriter, forceClose bool) {
	header := w.Header()
	for name := range header {
		header.Del(name)
	}
	if forceClose {
		header.Set("Connection", "close")
	}
	http.Error(w, "invalid terminal response", http.StatusInternalServerError)
}

func normalizeRequestURL(request *http.Request) error {
	if request == nil || request.URL == nil || request.URL.User != nil || request.URL.Opaque != "" || request.URL.Fragment != "" || request.URL.RawFragment != "" {
		return errors.New("invalid request URL")
	}
	if !strings.EqualFold(request.URL.Scheme, "https") {
		return errors.New("rewritten request URL must use HTTPS")
	}
	if _, err := url.QueryUnescape(request.URL.RawQuery); err != nil {
		return fmt.Errorf("invalid request URL query: %w", err)
	}
	host, port, err := parseAuthority(request.URL.Host, 443)
	if err != nil {
		return err
	}
	target := *request.URL
	target.Scheme = "https"
	target.Host = net.JoinHostPort(host, strconv.Itoa(int(port)))
	request.URL = &target
	if !validMethod(request.Method) || request.Method == http.MethodConnect || request.Method == "PRI" {
		return errors.New("invalid or unsupported rewritten method")
	}
	return nil
}

func validMethod(method string) bool {
	if method == "" {
		return false
	}
	for i := 0; i < len(method); i++ {
		c := method[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c))) {
			return false
		}
	}
	return true
}

func sameURLAuthority(a, b string) bool {
	aHost, aPort, aErr := parseAuthority(a, 443)
	bHost, bPort, bErr := parseAuthority(b, 443)
	return aErr == nil && bErr == nil && normalizeDomain(aHost) == normalizeDomain(bHost) && aPort == bPort
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
		metadata.DNSMode = C.DNSNormal
		metadata.RawDstAddr = nil
		metadata.DstGeoIP = nil
		metadata.DstIPASN = ""
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
		Proxy:           nil,
		TLSClientConfig: tlsConfig,
		// Each request owns this transport. CloseIdleConnections below prevents
		// pooling without forcing Connection: close onto upstream responses.
		DisableKeepAlives:     false,
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
			// The request URL is the source of truth after URL Rewrite. Use its
			// hostname for both SNI and certificate verification even when the
			// physical Native Dialer connects through a different address.
			serverName := request.URL.Hostname()
			if serverName == "" {
				serverName = strings.Trim(host, "[]")
			}
			serverTLSConfig.ServerName = serverName
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
	response, err := transport.RoundTrip(request)
	if err != nil {
		return response, err
	}
	// ReverseProxy removes Connection before ModifyResponse. Capture its trailer
	// nominations here, while they are still available, including late EOF values.
	nominated := responseConnectionFields(response.Header)
	if len(response.Trailer) > 0 && (len(nominated) > 0 || response.Close) {
		// net/http removes the entire Connection header when it contains close,
		// including any trailer nominations. Such trailers cannot be verified;
		// omit them while continuing to stream the response body.
		dropAll := response.Close
		if dropAll {
			for name := range response.Trailer {
				delete(response.Trailer, name)
			}
		}
		for _, name := range nominated {
			response.Trailer.Del(name)
		}
		response.Body = &responseTrailerFilterBody{body: response.Body, trailers: response.Trailer, names: nominated, dropAll: dropAll}
	}
	return response, nil
}

func (listener *singleConnListener) Addr() net.Addr {
	if listener.conn == nil {
		return &net.TCPAddr{}
	}
	return listener.conn.LocalAddr()
}

var _ net.Listener = (*singleConnListener)(nil)
