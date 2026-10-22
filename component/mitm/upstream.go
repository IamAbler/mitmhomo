package mitm

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"

	"golang.org/x/net/http2"
)

// roundTripProtocol selects the wire protocol only after native routing and a
// verified TLS handshake. No Transport is allowed to dial outside native routing.
// Each request owns its connection; a future shared pool requires a native route
// lease, including dynamic proxy selection and policy invalidation semantics.
func (rt *nativeRoundTripper) roundTripProtocol(req *http.Request) (*http.Response, error) {
	cfg := rt.tlsConfig.Clone()
	cfg.ServerName = req.URL.Hostname()
	handshakeCtx, cancel := context.WithTimeout(req.Context(), rt.handshakeTimeout)
	conn, err := rt.dial(handshakeCtx, rt.target.Clone(), func(ctx context.Context, raw net.Conn) (net.Conn, error) {
		secure := tls.Client(raw, cfg.Clone())
		if err := secure.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		return secure, nil
	})
	cancel()
	if err != nil {
		// Defensive ownership: NativeDialContext must close on error, but never leak
		// a connection if an adapter returns both a connection and an error.
		if conn != nil {
			_ = conn.Close()
		}
		return nil, err
	}
	if conn == nil {
		return nil, errors.New("native TLS dial returned no connection")
	}
	secure, ok := conn.(*tls.Conn)
	if !ok || !secure.ConnectionState().HandshakeComplete {
		_ = conn.Close()
		return nil, errors.New("native TLS dial returned an unverified connection type")
	}
	// This context is the exact request context, never Transport's detached dial
	// context. It remains armed throughout streaming of the response body.
	var once sync.Once
	closeConn := func() { once.Do(func() { _ = conn.Close() }) }
	stop := closeOnContextDone(req.Context(), closeConn)
	var finishOnce sync.Once
	finish := func() { finishOnce.Do(func() { closeConn(); stop() }) }
	var response *http.Response
	switch protocol := secure.ConnectionState().NegotiatedProtocol; protocol {
	case "h2":
		transport := &http2.Transport{
			IdleConnTimeout:   rt.idleTimeout,
			ReadIdleTimeout:   rt.idleTimeout,
			PingTimeout:       rt.handshakeTimeout,
			WriteByteTimeout:  rt.requestTimeout,
			MaxHeaderListSize: 1 << 20,
		}
		var cc *http2.ClientConn
		cc, err = transport.NewClientConn(secure)
		if err == nil {
			// ClientConn.RoundTrip does not perform Transport.RoundTrip's retries.
			// A GOAWAY/RST_STREAM failure is returned, never replayed here.
			response, err = cc.RoundTrip(req)
		}
	case "", "http/1.1":
		transport := &http.Transport{
			Proxy:                  nil,
			TLSNextProto:           map[string]func(string, *tls.Conn) http.RoundTripper{},
			ResponseHeaderTimeout:  rt.requestTimeout,
			IdleConnTimeout:        rt.idleTimeout,
			MaxResponseHeaderBytes: 1 << 20,
		}
		handedOff := false
		transport.DialTLSContext = func(context.Context, string, string) (net.Conn, error) {
			if handedOff {
				return nil, errors.New("native upstream connection cannot be redialed")
			}
			handedOff = true
			return secure, nil
		}
		response, err = transport.RoundTrip(req)
		// Active bodies remain owned by the caller; idle connections cannot escape.
		transport.CloseIdleConnections()
	default:
		err = fmt.Errorf("unsupported upstream ALPN %q", protocol)
	}
	if err != nil {
		finish()
		return nil, err
	}
	// H2 can carry Content-Length together with trailing HEADERS. H1 must
	// use chunked framing to carry those trailers, even without Rewrite.
	if response.ProtoMajor == 2 && len(response.Trailer) > 0 {
		response.Header.Del("Content-Length")
		response.ContentLength = -1
	}
	response.Body = &upstreamResponseBody{ReadCloser: response.Body, finish: finish}
	return response, nil
}

// Response body closure owns the request's connection, including when Rewrite
// replaces the original response. There are no sibling streams on this socket.
// Do not close at read EOF: an early response can overlap an active upload.
type upstreamResponseBody struct {
	io.ReadCloser
	finish func()
}

func (b *upstreamResponseBody) Close() error {
	// Closing the connection also unblocks an unfinished upload before Body.Close.
	b.finish()
	return b.ReadCloser.Close()
}
