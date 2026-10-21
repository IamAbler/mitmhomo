package mitm

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"

	"golang.org/x/net/http2"
)

// serveHTTP2Connection consumes an already-handshaken TLS connection. The
// caller owns the socket and connection context; http2 owns stream parsing,
// request bodies and concurrent handler calls. BaseConfig.Handler captures
// the same immutable connection snapshot as the HTTP/1.1 adapter.
func serveHTTP2Connection(ctx context.Context, conn *tls.Conn, base *http.Server) {
	server := &http2.Server{
		MaxConcurrentStreams: 100,
		IdleTimeout:          base.IdleTimeout,
		ReadIdleTimeout:      base.IdleTimeout,
		PingTimeout:          base.ReadHeaderTimeout,
		WriteByteTimeout:     base.WriteTimeout,
	}
	server.ServeConn(conn, &http2.ServeConnOpts{Context: ctx, BaseConfig: base, Handler: base.Handler})
}

// Request.Clone copies Trailer before the server body has populated its values.
// Bridge only declared fields, at EOF, into the final Transport request map.
// A replacement body clears Trailer and must never inherit upload trailers.
func bridgeHTTP2RequestTrailers(request *http.Request, source http.Header) error {
	if len(source) == 0 || len(request.Trailer) == 0 {
		return nil
	}
	if err := validateResponseTrailers(request.Trailer); err != nil {
		return err
	}
	request.ContentLength = -1 // H1 trailers require chunked framing, even for known H2 lengths.
	request.Header.Del("Content-Length")
	request.Body = &http2RequestTrailerBody{ReadCloser: request.Body, source: source, target: request.Trailer}
	return nil
}

type http2RequestTrailerBody struct {
	io.ReadCloser
	source, target http.Header
}

func (b *http2RequestTrailerBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err == io.EOF {
		for name := range b.target {
			b.target[name] = append([]string(nil), b.source.Values(name)...)
		}
		if invalid := validateResponseTrailers(b.target); invalid != nil {
			return n, invalid
		}
	}
	return n, err
}
