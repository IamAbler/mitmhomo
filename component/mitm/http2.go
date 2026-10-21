package mitm

import (
	"context"
	"crypto/tls"
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
