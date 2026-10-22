package mitm

import (
	"context"
	"io"
	"net/http"
	"time"
)

// InboundBodySource is a handler-scoped capability for the ORIGINAL server
// upload, before internal hooks replace or wrap request.Body. The server retains
// final Close ownership. It must not be paired with an unrelated Reader.
// Interrupt is nonblocking and targets this upload, not an upstream response.
type InboundBodySource struct {
	Reader    io.ReadCloser
	Interrupt func()
}
type inboundBodyKey struct{}

func withInboundBodySource(w http.ResponseWriter, r *http.Request) *http.Request {
	source := InboundBodySource{Reader: r.Body}
	switch r.ProtoMajor {
	case 1:
		// net/http's H1 Body.Close may drain and wait behind Read. A read deadline
		// interrupts the active connection read instead; H1 has no sibling streams.
		controller := http.NewResponseController(w)
		source.Interrupt = func() { _ = controller.SetReadDeadline(time.Now()) }
	case 2:
		// x/net/http2.requestBody.Close is closeOnce + pipe.BreakWithError. It does
		// not close the shared TLS connection and unblocks this stream's pipe.Read.
		body := r.Body
		source.Interrupt = func() {
			if body != nil {
				_ = body.Close()
			}
		}
	}
	return r.WithContext(context.WithValue(r.Context(), inboundBodyKey{}, source))
}

func InboundBodySourceFromContext(ctx context.Context) (InboundBodySource, bool) {
	source, ok := ctx.Value(inboundBodyKey{}).(InboundBodySource)
	return source, ok
}
