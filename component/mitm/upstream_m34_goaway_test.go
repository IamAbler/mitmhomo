package mitm

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// Wire-level GOAWAY last-stream-id=1 keeps stream 1 alive, rejects POST on
// stream 3, and forces a later request onto a new native-routed connection.
func TestM34GoAwayDrainAndNoReplay(t *testing.T) {
	m34GoAwayDrainAndNoReplay(t)
}

func m34GoAwayDrainAndNoReplay(t *testing.T) {
	t.Helper()
	cert, roots := makeTestUpstreamCertificate(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	var accepts, processedPost atomic.Int32
	firstEntered := make(chan struct{})
	serverErrors := make(chan error, 1)
	var wg sync.WaitGroup
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			raw, e := listener.Accept()
			if e != nil {
				return
			}
			n := accepts.Add(1)
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer raw.Close()
				secure := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2"}, MinVersion: tls.VersionTLS12})
				if e := secure.Handshake(); e != nil {
					return
				}
				if n != 1 {
					(&http2.Server{}).ServeConn(secure, &http2.ServeConnOpts{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						if r.Method == "POST" {
							processedPost.Add(1)
						}
						io.Copy(io.Discard, r.Body)
						io.WriteString(w, "new")
					})})
					return
				}
				secure.SetDeadline(time.Now().Add(10 * time.Second))
				preface := make([]byte, len(http2.ClientPreface))
				if _, e := io.ReadFull(secure, preface); e != nil {
					serverErrors <- e
					return
				}
				fr := http2.NewFramer(secure, secure)
				if e := fr.WriteSettings(); e != nil {
					serverErrors <- e
					return
				}
				for {
					frame, e := fr.ReadFrame()
					if e != nil {
						serverErrors <- e
						return
					}
					if h, ok := frame.(*http2.HeadersFrame); ok {
						if h.StreamID == 1 {
							close(firstEntered)
							continue
						}
						if h.StreamID != 3 {
							serverErrors <- io.ErrUnexpectedEOF
							return
						}
						if e := fr.WriteGoAway(1, http2.ErrCodeNo, nil); e != nil {
							serverErrors <- e
							return
						}
						var block bytes.Buffer
						encoder := hpack.NewEncoder(&block)
						encoder.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
						encoder.WriteField(hpack.HeaderField{Name: "content-length", Value: "2"})
						if e := fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, EndHeaders: true, BlockFragment: block.Bytes()}); e != nil {
							serverErrors <- e
							return
						}
						if e := fr.WriteData(1, true, []byte("ok")); e != nil {
							serverErrors <- e
							return
						}
						serverErrors <- nil
						for {
							if _, e := fr.ReadFrame(); e != nil {
								return
							}
						}
					}
				}
			}()
		}
	}()
	defer func() { listener.Close(); <-acceptDone; wg.Wait() }()
	pool := newUpstreamManager(context.Background(), time.Second)
	defer pool.Close()
	rt := &nativeRoundTripper{pool: pool, target: &C.Metadata{NetWork: C.TCP, Host: "localhost", DstPort: 443}, tlsConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12, NextProtos: []string{"h2"}}, handshakeTimeout: time.Second, requestTimeout: 3 * time.Second, idleTimeout: time.Second, dial: m34Dial(func(*C.Metadata) string { return listener.Addr().String() })}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	sibling := make(chan string, 1)
	go func() {
		req, _ := http.NewRequestWithContext(ctx, "GET", "https://localhost/sibling", nil)
		res, e := rt.RoundTrip(req)
		if e != nil {
			sibling <- e.Error()
			return
		}
		b, e := io.ReadAll(res.Body)
		res.Body.Close()
		if e != nil {
			sibling <- e.Error()
			return
		}
		sibling <- string(b)
	}()
	select {
	case <-firstEntered:
	case <-ctx.Done():
		t.Fatal("first stream not active")
	}
	req, _ := http.NewRequestWithContext(ctx, "POST", "https://localhost/once", strings.NewReader("once"))
	res, err := rt.RoundTrip(req)
	if res != nil {
		res.Body.Close()
	}
	require.Error(t, err)
	select {
	case err := <-serverErrors:
		require.NoError(t, err)
	case <-ctx.Done():
		t.Fatal("GOAWAY server did not finish:", ctx.Err())
	}
	select {
	case result := <-sibling:
		require.Equal(t, "ok", result, "GOAWAY must let stream <= last-stream-id complete")
	case <-ctx.Done():
		t.Fatal("GOAWAY sibling did not finish:", ctx.Err())
	}
	require.EqualValues(t, 1, accepts.Load(), "failed POST was not redialed/replayed")
	req, _ = http.NewRequestWithContext(ctx, "GET", "https://localhost/after", nil)
	res, err = rt.RoundTrip(req)
	require.NoError(t, err)
	require.Equal(t, "new", readM2ResponseBody(t, res))
	require.EqualValues(t, 2, accepts.Load())
	require.Zero(t, processedPost.Load())
}
