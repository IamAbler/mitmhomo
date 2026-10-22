package mitm

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
)

// A real TLS origin emits GOAWAY or RST_STREAM after receiving request HEADERS.
// Even REFUSED_STREAM must not cause this adapter to replay a POST.
func TestM33GoAwayAndResetDoNotReplay(t *testing.T) {
	for _, kind := range []string{"goaway", "reset"} {
		t.Run(kind, func(t *testing.T) {
			cert, roots := makeTestUpstreamCertificate(t)
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			defer listener.Close()
			serverDone := make(chan error, 1)
			go func() {
				raw, err := listener.Accept()
				if err != nil {
					serverDone <- err
					return
				}
				defer raw.Close()
				secure := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2"}, MinVersion: tls.VersionTLS12})
				secure.SetDeadline(time.Now().Add(3 * time.Second))
				if err = secure.Handshake(); err != nil {
					serverDone <- err
					return
				}
				preface := make([]byte, len(http2.ClientPreface))
				if _, err = io.ReadFull(secure, preface); err != nil {
					serverDone <- err
					return
				}
				if string(preface) != http2.ClientPreface {
					serverDone <- io.ErrUnexpectedEOF
					return
				}
				fr := http2.NewFramer(secure, secure)
				if err = fr.WriteSettings(); err != nil {
					serverDone <- err
					return
				}
				for {
					frame, err := fr.ReadFrame()
					if err != nil {
						serverDone <- err
						return
					}
					if headers, ok := frame.(*http2.HeadersFrame); ok {
						if kind == "goaway" {
							err = fr.WriteGoAway(0, http2.ErrCodeNo, nil)
						} else {
							err = fr.WriteRSTStream(headers.StreamID, http2.ErrCodeRefusedStream)
						}
						serverDone <- err
						return
					}
				}
			}()
			var dials atomic.Int32
			rt := &nativeRoundTripper{target: &C.Metadata{NetWork: C.TCP, Host: "localhost", DstPort: 443}, tlsConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"}}, handshakeTimeout: time.Second, requestTimeout: time.Second, idleTimeout: time.Second,
				dial: func(ctx context.Context, _ *C.Metadata, handshake NativeTLSHandshake) (net.Conn, error) {
					dials.Add(1)
					raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
					if err != nil {
						return nil, err
					}
					secure, err := handshake(ctx, raw)
					if err != nil {
						raw.Close()
					}
					return secure, err
				},
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, "POST", "https://localhost/", strings.NewReader("send-only-once"))
			require.NoError(t, err)
			res, err := rt.RoundTrip(req)
			if res != nil {
				res.Body.Close()
			}
			require.Error(t, err)
			require.NoError(t, <-serverDone)
			require.EqualValues(t, 1, dials.Load())
		})
	}
}

func TestM33TLSVerificationFailure(t *testing.T) {
	h := newProtocolHarness(t, nil, "localhost", 443, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("untrusted origin received HTTP") }), false, false, true, []string{"h2"})
	res := h2Request(t, h, "POST", "/", "secret")
	require.Equal(t, 502, res.StatusCode)
	res.Body.Close()
	require.EqualValues(t, 1, h.dials.Load())
}

func TestM33EarlyEOFAndTimeout(t *testing.T) {
	h := newProtocolHarness(t, nil, "localhost", 443, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, 2, r.ProtoMajor)
		if r.URL.Path == "/timeout" {
			<-r.Context().Done()
			return
		}
		if r.URL.Path == "/short" {
			w.Header().Set("Content-Length", "100")
			io.WriteString(w, "short")
			return
		}
		io.WriteString(w, "healthy")
	}), false, true, true, []string{"h2"}, func(c *Config) { c.RequestTimeout = 150 * time.Millisecond })
	res, err := h.client.RoundTrip(m33Request(t, "/short"))
	if err == nil {
		_, err = io.ReadAll(res.Body)
		res.Body.Close()
	}
	require.Error(t, err)
	res = h2Request(t, h, "GET", "/timeout", "")
	require.Equal(t, 504, res.StatusCode)
	res.Body.Close()
	res = h2Request(t, h, "GET", "/after", "")
	require.Equal(t, "healthy", readM2ResponseBody(t, res))
}

func m33Request(t *testing.T, path string) *http.Request {
	t.Helper()
	req, err := http.NewRequest("GET", "https://localhost"+path, nil)
	require.NoError(t, err)
	return req
}

func TestM33TLSHandshakeAndHostnameFailure(t *testing.T) {
	for _, kind := range []string{"hostname", "plaintext"} {
		t.Run(kind, func(t *testing.T) {
			cert, roots := makeTestUpstreamCertificate(t)
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			defer listener.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				raw, err := listener.Accept()
				if err != nil {
					return
				}
				defer raw.Close()
				raw.SetDeadline(time.Now().Add(time.Second))
				if kind == "plaintext" {
					raw.Write([]byte("this is not TLS\r\n"))
					return
				}
				secure := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2"}, MinVersion: tls.VersionTLS12})
				if secure.Handshake() == nil {
					buffer := make([]byte, 1)
					n, _ := secure.Read(buffer)
					if n > 0 {
						t.Error("HTTP must never be sent after certificate name failure")
					}
				}
			}()
			var dials atomic.Int32
			rt := &nativeRoundTripper{target: &C.Metadata{NetWork: C.TCP, Host: "wrong.example", DstPort: 443}, tlsConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"}}, handshakeTimeout: time.Second, requestTimeout: time.Second,
				dial: func(ctx context.Context, _ *C.Metadata, handshake NativeTLSHandshake) (net.Conn, error) {
					dials.Add(1)
					raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
					if err != nil {
						return nil, err
					}
					conn, err := handshake(ctx, raw)
					if err != nil {
						raw.Close()
					}
					return conn, err
				},
			}
			req, err := http.NewRequest("POST", "https://wrong.example/", strings.NewReader("secret"))
			require.NoError(t, err)
			res, err := rt.RoundTrip(req)
			require.Nil(t, res)
			require.Error(t, err)
			if kind == "hostname" {
				require.Contains(t, err.Error(), "wrong.example")
			}
			require.EqualValues(t, 1, dials.Load())
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("TLS failure leaked native socket")
			}
		})
	}
}

func TestM33RequestBodyEarlyEOF(t *testing.T) {
	h := newProtocolHarness(t, nil, "localhost", 443, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, 2, r.ProtoMajor)
		if r.URL.Path == "/short" {
			_, err := io.ReadAll(r.Body)
			if err == nil {
				t.Error("truncated request unexpectedly complete")
			}
			return
		}
		io.WriteString(w, "healthy")
	}), false, true, true, []string{"h2"})
	req, err := http.NewRequest("POST", "https://localhost/short", io.NopCloser(strings.NewReader("short")))
	require.NoError(t, err)
	req.ContentLength = 100
	response, err := h.client.RoundTrip(req)
	if err == nil {
		// A forwarded body read error can become a 502 before downstream
		// headers, or a stream error after headers. Neither may be a 2xx.
		require.Equal(t, http.StatusBadGateway, response.StatusCode)
		response.Body.Close()
	}
	res := h2Request(t, h, "GET", "/after", "")
	require.Equal(t, "healthy", readM2ResponseBody(t, res))
}
