package mitm

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestM35RejectAmbiguousH1Framing(t *testing.T) {
	for _, test := range []struct {
		name, raw string
		status    int
	}{
		{"conflicting-content-length", "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nContent-Length: 9\r\n\r\nsmuggled!", 400},
		{"unsupported-transfer-encoding", "POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked, chunked\r\n\r\n0\r\n\r\n", 501},
		{"invalid-header-name", "GET / HTTP/1.1\r\nHost: localhost\r\nBad Header: injected\r\n\r\n", 400},
		{"duplicate-host", "GET / HTTP/1.1\r\nHost: localhost\r\nHost: evil.example\r\n\r\n", 400},
	} {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int32
			h := newProtocolHarness(t, nil, "localhost", 443, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }), false, true, false, []string{"http/1.1"})
			secure, e := h.wire.(*http.Transport).DialTLSContext(context.Background(), "tcp", "localhost:443")
			require.NoError(t, e)
			secure.SetDeadline(time.Now().Add(3 * time.Second))
			_, e = io.WriteString(secure, test.raw)
			require.NoError(t, e)
			res, e := http.ReadResponse(bufio.NewReader(secure), &http.Request{Method: "GET"})
			require.NoError(t, e)
			require.Equal(t, test.status, res.StatusCode)
			body, e := io.ReadAll(res.Body)
			res.Body.Close()
			require.NoError(t, e)
			require.Zero(t, h.dials.Load())
			require.Zero(t, calls.Load())
			require.NotContains(t, string(body), "PRIVATE KEY")
			require.NotContains(t, string(body), "mitm-ca")
		})
	}
}

// Go's HTTP server canonically accepts CL+chunked by removing Content-Length.
// Verify both outbound protocols receive precisely the decoded body and cannot
// observe two competing framing declarations. No hidden second request is sent.
func TestM35CLTECanonicalization(t *testing.T) {
	for _, protocols := range [][]string{{"http/1.1"}, {"h2"}} {
		t.Run(protocols[0], func(t *testing.T) {
			var calls atomic.Int32
			h := newProtocolHarness(t, nil, "localhost", 443, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				assert.Empty(t, r.Header.Values("Content-Length"))
				assert.Less(t, r.ContentLength, int64(0))
				b, e := io.ReadAll(r.Body)
				assert.NoError(t, e)
				assert.Equal(t, "abc", string(b))
				io.WriteString(w, "ok")
			}), false, true, false, protocols)
			secure, e := h.wire.(*http.Transport).DialTLSContext(context.Background(), "tcp", "localhost:443")
			require.NoError(t, e)
			secure.SetDeadline(time.Now().Add(3 * time.Second))
			_, e = io.WriteString(secure, "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 999\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n3\r\nabc\r\n0\r\n\r\n")
			require.NoError(t, e)
			res, e := http.ReadResponse(bufio.NewReader(secure), &http.Request{Method: "POST"})
			require.NoError(t, e)
			require.Equal(t, 200, res.StatusCode)
			require.Equal(t, "ok", readM2ResponseBody(t, res))
			require.EqualValues(t, 1, calls.Load())
			require.EqualValues(t, 1, h.dials.Load())
		})
	}
}

func TestM35UpstreamErrorDoesNotExposeDetails(t *testing.T) {
	const secret = "proxy-password-and-private-ca-path"
	for _, downH2 := range []bool{false, true} {
		t.Run(map[bool]string{false: "h1", true: "h2"}[downH2], func(t *testing.T) {
			h := newProtocolHarness(t, nil, "localhost", 443, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}), true, true, downH2, []string{"h2"})
			// Native failure remains generic, without dial details or request data.
			req, _ := http.NewRequest("POST", "https://localhost/", strings.NewReader(secret))
			res, e := h.wire.RoundTrip(req)
			require.NoError(t, e)
			require.Equal(t, 502, res.StatusCode)
			body := readM2ResponseBody(t, res)
			require.Equal(t, "upstream request failed\n", body)
			require.NotContains(t, body, secret)
			require.NotContains(t, body, "test native dial failure")
		})
	}
}
