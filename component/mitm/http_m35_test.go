package mitm

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/metacubex/mihomo/component/mitm/rewrite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestM35ProtocolAcceptance(t *testing.T) {
	for _, downH2 := range []bool{false, true} {
		for _, upH2 := range []bool{false, true} {
			t.Run(fmt.Sprintf("downH2=%v/upH2=%v", downH2, upH2), func(t *testing.T) {
				requestCtx, cancelRequests := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancelRequests()
				payload := strings.Repeat("large-payload-", 81920) // >1 MiB, streaming without rewrite buffering.
				cancelEntered, cancelObserved := make(chan struct{}), make(chan struct{})
				pipeline := compileM2Rules(t,
					rewrite.Rule{Name: "request", Match: rewrite.Match{Path: "/rewrite"}, Request: &rewrite.RequestAction{URL: "https://localhost/final", Method: "PATCH", Headers: rewrite.HeaderAction{Set: map[string]string{"X-Rewritten": "yes"}}, Body: &rewrite.BodyReplacement{Replace: "replaced"}}},
					rewrite.Rule{Name: "response", Match: rewrite.Match{Path: "/final"}, Response: &rewrite.ResponseAction{Status: 201, Headers: rewrite.HeaderAction{Set: map[string]string{"X-Response-Rewritten": "yes"}}}},
					rewrite.Rule{Name: "mock", Match: rewrite.Match{Path: "/mock"}, LocalResponse: &rewrite.LocalResponse{Status: 202, Body: "mock"}},
					rewrite.Rule{Name: "redirect", Match: rewrite.Match{Path: "/redirect"}, Redirect: &rewrite.Redirect{Status: 307, Location: "https://localhost/final"}},
				)
				protocols := []string{"http/1.1"}
				if upH2 {
					protocols = []string{"h2"}
				}
				h := newProtocolHarness(t, nil, "localhost", 443, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					wantProto := 1
					if upH2 {
						wantProto = 2
					}
					assert.Equal(t, wantProto, r.ProtoMajor)
					assert.Equal(t, "localhost", r.TLS.ServerName)
					assert.Contains(t, []string{"localhost", "localhost:443"}, r.Host)
					assert.Empty(t, r.Header.Get("X-Hop"))
					assert.Empty(t, r.Header.Get("Keep-Alive"))
					w.Header().Add("X-Multi", "one")
					w.Header().Add("X-Multi", "two")
					w.Header().Add("Set-Cookie", "a=1; Path=/; HttpOnly")
					w.Header().Add("Set-Cookie", "b=2; Secure")
					switch r.URL.Path {
					case "/method":
						assert.Equal(t, []string{"one", "two"}, r.Header.Values("X-Multi"))
						assert.Len(t, r.Cookies(), 2)
						b, e := io.ReadAll(r.Body)
						assert.NoError(t, e)
						io.WriteString(w, r.Method+":"+string(b))
					case "/large":
						// H1's default server consumes uploads before writing a response.
						b, err := io.ReadAll(r.Body)
						assert.NoError(t, err)
						w.Write(b)
					case "/trailers":
						b, e := io.ReadAll(r.Body)
						assert.NoError(t, e)
						assert.Equal(t, "upload", string(b))
						assert.Equal(t, "done", r.Trailer.Get("X-Up"))
						w.Header().Set("Trailer", "X-Down")
						io.WriteString(w, "download")
						w.Header().Set("X-Down", "done")
					case "/empty204":
						w.WriteHeader(204)
					case "/empty304":
						w.Header().Set("Content-Length", "12")
						w.WriteHeader(304)
					case "/head":
						w.Header().Set("Content-Length", "12")
						io.WriteString(w, "head-payload")
					case "/gzip":
						w.Header().Set("Content-Encoding", "gzip")
						gz := gzip.NewWriter(w)
						io.WriteString(gz, "compressed")
						gz.Close()
					case "/br":
						w.Header().Set("Content-Encoding", "br")
						br := brotli.NewWriter(w)
						io.WriteString(br, "compressed")
						br.Close()
					case "/final":
						b, e := io.ReadAll(r.Body)
						assert.NoError(t, e)
						assert.Equal(t, "PATCH", r.Method)
						assert.Equal(t, "yes", r.Header.Get("X-Rewritten"))
						assert.Equal(t, "replaced", string(b))
						io.WriteString(w, "rewritten")
					case "/cancel":
						close(cancelEntered)
						<-r.Context().Done()
						close(cancelObserved)
					default:
						t.Error("unexpected upstream path", r.URL.Path)
					}
				}), false, true, downH2, protocols, func(c *Config) { c.Rewrite = pipeline })
				request := func(method, path, body string) *http.Response {
					req, _ := http.NewRequestWithContext(requestCtx, method, "https://localhost"+path, strings.NewReader(body))
					req.Header["X-Multi"] = []string{"one", "two"}
					req.AddCookie(&http.Cookie{Name: "a", Value: "1"})
					req.AddCookie(&http.Cookie{Name: "b", Value: "2"})
					req.Header.Set("Accept-Encoding", "gzip, br")
					if !downH2 {
						req.Header.Set("Connection", "X-Hop, Keep-Alive")
						req.Header.Set("X-Hop", "strip")
						req.Header.Set("Keep-Alive", "timeout=10")
					}
					res, e := h.wire.RoundTrip(req)
					require.NoError(t, e)
					return res
				}
				for _, method := range []string{"GET", "POST", "PUT", "PATCH", "DELETE"} {
					res := request(method, "/method", "body")
					require.Equal(t, []string{"one", "two"}, res.Header.Values("X-Multi"))
					require.Len(t, res.Cookies(), 2)
					require.Len(t, res.Header.Values("Set-Cookie"), 2)
					require.Equal(t, method+":body", readM2ResponseBody(t, res))
				}
				require.Equal(t, payload, readM2ResponseBody(t, request("POST", "/large", payload)))
				req, _ := http.NewRequestWithContext(requestCtx, "POST", "https://localhost/trailers", strings.NewReader("upload"))
				req.ContentLength = -1
				req.Trailer = http.Header{"X-Up": {"done"}}
				res, e := h.wire.RoundTrip(req)
				require.NoError(t, e)
				require.Equal(t, "download", readM2ResponseBody(t, res))
				require.Equal(t, "done", res.Trailer.Get("X-Down"))
				for _, test := range []struct {
					method, path string
					status       int
				}{{"GET", "/empty204", 204}, {"GET", "/empty304", 304}, {"HEAD", "/head", 200}} {
					res := request(test.method, test.path, "")
					require.Equal(t, test.status, res.StatusCode)
					require.Empty(t, readM2ResponseBody(t, res))
				}
				for _, encoding := range []string{"gzip", "br"} {
					res := request("GET", "/"+encoding, "")
					require.Equal(t, encoding, res.Header.Get("Content-Encoding"))
					data, e := io.ReadAll(res.Body)
					res.Body.Close()
					require.NoError(t, e)
					var reader io.Reader
					if encoding == "gzip" {
						gz, e := gzip.NewReader(bytes.NewReader(data))
						require.NoError(t, e)
						defer gz.Close()
						reader = gz
					} else {
						reader = brotli.NewReader(bytes.NewReader(data))
					}
					decoded, e := io.ReadAll(reader)
					require.NoError(t, e)
					require.Equal(t, "compressed", string(decoded))
				}
				res = request("POST", "/rewrite", "original")
				require.Equal(t, 201, res.StatusCode)
				require.Equal(t, "yes", res.Header.Get("X-Response-Rewritten"))
				require.Equal(t, "rewritten", readM2ResponseBody(t, res))
				before := h.dials.Load()
				res = request("GET", "/mock", "")
				require.Equal(t, 202, res.StatusCode)
				require.Equal(t, "mock", readM2ResponseBody(t, res))
				res = request("GET", "/redirect", "")
				require.Equal(t, 307, res.StatusCode)
				require.Equal(t, "https://localhost/final", res.Header.Get("Location"))
				res.Body.Close()
				require.Equal(t, before, h.dials.Load())
				misdirected := newProtocolHarness(t, nil, "localhost", 443, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
					t.Error("misdirected request reached upstream")
				}), false, true, downH2, protocols)
				req, _ = http.NewRequestWithContext(requestCtx, "GET", "https://localhost/misdirected", nil)
				req.Host = "evil.example"
				res, e = misdirected.wire.RoundTrip(req)
				require.NoError(t, e)
				require.Equal(t, 421, res.StatusCode)
				res.Body.Close()
				require.Zero(t, misdirected.dials.Load())
				// A connected client cancel must terminate its own upstream request.
				ctx, cancel := context.WithCancel(requestCtx)
				defer cancel()
				req, _ = http.NewRequestWithContext(ctx, "GET", "https://localhost/cancel", nil)
				done := make(chan error, 1)
				go func() {
					res, e := h.wire.RoundTrip(req)
					if res != nil {
						res.Body.Close()
					}
					done <- e
				}()
				m34Await(t, cancelEntered)
				cancel()
				select {
				case e := <-done:
					require.ErrorIs(t, e, context.Canceled)
				case <-time.After(time.Second):
					t.Fatal("cancel blocked")
				}
				m34Await(t, cancelObserved)
				t.Logf("methods=5 payload_bytes=%s upstream_dials=%d", strconv.Itoa(len(payload)), h.dials.Load())
			})
		}
	}
}
