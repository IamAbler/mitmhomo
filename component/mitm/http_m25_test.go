package mitm

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/metacubex/mihomo/component/mitm/rewrite"
	"github.com/stretchr/testify/require"
)

// Read real HTTP/1.1 over TLS, including a subsequent request on the same socket.
func TestM25MethodMatrix(t *testing.T) {
	for _, methods := range [][2]string{{"GET", "GET"}, {"GET", "HEAD"}, {"HEAD", "GET"}, {"HEAD", "HEAD"}, {"POST", "GET"}, {"GET", "POST"}} {
		for _, replace := range []bool{false, true} {
			t.Run(fmt.Sprint(methods, replace), func(t *testing.T) {
				rule := rewrite.Rule{Name: "method", Match: rewrite.Match{Path: "/rewrite"}, Request: &rewrite.RequestAction{Method: methods[1]}}
				if replace {
					rule.Response = &rewrite.ResponseAction{Body: &rewrite.BodyReplacement{Replace: "replacement"}}
				}
				observed := make(chan string, 2)
				h := newM2HTTPHarness(t, "localhost", compileM2Rules(t, rule), func(w http.ResponseWriter, r *http.Request) {
					observed <- r.Method
					if r.Method == "HEAD" {
						w.Header().Set("Content-Encoding", "gzip")
						w.Header().Set("ETag", `"upstream"`)
					}
					w.Header().Set("Content-Length", "6")
					_, _ = io.WriteString(w, "origin")
				})
				client, done := h.startTCPClient(t)
				reader := bufio.NewReader(client)
				response := sendM2Request(t, client, reader, methods[0]+" /rewrite HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n", methods[0])
				require.Equal(t, methods[1], <-observed)
				body := "origin"
				if methods[1] == "HEAD" {
					body = ""
				}
				if replace {
					body = "replacement"
				}
				length := len(body)
				if methods[0] == "HEAD" {
					body = ""
					if !replace {
						length = 6
					}
				}
				require.Equal(t, body, readM2ResponseBody(t, response))
				require.Equal(t, fmt.Sprint(length), response.Header.Get("Content-Length"))
				require.Empty(t, response.TransferEncoding)
				if methods[0] != "HEAD" && methods[1] == "HEAD" {
					require.Empty(t, response.Header.Get("Content-Encoding"))
					require.Empty(t, response.Header.Get("ETag"))
				}
				next := sendM2Request(t, client, reader, "GET /next HTTP/1.1\r\nHost: localhost\r\n\r\n", "GET")
				require.Equal(t, "origin", readM2ResponseBody(t, next))
				require.Equal(t, "GET", <-observed)
				finishM2Dispatch(t, client, done)
			})
		}
	}
}

func TestM25BodylessUpstreamToContentStatus(t *testing.T) {
	for _, status := range []int{204, 205, 304} {
		for _, replace := range []bool{false, true} {
			t.Run(fmt.Sprint(status, replace), func(t *testing.T) {
				action := &rewrite.ResponseAction{Status: 200}
				if replace {
					action.Body = &rewrite.BodyReplacement{Replace: "replacement"}
				}
				pipeline := compileM2Rules(t, rewrite.Rule{Name: "status", Match: rewrite.Match{Path: "/rewrite"}, Response: action})
				h := newM2HTTPHarness(t, "localhost", pipeline, func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/rewrite" {
						if status == 304 {
							// Go Server suppresses 304 Content-Length; a legal upstream may send it.
							conn, rw, err := w.(http.Hijacker).Hijack()
							if err != nil {
								return
							}
							defer conn.Close()
							_, _ = rw.WriteString("HTTP/1.1 304 Not Modified\r\nContent-Length: 123\r\nContent-Encoding: gzip\r\nETag: \"original\"\r\n\r\n")
							_ = rw.Flush()
							return
						}
						if status == 205 {
							w.Header().Set("Content-Length", "0")
						}
						w.WriteHeader(status)
						return
					}
					_, _ = io.WriteString(w, "next")
				})
				client, done := h.startTCPClient(t)
				reader := bufio.NewReader(client)
				response := sendM2Request(t, client, reader, "GET /rewrite HTTP/1.1\r\nHost: localhost\r\n\r\n", "GET")
				require.Equal(t, 200, response.StatusCode)
				want := ""
				if replace {
					want = "replacement"
				}
				require.Equal(t, want, readM2ResponseBody(t, response))
				require.Equal(t, fmt.Sprint(len(want)), response.Header.Get("Content-Length"))
				require.Empty(t, response.Header.Get("Content-Encoding"))
				require.Empty(t, response.Header.Get("ETag"))
				require.Empty(t, response.TransferEncoding)
				next := sendM2Request(t, client, reader, "GET /next HTTP/1.1\r\nHost: localhost\r\n\r\n", "GET")
				require.Equal(t, "next", readM2ResponseBody(t, next))
				finishM2Dispatch(t, client, done)
			})
		}
	}
}

func TestM25TerminalUsesOriginalClientMethod(t *testing.T) {
	for _, methods := range [][2]string{{"GET", "HEAD"}, {"HEAD", "GET"}} {
		t.Run(fmt.Sprint(methods), func(t *testing.T) {
			h := newM2HTTPHarness(t, "localhost", compileM2Rules(t, rewrite.Rule{Name: "local", LocalResponse: &rewrite.LocalResponse{Status: 200, Body: "local"}}), nil)
			config := h.manager.ConfigSnapshot()
			config.RequestHook = func(r *http.Request) error { r.Method = methods[1]; return nil }
			h.manager.Update(config)
			client, done := h.startTCPClient(t)
			reader := bufio.NewReader(client)
			for i := 0; i < 2; i++ {
				response := sendM2Request(t, client, reader, methods[0]+" / HTTP/1.1\r\nHost: localhost\r\n\r\n", methods[0])
				want := "local"
				if methods[0] == "HEAD" {
					want = ""
				}
				require.Equal(t, want, readM2ResponseBody(t, response))
				require.Equal(t, "5", response.Header.Get("Content-Length"))
			}
			require.Zero(t, h.dialCount.Load())
			finishM2Dispatch(t, client, done)
		})
	}
}

func TestM25PartialContentReplacementRequiresExplicitStatus(t *testing.T) {
	for _, status := range []int{0, 200} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			h := newM2HTTPHarness(t, "localhost", compileM2Rules(t, rewrite.Rule{Name: "replace", Response: &rewrite.ResponseAction{Status: status, Body: &rewrite.BodyReplacement{Replace: "replacement"}}}), func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Range", "bytes 0-3/10")
				w.WriteHeader(206)
				_, _ = io.WriteString(w, "part")
			})
			client, done := h.startTCPClient(t)
			reader := bufio.NewReader(client)
			for i := 0; i < 2; i++ {
				response := sendM2Request(t, client, reader, "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n", "GET")
				if status == 0 {
					require.Equal(t, 502, response.StatusCode)
					_ = readM2ResponseBody(t, response)
				} else {
					require.Equal(t, 200, response.StatusCode)
					require.Equal(t, "replacement", readM2ResponseBody(t, response))
					require.Empty(t, response.Header.Get("Content-Range"))
				}
			}
			finishM2Dispatch(t, client, done)
		})
	}
}

func TestM25FinalStatusMatrixOnWire(t *testing.T) {
	for _, status := range []int{200, 204, 205, 304, 301, 302, 307, 308, 400, 500} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			h := newM2HTTPHarness(t, "localhost", compileM2Rules(t, rewrite.Rule{Name: "status", Match: rewrite.Match{Path: "/rewrite"}, Response: &rewrite.ResponseAction{Status: status}}), func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("ETag", `"original"`)
				w.Header().Set("Last-Modified", "Wed, 21 Oct 2015 07:28:00 GMT")
				w.Header().Set("Location", "/target")
				_, _ = io.WriteString(w, "origin")
			})
			client, done := h.startTCPClient(t)
			reader := bufio.NewReader(client)
			response := sendM2Request(t, client, reader, "GET /rewrite HTTP/1.1\r\nHost: localhost\r\n\r\n", "GET")
			require.Equal(t, status, response.StatusCode)
			want := "origin"
			if responseForbidsBody(status) {
				want = ""
			}
			require.Equal(t, want, readM2ResponseBody(t, response))
			require.Empty(t, response.TransferEncoding)
			if status == 204 || status == 304 {
				require.Empty(t, response.Header.Get("Content-Length"))
			}
			if status == 205 {
				require.Equal(t, "0", response.Header.Get("Content-Length"))
			}
			if status == 304 {
				require.Empty(t, response.Header.Get("Content-Type"))
				require.Equal(t, `"original"`, response.Header.Get("ETag"))
			}
			next := sendM2Request(t, client, reader, "GET /next HTTP/1.1\r\nHost: localhost\r\n\r\n", "GET")
			require.Equal(t, "origin", readM2ResponseBody(t, next))
			finishM2Dispatch(t, client, done)
		})
	}
}

func TestM25Raw304RepresentationLength(t *testing.T) {
	for _, method := range []string{"GET", "HEAD"} {
		t.Run(method, func(t *testing.T) {
			h := newM2HTTPHarness(t, "localhost", nil, func(w http.ResponseWriter, r *http.Request) {
				conn, rw, err := w.(http.Hijacker).Hijack()
				if err != nil {
					return
				}
				defer conn.Close()
				_, _ = rw.WriteString("HTTP/1.1 304 Not Modified\r\nContent-Length: 123\r\nETag: \"original\"\r\n\r\n")
				_ = rw.Flush()
			})
			client, done := h.startTCPClient(t)
			reader := bufio.NewReader(client)
			for i := 0; i < 2; i++ {
				response := sendM2Request(t, client, reader, method+" / HTTP/1.1\r\nHost: localhost\r\n\r\n", method)
				require.Equal(t, 304, response.StatusCode)
				require.Empty(t, readM2ResponseBody(t, response))
				require.Empty(t, response.Header.Get("Content-Length"), "Go HTTP Server suppresses the representation length for 304")
				require.Equal(t, `"original"`, response.Header.Get("ETag"))
			}
			finishM2Dispatch(t, client, done)
		})
	}
}
