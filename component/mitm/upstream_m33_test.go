package mitm

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/mitm/rewrite"
	"github.com/stretchr/testify/require"
)

func TestM33ProtocolMatrix(t *testing.T) {
	for _, downH2 := range []bool{false, true} {
		for _, protocols := range [][]string{{"h2"}, {"h2", "http/1.1"}, {"http/1.1"}, {}} {
			t.Run(fmt.Sprintf("downH2=%v/up=%v", downH2, protocols), func(t *testing.T) {
				want := 1
				if len(protocols) > 0 && protocols[0] == "h2" {
					want = 2
				}
				h := newProtocolHarness(t, nil, "localhost", 443, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					require.Equal(t, want, r.ProtoMajor, "actual upstream wire protocol")
					require.Equal(t, "localhost", r.TLS.ServerName)
					if want == 2 {
						require.Equal(t, "h2", r.TLS.NegotiatedProtocol)
					}
					require.Empty(t, r.Header.Get("Connection"))
					require.Empty(t, r.Header.Get("Keep-Alive"))
					body, err := io.ReadAll(r.Body)
					require.NoError(t, err)
					require.Equal(t, "finished", r.Trailer.Get("X-Upload"))
					w.Header().Set("Trailer", "X-Download")
					fmt.Fprintf(w, "%s:%s", r.Method, body)
					w.Header().Set("X-Download", "complete")
				}), false, true, downH2, protocols)
				for _, method := range []string{"GET", "POST"} {
					req, err := http.NewRequest(method, "https://localhost/matrix", strings.NewReader("payload"))
					require.NoError(t, err)
					req.ContentLength = -1
					req.Trailer = http.Header{"X-Upload": []string{"finished"}}
					req.Header.Set("Connection", "keep-alive, X-Hop")
					req.Header.Set("X-Hop", "remove")
					req.Header.Set("Keep-Alive", "timeout=10")
					// HTTP/2 clients reject Connection before sending; test hop stripping via H1.
					if downH2 {
						req.Header.Del("Connection")
						req.Header.Del("Keep-Alive")
					}
					res, err := h.wire.RoundTrip(req)
					require.NoError(t, err)
					require.Equal(t, 200, res.StatusCode)
					body, err := io.ReadAll(res.Body)
					require.NoError(t, err)
					require.NoError(t, res.Body.Close())
					require.Equal(t, method+":payload", string(body))
					require.Equal(t, "complete", res.Trailer.Get("X-Download"))
				}
				wantDials := 2
				if downH2 && want == 2 {
					wantDials = 1
				}
				require.EqualValues(t, wantDials, h.dials.Load(), "only downstream H2/upstream H2 shares its native route lease")
			})
		}
	}
}

func TestM33ConcurrentCancellationIsolation(t *testing.T) {
	entered := make(chan struct{}, 2)
	canceled := make(chan struct{})
	release := make(chan struct{})
	h := newProtocolHarness(t, nil, "localhost", 443, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, 2, r.ProtoMajor)
		entered <- struct{}{}
		if r.URL.Path == "/cancel" {
			<-r.Context().Done()
			close(canceled)
			return
		}
		select {
		case <-release:
			io.WriteString(w, "survivor")
		case <-r.Context().Done():
		}
	}), false, true, true, []string{"h2"})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	failed := make(chan error, 1)
	success := make(chan string, 1)
	go func() {
		req, _ := http.NewRequestWithContext(ctx, "POST", "https://localhost/cancel", strings.NewReader("once"))
		res, err := h.wire.RoundTrip(req)
		if res != nil {
			res.Body.Close()
		}
		failed <- err
	}()
	go func() {
		req, _ := http.NewRequest("GET", "https://localhost/survive", nil)
		res, err := h.wire.RoundTrip(req)
		if err != nil {
			success <- err.Error()
			return
		}
		defer res.Body.Close()
		b, err := io.ReadAll(res.Body)
		if err != nil {
			success <- err.Error()
			return
		}
		success <- string(b)
	}()
	for i := 0; i < 2; i++ {
		select {
		case <-entered:
		case <-time.After(3 * time.Second):
			t.Fatal("upstream streams did not overlap")
		}
	}
	cancel()
	select {
	case err := <-failed:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(3 * time.Second):
		t.Fatal("cancel hung")
	}
	select {
	case <-canceled:
	case <-time.After(3 * time.Second):
		t.Fatal("upstream cancel hung")
	}
	close(release)
	select {
	case body := <-success:
		require.Equal(t, "survivor", body)
	case <-time.After(3 * time.Second):
		t.Fatal("sibling hung")
	}
	res := h2Request(t, h, "GET", "/after", "")
	io.Copy(io.Discard, res.Body)
	res.Body.Close()
	require.EqualValues(t, 1, h.dials.Load(), "cancel must preserve the shared upstream socket")
}

func TestM33RewriteAcrossProtocols(t *testing.T) {
	for _, downH2 := range []bool{false, true} {
		for _, upH2 := range []bool{false, true} {
			t.Run(fmt.Sprintf("downH2=%v/upH2=%v", downH2, upH2), func(t *testing.T) {
				protocols := []string{"http/1.1"}
				if upH2 {
					protocols = []string{"h2"}
				}
				h := newProtocolHarness(t, nil, "localhost", 443, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					want := 1
					if upH2 {
						want = 2
					}
					require.Equal(t, want, r.ProtoMajor)
					require.Equal(t, "PATCH", r.Method)
					require.Equal(t, "/final/old", r.URL.Path)
					b, err := io.ReadAll(r.Body)
					require.NoError(t, err)
					require.Equal(t, "request-old", string(b))
					require.Empty(t, r.Trailer)
					w.Header().Set("X-Echo", r.Header.Get("X-Step"))
					w.Header().Set("Content-Encoding", "identity")
					w.Header().Set("Trailer", "X-Old")
					io.WriteString(w, "origin")
					w.Header().Set("X-Old", "stale")
				}), false, true, downH2, protocols, func(c *Config) { c.Rewrite = m24Pipeline(t, "old") })
				cfg := h.manager.ConfigSnapshot()
				cfg.Rewrite = m24Pipeline(t, "new")
				h.manager.Update(cfg)
				for i := 0; i < 2; i++ {
					req, _ := http.NewRequest("POST", "https://localhost/start", strings.NewReader("original"))
					if downH2 {
						req.Trailer = http.Header{"X-Original": []string{"stale"}}
						req.ContentLength = -1
					}
					res, err := h.wire.RoundTrip(req)
					require.NoError(t, err)
					require.Equal(t, 202, res.StatusCode)
					require.Equal(t, "old", res.Header.Get("X-Response-Step"))
					require.Empty(t, res.Header.Get("Content-Encoding"))
					require.Equal(t, "response-old", readM2ResponseBody(t, res))
					require.Empty(t, res.Trailer)
				}
			})
		}
	}
}

func TestM33AuthorityRewriteAndTerminal(t *testing.T) {
	for _, downH2 := range []bool{false, true} {
		t.Run(fmt.Sprint(downH2), func(t *testing.T) {
			pipeline := compileM2Rules(t,
				rewrite.Rule{Name: "local", Match: rewrite.Match{Path: "/local"}, LocalResponse: &rewrite.LocalResponse{Status: 201, Body: "local"}},
				rewrite.Rule{Name: "redirect", Match: rewrite.Match{Path: "/redirect"}, Redirect: &rewrite.Redirect{Status: 302, Location: "https://localhost/local"}},
				rewrite.Rule{Name: "authority", Request: &rewrite.RequestAction{URL: "https://rewritten.example:8443/new?value=2"}},
			)
			h := newProtocolHarness(t, nil, "rewritten.example", 8443, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, 2, r.ProtoMajor)
				require.Equal(t, "rewritten.example:8443", r.Host)
				require.Equal(t, "rewritten.example", r.TLS.ServerName)
				require.Equal(t, "/new?value=2", r.URL.RequestURI())
				io.WriteString(w, "verified")
			}), false, true, downH2, []string{"h2"}, func(c *Config) { c.Rewrite = pipeline })
			for _, path := range []string{"/local", "/redirect"} {
				req, _ := http.NewRequest("GET", "https://localhost"+path, nil)
				res, err := h.wire.RoundTrip(req)
				require.NoError(t, err)
				if path == "/local" {
					require.Equal(t, 201, res.StatusCode)
					require.Equal(t, "local", readM2ResponseBody(t, res))
				} else {
					require.Equal(t, 302, res.StatusCode)
					require.Equal(t, "https://localhost/local", res.Header.Get("Location"))
					res.Body.Close()
				}
			}
			require.Zero(t, h.dials.Load())
			req, _ := http.NewRequest("GET", "https://localhost/old", nil)
			res, err := h.wire.RoundTrip(req)
			require.NoError(t, err)
			require.Equal(t, "verified", readM2ResponseBody(t, res))
		})
	}
}

func TestM33HookHostIndependentOfTLSAndNativeTarget(t *testing.T) {
	for _, downH2 := range []bool{false, true} {
		t.Run(fmt.Sprint(downH2), func(t *testing.T) {
			h := newProtocolHarness(t, nil, "localhost", 443, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, 2, r.ProtoMajor)
				require.Equal(t, "virtual.example:9443", r.Host)
				require.Equal(t, "localhost", r.TLS.ServerName)
				io.WriteString(w, "verified-url-target")
			}), false, true, downH2, []string{"h2"}, func(c *Config) {
				c.RequestHook = func(r *http.Request) error { r.Host = "virtual.example:9443"; return nil }
			})
			req, _ := http.NewRequest("GET", "https://localhost/", nil)
			res, err := h.wire.RoundTrip(req)
			require.NoError(t, err)
			require.Equal(t, "verified-url-target", readM2ResponseBody(t, res))
			require.EqualValues(t, 1, h.dials.Load())
		})
	}
}

// H1 can initialize its Trailer map only at EOF for undeclared fields. A
// replaced upload must not read that map concurrently with the discard reader.
func TestM33H1ReplacementDiscardsLateTrailer(t *testing.T) {
	pipeline := compileM2Rules(t, rewrite.Rule{Name: "replace", Request: &rewrite.RequestAction{Body: &rewrite.BodyReplacement{Replace: "replacement"}}})
	h := newM2HTTPHarness(t, "localhost", pipeline, nil)
	client, done := h.startTCPClient(t)
	_, err := io.WriteString(client, "POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nbody\r\n0\r\nX-Late: discarded\r\n\r\n")
	require.NoError(t, err)
	res, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: "POST"})
	require.NoError(t, err)
	require.Equal(t, 200, res.StatusCode)
	require.Equal(t, "upstream-ok", readM2ResponseBody(t, res))
	observation := <-h.observations
	require.Equal(t, "replacement", observation.body)
	require.Empty(t, observation.trailer)
	finishM2Dispatch(t, client, done)
}
