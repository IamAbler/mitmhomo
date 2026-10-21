package mitm

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/mitm/rewrite"
	"github.com/stretchr/testify/require"
)

func TestM32HTTP2RequestTrailer(t *testing.T) {
	observed := make(chan http.Header, 1)
	h := newH2Harness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		if string(b) != "upload" {
			t.Error(string(b))
		}
		observed <- r.Trailer.Clone()
		io.WriteString(w, "ok")
	}), false, true)
	req, err := http.NewRequest("POST", "https://localhost/", strings.NewReader("upload"))
	require.NoError(t, err)
	req.Trailer = http.Header{"X-Upload": {"complete"}}
	response, err := h.client.RoundTrip(req)
	require.NoError(t, err)
	require.Equal(t, 2, response.ProtoMajor)
	require.Equal(t, "ok", readM2ResponseBody(t, response))
	require.Equal(t, "complete", (<-observed).Get("X-Upload"))
}

func TestM32HTTP2MethodStatus(t *testing.T) {
	for _, original := range []string{"GET", "POST", "HEAD"} {
		for _, upstream := range []string{"GET", "HEAD"} {
			for _, status := range []int{200, 204, 205, 206, 304, 301, 302, 307, 308, 404, 503} {
				for _, replace := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s-%s-%d-replace=%v", original, upstream, status, replace), func(t *testing.T) {
						rules := []rewrite.Rule{{Name: "method", Request: &rewrite.RequestAction{Method: upstream}}}
						if replace {
							rules = append(rules, rewrite.Rule{Name: "body", Response: &rewrite.ResponseAction{Body: &rewrite.BodyReplacement{Replace: "replacement"}}})
						}
						h := newH2Harness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
							if r.Method != upstream {
								t.Error(r.Method)
							}
							w.Header().Set("Content-Length", "6")
							if status == 204 || status == 205 {
								w.Header().Del("Content-Length")
							}
							if status == 206 {
								w.Header().Set("Content-Range", "bytes 0-5/10")
							}
							w.WriteHeader(status)
							if status != 204 && status != 205 && status != 304 {
								io.WriteString(w, "origin")
							}
						}), false, true, func(c *Config) { c.Rewrite = compileM2Rules(t, rules...) })
						res := h2Request(t, h, original, "/", "")
						wantStatus := status
						if replace && (status == 204 || status == 205 || status == 206) {
							wantStatus = 502
						}
						require.Equal(t, wantStatus, res.StatusCode)
						body := readM2ResponseBody(t, res)
						if original == "HEAD" || wantStatus == 204 || wantStatus == 205 || wantStatus == 304 {
							require.Empty(t, body)
						} else if wantStatus == 502 {
							require.Contains(t, body, "upstream request failed")
						} else if replace {
							require.Equal(t, "replacement", body)
							require.EqualValues(t, 11, res.ContentLength)
						} else if upstream == "HEAD" {
							require.Empty(t, body)
							require.EqualValues(t, 0, res.ContentLength)
						} else {
							require.Equal(t, "origin", body)
						}
						require.Empty(t, res.Header.Get("Connection"))
						require.Empty(t, res.Header.Get("Transfer-Encoding"))
					})
				}
			}
		}
	}
}

func TestM32HTTP2ResponseTrailers(t *testing.T) {
	for _, mode := range []string{"pass", "headers", "body"} {
		t.Run(mode, func(t *testing.T) {
			var rules []rewrite.Rule
			if mode == "headers" {
				rules = append(rules, rewrite.Rule{Name: "headers", Response: &rewrite.ResponseAction{Headers: rewrite.HeaderAction{Set: map[string]string{"X-Rewritten": "yes"}}}})
			}
			if mode == "body" {
				rules = append(rules, rewrite.Rule{Name: "body", Response: &rewrite.ResponseAction{Body: &rewrite.BodyReplacement{Replace: "new"}}})
			}
			h := newH2Harness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Trailer", "X-Final")
				w.Header().Set("Connection", "keep-alive")
				io.WriteString(w, "origin")
				w.Header().Set("X-Final", "complete")
			}), false, true, func(c *Config) { c.Rewrite = compileM2Rules(t, rules...) })
			res := h2Request(t, h, "GET", "/", "")
			body := readM2ResponseBody(t, res)
			if mode == "body" {
				require.Equal(t, "new", body)
				require.Empty(t, res.Trailer)
			} else {
				require.Equal(t, "origin", body)
				require.Equal(t, "complete", res.Trailer.Get("X-Final"))
			}
			if mode == "headers" {
				require.Equal(t, "yes", res.Header.Get("X-Rewritten"))
			}
			require.Empty(t, res.Header.Get("Connection"))
			require.Empty(t, res.TransferEncoding)
		})
	}
}

func TestM32HTTP2ConcurrentRewrite(t *testing.T) {
	h := newH2Harness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Echo", r.Header.Get("X-Step"))
		io.WriteString(w, r.URL.Path)
	}), false, true, func(c *Config) { c.Rewrite = m24Pipeline(t, "parallel") })
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			method, path := "GET", fmt.Sprintf("/plain/%d", i)
			if i%2 == 0 {
				method, path = "POST", "/start"
			}
			res := h2Request(t, h, method, path, "original")
			body := readM2ResponseBody(t, res)
			if i%2 == 0 {
				require.Equal(t, "response-parallel", body)
			} else {
				require.Equal(t, path, body)
			}
		}(i)
	}
	wg.Wait()
}

func TestM32HTTP2Streaming(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	h := newH2Harness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "first")
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		io.CopyN(w, strings.NewReader(strings.Repeat("z", 2<<20)), 2<<20)
	}), false, true, func(c *Config) {
		c.Rewrite = compileM2Rules(t, rewrite.Rule{Name: "header", Response: &rewrite.ResponseAction{Headers: rewrite.HeaderAction{Set: map[string]string{"X-Stream": "yes"}}}})
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://localhost/", nil)
	res, err := h.client.RoundTrip(req)
	require.NoError(t, err)
	first := make([]byte, 5)
	_, err = io.ReadFull(res.Body, first)
	require.NoError(t, err)
	require.Equal(t, "first", string(first))
	// Reading the first flushed bytes while upstream is blocked proves no full buffering.
	cancel()
	res.Body.Close()
}

func TestM32HTTP2URLHeadersAndBody(t *testing.T) {
	rules := []rewrite.Rule{
		{Name: "url", Match: rewrite.Match{Path: "/start"}, Request: &rewrite.RequestAction{URL: "https://localhost:443/stage?q=rewritten", Method: "PUT", Headers: rewrite.HeaderAction{Set: map[string]string{"X-Step": "first"}, Remove: []string{"X-Client"}}, Body: &rewrite.BodyReplacement{Replace: "first"}}},
		{Name: "next", Match: rewrite.Match{Path: "/stage", Methods: []string{"PUT"}}, Request: &rewrite.RequestAction{Method: "POST", Headers: rewrite.HeaderAction{Set: map[string]string{"X-Step": "second"}}, Body: &rewrite.BodyReplacement{Replace: "final"}}},
		{Name: "response", Response: &rewrite.ResponseAction{Status: 201, Headers: rewrite.HeaderAction{Set: map[string]string{"X-Response": "first"}, Remove: []string{"X-Remove"}}, Body: &rewrite.BodyReplacement{Replace: "first"}}},
		{Name: "response-next", Match: rewrite.Match{ResponseStatus: []int{201}}, Response: &rewrite.ResponseAction{Status: 202, Headers: rewrite.HeaderAction{Set: map[string]string{"X-Response": "second"}}, Body: &rewrite.BodyReplacement{Replace: "final"}}},
	}
	h := newH2Harness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "localhost", r.Host)
		require.Equal(t, "/stage?q=rewritten", r.URL.RequestURI())
		require.Equal(t, "POST", r.Method)
		require.Empty(t, r.Header.Get("X-Client"))
		require.Equal(t, "second", r.Header.Get("X-Step"))
		require.EqualValues(t, 5, r.ContentLength)
		b, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.Equal(t, "final", string(b))
		require.Empty(t, r.Trailer)
		w.Header().Set("ETag", "old")
		w.Header().Set("Content-Encoding", "identity")
		w.Header().Set("Last-Modified", "old")
		w.Header().Set("Content-Range", "bytes 0-2/10")
		w.Header().Set("X-Remove", "old")
		io.WriteString(w, "old")
	}), false, true, func(c *Config) { c.Rewrite = compileM2Rules(t, rules...) })
	res := h2Request(t, h, "POST", "/start", "original")
	require.Equal(t, 202, res.StatusCode)
	require.Equal(t, "second", res.Header.Get("X-Response"))
	require.Equal(t, "final", readM2ResponseBody(t, res))
	for _, name := range []string{"ETag", "Last-Modified", "Content-Range", "X-Remove", "Content-Encoding"} {
		require.Empty(t, res.Header.Get(name))
	}
}

func TestM32HTTP2TerminalAndRedirect(t *testing.T) {
	rules := []rewrite.Rule{{Name: "local", Match: rewrite.Match{Path: "/local"}, LocalResponse: &rewrite.LocalResponse{Status: 201, Body: "mock"}},
		{Name: "request-terminal", Match: rewrite.Match{Path: "/terminal"}, Request: &rewrite.RequestAction{URL: "https://localhost/local"}},
		{Name: "terminal-after-rewrite", Match: rewrite.Match{Path: "/local"}, LocalResponse: &rewrite.LocalResponse{Status: 201, Body: "mock"}}}
	for _, status := range []int{301, 302, 307, 308} {
		rules = append(rules, rewrite.Rule{Name: fmt.Sprint(status), Match: rewrite.Match{Path: fmt.Sprintf("/%d", status)}, Redirect: &rewrite.Redirect{Status: status, Location: "/target"}})
	}
	h := newH2Harness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "forwarded") }), false, true, func(c *Config) { c.Rewrite = compileM2Rules(t, rules...) })
	for _, method := range []string{"GET", "HEAD"} {
		for _, path := range []string{"/local", "/terminal", "/301", "/302", "/307", "/308"} {
			res := h2Request(t, h, method, path, "")
			if strings.HasPrefix(path, "/3") {
				require.Equal(t, "/target", res.Header.Get("Location"))
			} else {
				require.Equal(t, 201, res.StatusCode)
			}
			body := readM2ResponseBody(t, res)
			if method == "HEAD" {
				require.Empty(t, body)
			} else if res.StatusCode == 201 {
				require.Equal(t, "mock", body)
			}
		}
	}
	require.Zero(t, h.dials.Load())
	require.Equal(t, "forwarded", readM2ResponseBody(t, h2Request(t, h, "GET", "/unmatched", "")))
}

func TestM32HTTP2LargeBodyAndEarlyEOF(t *testing.T) {
	payload := strings.Repeat("x", 2<<20)
	h := newH2Harness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/eof" {
			w.Header().Set("Content-Length", "100")
			io.WriteString(w, "short")
			return
		}
		b, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.Equal(t, payload, string(b))
		io.WriteString(w, payload)
	}), false, true)
	res := h2Request(t, h, "POST", "/large", payload)
	require.Equal(t, payload, readM2ResponseBody(t, res))
	req, err := http.NewRequest("GET", "https://localhost/eof", nil)
	require.NoError(t, err)
	res, err = h.client.RoundTrip(req)
	if err == nil {
		_, err = io.ReadAll(res.Body)
		res.Body.Close()
	}
	require.Error(t, err)
	// Failed response body must not poison the shared downstream connection.
	res = h2Request(t, h, "POST", "/large", payload)
	require.Equal(t, payload, readM2ResponseBody(t, res))
}

func TestM32HTTP2SnapshotConcurrent(t *testing.T) {
	h := newH2Harness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Echo", "old")
		io.WriteString(w, "origin")
	}), false, true, func(c *Config) { c.Rewrite = m24Pipeline(t, "old") })
	cfg := h.manager.ConfigSnapshot()
	cfg.Rewrite = m24Pipeline(t, "new")
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			h.manager.Update(cfg)
		}
	}()
	for i := 0; i < 10; i++ {
		res := h2Request(t, h, "POST", "/start", "old")
		require.Equal(t, "response-old", readM2ResponseBody(t, res))
	}
	wg.Wait()
	// A fresh TLS connection captures the published configuration, including
	// both phases, rather than reading global rules at response time.
	fresh := newH2Harness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Echo", "new")
		io.WriteString(w, "origin")
	}), false, true, func(c *Config) { c.Rewrite = h.manager.ConfigSnapshot().Rewrite })
	require.Equal(t, "response-new", readM2ResponseBody(t, h2Request(t, fresh, "POST", "/start", "new")))
}

func TestM32HTTP2UnsafeRewriteRejected(t *testing.T) {
	for _, name := range []string{":authority", ":method", "Host", "Connection", "Transfer-Encoding", "Content-Length", "Trailer"} {
		_, err := rewrite.Compile(rewrite.Config{Enable: true, Rules: []rewrite.Rule{{Name: "unsafe", Request: &rewrite.RequestAction{Headers: rewrite.HeaderAction{Set: map[string]string{name: "bad"}}}}}})
		require.Error(t, err)
	}
	_, err := rewrite.Compile(rewrite.Config{Enable: true, Rules: []rewrite.Rule{{Name: "crlf", Response: &rewrite.ResponseAction{Headers: rewrite.HeaderAction{Set: map[string]string{"X-Test": "a\r\nb"}}}}}})
	require.Error(t, err)
	_, err = rewrite.Compile(rewrite.Config{Enable: true, Rules: []rewrite.Rule{{Name: "cleartext", Request: &rewrite.RequestAction{URL: "http://localhost/"}}}})
	require.Error(t, err)
	h := newH2Harness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }), false, true)
	req, _ := http.NewRequest("GET", "https://localhost/", nil)
	req.Host = "other.example"
	res, err := h.client.RoundTrip(req)
	require.NoError(t, err)
	require.Equal(t, 421, res.StatusCode)
	readM2ResponseBody(t, res)
	require.Zero(t, h.dials.Load())
	require.Equal(t, "ok", readM2ResponseBody(t, h2Request(t, h, "GET", "/", "")))
}

func TestM32HTTP2RequestTrailerRewrite(t *testing.T) {
	for _, replace := range []bool{false, true} {
		t.Run(fmt.Sprint(replace), func(t *testing.T) {
			action := &rewrite.RequestAction{Headers: rewrite.HeaderAction{Set: map[string]string{"X-Rewritten": "yes"}}}
			if replace {
				action.Body = &rewrite.BodyReplacement{Replace: "new"}
			}
			observed := make(chan http.Header, 1)
			h := newH2Harness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				b, err := io.ReadAll(r.Body)
				require.NoError(t, err)
				require.Equal(t, "yes", r.Header.Get("X-Rewritten"))
				if replace {
					require.Equal(t, "new", string(b))
				} else {
					require.Equal(t, "old", string(b))
				}
				observed <- r.Trailer.Clone()
				io.WriteString(w, "ok")
			}), false, true, func(c *Config) { c.Rewrite = compileM2Rules(t, rewrite.Rule{Name: "request", Request: action}) })
			req, _ := http.NewRequest("POST", "https://localhost/", strings.NewReader("old"))
			req.Trailer = http.Header{"X-Upload": {"complete"}}
			res, err := h.client.RoundTrip(req)
			require.NoError(t, err)
			require.Equal(t, 2, res.ProtoMajor)
			readM2ResponseBody(t, res)
			trailer := <-observed
			if replace {
				require.Empty(t, trailer)
			} else {
				require.Equal(t, "complete", trailer.Get("X-Upload"))
			}
		})
	}
}

func TestM32HTTP2StatusRewriteReleasesBody(t *testing.T) {
	for _, status := range []int{204, 205, 206, 304} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			h := newH2Harness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if status == 206 {
					w.Header().Set("Content-Range", "bytes 0-2/6")
				}
				w.WriteHeader(status)
				if status == 206 {
					io.WriteString(w, "old")
				}
			}), false, true, func(c *Config) {
				c.Rewrite = compileM2Rules(t, rewrite.Rule{Name: "representation", Response: &rewrite.ResponseAction{Status: 200, Body: &rewrite.BodyReplacement{Replace: "full"}}})
			})
			res := h2Request(t, h, "GET", "/", "")
			require.Equal(t, 200, res.StatusCode)
			require.Equal(t, "full", readM2ResponseBody(t, res))
			require.Empty(t, res.Header.Get("Content-Range"))
		})
	}
}

func TestM32HTTP2RewriteCancellationIsolation(t *testing.T) {
	entered := make(chan struct{})
	canceled := make(chan struct{})
	h := newH2Harness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/wait" {
			close(entered)
			<-r.Context().Done()
			close(canceled)
			return
		}
		io.WriteString(w, r.Header.Get("X-Rewrite"))
	}), false, true, func(c *Config) {
		c.Rewrite = compileM2Rules(t,
			rewrite.Rule{Name: "header", Request: &rewrite.RequestAction{Headers: rewrite.HeaderAction{Set: map[string]string{"X-Rewrite": "isolated"}}}},
			rewrite.Rule{Name: "local", Match: rewrite.Match{Path: "/local"}, LocalResponse: &rewrite.LocalResponse{Status: 200, Body: "local"}})
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://localhost/wait", nil)
	done := make(chan error, 1)
	go func() {
		res, err := h.client.RoundTrip(req)
		if res != nil {
			res.Body.Close()
		}
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("upstream not entered")
	}
	require.Equal(t, "local", readM2ResponseBody(t, h2Request(t, h, "GET", "/local", "")))
	cancel()
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(3 * time.Second):
		t.Fatal("stream not canceled")
	}
	select {
	case <-canceled:
	case <-time.After(3 * time.Second):
		t.Fatal("upstream context not canceled")
	}
	require.Equal(t, "isolated", readM2ResponseBody(t, h2Request(t, h, "GET", "/survivor", "")))
}

func TestM32HTTP2NewConnectionSnapshot(t *testing.T) {
	local := func(version string) *rewrite.Snapshot {
		return compileM2Rules(t, rewrite.Rule{Name: "version", LocalResponse: &rewrite.LocalResponse{Status: 200, Body: version}})
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("local response dialed upstream") })
	old := newH2Harness(t, handler, false, true, func(c *Config) { c.Rewrite = local("old") })
	cfg := old.manager.ConfigSnapshot()
	cfg.Rewrite = local("new")
	old.manager.Update(cfg)
	fresh := newH2HarnessWithManager(t, old.manager, handler, false, true)
	require.Same(t, old.manager, fresh.manager)
	require.Equal(t, "old", readM2ResponseBody(t, h2Request(t, old, "GET", "/", "")))
	require.Equal(t, "new", readM2ResponseBody(t, h2Request(t, fresh, "GET", "/", "")))
	require.Zero(t, old.dials.Load())
	require.Zero(t, fresh.dials.Load())
}

func TestM32HTTP2AuthorityRewrite(t *testing.T) {
	h := newH2HarnessTarget(t, nil, "rewritten.example", 8443, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "rewritten.example:8443", r.Host)
		require.Equal(t, "rewritten.example", r.TLS.ServerName)
		require.Equal(t, "/new?value=2", r.URL.RequestURI())
		io.WriteString(w, "verified-target")
	}), false, true, func(c *Config) {
		c.Rewrite = compileM2Rules(t, rewrite.Rule{Name: "authority", Request: &rewrite.RequestAction{URL: "https://rewritten.example:8443/new?value=2"}})
	})
	require.Equal(t, "verified-target", readM2ResponseBody(t, h2Request(t, h, "GET", "/old?value=1", "")))
}
