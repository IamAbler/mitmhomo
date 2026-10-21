package mitm

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/mitm/rewrite"
	"github.com/stretchr/testify/require"
)

// Reuse the verified dual-TLS/native-dial harness, including real HTTP framing.
func m24Pipeline(t *testing.T, version string) *rewrite.Snapshot {
	t.Helper()
	return compileM2Rules(t,
		rewrite.Rule{Name: "first-request", Match: rewrite.Match{Path: "/start", Methods: []string{"POST"}}, Request: &rewrite.RequestAction{URL: "https://localhost/stage", Method: "PUT", Headers: rewrite.HeaderAction{Set: map[string]string{"X-Step": "first"}}, Body: &rewrite.BodyReplacement{Replace: "intermediate"}}},
		rewrite.Rule{Name: "second-request", Match: rewrite.Match{Path: "/stage", Methods: []string{"PUT"}, Headers: map[string]string{"X-Step": "first"}}, Request: &rewrite.RequestAction{URL: "https://localhost/final/" + version, Method: "PATCH", Headers: rewrite.HeaderAction{Set: map[string]string{"X-Step": version}}, Body: &rewrite.BodyReplacement{Replace: "request-" + version, ContentType: "text/plain"}}},
		rewrite.Rule{Name: "first-response", Match: rewrite.Match{Path: "/final/" + version, Methods: []string{"PATCH"}, Headers: map[string]string{"X-Echo": version}}, Response: &rewrite.ResponseAction{Status: 201, Headers: rewrite.HeaderAction{Set: map[string]string{"X-Response-Step": "first"}}, Body: &rewrite.BodyReplacement{Replace: "intermediate-response"}}},
		rewrite.Rule{Name: "second-response", Match: rewrite.Match{Path: "/final/" + version, Methods: []string{"PATCH"}, ResponseStatus: []int{201}, Headers: map[string]string{"X-Response-Step": "first"}}, Response: &rewrite.ResponseAction{Status: 202, Headers: rewrite.HeaderAction{Set: map[string]string{"X-Response-Step": version}}, Body: &rewrite.BodyReplacement{Replace: "response-" + version, ContentType: "text/plain"}}},
	)
}

func TestM24BidirectionalCompositionKeepAliveAndReload(t *testing.T) {
	observed := make(chan m2RequestObservation, 8)
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	var calls atomic.Int32
	h := newM2HTTPHarness(t, "localhost", m24Pipeline(t, "old"), func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "body", 400)
			return
		}
		observed <- m2RequestObservation{method: r.Method, urlPath: r.URL.Path, header: r.Header.Clone(), body: string(body), contentLength: r.ContentLength}
		if calls.Add(1) == 1 {
			entered <- struct{}{}
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
		}
		w.Header().Set("X-Echo", r.Header.Get("X-Step"))
		_, _ = io.WriteString(w, "origin")
	})
	oldClient, oldDone := h.startTCPClient(t)
	oldReader := bufio.NewReader(oldClient)
	send := func(client io.Writer) {
		_, err := io.WriteString(client, "POST /start HTTP/1.1\r\nHost: localhost\r\nContent-Length: 8\r\n\r\noriginal")
		require.NoError(t, err)
	}
	send(oldClient)
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not receive rewritten request")
	}
	config := h.manager.ConfigSnapshot()
	config.Rewrite = m24Pipeline(t, "new")
	h.manager.Update(config)
	close(release)
	check := func(reader *bufio.Reader, version string) {
		response, err := http.ReadResponse(reader, &http.Request{Method: "POST"})
		require.NoError(t, err)
		require.Equal(t, 202, response.StatusCode)
		require.Equal(t, version, response.Header.Get("X-Response-Step"))
		require.Equal(t, fmt.Sprint(len("response-"+version)), response.Header.Get("Content-Length"))
		require.Equal(t, "response-"+version, readM2ResponseBody(t, response))
		require.False(t, response.Close)
		select {
		case request := <-observed:
			require.Equal(t, "PATCH", request.method)
			require.Equal(t, "/final/"+version, request.urlPath)
			require.Equal(t, version, request.header.Get("X-Step"))
			require.Equal(t, "request-"+version, request.body)
			require.EqualValues(t, len(request.body), request.contentLength)
		case <-time.After(time.Second):
			t.Fatal("missing upstream observation")
		}
	}
	check(oldReader, "old") // Reload occurred between the two pipeline phases.
	newClient, newDone := h.startTCPClient(t)
	newReader := bufio.NewReader(newClient)
	for i := 0; i < 2; i++ {
		send(oldClient)
		check(oldReader, "old")
		send(newClient)
		check(newReader, "new")
	}
	require.EqualValues(t, 5, h.dialCount.Load(), "each request retains an independent native outbound")
	finishM2Dispatch(t, oldClient, oldDone)
	finishM2Dispatch(t, newClient, newDone)
}

func TestM24TerminalSkipsBothResponsePipelinesAndLaterRequestRules(t *testing.T) {
	pipeline := compileM2Rules(t,
		rewrite.Rule{Name: "prepare", Match: rewrite.Match{Path: "/local"}, Request: &rewrite.RequestAction{Method: "PUT", Headers: rewrite.HeaderAction{Set: map[string]string{"X-Step": "ready"}}, Body: &rewrite.BodyReplacement{Replace: "discarded"}}},
		rewrite.Rule{Name: "local", Match: rewrite.Match{Path: "/local", Methods: []string{"PUT"}, Headers: map[string]string{"X-Step": "ready"}}, LocalResponse: &rewrite.LocalResponse{Status: 201, Body: "local"}},
		rewrite.Rule{Name: "redirect", Match: rewrite.Match{Path: "/redirect"}, Redirect: &rewrite.Redirect{Status: 307, Location: "/target"}},
		rewrite.Rule{Name: "later-request", Request: &rewrite.RequestAction{URL: "https://localhost/later"}},
		rewrite.Rule{Name: "ordinary-response", Response: &rewrite.ResponseAction{Status: 202, Body: &rewrite.BodyReplacement{Replace: "ordinary"}}},
	)
	h := newM2HTTPHarness(t, "localhost", pipeline, nil)
	var hookCalls atomic.Int32
	config := h.manager.ConfigSnapshot()
	config.ResponseHook = func(response *http.Response) error {
		hookCalls.Add(1)
		response.Header.Set("X-Hook", "yes")
		return nil
	}
	h.manager.Update(config)
	client, done := h.startTCPClient(t)
	reader := bufio.NewReader(client)
	for _, test := range []struct {
		path   string
		status int
		body   string
	}{{"/local", 201, "local"}, {"/redirect", 307, ""}, {"/local", 201, "local"}} {
		response := sendM2Request(t, client, reader, "GET "+test.path+" HTTP/1.1\r\nHost: localhost\r\n\r\n", "GET")
		require.Equal(t, test.status, response.StatusCode)
		require.Equal(t, test.body, readM2ResponseBody(t, response))
		require.Empty(t, response.Header.Get("X-Hook"))
		require.False(t, response.Close)
		if test.path == "/redirect" {
			require.Equal(t, "/target", response.Header.Get("Location"))
		}
	}
	require.Zero(t, h.dialCount.Load())
	require.Zero(t, hookCalls.Load())
	response := sendM2Request(t, client, reader, "GET /ordinary HTTP/1.1\r\nHost: localhost\r\n\r\n", "GET")
	require.Equal(t, 202, response.StatusCode)
	require.Equal(t, "ordinary", readM2ResponseBody(t, response))
	require.EqualValues(t, 1, hookCalls.Load())
	require.EqualValues(t, 1, h.dialCount.Load())
	require.Equal(t, "/later", (<-h.observations).urlPath)
	finishM2Dispatch(t, client, done)
}

func TestM24MethodRewriteHEADFraming(t *testing.T) {
	for _, replacement := range []bool{false, true} {
		t.Run(fmt.Sprint("replacement=", replacement), func(t *testing.T) {
			rule := rewrite.Rule{Name: "method", Match: rewrite.Match{Path: "/head"}, Request: &rewrite.RequestAction{Method: "HEAD"}}
			if replacement {
				rule.Response = &rewrite.ResponseAction{Body: &rewrite.BodyReplacement{Replace: "replacement"}}
			}
			h := newM2HTTPHarness(t, "localhost", compileM2Rules(t, rule), func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Length", "8")
				_, _ = io.WriteString(w, "original")
			})
			client, done := h.startTCPClient(t)
			reader := bufio.NewReader(client)
			response := sendM2Request(t, client, reader, "GET /head HTTP/1.1\r\nHost: localhost\r\n\r\n", "GET")
			require.Equal(t, 200, response.StatusCode)
			want := ""
			if replacement {
				want = "replacement"
			}
			require.Equal(t, want, readM2ResponseBody(t, response))
			require.Equal(t, fmt.Sprint(len(want)), response.Header.Get("Content-Length"))
			response = sendM2Request(t, client, reader, "GET /ordinary HTTP/1.1\r\nHost: localhost\r\n\r\n", "GET")
			require.Equal(t, "original", readM2ResponseBody(t, response))
			finishM2Dispatch(t, client, done)
		})
	}
}

func TestM24OriginalHEADAfterOutboundGETKeepsConnectionAligned(t *testing.T) {
	pipeline := compileM2Rules(t, rewrite.Rule{Name: "get", Match: rewrite.Match{Path: "/head"}, Request: &rewrite.RequestAction{Method: "GET"}, Response: &rewrite.ResponseAction{Body: &rewrite.BodyReplacement{Replace: "replacement"}}})
	h := newM2HTTPHarness(t, "localhost", pipeline, nil)
	client, done := h.startTCPClient(t)
	reader := bufio.NewReader(client)
	response := sendM2Request(t, client, reader, "HEAD /head HTTP/1.1\r\nHost: localhost\r\n\r\n", "HEAD")
	require.Empty(t, readM2ResponseBody(t, response))
	require.Equal(t, "11", response.Header.Get("Content-Length"))
	response = sendM2Request(t, client, reader, "GET /ordinary HTTP/1.1\r\nHost: localhost\r\n\r\n", "GET")
	require.Equal(t, "upstream-ok", readM2ResponseBody(t, response))
	first := <-h.observations
	require.Equal(t, "GET", first.method)
	require.Equal(t, "/head", first.urlPath)
	finishM2Dispatch(t, client, done)
}

func TestM24RewrittenUploadStreamFailuresReleaseUpstream(t *testing.T) {
	for _, kind := range []string{"cancel", "timeout", "early-eof"} {
		t.Run(kind, func(t *testing.T) {
			observed := make(chan string, 1)
			released := make(chan struct{})
			pipeline := compileM2Rules(t, rewrite.Rule{Name: "upload", Request: &rewrite.RequestAction{Method: "PATCH", Body: &rewrite.BodyReplacement{Replace: "rewritten-upload"}}, Response: &rewrite.ResponseAction{Headers: rewrite.HeaderAction{Set: map[string]string{"X-Response": "rewritten"}}}})
			h := newM2HTTPHarness(t, "localhost", pipeline, func(w http.ResponseWriter, r *http.Request) {
				defer close(released)
				body, err := io.ReadAll(r.Body)
				if err != nil {
					return
				}
				observed <- r.Method + " " + string(body)
				if kind == "early-eof" {
					conn, rw, err := w.(http.Hijacker).Hijack()
					if err == nil {
						_, _ = rw.WriteString("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nfirst\r\n")
						_ = rw.Flush()
						_ = conn.Close()
					}
					return
				}
				w.WriteHeader(200)
				_, _ = io.WriteString(w, "first")
				w.(http.Flusher).Flush()
				<-r.Context().Done()
			})
			if kind == "timeout" {
				config := h.manager.ConfigSnapshot()
				config.RequestTimeout = 400 * time.Millisecond
				h.manager.Update(config)
			}
			client, done := h.startTCPClient(t)
			response := sendM2Request(t, client, bufio.NewReader(client), "POST /stream HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n\r\nbody", "POST")
			require.Equal(t, "rewritten", response.Header.Get("X-Response"))
			if kind == "cancel" {
				first := make([]byte, 5)
				_, err := io.ReadFull(response.Body, first)
				require.NoError(t, err)
				require.Equal(t, "first", string(first))
				_ = client.Close()
			} else {
				body, err := io.ReadAll(response.Body)
				require.Equal(t, "first", string(body))
				require.Error(t, err)
			}
			select {
			case request := <-observed:
				require.Equal(t, "PATCH rewritten-upload", request)
			case <-time.After(time.Second):
				t.Fatal("missing rewritten upload")
			}
			select {
			case <-released:
			case <-time.After(3 * time.Second):
				t.Fatal("upstream not released")
			}
			_ = response.Body.Close()
			finishM2Dispatch(t, client, done)
		})
	}
}

func TestM24LegacyHookContentLengthField(t *testing.T) {
	for _, replace := range []bool{false, true} {
		t.Run(fmt.Sprint("replacement=", replace), func(t *testing.T) {
			var pipeline *rewrite.Snapshot
			if replace {
				pipeline = compileM2Rules(t, rewrite.Rule{Name: "body", Response: &rewrite.ResponseAction{Body: &rewrite.BodyReplacement{Replace: "static"}}})
			}
			h := newM2HTTPHarness(t, "localhost", pipeline, nil)
			config := h.manager.ConfigSnapshot()
			config.ResponseHook = func(response *http.Response) error { response.ContentLength = 999; return nil }
			h.manager.Update(config)
			client, done := h.startClient(t)
			response := sendM2Request(t, client, bufio.NewReader(client), "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n", "GET")
			if replace {
				require.Equal(t, 200, response.StatusCode)
				require.Equal(t, "6", response.Header.Get("Content-Length"))
				require.Equal(t, "static", readM2ResponseBody(t, response))
			} else {
				require.Equal(t, 502, response.StatusCode)
				_ = readM2ResponseBody(t, response)
			}
			finishM2Dispatch(t, client, done)
		})
	}
}
