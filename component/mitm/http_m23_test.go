package mitm

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/metacubex/mihomo/component/mitm/rewrite"
	"github.com/stretchr/testify/require"
)

func TestM23ResponseRewriteOrderAndFinalRequestTarget(t *testing.T) {
	received := make(chan string, 1)
	pipeline := compileM2Rules(t,
		rewrite.Rule{
			Name:    "request-final-target",
			Match:   rewrite.Match{Path: "/old", Methods: []string{http.MethodGet}},
			Request: &rewrite.RequestAction{URL: "https://rewrite.example/final", Method: http.MethodPost},
		},
		rewrite.Rule{
			Name: "response-first",
			Match: rewrite.Match{
				Domains: []string{"rewrite.example"}, Path: "/final", Methods: []string{http.MethodPost},
				Headers: map[string]string{"X-Legacy-Hook": "ready"},
			},
			Response: &rewrite.ResponseAction{
				Status:  http.StatusCreated,
				Headers: rewrite.HeaderAction{Set: map[string]string{"X-Stage": "one", "Content-Type": "application/x-rewritten"}, Remove: []string{"X-Old"}},
				Body:    &rewrite.BodyReplacement{Replace: "response-body"},
			},
		},
		rewrite.Rule{
			Name:     "response-second",
			Match:    rewrite.Match{Path: "/final", ResponseStatus: []int{http.StatusCreated}, Headers: map[string]string{"X-Stage": "one"}},
			Response: &rewrite.ResponseAction{Status: http.StatusAccepted, Headers: rewrite.HeaderAction{Set: map[string]string{"X-Stage": "two"}}},
		},
		rewrite.Rule{
			Name:     "response-third",
			Match:    rewrite.Match{Path: "/final", ResponseStatus: []int{http.StatusAccepted}, Headers: map[string]string{"X-Stage": "two"}},
			Response: &rewrite.ResponseAction{Status: http.StatusNonAuthoritativeInfo, Headers: rewrite.HeaderAction{Set: map[string]string{"X-Stage": "final"}}},
		},
	)
	h := newM2HTTPHarnessForUpstream(t, "origin.example", "rewrite.example", pipeline, func(w http.ResponseWriter, r *http.Request) {
		received <- r.Method + " " + r.URL.RequestURI() + " " + r.Host
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-Old", "old")
		_, _ = io.WriteString(w, "origin-body")
	})
	config := h.manager.ConfigSnapshot()
	config.ResponseHook = func(response *http.Response) error {
		response.Header.Set("X-Legacy-Hook", "ready")
		response.Header.Set("Connection", "X-Hop, keep-alive")
		response.Header.Set("X-Hop", "must-not-cross")
		response.Header.Set("Keep-Alive", "timeout=5")
		response.Header.Set("Proxy-Authenticate", "Basic realm=upstream")
		response.Header.Set("Transfer-Encoding", "chunked")
		response.Header.Set("Trailer", "X-Stale-Trailer")
		return nil
	}
	h.manager.Update(config)

	client, done := h.startClient(t)
	response := sendM2Request(t, client, bufio.NewReader(client), "GET /old HTTP/1.1\r\nHost: origin.example\r\n\r\n", http.MethodGet)
	require.Equal(t, http.StatusNonAuthoritativeInfo, response.StatusCode)
	require.Equal(t, "response-body", readM2ResponseBody(t, response))
	require.Equal(t, "POST /final rewrite.example:443", <-received)
	require.Equal(t, "final", response.Header.Get("X-Stage"))
	require.Empty(t, response.Header.Get("X-Old"))
	require.Equal(t, "application/x-rewritten", response.Header.Get("Content-Type"), "a later header action survives a body replacement")
	require.Equal(t, fmt.Sprint(len("response-body")), response.Header.Get("Content-Length"))
	require.Empty(t, response.Header.Get("Transfer-Encoding"))
	require.Empty(t, response.TransferEncoding)
	require.Empty(t, response.Header.Get("Trailer"))
	require.Empty(t, response.Header.Get("Connection"))
	require.Empty(t, response.Header.Get("Keep-Alive"))
	require.Empty(t, response.Header.Get("Proxy-Authenticate"))
	require.Empty(t, response.Header.Get("X-Hop"))
	finishM2Dispatch(t, client, done)
}

func TestM23BodyReplacementFramingAndCompression(t *testing.T) {
	pipeline := compileM2Rules(t,
		rewrite.Rule{Name: "gzip", Match: rewrite.Match{Path: "/gzip"}, Response: &rewrite.ResponseAction{Body: &rewrite.BodyReplacement{Replace: "plain-gzip-replacement", ContentType: "text/plain"}}},
		rewrite.Rule{Name: "br", Match: rewrite.Match{Path: "/br"}, Response: &rewrite.ResponseAction{Headers: rewrite.HeaderAction{Set: map[string]string{"Content-Type": "application/from-header"}}, Body: &rewrite.BodyReplacement{Replace: "plain-br-replacement"}}},
		rewrite.Rule{Name: "empty", Match: rewrite.Match{Path: "/empty"}, Response: &rewrite.ResponseAction{Body: &rewrite.BodyReplacement{}}},
		rewrite.Rule{Name: "chunked", Match: rewrite.Match{Path: "/chunked-replace"}, Response: &rewrite.ResponseAction{Body: &rewrite.BodyReplacement{Replace: "chunked-replacement"}}},
	)
	h := newM2HTTPHarness(t, "localhost", pipeline, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/gzip", "/gzip-pass":
			var compressed bytes.Buffer
			writer := gzip.NewWriter(&compressed)
			_, _ = io.WriteString(writer, "gzip-origin-body")
			_ = writer.Close()
			w.Header().Set("Content-Encoding", "gzip")
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("ETag", `"old-gzip"`)
			w.Header().Set("Content-Range", "bytes 0-15/16")
			w.Header().Set("Accept-Ranges", "bytes")
			w.Header().Set("Digest", "sha-256=old")
			w.Header().Set("Cache-Control", "max-age=30")
			w.Header().Add("Set-Cookie", "session=kept")
			_, _ = w.Write(compressed.Bytes())
		case "/br", "/br-pass":
			var compressed bytes.Buffer
			writer := brotli.NewWriter(&compressed)
			_, _ = io.WriteString(writer, "br-origin-body")
			_ = writer.Close()
			w.Header().Set("Content-Encoding", "br")
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("ETag", `"old-br"`)
			_, _ = w.Write(compressed.Bytes())
		case "/empty":
			w.Header().Set("Content-Type", "application/old")
			_, _ = io.WriteString(w, "old-body")
		case "/chunked-replace":
			w.Header().Add("Trailer", "X-Upstream-Trailer")
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			_, _ = io.WriteString(w, "old-chunk")
			w.(http.Flusher).Flush()
			w.Header().Set("X-Upstream-Trailer", "must-be-discarded")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	client, done := h.startClient(t)
	reader := bufio.NewReader(client)
	for _, test := range []struct {
		path            string
		acceptEncoding  string
		wantBody        string
		wantContentType string
		wantEncoding    string
		wantPreserved   bool
	}{
		{path: "/gzip", acceptEncoding: "gzip", wantBody: "plain-gzip-replacement", wantContentType: "text/plain", wantPreserved: true},
		{path: "/br", acceptEncoding: "br", wantBody: "plain-br-replacement", wantContentType: "application/from-header"},
		{path: "/empty", wantBody: ""},
		{path: "/chunked-replace", wantBody: "chunked-replacement"},
		{path: "/gzip-pass", acceptEncoding: "gzip", wantEncoding: "gzip", wantPreserved: true},
		{path: "/br-pass", acceptEncoding: "br", wantEncoding: "br"},
	} {
		headers := ""
		if test.acceptEncoding != "" {
			headers = "Accept-Encoding: " + test.acceptEncoding + "\r\n"
		}
		response := sendM2Request(t, client, reader, "GET "+test.path+" HTTP/1.1\r\nHost: localhost\r\n"+headers+"\r\n", http.MethodGet)
		body := readM2ResponseBody(t, response)
		if test.path != "/gzip-pass" && test.path != "/br-pass" {
			require.Equal(t, test.wantBody, body, test.path)
		}
		if test.wantEncoding != "" {
			require.Equal(t, test.wantEncoding, response.Header.Get("Content-Encoding"), test.path)
		} else {
			require.Empty(t, response.Header.Get("Content-Encoding"), test.path)
			require.Empty(t, response.Header.Get("Transfer-Encoding"), test.path)
			require.Empty(t, response.TransferEncoding, test.path)
			require.Empty(t, response.Header.Get("Trailer"), test.path)
			require.Empty(t, response.Trailer, test.path)
			require.Equal(t, fmt.Sprint(len(test.wantBody)), response.Header.Get("Content-Length"), test.path)
			require.EqualValues(t, len(test.wantBody), response.ContentLength, test.path)
			if test.wantContentType != "" {
				require.Equal(t, test.wantContentType, response.Header.Get("Content-Type"), test.path)
			} else if test.path == "/empty" {
				require.Empty(t, response.Header.Get("Content-Type"), "empty replacement must not keep an unrelated type")
			}
			if test.path == "/chunked-replace" {
				require.Empty(t, response.Trailer)
			}
		}
		if test.wantPreserved && test.wantEncoding == "" {
			require.Equal(t, "max-age=30", response.Header.Get("Cache-Control"))
			require.Equal(t, "session=kept", response.Header.Get("Set-Cookie"))
			require.Empty(t, response.Header.Get("ETag"))
			require.Empty(t, response.Header.Get("Content-Range"))
			require.Empty(t, response.Header.Get("Accept-Ranges"))
			require.Empty(t, response.Header.Get("Digest"))
		}
		if test.path == "/gzip-pass" {
			zr, err := gzip.NewReader(bytes.NewReader([]byte(body)))
			require.NoError(t, err)
			decoded, err := io.ReadAll(zr)
			require.NoError(t, err)
			require.NoError(t, zr.Close())
			require.Equal(t, "gzip-origin-body", string(decoded))
		}
		if test.path == "/br-pass" {
			decoded, err := io.ReadAll(brotli.NewReader(bytes.NewReader([]byte(body))))
			require.NoError(t, err)
			require.Equal(t, "br-origin-body", string(decoded))
		}
		require.False(t, response.Close, "response rewriting should preserve client Keep-Alive")
	}
	finishM2Dispatch(t, client, done)
}

func TestM23BodylessStatusesAndHEADFraming(t *testing.T) {
	pipeline := compileM2Rules(t,
		rewrite.Rule{Name: "204", Match: rewrite.Match{Path: "/status-204"}, Response: &rewrite.ResponseAction{Status: http.StatusNoContent}},
		rewrite.Rule{Name: "205", Match: rewrite.Match{Path: "/status-205"}, Response: &rewrite.ResponseAction{Status: http.StatusResetContent}},
		rewrite.Rule{Name: "304", Match: rewrite.Match{Path: "/status-304"}, Response: &rewrite.ResponseAction{Status: http.StatusNotModified}},
		rewrite.Rule{Name: "304-replacement", Match: rewrite.Match{Path: "/status-304-replacement"}, Response: &rewrite.ResponseAction{Status: http.StatusNotModified, Body: &rewrite.BodyReplacement{Replace: "cached-replacement", ContentType: "application/cache"}}},
		rewrite.Rule{Name: "HEAD-replacement", Match: rewrite.Match{Path: "/head", Methods: []string{http.MethodHead}}, Response: &rewrite.ResponseAction{Body: &rewrite.BodyReplacement{Replace: "head-view", ContentType: "text/x-head"}}},
	)
	h := newM2HTTPHarness(t, "localhost", pipeline, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("ETag", `"upstream-v1"`)
		w.Header().Set("Last-Modified", "Wed, 21 Oct 2015 07:28:00 GMT")
		w.Header().Set("Content-Length", fmt.Sprint(len("upstream-body")))
		_, _ = io.WriteString(w, "upstream-body")
	})
	client, done := h.startClient(t)
	reader := bufio.NewReader(client)
	for _, test := range []struct {
		path       string
		method     string
		status     int
		length     string
		contentTyp string
		body       string
	}{
		{path: "/status-204", method: http.MethodGet, status: http.StatusNoContent, contentTyp: "text/plain"},
		{path: "/status-205", method: http.MethodGet, status: http.StatusResetContent, length: "0", contentTyp: "text/plain"},
		{path: "/status-304", method: http.MethodGet, status: http.StatusNotModified},
		{path: "/status-304-replacement", method: http.MethodGet, status: http.StatusNotModified},
		{path: "/head", method: http.MethodHead, status: http.StatusOK, length: fmt.Sprint(len("head-view")), contentTyp: "text/x-head"},
	} {
		response := sendM2Request(t, client, reader, test.method+" "+test.path+" HTTP/1.1\r\nHost: localhost\r\n\r\n", test.method)
		require.Equal(t, test.status, response.StatusCode, test.path)
		require.Empty(t, readM2ResponseBody(t, response), "no response body is allowed for "+test.path)
		require.Equal(t, test.length, response.Header.Get("Content-Length"), test.path)
		require.Equal(t, test.contentTyp, response.Header.Get("Content-Type"), test.path)
		require.Empty(t, response.Header.Get("Transfer-Encoding"), test.path)
		require.Empty(t, response.Header.Get("Trailer"), test.path)
		if test.path == "/status-304" {
			require.Equal(t, `"upstream-v1"`, response.Header.Get("ETag"), "304 keeps representation validators")
			require.Equal(t, "Wed, 21 Oct 2015 07:28:00 GMT", response.Header.Get("Last-Modified"))
		}
	}
	finishM2Dispatch(t, client, done)
}

func TestM23UnmatchedChunkedResponseStreamsAndForwardsTrailers(t *testing.T) {
	pipeline := compileM2Rules(t, rewrite.Rule{Name: "miss", Match: rewrite.Match{Domains: []string{"other.example"}}, Response: &rewrite.ResponseAction{Status: http.StatusCreated}})
	release := make(chan struct{})
	started := make(chan struct{})
	finished := make(chan struct{})
	var releaseOnce sync.Once
	releaseUpstream := func() { releaseOnce.Do(func() { close(release) }) }
	h := newM2HTTPHarness(t, "localhost", pipeline, func(w http.ResponseWriter, _ *http.Request) {
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = rw.WriteString("HTTP/1.1 200 OK\r\nConnection: X-Connection-Trailer\r\nTransfer-Encoding: chunked\r\nTrailer: X-Upstream-Trailer, X-Connection-Trailer\r\n\r\n5\r\nfirst\r\n")
		_ = rw.Flush()
		close(started)
		<-release
		_, _ = rw.WriteString("6\r\nsecond\r\n0\r\nX-Upstream-Trailer: done\r\nX-Connection-Trailer: must-not-cross\r\n\r\n")
		_ = rw.Flush()
		close(finished)
	})
	defer releaseUpstream()
	client, done := h.startClient(t)
	response := sendM2Request(t, client, bufio.NewReader(client), "GET /stream HTTP/1.1\r\nHost: localhost\r\nTE: trailers\r\n\r\n", http.MethodGet)
	require.Contains(t, response.TransferEncoding, "chunked")
	require.Contains(t, response.Trailer, "X-Upstream-Trailer")
	require.NotContains(t, response.Trailer, "X-Connection-Trailer")
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not begin streaming")
	}
	first := make([]byte, len("first"))
	_, err := io.ReadFull(response.Body, first)
	require.NoError(t, err)
	require.Equal(t, "first", string(first))
	select {
	case <-finished:
		t.Fatal("response was buffered until the upstream completed")
	default:
	}
	releaseUpstream()
	remaining, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())
	require.Equal(t, "second", string(remaining))
	require.Equal(t, "done", response.Trailer.Get("X-Upstream-Trailer"))
	require.Empty(t, response.Trailer.Get("X-Connection-Trailer"))
	<-finished
	finishM2Dispatch(t, client, done)
}

func TestM23Interim103BypassesFinalResponseRewrite(t *testing.T) {
	pipeline := compileM2Rules(t, rewrite.Rule{
		Name:     "final-only",
		Match:    rewrite.Match{Path: "/early", ResponseStatus: []int{http.StatusOK}},
		Response: &rewrite.ResponseAction{Status: http.StatusAccepted, Headers: rewrite.HeaderAction{Set: map[string]string{"X-Final-Rewrite": "yes"}}},
	})
	h := newM2HTTPHarness(t, "localhost", pipeline, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Link", "</asset>; rel=preload")
		w.WriteHeader(103)
		w.Header().Set("X-Origin-Final", "yes")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "final")
	})
	client, done := h.startClient(t)
	reader := bufio.NewReader(client)
	interim := sendM2Request(t, client, reader, "GET /early HTTP/1.1\r\nHost: localhost\r\n\r\n", http.MethodGet)
	require.Equal(t, 103, interim.StatusCode)
	require.Equal(t, "</asset>; rel=preload", interim.Header.Get("Link"))
	require.Empty(t, interim.Header.Get("X-Final-Rewrite"))
	_ = interim.Body.Close()
	final, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	require.NoError(t, err)
	require.Equal(t, http.StatusAccepted, final.StatusCode)
	require.Equal(t, "yes", final.Header.Get("X-Final-Rewrite"))
	require.Equal(t, "yes", final.Header.Get("X-Origin-Final"))
	require.Equal(t, "final", readM2ResponseBody(t, final))
	finishM2Dispatch(t, client, done)
}

func TestM23KeepAliveAndConnectionRewriteSnapshot(t *testing.T) {
	oldPipeline := compileM2Rules(t, rewrite.Rule{Name: "old-response", Match: rewrite.Match{Path: "/version"}, Response: &rewrite.ResponseAction{Headers: rewrite.HeaderAction{Set: map[string]string{"X-Version": "old"}}}})
	newPipeline := compileM2Rules(t, rewrite.Rule{Name: "new-response", Match: rewrite.Match{Path: "/version"}, Response: &rewrite.ResponseAction{Headers: rewrite.HeaderAction{Set: map[string]string{"X-Version": "new"}}}})
	h := newM2HTTPHarness(t, "localhost", oldPipeline, nil)
	client, oldDone := h.startTCPClient(t)
	reader := bufio.NewReader(client)
	for i := 0; i < 2; i++ {
		response := sendM2Request(t, client, reader, "GET /version HTTP/1.1\r\nHost: localhost\r\n\r\n", http.MethodGet)
		require.Equal(t, "old", response.Header.Get("X-Version"))
		require.False(t, response.Close)
		require.Equal(t, "upstream-ok", readM2ResponseBody(t, response))
	}
	config := h.manager.ConfigSnapshot()
	config.Rewrite = newPipeline
	h.manager.Update(config)
	response := sendM2Request(t, client, reader, "GET /version HTTP/1.1\r\nHost: localhost\r\n\r\n", http.MethodGet)
	require.Equal(t, "old", response.Header.Get("X-Version"), "the existing connection holds its original response rules")
	require.Equal(t, "upstream-ok", readM2ResponseBody(t, response))
	finishM2Dispatch(t, client, oldDone)

	newClient, newDone := h.startTCPClient(t)
	newResponse := sendM2Request(t, newClient, bufio.NewReader(newClient), "GET /version HTTP/1.1\r\nHost: localhost\r\n\r\n", http.MethodGet)
	require.Equal(t, "new", newResponse.Header.Get("X-Version"), "a new connection sees the new response snapshot")
	require.Equal(t, "upstream-ok", readM2ResponseBody(t, newResponse))
	finishM2Dispatch(t, newClient, newDone)
}

func TestM23ResponseBodyReplacementCancelsUnreadUpstream(t *testing.T) {
	pipeline := compileM2Rules(t, rewrite.Rule{Name: "replace", Match: rewrite.Match{Path: "/replace"}, Response: &rewrite.ResponseAction{Body: &rewrite.BodyReplacement{Replace: "replacement"}}})
	started := make(chan struct{})
	canceled := make(chan struct{})
	h := newM2HTTPHarness(t, "localhost", pipeline, func(w http.ResponseWriter, r *http.Request) {
		w.(http.Flusher).Flush()
		_, _ = io.WriteString(w, "unread-upstream-body")
		w.(http.Flusher).Flush()
		close(started)
		<-r.Context().Done()
		close(canceled)
	})
	client, done := h.startClient(t)
	response := sendM2Request(t, client, bufio.NewReader(client), "GET /replace HTTP/1.1\r\nHost: localhost\r\n\r\n", http.MethodGet)
	require.Equal(t, "replacement", readM2ResponseBody(t, response))
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not start its streaming body")
	}
	select {
	case <-canceled:
	case <-time.After(3 * time.Second):
		t.Fatal("closing the replaced response body did not release the upstream")
	}
	finishM2Dispatch(t, client, done)
}

func TestM23UpstreamPrematureDisconnectAbortsClientResponse(t *testing.T) {
	h := newM2HTTPHarness(t, "localhost", nil, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "64")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "partial")
		w.(http.Flusher).Flush()
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			_ = conn.Close()
		}
	})
	client, done := h.startClient(t)
	_, err := io.WriteString(client, "GET /truncated HTTP/1.1\r\nHost: localhost\r\n\r\n")
	require.NoError(t, err)
	response, headerErr := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: http.MethodGet})
	if headerErr == nil {
		require.Equal(t, http.StatusOK, response.StatusCode)
		body, bodyErr := io.ReadAll(response.Body)
		require.Equal(t, "partial", string(body))
		require.Error(t, bodyErr, "a premature upstream close must not be mistaken for a complete response")
		_ = response.Body.Close()
	} else {
		require.Error(t, headerErr, "the client must not receive a complete response after upstream truncation")
	}
	finishM2Dispatch(t, client, done)
}

func TestM23ResponseStreamClientCancellationAndTimeout(t *testing.T) {
	for _, test := range []struct {
		name         string
		timeout      time.Duration
		cancelClient bool
	}{
		{name: "client cancellation", cancelClient: true},
		{name: "request timeout", timeout: 400 * time.Millisecond},
	} {
		t.Run(test.name, func(t *testing.T) {
			started := make(chan struct{})
			canceled := make(chan struct{})
			h := newM2HTTPHarness(t, "localhost", nil, func(w http.ResponseWriter, r *http.Request) {
				w.(http.Flusher).Flush()
				_, _ = io.WriteString(w, "first")
				w.(http.Flusher).Flush()
				close(started)
				<-r.Context().Done()
				close(canceled)
			})
			if test.timeout > 0 {
				config := h.manager.ConfigSnapshot()
				config.RequestTimeout = test.timeout
				h.manager.Update(config)
			}
			client, done := h.startTCPClient(t)
			response := sendM2Request(t, client, bufio.NewReader(client), "GET /stream HTTP/1.1\r\nHost: localhost\r\n\r\n", http.MethodGet)
			select {
			case <-started:
			case <-time.After(2 * time.Second):
				t.Fatal("upstream did not start the response")
			}
			first := make([]byte, len("first"))
			_, err := io.ReadFull(response.Body, first)
			require.NoError(t, err)
			require.Equal(t, "first", string(first))
			if test.cancelClient {
				_ = client.Close()
			} else {
				select {
				case <-canceled:
				case <-time.After(3 * time.Second):
					t.Fatal("request timeout did not cancel the upstream stream")
				}
				_ = response.Body.Close()
				_ = client.Close()
			}
			select {
			case <-canceled:
			case <-time.After(3 * time.Second):
				t.Fatal("client cancellation did not cancel the upstream stream")
			}
			select {
			case result := <-done:
				require.Equal(t, DispatchIntercepted, result.outcome)
				require.NoError(t, result.err)
			case <-time.After(5 * time.Second):
				t.Fatal("canceled response stream did not release the TLS connection")
			}
		})
	}
}

func TestM23ResponseHookRejects101AndHeaderInjection(t *testing.T) {
	for _, test := range []struct {
		name string
		hook ResponseHook
	}{
		{name: "101 is rejected", hook: func(response *http.Response) error { response.StatusCode = http.StatusSwitchingProtocols; return nil }},
		{name: "header CRLF is rejected", hook: func(response *http.Response) error { response.Header.Set("X-Bad", "ok\r\nX-Injected: yes"); return nil }},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := newM2HTTPHarness(t, "localhost", nil, nil)
			config := h.manager.ConfigSnapshot()
			config.ResponseHook = test.hook
			h.manager.Update(config)
			client, done := h.startClient(t)
			response := sendM2Request(t, client, bufio.NewReader(client), "GET /hook HTTP/1.1\r\nHost: localhost\r\n\r\n", http.MethodGet)
			require.Equal(t, http.StatusBadGateway, response.StatusCode)
			require.Empty(t, response.Header.Get("X-Injected"))
			_ = readM2ResponseBody(t, response)
			finishM2Dispatch(t, client, done)
		})
	}
}

func TestM23ConcurrentResponseRequestsDoNotShareResults(t *testing.T) {
	const count = 8
	rules := make([]rewrite.Rule, 0, count)
	for i := 0; i < count; i++ {
		path := fmt.Sprintf("/parallel/%d", i)
		rules = append(rules, rewrite.Rule{Name: fmt.Sprintf("response-%d", i), Match: rewrite.Match{Path: path}, Response: &rewrite.ResponseAction{Status: http.StatusAccepted, Headers: rewrite.HeaderAction{Set: map[string]string{"X-Path": path}}, Body: &rewrite.BodyReplacement{Replace: fmt.Sprintf("body-%d", i)}}})
	}
	h := newM2HTTPHarness(t, "localhost", compileM2Rules(t, rules...), nil)
	clients := make([]*tls.Conn, count)
	dones := make([]<-chan dispatchResult, count)
	for i := range clients {
		clients[i], dones[i] = h.startClient(t)
	}
	type result struct {
		status int
		path   string
		body   string
		err    error
	}
	results := make([]result, count)
	var group sync.WaitGroup
	for i := range clients {
		group.Add(1)
		go func(i int) {
			defer group.Done()
			path := fmt.Sprintf("/parallel/%d", i)
			_, err := io.WriteString(clients[i], "GET "+path+" HTTP/1.1\r\nHost: localhost\r\n\r\n")
			if err != nil {
				results[i].err = err
				return
			}
			response, err := http.ReadResponse(bufio.NewReader(clients[i]), &http.Request{Method: http.MethodGet})
			if err != nil {
				results[i].err = err
				return
			}
			body, err := io.ReadAll(response.Body)
			_ = response.Body.Close()
			results[i] = result{status: response.StatusCode, path: response.Header.Get("X-Path"), body: string(body), err: err}
		}(i)
	}
	group.Wait()
	for i, got := range results {
		require.NoError(t, got.err)
		require.Equal(t, http.StatusAccepted, got.status)
		require.Equal(t, fmt.Sprintf("/parallel/%d", i), got.path)
		require.Equal(t, fmt.Sprintf("body-%d", i), got.body)
		_ = clients[i].Close()
		select {
		case result := <-dones[i]:
			require.Equal(t, DispatchIntercepted, result.outcome)
			require.NoError(t, result.err)
		case <-time.After(5 * time.Second):
			t.Fatal("parallel MITM connection did not close")
		}
	}
}

func TestM23ResponseHeaderRewriteRejectsManagedFramingFields(t *testing.T) {
	for _, name := range []string{"Content-Length", "Transfer-Encoding", "Trailer", "Connection"} {
		_, err := rewrite.Compile(rewrite.Config{Enable: true, Rules: []rewrite.Rule{{Name: "bad", Response: &rewrite.ResponseAction{Headers: rewrite.HeaderAction{Set: map[string]string{name: "unsafe"}}}}}})
		require.Error(t, err, name)
	}
}

func TestM23LegacyHookLengthConflictAndReplacement(t *testing.T) {
	for _, replace := range []bool{false, true} {
		t.Run(fmt.Sprint("replace=", replace), func(t *testing.T) {
			var pipeline *rewrite.Snapshot
			if replace {
				pipeline = compileM2Rules(t, rewrite.Rule{Name: "replace", Response: &rewrite.ResponseAction{Body: &rewrite.BodyReplacement{Replace: "static"}}})
			}
			h := newM2HTTPHarness(t, "localhost", pipeline, func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "original") })
			config := h.manager.ConfigSnapshot()
			config.ResponseHook = func(response *http.Response) error { response.Header.Set("Content-Length", "999"); return nil }
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

func TestM23IncompleteTrailersAbortStream(t *testing.T) {
	h := newM2HTTPHarness(t, "localhost", nil, func(w http.ResponseWriter, r *http.Request) {
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = rw.WriteString("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-End\r\n\r\n5\r\nfirst\r\n0\r\nX-End: unfinished")
		_ = rw.Flush()
	})
	client, done := h.startClient(t)
	_, err := io.WriteString(client, "GET / HTTP/1.1\r\nHost: localhost\r\nTE: trailers\r\n\r\n")
	require.NoError(t, err)
	response, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: "GET"})
	if err == nil {
		_, bodyErr := io.ReadAll(response.Body)
		require.Error(t, bodyErr)
		require.Empty(t, response.Trailer.Get("X-End"))
		_ = response.Body.Close()
	}
	finishM2Dispatch(t, client, done)
}

func TestM23CloseNominatedTrailersAreNotForwarded(t *testing.T) {
	h := newM2HTTPHarness(t, "localhost", nil, func(w http.ResponseWriter, r *http.Request) {
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = rw.WriteString("HTTP/1.1 200 OK\r\nConnection: close, X-Hop\r\nTransfer-Encoding: chunked\r\nTrailer: X-Hop, X-End\r\n\r\n4\r\nbody\r\n0\r\nX-Hop: forbidden\r\nX-End: ordinary\r\n\r\n")
		_ = rw.Flush()
	})
	client, done := h.startClient(t)
	response := sendM2Request(t, client, bufio.NewReader(client), "GET / HTTP/1.1\r\nHost: localhost\r\nTE: trailers\r\n\r\n", "GET")
	require.Equal(t, "body", readM2ResponseBody(t, response))
	require.Empty(t, response.Trailer, "Go Transport discards close Connection nominations; omit unverifiable trailers")
	finishM2Dispatch(t, client, done)
}
