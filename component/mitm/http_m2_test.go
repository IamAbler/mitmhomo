package mitm

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/mitm/rewrite"
	C "github.com/metacubex/mihomo/constant"
	"github.com/stretchr/testify/require"
)

type m2RequestObservation struct {
	method           string
	urlPath          string
	host             string
	contentLength    int64
	transferEncoding []string
	trailer          http.Header
	header           http.Header
	body             string
}

type m2HTTPHarness struct {
	manager      *Manager
	clientRoots  *x509.CertPool
	upstream     *httptest.Server
	upstreamAddr string
	observations chan m2RequestObservation
	upstreamSNI  chan string
	clientSNI    chan string
	metadata     chan *C.Metadata
	dialCount    atomic.Int32
	serverName   string
}

type m2TrackedBody struct {
	reads  atomic.Int32
	closed atomic.Int32
}

func (body *m2TrackedBody) Read([]byte) (int, error) { body.reads.Add(1); return 0, io.EOF }
func (body *m2TrackedBody) Close() error             { body.closed.Add(1); return nil }

func newM2HTTPHarness(t *testing.T, serverName string, pipeline *rewrite.Snapshot, handler http.HandlerFunc) *m2HTTPHarness {
	return newM2HTTPHarnessForUpstream(t, serverName, "localhost", pipeline, handler)
}

func newM2HTTPHarnessForUpstream(t *testing.T, serverName, upstreamName string, pipeline *rewrite.Snapshot, handler http.HandlerFunc) *m2HTTPHarness {
	t.Helper()
	upstreamCertificate, upstreamRoots := makeTestUpstreamCertificateFor(t, upstreamName)
	observations := make(chan m2RequestObservation, 32)
	upstreamSNI := make(chan string, 32)
	if handler == nil {
		handler = func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "read body", http.StatusInternalServerError)
				return
			}
			observations <- m2RequestObservation{
				method:           r.Method,
				urlPath:          r.URL.RequestURI(),
				host:             r.Host,
				contentLength:    r.ContentLength,
				transferEncoding: append([]string(nil), r.TransferEncoding...),
				trailer:          r.Trailer.Clone(),
				header:           r.Header.Clone(),
				body:             string(body),
			}
			_, _ = io.WriteString(w, "upstream-ok")
		}
	}
	upstream := httptest.NewUnstartedServer(handler)
	upstream.TLS = &tls.Config{
		Certificates: []tls.Certificate{upstreamCertificate},
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			upstreamSNI <- hello.ServerName
			return nil, nil
		},
	}
	upstream.StartTLS()
	t.Cleanup(upstream.Close)
	ca, clientRoots := makeTestAuthority(t)
	manager := NewManager(Config{
		Enabled:           true,
		Ports:             []uint16{443},
		Domains:           []string{serverName},
		CA:                ca,
		HandshakeTimeout:  3 * time.Second,
		ReadHeaderTimeout: 3 * time.Second,
		RequestTimeout:    3 * time.Second,
		IdleTimeout:       3 * time.Second,
		Rewrite:           pipeline,
		upstreamRootCAs:   upstreamRoots,
	})
	h := &m2HTTPHarness{
		manager:      manager,
		clientRoots:  clientRoots,
		upstream:     upstream,
		upstreamAddr: upstream.Listener.Addr().String(),
		observations: observations,
		upstreamSNI:  upstreamSNI,
		clientSNI:    make(chan string, 32),
		metadata:     make(chan *C.Metadata, 32),
		serverName:   serverName,
	}
	return h
}

func (h *m2HTTPHarness) startClient(t *testing.T) (*tls.Conn, <-chan dispatchResult) {
	t.Helper()
	serverRaw, clientRaw := net.Pipe()
	done := make(chan dispatchResult, 1)
	go func() {
		outcome, err := h.manager.Dispatch(context.Background(), N.NewBufferedConn(serverRaw), &C.Metadata{
			NetWork: C.TCP,
			Type:    C.TUNNEL,
			Host:    h.serverName,
			DstPort: 443,
		}, nil, h.dial)
		done <- dispatchResult{outcome: outcome, err: err}
	}()
	client := tls.Client(clientRaw, &tls.Config{
		RootCAs:    h.clientRoots,
		ServerName: h.serverName,
		NextProtos: []string{"http/1.1"},
	})
	_ = client.SetDeadline(time.Now().Add(10 * time.Second))
	if err := client.Handshake(); err != nil {
		_ = client.Close()
		_ = serverRaw.Close()
		t.Fatalf("M2 client TLS handshake: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client, done
}

func (h *m2HTTPHarness) startTCPClient(t *testing.T) (*tls.Conn, <-chan dispatchResult) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	done := make(chan dispatchResult, 1)
	go func() {
		serverRaw, err := listener.Accept()
		if err != nil {
			done <- dispatchResult{outcome: DispatchFailed, err: err}
			return
		}
		outcome, err := h.manager.Dispatch(context.Background(), N.NewBufferedConn(serverRaw), &C.Metadata{
			NetWork: C.TCP,
			Type:    C.TUNNEL,
			Host:    h.serverName,
			DstPort: 443,
		}, nil, h.dial)
		done <- dispatchResult{outcome: outcome, err: err}
	}()
	clientRaw, err := net.DialTimeout("tcp", listener.Addr().String(), 3*time.Second)
	require.NoError(t, err)
	client := tls.Client(clientRaw, &tls.Config{
		RootCAs:    h.clientRoots,
		ServerName: h.serverName,
		NextProtos: []string{"http/1.1"},
	})
	_ = client.SetDeadline(time.Now().Add(10 * time.Second))
	if err := client.Handshake(); err != nil {
		_ = client.Close()
		t.Fatalf("M2 TCP client TLS handshake: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client, done
}

func (h *m2HTTPHarness) dial(ctx context.Context, metadata *C.Metadata, handshake NativeTLSHandshake) (net.Conn, error) {
	h.dialCount.Add(1)
	h.metadata <- metadata.Clone()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", h.upstreamAddr)
	if err != nil {
		return nil, err
	}
	secure, err := handshake(ctx, conn)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if tlsConn, ok := secure.(*tls.Conn); ok {
		h.clientSNI <- tlsConn.ConnectionState().ServerName
	}
	return secure, nil
}

func compileM2Rules(t *testing.T, rules ...rewrite.Rule) *rewrite.Snapshot {
	t.Helper()
	snapshot, err := rewrite.Compile(rewrite.Config{Enable: true, Rules: rules})
	require.NoError(t, err)
	return snapshot
}

func sendM2Request(t *testing.T, client *tls.Conn, reader *bufio.Reader, request string, method string) *http.Response {
	t.Helper()
	_, err := io.WriteString(client, request)
	require.NoError(t, err)
	response, err := http.ReadResponse(reader, &http.Request{Method: method})
	require.NoError(t, err)
	return response
}

func readM2ResponseBody(t *testing.T, response *http.Response) string {
	t.Helper()
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())
	return string(body)
}

func finishM2Dispatch(t *testing.T, client *tls.Conn, done <-chan dispatchResult) {
	t.Helper()
	_ = client.Close()
	select {
	case result := <-done:
		require.Equal(t, DispatchIntercepted, result.outcome)
		require.NoError(t, result.err)
	case <-time.After(5 * time.Second):
		t.Fatal("M2 HTTP connection did not stop after client close")
	}
}

func TestM2RequestRewriteCrossDomainMethodHeadersAndChunkedBody(t *testing.T) {
	pipeline := compileM2Rules(t, rewrite.Rule{
		Name:  "rewrite-request",
		Match: rewrite.Match{Path: "/original", Methods: []string{http.MethodPost}},
		Request: &rewrite.RequestAction{
			URL:     "https://rewrite.example/rewritten?from=m2",
			Method:  http.MethodPatch,
			Headers: rewrite.HeaderAction{Set: map[string]string{"X-Rewritten": "yes"}, Remove: []string{"X-Remove"}},
			Body:    &rewrite.BodyReplacement{Replace: "replacement-body", ContentType: "application/json"},
		},
	})
	h := newM2HTTPHarnessForUpstream(t, "origin.example", "rewrite.example", pipeline, nil)
	client, done := h.startClient(t)
	reader := bufio.NewReader(client)
	request := "POST /original HTTP/1.1\r\n" +
		"Host: origin.example\r\n" +
		"Content-Type: application/old\r\n" +
		"Content-Encoding: gzip\r\n" +
		"Content-MD5: old-digest\r\n" +
		"X-Remove: old\r\n" +
		"Transfer-Encoding: chunked\r\n" +
		"Trailer: X-Client-Trailer\r\n\r\n" +
		"7\r\npayload\r\n0\r\nX-Client-Trailer: stale\r\n\r\n"
	response := sendM2Request(t, client, reader, request, http.MethodPost)
	require.Equal(t, http.StatusOK, response.StatusCode)
	require.Equal(t, "upstream-ok", readM2ResponseBody(t, response))
	select {
	case observed := <-h.observations:
		require.Equal(t, http.MethodPatch, observed.method)
		require.Equal(t, "/rewritten?from=m2", observed.urlPath)
		require.Equal(t, "rewrite.example:443", observed.host)
		select {
		case sni := <-h.upstreamSNI:
			require.Equal(t, "rewrite.example", sni, "the URL authority determines verified upstream SNI")
		case <-time.After(time.Second):
			t.Fatal("upstream TLS ClientHello was not observed")
		}
		require.Equal(t, "rewrite.example", <-h.clientSNI)
		require.Equal(t, "replacement-body", observed.body)
		require.EqualValues(t, len("replacement-body"), observed.contentLength)
		require.Empty(t, observed.transferEncoding)
		require.Empty(t, observed.trailer)
		require.Equal(t, "yes", observed.header.Get("X-Rewritten"))
		require.Empty(t, observed.header.Get("X-Remove"))
		require.Equal(t, "application/json", observed.header.Get("Content-Type"))
		require.Empty(t, observed.header.Get("Content-Encoding"))
		require.Empty(t, observed.header.Get("Content-MD5"))
	case <-time.After(3 * time.Second):
		t.Fatal("rewritten request did not reach the TLS upstream")
	}
	select {
	case metadata := <-h.metadata:
		require.Equal(t, "rewrite.example", metadata.Host)
		require.Equal(t, uint16(443), metadata.DstPort)
		require.Equal(t, C.DNSNormal, metadata.DNSMode)
	case <-time.After(time.Second):
		t.Fatal("rewritten target Metadata was not used for native dialing")
	}
	require.EqualValues(t, 1, h.dialCount.Load())
	finishM2Dispatch(t, client, done)
}

func TestM2TerminalRedirectAndLocalResponseNeverDial(t *testing.T) {
	tests := []struct {
		name       string
		terminal   rewrite.Rule
		method     string
		wantStatus int
		wantBody   string
		wantLength string
		wantLoc    string
		prior      bool
	}{
		{
			name: "redirect stops later rules",
			terminal: rewrite.Rule{
				Name: "redirect", Match: rewrite.Match{Methods: []string{http.MethodPut}, Headers: map[string]string{"X-Step": "ready"}},
				Redirect: &rewrite.Redirect{Status: http.StatusTemporaryRedirect, Location: "/local-target"},
			},
			method: http.MethodPost, wantStatus: http.StatusTemporaryRedirect, wantLoc: "/local-target",
			prior: true,
		},
		{
			name: "HEAD local response preserves representation length",
			terminal: rewrite.Rule{
				Name: "head-local", Match: rewrite.Match{Methods: []string{http.MethodHead}},
				LocalResponse: &rewrite.LocalResponse{Status: http.StatusOK, Body: "local-body", Headers: map[string]string{"X-Local": "yes"}},
			},
			method: http.MethodHead, wantStatus: http.StatusOK, wantLength: fmt.Sprint(len("local-body")),
		},
		{
			name: "bodyless local response",
			terminal: rewrite.Rule{
				Name: "no-content", Match: rewrite.Match{Methods: []string{http.MethodGet}},
				LocalResponse: &rewrite.LocalResponse{Status: http.StatusNoContent, Headers: map[string]string{"X-Local": "empty"}},
			},
			method: http.MethodGet, wantStatus: http.StatusNoContent,
		},
		{
			name: "205 local response uses zero length",
			terminal: rewrite.Rule{
				Name: "reset-content", Match: rewrite.Match{Methods: []string{http.MethodGet}},
				LocalResponse: &rewrite.LocalResponse{Status: http.StatusResetContent},
			},
			method: http.MethodGet, wantStatus: http.StatusResetContent, wantLength: "0",
		},
		{
			name: "304 preserves cache representation headers without a body",
			terminal: rewrite.Rule{
				Name: "not-modified", Match: rewrite.Match{Methods: []string{http.MethodGet}},
				LocalResponse: &rewrite.LocalResponse{Status: http.StatusNotModified, Headers: map[string]string{
					"Cache-Control": "max-age=60", "Content-Location": "/cached", "Content-Type": "application/json", "ETag": `"local-v1"`,
				}},
			},
			method: http.MethodGet, wantStatus: http.StatusNotModified,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			first := rewrite.Rule{
				Name:    "before-terminal",
				Match:   rewrite.Match{Path: "/terminal"},
				Request: &rewrite.RequestAction{Method: http.MethodPut, Headers: rewrite.HeaderAction{Set: map[string]string{"X-Step": "ready"}}, Body: &rewrite.BodyReplacement{Replace: "must-be-discarded"}},
			}
			later := rewrite.Rule{Name: "after-terminal", Match: rewrite.Match{}, LocalResponse: &rewrite.LocalResponse{Status: http.StatusInternalServerError, Body: "wrong"}}
			rules := []rewrite.Rule{test.terminal, later}
			if test.prior {
				rules = append([]rewrite.Rule{first}, rules...)
			}
			pipeline := compileM2Rules(t, rules...)
			h := newM2HTTPHarness(t, "localhost", pipeline, nil)
			client, done := h.startTCPClient(t)
			reader := bufio.NewReader(client)
			path := "/terminal"
			if test.name == "bodyless local response" {
				path = "/bodyless"
			}
			request := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n\r\ndata", test.method, path)
			response := sendM2Request(t, client, reader, request, test.method)
			require.Equal(t, test.wantStatus, response.StatusCode)
			if test.wantLoc != "" {
				require.Equal(t, test.wantLoc, response.Header.Get("Location"))
				require.Empty(t, readM2ResponseBody(t, response))
			} else {
				require.Equal(t, test.wantLength, response.Header.Get("Content-Length"))
				if test.wantStatus == http.StatusOK {
					require.Equal(t, "yes", response.Header.Get("X-Local"))
				}
				if test.wantStatus == http.StatusNoContent {
					require.Empty(t, response.Header.Get("Content-Length"))
					require.Equal(t, "empty", response.Header.Get("X-Local"))
				}
				if test.wantStatus == http.StatusNotModified {
					require.Equal(t, "max-age=60", response.Header.Get("Cache-Control"))
					require.Equal(t, "/cached", response.Header.Get("Content-Location"))
					require.Equal(t, `"local-v1"`, response.Header.Get("ETag"))
					require.Empty(t, response.Header.Get("Content-Length"))
				}
				require.Empty(t, readM2ResponseBody(t, response))
			}
			require.Zero(t, h.dialCount.Load(), "terminal handling must not enter ReverseProxy or Native Outbound")
			select {
			case observed := <-h.observations:
				t.Fatalf("terminal request reached upstream: %+v", observed)
			default:
			}
			finishM2Dispatch(t, client, done)
		})
	}
}

func TestM2KeepAliveRequestIsolationAndConnectionSnapshotReload(t *testing.T) {
	oldPipeline := compileM2Rules(t,
		rewrite.Rule{Name: "replace-only", Match: rewrite.Match{Path: "/replace"}, Request: &rewrite.RequestAction{Headers: rewrite.HeaderAction{Set: map[string]string{"X-Version": "old"}}, Body: &rewrite.BodyReplacement{Replace: "replacement"}}},
		rewrite.Rule{Name: "version-old", Match: rewrite.Match{Path: "/version"}, Request: &rewrite.RequestAction{Headers: rewrite.HeaderAction{Set: map[string]string{"X-Version": "old"}}}},
	)
	newPipeline := compileM2Rules(t, rewrite.Rule{
		Name: "version-new", Match: rewrite.Match{Path: "/version"},
		Request: &rewrite.RequestAction{Headers: rewrite.HeaderAction{Set: map[string]string{"X-Version": "new"}}},
	})
	h := newM2HTTPHarness(t, "localhost", oldPipeline, nil)
	client, oldDone := h.startTCPClient(t)
	reader := bufio.NewReader(client)

	first := sendM2Request(t, client, reader, "POST /replace HTTP/1.1\r\nHost: localhost\r\nContent-Length: 3\r\n\r\nold", http.MethodPost)
	require.Equal(t, "upstream-ok", readM2ResponseBody(t, first))
	require.NotEqual(t, "close", strings.ToLower(first.Header.Get("Connection")), "a small known-length discarded body may keep the connection reusable")
	firstObserved := <-h.observations
	require.Equal(t, "old", firstObserved.header.Get("X-Version"))
	require.Equal(t, "replacement", firstObserved.body)

	config := h.manager.ConfigSnapshot()
	config.Rewrite = newPipeline
	h.manager.Update(config)

	second := sendM2Request(t, client, reader, "POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n\r\nbody", http.MethodPost)
	require.Equal(t, "upstream-ok", readM2ResponseBody(t, second))
	secondObserved := <-h.observations
	require.Empty(t, secondObserved.header.Get("X-Version"), "the previous request's header patch must not leak")
	require.Equal(t, "body", secondObserved.body, "the previous request's body reader must not leak")

	third := sendM2Request(t, client, reader, "GET /version HTTP/1.1\r\nHost: localhost\r\n\r\n", http.MethodGet)
	require.Equal(t, "upstream-ok", readM2ResponseBody(t, third))
	require.Equal(t, "old", (<-h.observations).header.Get("X-Version"), "an existing TLS connection keeps the old Rewrite snapshot")
	finishM2Dispatch(t, client, oldDone)

	newClient, newDone := h.startTCPClient(t)
	newResponse := sendM2Request(t, newClient, bufio.NewReader(newClient), "GET /version HTTP/1.1\r\nHost: localhost\r\n\r\n", http.MethodGet)
	require.Equal(t, "upstream-ok", readM2ResponseBody(t, newResponse))
	require.Equal(t, "new", (<-h.observations).header.Get("X-Version"), "a new TLS connection observes the published Rewrite snapshot")
	finishM2Dispatch(t, newClient, newDone)
}

func TestM2RequestReplacementClosesWithoutReadingOldBody(t *testing.T) {
	oldBody := &m2TrackedBody{}
	body := &http.Request{Body: oldBody, Header: http.Header{
		"Content-Type":      {"application/old"},
		"Content-Encoding":  {"gzip"},
		"Content-Md5":       {"old"},
		"Trailer":           {"X-Old"},
		"Transfer-Encoding": {"chunked"},
	}}
	body.ContentLength = -1
	body.TransferEncoding = []string{"chunked"}
	body.Trailer = http.Header{"X-Old": {"stale"}}
	result := rewrite.RequestResult{
		Request: rewrite.RequestView{Method: http.MethodPut, URL: rewriteURL("https://localhost/replaced"), Headers: rewrite.HeaderMap(body.Header)},
		Body:    &rewrite.BodyReplacement{Replace: "new", ContentType: "application/json"},
	}
	require.NoError(t, applyRequestResult(body, result))
	require.EqualValues(t, 0, oldBody.reads.Load())
	require.EqualValues(t, 0, oldBody.closed.Load(), "the HTTP server remains the owner of the inbound request body")
	require.EqualValues(t, 3, body.ContentLength)
	require.Empty(t, body.TransferEncoding)
	require.Nil(t, body.Trailer)
	require.Empty(t, body.Header.Get("Transfer-Encoding"))
	require.Empty(t, body.Header.Get("Trailer"))
	require.Empty(t, body.Header.Get("Content-Encoding"))
	require.Empty(t, body.Header.Get("Content-MD5"))
	require.Equal(t, "application/json", body.Header.Get("Content-Type"))
	reader, err := body.GetBody()
	require.NoError(t, err)
	data, err := io.ReadAll(reader)
	require.NoError(t, err)
	require.NoError(t, reader.Close())
	require.Equal(t, "new", string(data))
	secondReader, err := body.GetBody()
	require.NoError(t, err)
	secondData, err := io.ReadAll(secondReader)
	require.NoError(t, err)
	require.NoError(t, secondReader.Close())
	require.Equal(t, "new", string(secondData))
	require.NoError(t, oldBody.Close(), "simulate the server's single body cleanup")
	require.EqualValues(t, 1, oldBody.closed.Load(), "the adapter must not double-close the discarded reader")
}

func TestM2TerminalAdapterStripsFramingAndHopByHopHeaders(t *testing.T) {
	response := httptest.NewRecorder()
	request, err := http.NewRequest(http.MethodGet, "https://localhost/terminal", nil)
	require.NoError(t, err)
	writeTerminalResponse(response, request, &rewrite.TerminalResponse{
		Decision:   rewrite.LocalResponseDecision,
		StatusCode: http.StatusOK,
		Body:       "local-body",
		Headers: rewrite.HeaderMap{
			"Content-Length":    {"999"},
			"Transfer-Encoding": {"chunked"},
			"Trailer":           {"X-Trailer"},
			"Connection":        {"X-Hop"},
			"X-Hop":             {"must-be-removed"},
			"Content-Type":      {"application/json"},
			"Cache-Control":     {"max-age=30"},
			"ETag":              {`"v1"`},
		},
	}, false)

	result := response.Result()
	require.Equal(t, http.StatusOK, result.StatusCode)
	require.Equal(t, "10", result.Header.Get("Content-Length"))
	require.Empty(t, result.Header.Get("Transfer-Encoding"))
	require.Empty(t, result.Header.Get("Trailer"))
	require.Empty(t, result.Header.Get("Connection"))
	require.Empty(t, result.Header.Get("X-Hop"))
	require.Equal(t, "application/json", result.Header.Get("Content-Type"))
	require.Equal(t, "max-age=30", result.Header.Get("Cache-Control"))
	require.Equal(t, `"v1"`, result.Header.Get("ETag"))
	require.Equal(t, "local-body", response.Body.String())
}

func TestM2TerminalAdapterRejectsInvalidOutput(t *testing.T) {
	tests := []struct {
		name     string
		decision rewrite.Decision
		headers  rewrite.HeaderMap
	}{
		{name: "redirect header injection", decision: rewrite.RedirectResponse, headers: rewrite.HeaderMap{"Location": {"/ok\r\nX-Injected: yes"}}},
		{name: "invalid absolute redirect authority", decision: rewrite.RedirectResponse, headers: rewrite.HeaderMap{"Location": {"https://example.test:bad/path"}}},
		{name: "invalid header name", decision: rewrite.LocalResponseDecision, headers: rewrite.HeaderMap{"X-Bad\r\nX-Injected": {"yes"}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			request, err := http.NewRequest(http.MethodGet, "https://localhost/terminal", nil)
			require.NoError(t, err)
			response.Header().Set("X-Stale", "must-not-survive")
			writeTerminalResponse(response, request, &rewrite.TerminalResponse{
				Decision: test.decision, StatusCode: http.StatusFound, Body: "bad", Headers: test.headers,
			}, false)
			require.Equal(t, http.StatusInternalServerError, response.Code)
			require.Empty(t, response.Header().Get("Location"))
			require.Empty(t, response.Header().Get("X-Injected"))
			require.Empty(t, response.Header().Get("X-Stale"))
		})
	}
}

func TestM2LargeBodyReplacementClosesConnectionAfterResponse(t *testing.T) {
	pipeline := compileM2Rules(t, rewrite.Rule{
		Name: "large-body", Match: rewrite.Match{Path: "/replace"},
		Request: &rewrite.RequestAction{Body: &rewrite.BodyReplacement{Replace: "upstream-body"}},
	})
	// The rewritten upstream request can proceed while the original client
	// upload is being discarded. Hold the response so it cannot close the
	// client socket while the test sends the required discard-limit prefix.
	responseGate := make(chan struct{})
	var releaseGateOnce sync.Once
	releaseGate := func() { releaseGateOnce.Do(func() { close(responseGate) }) }
	observedBody := make(chan string, 1)
	h := newM2HTTPHarness(t, "localhost", pipeline, func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read replacement body", http.StatusInternalServerError)
			return
		}
		observedBody <- string(body)
		timer := time.NewTimer(5 * time.Second)
		defer timer.Stop()
		select {
		case <-responseGate:
		case <-timer.C:
			http.Error(w, "response gate timed out", http.StatusGatewayTimeout)
			return
		case <-r.Context().Done():
			return
		}
		_, _ = io.WriteString(w, "upstream-ok")
	})
	t.Cleanup(releaseGate)
	client, done := h.startTCPClient(t)
	reader := bufio.NewReader(client)
	original := strings.Repeat("x", 128<<10)
	header := fmt.Sprintf("POST /replace HTTP/1.1\r\nHost: localhost\r\nContent-Length: %d\r\n\r\n", len(original))
	written, err := io.WriteString(client, header)
	require.NoError(t, err, "the request headers must reach the MITM server")
	require.Equal(t, len(header), written)
	const discardLimit = (64 << 10) + 1
	bodyPrefix := original[:discardLimit+1]
	written, err = io.WriteString(client, bodyPrefix)
	require.NoError(t, err, "the client must send beyond the bounded discard limit before the response is released")
	require.Equal(t, len(bodyPrefix), written)
	var upstreamBody string
	select {
	case body := <-observedBody:
		upstreamBody = body
	case <-time.After(3 * time.Second):
		t.Fatal("the upstream did not receive the replacement request while its response was gated")
	}
	t.Logf("M2_DIAG declared_body_bytes=%d sent_body_prefix_bytes=%d discard_limit_bytes=%d upstream_body=%q", len(original), len(bodyPrefix), discardLimit, upstreamBody)
	require.Equal(t, "upstream-body", upstreamBody, "the upstream must receive the replacement body")
	releaseGate()
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodPost})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.StatusCode)
	// net/http folds the wire Connection: close header into Response.Close.
	require.True(t, response.Close, "the HTTP/1 response must signal Connection: close for the large discarded request body")
	require.Equal(t, "upstream-ok", readM2ResponseBody(t, response))
	requireM2ConnectionIsClosed(t, client, reader)
	finishM2Dispatch(t, client, done)
}

func TestM2ChunkedReplacementClosesWithoutReusingUnreadFraming(t *testing.T) {
	pipeline := compileM2Rules(t, rewrite.Rule{
		Name: "chunked-body", Match: rewrite.Match{Path: "/replace"},
		Request: &rewrite.RequestAction{Body: &rewrite.BodyReplacement{Replace: "chunked-replacement"}},
	})
	h := newM2HTTPHarness(t, "localhost", pipeline, nil)
	client, done := h.startTCPClient(t)
	reader := bufio.NewReader(client)
	request := "POST /replace HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nTrailer: X-Upload-End\r\n\r\n" +
		"5\r\nhello\r\n0\r\nX-Upload-End: yes\r\n\r\n"
	response := sendM2Request(t, client, reader, request, http.MethodPost)
	require.Equal(t, http.StatusOK, response.StatusCode)
	require.True(t, response.Close, "chunked discarded request bodies must close the client connection")
	require.Equal(t, "upstream-ok", readM2ResponseBody(t, response))
	observed := <-h.observations
	require.Equal(t, "chunked-replacement", observed.body)
	require.Empty(t, observed.transferEncoding)
	require.Empty(t, observed.trailer)
	requireM2ConnectionIsClosed(t, client, reader)
	finishM2Dispatch(t, client, done)
}

func TestM2IncompleteUploadReplacementDoesNotWaitForBodyCompletion(t *testing.T) {
	pipeline := compileM2Rules(t, rewrite.Rule{
		Name: "incomplete-body", Match: rewrite.Match{Path: "/replace"},
		Request: &rewrite.RequestAction{Body: &rewrite.BodyReplacement{Replace: "complete-upstream-body"}},
	})
	h := newM2HTTPHarness(t, "localhost", pipeline, nil)
	client, done := h.startTCPClient(t)
	reader := bufio.NewReader(client)
	_, err := io.WriteString(client, "POST /replace HTTP/1.1\r\nHost: localhost\r\nContent-Length: 131072\r\n\r\npartial")
	require.NoError(t, err)
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodPost})
	require.NoError(t, err, "the replacement response must not wait for the declared upload to finish")
	require.Equal(t, http.StatusOK, response.StatusCode)
	require.True(t, response.Close, "an incomplete discarded upload must close the client connection")
	require.Equal(t, "upstream-ok", readM2ResponseBody(t, response))
	require.Equal(t, "complete-upstream-body", (<-h.observations).body)
	finishM2Dispatch(t, client, done)
}

func TestM2ExpectContinueReplacementDoesNotRequestDiscardedBody(t *testing.T) {
	pipeline := compileM2Rules(t, rewrite.Rule{
		Name: "expect-continue", Match: rewrite.Match{Path: "/replace"},
		Request: &rewrite.RequestAction{Body: &rewrite.BodyReplacement{Replace: "replacement"}},
	})
	h := newM2HTTPHarness(t, "localhost", pipeline, nil)
	client, done := h.startTCPClient(t)
	reader := bufio.NewReader(client)
	_, err := io.WriteString(client, "POST /replace HTTP/1.1\r\nHost: localhost\r\nContent-Length: 8\r\nExpect: 100-continue\r\n\r\n")
	require.NoError(t, err)
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodPost})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.StatusCode, "the adapter must not send 100 Continue just to discard the original body")
	require.True(t, response.Close)
	require.Equal(t, "upstream-ok", readM2ResponseBody(t, response))
	require.Equal(t, "replacement", (<-h.observations).body)
	requireM2ConnectionIsClosed(t, client, reader)
	finishM2Dispatch(t, client, done)
}

func TestM2IncompleteTerminalUploadDoesNotWaitForBodyCompletion(t *testing.T) {
	pipeline := compileM2Rules(t, rewrite.Rule{
		Name: "terminal-partial-upload", Match: rewrite.Match{Path: "/terminal"},
		LocalResponse: &rewrite.LocalResponse{Status: http.StatusOK, Body: "terminal-response"},
	})
	h := newM2HTTPHarness(t, "localhost", pipeline, nil)
	client, done := h.startTCPClient(t)
	reader := bufio.NewReader(client)
	_, err := io.WriteString(client, "POST /terminal HTTP/1.1\r\nHost: localhost\r\nContent-Length: 131072\r\n\r\npartial")
	require.NoError(t, err)
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodPost})
	require.NoError(t, err, "terminal response must not wait for an incomplete upload")
	require.Equal(t, http.StatusOK, response.StatusCode)
	require.True(t, response.Close, "a terminal response must close when the discarded upload cannot be drained")
	require.Equal(t, "terminal-response", readM2ResponseBody(t, response))
	require.Zero(t, h.dialCount.Load(), "terminal response must not dial upstream")
	requireM2ConnectionIsClosed(t, client, reader)
	finishM2Dispatch(t, client, done)
}

func requireM2ConnectionIsClosed(t *testing.T, client *tls.Conn, reader *bufio.Reader) {
	t.Helper()
	_, writeErr := io.WriteString(client, "GET /after-close HTTP/1.1\r\nHost: localhost\r\n\r\n")
	if writeErr != nil {
		return
	}
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	_, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	require.Error(t, err, "a request following an intentionally closed connection must not receive a response")
}

func rewriteURL(raw string) (result url.URL) {
	parsed, _ := url.Parse(raw)
	return *parsed
}

func TestM2RewriteSnapshotConcurrentConnections(t *testing.T) {
	pipeline := compileM2Rules(t, rewrite.Rule{
		Name: "concurrent", Match: rewrite.Match{Path: "/concurrent"},
		Request: &rewrite.RequestAction{Headers: rewrite.HeaderAction{Set: map[string]string{"X-Snapshot": "shared"}}},
	})
	h := newM2HTTPHarness(t, "localhost", pipeline, nil)
	const clients = 8
	var accepted atomic.Int32
	var workers atomic.Int32
	done := make(chan struct{}, clients)
	for i := 0; i < clients; i++ {
		go func() {
			client, dispatchDone := h.startClient(t)
			response := sendM2Request(t, client, bufio.NewReader(client), "GET /concurrent HTTP/1.1\r\nHost: localhost\r\n\r\n", http.MethodGet)
			if response.StatusCode == http.StatusOK && readM2ResponseBody(t, response) == "upstream-ok" {
				accepted.Add(1)
			}
			finishM2Dispatch(t, client, dispatchDone)
			workers.Add(1)
			done <- struct{}{}
		}()
	}
	for i := 0; i < clients; i++ {
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("concurrent Rewrite requests did not finish")
		}
		observed := <-h.observations
		require.Equal(t, "shared", observed.header.Get("X-Snapshot"))
	}
	require.EqualValues(t, clients, accepted.Load())
	require.EqualValues(t, clients, workers.Load())
}

func TestM2URLAuthorityChangeOverridesOriginalHost(t *testing.T) {
	pipeline := compileM2Rules(t, rewrite.Rule{
		Name: "move-origin", Match: rewrite.Match{Path: "/move"},
		Request: &rewrite.RequestAction{URL: "https://rewrite.example/final"},
	})
	h := newM2HTTPHarnessForUpstream(t, "origin.example", "rewrite.example", pipeline, nil)
	client, done := h.startClient(t)
	response := sendM2Request(t, client, bufio.NewReader(client), "GET /move HTTP/1.1\r\nHost: origin.example\r\n\r\n", http.MethodGet)
	require.Equal(t, http.StatusOK, response.StatusCode)
	_ = readM2ResponseBody(t, response)
	observed := <-h.observations
	require.Equal(t, "rewrite.example:443", observed.host)
	require.Equal(t, "rewrite.example", <-h.upstreamSNI)
	require.Equal(t, "rewrite.example", <-h.clientSNI)
	metadata := <-h.metadata
	require.Equal(t, "rewrite.example", metadata.Host)
	finishM2Dispatch(t, client, done)
}

func TestM2URLRewriteVerifiesCertificateAgainstRewrittenHost(t *testing.T) {
	pipeline := compileM2Rules(t, rewrite.Rule{
		Name: "move-origin", Match: rewrite.Match{Path: "/move"},
		Request: &rewrite.RequestAction{URL: "https://rewrite.example/"},
	})
	h := newM2HTTPHarnessForUpstream(t, "origin.example", "wrong-certificate.example", pipeline, nil)
	client, done := h.startClient(t)
	response := sendM2Request(t, client, bufio.NewReader(client), "GET /move HTTP/1.1\r\nHost: origin.example\r\n\r\n", http.MethodGet)
	require.Equal(t, http.StatusBadGateway, response.StatusCode)
	_ = readM2ResponseBody(t, response)
	require.EqualValues(t, 1, h.dialCount.Load())
	select {
	case observed := <-h.observations:
		t.Fatalf("certificate mismatch reached the upstream HTTP handler: %+v", observed)
	default:
	}
	finishM2Dispatch(t, client, done)
}

func TestM2MetadataForURLDropsStaleDNSAndFakeIPState(t *testing.T) {
	base := &C.Metadata{
		NetWork:    C.TCP,
		Type:       C.TUNNEL,
		Host:       "origin.example",
		DstIP:      netip.MustParseAddr("198.18.0.8"),
		DstPort:    443,
		DNSMode:    C.DNSFakeIP,
		RawDstAddr: &net.TCPAddr{IP: net.IPv4(198, 18, 0, 8), Port: 443},
		DstGeoIP:   []string{"old-region"},
		DstIPASN:   "old-asn",
	}
	domainTarget := &url.URL{Scheme: "https", Host: "new.example:8443", Path: "/"}
	domainMetadata, err := metadataForURL(base, domainTarget, "origin.example")
	require.NoError(t, err)
	require.Equal(t, "new.example", domainMetadata.Host)
	require.False(t, domainMetadata.DstIP.IsValid())
	require.Equal(t, uint16(8443), domainMetadata.DstPort)
	require.Equal(t, C.DNSNormal, domainMetadata.DNSMode)
	require.Nil(t, domainMetadata.RawDstAddr)
	require.Nil(t, domainMetadata.DstGeoIP)
	require.Empty(t, domainMetadata.DstIPASN)
	require.Equal(t, netip.MustParseAddr("198.18.0.8"), base.DstIP, "rewriting must not mutate the connection Metadata")

	ipTarget := &url.URL{Scheme: "https", Host: "192.0.2.45:9443", Path: "/"}
	ipMetadata, err := metadataForURL(base, ipTarget, "origin.example")
	require.NoError(t, err)
	require.Empty(t, ipMetadata.Host)
	require.Equal(t, netip.MustParseAddr("192.0.2.45"), ipMetadata.DstIP)
	require.Equal(t, uint16(9443), ipMetadata.DstPort)
	require.Equal(t, C.DNSNormal, ipMetadata.DNSMode)
	require.Nil(t, ipMetadata.RawDstAddr)
}

func TestM2RequestURLRejectsNonHTTPSAfterLegacyHook(t *testing.T) {
	h := newM2HTTPHarness(t, "localhost", nil, nil)
	config := h.manager.ConfigSnapshot()
	config.RequestHook = func(request *http.Request) error {
		request.URL.Scheme = "http"
		return nil
	}
	h.manager.Update(config)
	client, done := h.startClient(t)
	response := sendM2Request(t, client, bufio.NewReader(client), "GET /bad HTTP/1.1\r\nHost: localhost\r\n\r\n", http.MethodGet)
	require.Equal(t, http.StatusBadRequest, response.StatusCode)
	_ = readM2ResponseBody(t, response)
	require.Zero(t, h.dialCount.Load())
	finishM2Dispatch(t, client, done)
}

func TestM2RequestTimeoutAndAbnormalUpstreamDisconnect(t *testing.T) {
	t.Run("unfinished discarded upload returns gateway timeout", func(t *testing.T) {
		started := make(chan struct{}, 1)
		pipeline := compileM2Rules(t, rewrite.Rule{
			Name: "timeout-discard", Match: rewrite.Match{Path: "/timeout"},
			Request: &rewrite.RequestAction{Body: &rewrite.BodyReplacement{Replace: "replacement"}},
		})
		h := newM2HTTPHarness(t, "localhost", pipeline, func(w http.ResponseWriter, _ *http.Request) {
			started <- struct{}{}
			time.Sleep(300 * time.Millisecond)
			_, _ = io.WriteString(w, "late upstream response")
		})
		config := h.manager.ConfigSnapshot()
		config.RequestTimeout = 150 * time.Millisecond
		h.manager.Update(config)
		client, done := h.startTCPClient(t)
		_, err := io.WriteString(client, "POST /timeout HTTP/1.1\r\nHost: localhost\r\nContent-Length: 131072\r\n\r\npartial")
		require.NoError(t, err)
		reader := bufio.NewReader(client)
		_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
		response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodPost})
		require.NoError(t, err)
		require.Equal(t, http.StatusGatewayTimeout, response.StatusCode, "request timeout must take precedence over the unfinished discarded body")
		require.True(t, response.Close)
		_ = readM2ResponseBody(t, response)
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("rewritten request did not reach upstream")
		}
		require.EqualValues(t, 1, h.dialCount.Load())
		finishM2Dispatch(t, client, done)
	})

	t.Run("upstream response timeout", func(t *testing.T) {
		started := make(chan struct{}, 1)
		canceled := make(chan struct{}, 1)
		h := newM2HTTPHarness(t, "localhost", nil, func(w http.ResponseWriter, r *http.Request) {
			started <- struct{}{}
			<-r.Context().Done()
			canceled <- struct{}{}
		})
		config := h.manager.ConfigSnapshot()
		config.RequestTimeout = 150 * time.Millisecond
		h.manager.Update(config)
		client, done := h.startClient(t)
		response := sendM2Request(t, client, bufio.NewReader(client), "GET /slow HTTP/1.1\r\nHost: localhost\r\n\r\n", http.MethodGet)
		require.Equal(t, http.StatusGatewayTimeout, response.StatusCode)
		_ = readM2ResponseBody(t, response)
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("upstream was not reached")
		}
		select {
		case <-canceled:
		case <-time.After(time.Second):
			t.Fatal("request timeout did not cancel upstream work")
		}
		require.EqualValues(t, 1, h.dialCount.Load())
		finishM2Dispatch(t, client, done)
	})

	t.Run("abrupt upstream disconnect", func(t *testing.T) {
		h := newM2HTTPHarness(t, "localhost", nil, func(w http.ResponseWriter, r *http.Request) {
			hijacker, ok := w.(http.Hijacker)
			if !ok {
				return
			}
			conn, _, err := hijacker.Hijack()
			if err == nil {
				_ = conn.Close()
			}
		})
		client, done := h.startClient(t)
		response := sendM2Request(t, client, bufio.NewReader(client), "GET /disconnect HTTP/1.1\r\nHost: localhost\r\n\r\n", http.MethodGet)
		require.Equal(t, http.StatusBadGateway, response.StatusCode)
		_ = readM2ResponseBody(t, response)
		require.EqualValues(t, 1, h.dialCount.Load())
		finishM2Dispatch(t, client, done)
	})
}

func TestM2ClientCancellationClosesRewrittenUpstreamConnection(t *testing.T) {
	started := make(chan struct{}, 1)
	canceled := make(chan struct{}, 1)
	upstreamConns := make(chan net.Conn, 1)
	pipeline := compileM2Rules(t, rewrite.Rule{
		Name: "cancel", Match: rewrite.Match{Path: "/cancel"},
		Request: &rewrite.RequestAction{
			Headers: rewrite.HeaderAction{Set: map[string]string{"X-Cancel-Test": "active"}},
			Body:    &rewrite.BodyReplacement{Replace: "replacement"},
		},
	})
	h := newM2HTTPHarness(t, "localhost", pipeline, func(w http.ResponseWriter, _ *http.Request) {
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			return
		}
		conn, _, err := hijacker.Hijack()
		if err != nil {
			return
		}
		upstreamConns <- conn
		started <- struct{}{}
		var one [1]byte
		for {
			_, err := conn.Read(one[:])
			if err != nil {
				canceled <- struct{}{}
				return
			}
		}
	})
	t.Cleanup(func() {
		select {
		case conn := <-upstreamConns:
			_ = conn.Close()
		default:
		}
	})
	client, done := h.startTCPClient(t)
	_, err := io.WriteString(client, "POST /cancel HTTP/1.1\r\nHost: localhost\r\nContent-Length: 131072\r\n\r\npartial")
	require.NoError(t, err)
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("rewritten request did not reach upstream")
	}
	upstreamConn := <-upstreamConns
	_ = client.Close()
	select {
	case <-canceled:
	case <-time.After(3 * time.Second):
		t.Fatal("client disconnect did not close the rewritten upstream connection")
	}
	_ = upstreamConn.Close()
	select {
	case result := <-done:
		require.Equal(t, DispatchIntercepted, result.outcome)
		require.NoError(t, result.err)
	case <-time.After(5 * time.Second):
		t.Fatal("canceled M2 HTTP connection did not release")
	}
	require.EqualValues(t, 1, h.dialCount.Load())
}

func TestM2BodyReplacementForwardsStaticReader(t *testing.T) {
	pipeline := compileM2Rules(t, rewrite.Rule{
		Name: "replace", Match: rewrite.Match{Path: "/replace"},
		Request: &rewrite.RequestAction{Body: &rewrite.BodyReplacement{Replace: "fresh"}},
	})
	h := newM2HTTPHarness(t, "localhost", pipeline, nil)
	client, done := h.startClient(t)
	response := sendM2Request(t, client, bufio.NewReader(client), "POST /replace HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/old\r\nContent-Length: 3\r\n\r\nold", http.MethodPost)
	require.Equal(t, http.StatusOK, response.StatusCode)
	_ = readM2ResponseBody(t, response)
	observed := <-h.observations
	require.Equal(t, "fresh", observed.body)
	require.Empty(t, observed.header.Get("Content-Type"), "the old Content-Type must not describe a replacement body")
	finishM2Dispatch(t, client, done)
}

func TestM2RequestHeaderValuesAreNotMutatedBySnapshot(t *testing.T) {
	pipeline := compileM2Rules(t, rewrite.Rule{
		Name: "header", Match: rewrite.Match{Path: "/header"},
		Request: &rewrite.RequestAction{Headers: rewrite.HeaderAction{Set: map[string]string{"X-Set": "new"}}},
	})
	h := newM2HTTPHarness(t, "localhost", pipeline, nil)
	client, done := h.startClient(t)
	response := sendM2Request(t, client, bufio.NewReader(client), "GET /header HTTP/1.1\r\nHost: localhost\r\nX-Original: value\r\n\r\n", http.MethodGet)
	require.Equal(t, http.StatusOK, response.StatusCode)
	_ = readM2ResponseBody(t, response)
	observed := <-h.observations
	require.Equal(t, "value", observed.header.Get("X-Original"))
	require.Equal(t, "new", observed.header.Get("X-Set"))
	finishM2Dispatch(t, client, done)
}

func TestM2RequestBodyContentTypeFromHeaderRewriteSurvivesReplacement(t *testing.T) {
	pipeline := compileM2Rules(t, rewrite.Rule{
		Name: "replace", Match: rewrite.Match{Path: "/replace"},
		Request: &rewrite.RequestAction{
			Headers: rewrite.HeaderAction{Set: map[string]string{"Content-Type": "application/rewrite"}},
			Body:    &rewrite.BodyReplacement{Replace: "new"},
		},
	})
	h := newM2HTTPHarness(t, "localhost", pipeline, nil)
	client, done := h.startClient(t)
	response := sendM2Request(t, client, bufio.NewReader(client), "POST /replace HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/old\r\nContent-Length: 3\r\n\r\nold", http.MethodPost)
	require.Equal(t, http.StatusOK, response.StatusCode)
	_ = readM2ResponseBody(t, response)
	require.Equal(t, "application/rewrite", (<-h.observations).header.Get("Content-Type"))
	finishM2Dispatch(t, client, done)
}

func TestM2EmptyRewriteBodyIsFramedAsZeroLength(t *testing.T) {
	pipeline := compileM2Rules(t, rewrite.Rule{
		Name: "empty", Match: rewrite.Match{Path: "/empty"},
		Request: &rewrite.RequestAction{Body: &rewrite.BodyReplacement{Replace: ""}},
	})
	h := newM2HTTPHarness(t, "localhost", pipeline, nil)
	client, done := h.startClient(t)
	response := sendM2Request(t, client, bufio.NewReader(client), "POST /empty HTTP/1.1\r\nHost: localhost\r\nContent-Length: 3\r\n\r\nold", http.MethodPost)
	require.Equal(t, http.StatusOK, response.StatusCode)
	_ = readM2ResponseBody(t, response)
	observed := <-h.observations
	require.Empty(t, observed.body)
	require.Zero(t, observed.contentLength)
	require.Empty(t, observed.transferEncoding)
	finishM2Dispatch(t, client, done)
}

func TestM2NoRewriteStillUsesOriginalTargetAndRequest(t *testing.T) {
	h := newM2HTTPHarness(t, "localhost", nil, nil)
	client, done := h.startClient(t)
	response := sendM2Request(t, client, bufio.NewReader(client), "POST /unchanged HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\nContent-Type: text/plain\r\n\r\nbody", http.MethodPost)
	require.Equal(t, http.StatusOK, response.StatusCode)
	_ = readM2ResponseBody(t, response)
	observed := <-h.observations
	require.Equal(t, http.MethodPost, observed.method)
	require.Equal(t, "/unchanged", observed.urlPath)
	require.Equal(t, "body", observed.body)
	require.Equal(t, "text/plain", observed.header.Get("Content-Type"))
	require.EqualValues(t, 1, h.dialCount.Load())
	finishM2Dispatch(t, client, done)
}

func TestM2HeaderRewriteKeepsOriginalHeaderMapUntouched(t *testing.T) {
	input := http.Header{"X-Original": {"old"}}
	request := &http.Request{Method: http.MethodGet, URL: &url.URL{Scheme: "https", Host: "localhost:443", Path: "/"}, Header: input.Clone()}
	pipeline := compileM2Rules(t, rewrite.Rule{Name: "header", Request: &rewrite.RequestAction{Headers: rewrite.HeaderAction{Set: map[string]string{"X-Original": "new"}}}})
	result, err := pipeline.ApplyRequest(context.Background(), rewrite.RequestView{Method: request.Method, URL: *request.URL, Headers: requestHeaders(request.Header, request.Host)})
	require.NoError(t, err)
	require.Equal(t, "old", input.Get("X-Original"))
	require.Equal(t, "new", result.Request.Headers["X-Original"][0])
	require.True(t, strings.Contains(result.Request.URL.Host, "localhost"))
}
