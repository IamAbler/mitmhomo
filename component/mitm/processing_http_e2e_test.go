package mitm

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/mitm/httphook"
	"github.com/metacubex/mihomo/component/mitm/processing/generation"
	"github.com/metacubex/mihomo/component/mitm/processing/gojaprocessor"
	"github.com/metacubex/mihomo/component/mitm/processing/model"
	"github.com/metacubex/mihomo/component/mitm/processing/pipeline"
	C "github.com/metacubex/mihomo/constant"
	"github.com/stretchr/testify/require"
)

func m52GojaFactory(t testing.TB, config gojaprocessor.Config) func() ([]pipeline.Entry, error) {
	t.Helper()
	factory, err := gojaprocessor.NewFactory(config)
	require.NoError(t, err)
	return func() ([]pipeline.Entry, error) {
		backend, err := factory.Build()
		if err != nil {
			return nil, err
		}
		return []pipeline.Entry{{Class: pipeline.Script, Priority: 0, Processor: backend}}, nil
	}
}

func m52ProtocolHarness(t testing.TB, h2 bool, upstream http.Handler, factory func() ([]pipeline.Entry, error), options ...func(*Config)) *h2Harness {
	t.Helper()
	allOptions := make([]func(*Config), 0, len(options)+1)
	allOptions = append(allOptions, func(config *Config) { config.ProcessorFactory = factory })
	allOptions = append(allOptions, options...)
	return newProtocolHarness(t, nil, "localhost", 443, upstream, false, true, h2, []string{"http/1.1"}, allOptions...)
}

func m52RoundTrip(t testing.TB, h *h2Harness, h2 bool, method, path, body string) *http.Response {
	t.Helper()
	if h2 {
		return h2Request(t, h, method, path, body)
	}
	request, err := http.NewRequest(method, "https://localhost"+path, strings.NewReader(body))
	require.NoError(t, err)
	response, err := h.wire.RoundTrip(request)
	require.NoError(t, err)
	require.Equal(t, 1, response.ProtoMajor)
	return response
}

func m52ReadResponse(t testing.TB, response *http.Response) string {
	t.Helper()
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	return string(body)
}

func TestM52GojaProductionHTTP11AndHTTP2RequestResponseChanges(t *testing.T) {
	const source = `function process(input) {
  if (input.phase === "request") return {kind:"request_change", request:{
    headers:[{op:"set",name:"X-Goja-Request",values:["yes"]}],
    body:{encoding:"base64",data:"bmV3LXVwbG9hZA=="}
  }};
  return {kind:"response_change", response:{
    status:201,
    headers:[{op:"set",name:"X-Goja-Response",values:["yes"]}],
    body:{encoding:"base64",data:"bmV3LXJlc3BvbnNl"}
  }};
}`
	for _, h2 := range []bool{false, true} {
		name := "http11"
		if h2 {
			name = "http2"
		}
		t.Run(name, func(t *testing.T) {
			var calls atomic.Int32
			upstreamBody := make(chan string, 1)
			upstreamHeader := make(chan string, 1)
			h := m52ProtocolHarness(t, h2, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				calls.Add(1)
				body, err := io.ReadAll(request.Body)
				require.NoError(t, err)
				upstreamBody <- string(body)
				upstreamHeader <- request.Header.Get("X-Goja-Request")
				w.Header().Set("X-Origin", "seen")
				_, _ = io.WriteString(w, "origin-response")
			}), m52GojaFactory(t, gojaprocessor.Config{
				ID: "m52-real-http", Source: source, Request: true, Response: true,
				RequestBody: model.FullBuffered, RequestMaxBodyBytes: 1 << 20,
				ResponseBody: model.FullBuffered, ResponseMaxBodyBytes: 1 << 20,
			}))
			response := m52RoundTrip(t, h, h2, http.MethodPost, "/goja", "old-upload")
			require.Equal(t, 201, response.StatusCode)
			require.Equal(t, "yes", response.Header.Get("X-Goja-Response"))
			require.Equal(t, "new-response", m52ReadResponse(t, response))
			require.Equal(t, "new-upload", <-upstreamBody)
			require.Equal(t, "yes", <-upstreamHeader)
			require.EqualValues(t, 1, calls.Load(), "the proxy must perform exactly one upstream exchange")
		})
	}
}

func TestM52GojaSyntheticResponseSkipsUpstream(t *testing.T) {
	const source = `function process(input) {
  if (input.phase === "request") return {kind:"respond", response:{
    status:202,
    headers:[{name:"X-Goja-Synthetic",values:["yes"]}],
    body:{encoding:"base64",data:"bG9jYWw="}
  }};
  return {kind:"response_change",response:{headers:[{op:"set",name:"X-Duplicate-Synthetic",values:["yes"]}]}};
}`
	for _, h2 := range []bool{false, true} {
		t.Run(map[bool]string{false: "http11", true: "http2"}[h2], func(t *testing.T) {
			var calls atomic.Int32
			h := m52ProtocolHarness(t, h2, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				_, _ = io.WriteString(w, "upstream")
			}), m52GojaFactory(t, gojaprocessor.Config{ID: "m52-synthetic", Source: source, Request: true, Response: true}))
			response := m52RoundTrip(t, h, h2, http.MethodGet, "/synthetic", "")
			require.Equal(t, 202, response.StatusCode)
			require.Equal(t, "yes", response.Header.Get("X-Goja-Synthetic"))
			require.Empty(t, response.Header.Get("X-Duplicate-Synthetic"), "synthetic responses must not re-enter the response phase")
			require.Equal(t, "local", m52ReadResponse(t, response))
			require.Zero(t, calls.Load())
			require.Zero(t, h.dials.Load())
		})
	}
}

func TestM52GojaStopPhaseRejectAndAbort(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		name := "http11"
		if h2 {
			name = "http2"
		}
		t.Run("stop phase/"+name, func(t *testing.T) {
			const source = `function process(input) {
  if (input.phase === "request") return {kind:"stop_phase"};
  return {kind:"response_change",response:{headers:[{op:"set",name:"X-Response-Phase",values:["ran"]}]}};
}`
			var calls atomic.Int32
			h := m52ProtocolHarness(t, h2, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				_, _ = io.WriteString(w, "origin")
			}), m52GojaFactory(t, gojaprocessor.Config{ID: "m52-stop-phase", Source: source, Request: true, Response: true}))
			response := m52RoundTrip(t, h, h2, http.MethodGet, "/stop", "")
			require.Equal(t, "ran", response.Header.Get("X-Response-Phase"))
			require.Equal(t, "origin", m52ReadResponse(t, response))
			require.EqualValues(t, 1, calls.Load())
		})
	}

	for _, h2 := range []bool{false, true} {
		name := "http11"
		if h2 {
			name = "http2"
		}
		t.Run("reject/"+name, func(t *testing.T) {
			const source = `function process(input) { return {kind:"reject",code:"policy"}; }`
			var calls atomic.Int32
			h := m52ProtocolHarness(t, h2, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }),
				m52GojaFactory(t, gojaprocessor.Config{ID: "m52-reject", Source: source, Request: true}))
			response := m52RoundTrip(t, h, h2, http.MethodGet, "/reject", "")
			require.Equal(t, http.StatusForbidden, response.StatusCode)
			require.Contains(t, m52ReadResponse(t, response), "request rejected")
			require.Zero(t, calls.Load())
		})
	}

	t.Run("abort closes the HTTP/1.1 connection", func(t *testing.T) {
		const source = `function process(input) { return {kind:"abort",reason:"policy"}; }`
		var calls atomic.Int32
		h := m52ProtocolHarness(t, false, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }),
			m52GojaFactory(t, gojaprocessor.Config{ID: "m52-abort-h1", Source: source, Request: true}))
		request, err := http.NewRequest(http.MethodGet, "https://localhost/abort", nil)
		require.NoError(t, err)
		_, err = h.wire.RoundTrip(request)
		require.Error(t, err)
		require.Zero(t, calls.Load())
	})

	t.Run("abort resets the current HTTP2 stream", func(t *testing.T) {
		const source = `function process(input) {
  if (input.request.url.indexOf("/abort") >= 0) return {kind:"abort",reason:"policy"};
  return {kind:"continue"};
}`
		var calls atomic.Int32
		h := m52ProtocolHarness(t, true, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }),
			m52GojaFactory(t, gojaprocessor.Config{ID: "m52-abort", Source: source, Request: true}))
		request, err := http.NewRequest(http.MethodGet, "https://localhost/abort", nil)
		require.NoError(t, err)
		_, err = h.client.RoundTrip(request)
		require.Error(t, err)
		require.Zero(t, calls.Load())
		// The HTTP/2 connection remains available for a sibling stream.
		response, err := h.client.RoundTrip(mustM52Request(t, http.MethodGet, "https://localhost/after-abort"))
		require.NoError(t, err)
		_ = m52ReadResponse(t, response)
	})
}

func mustM52Request(t *testing.T, method, target string) *http.Request {
	t.Helper()
	request, err := http.NewRequest(method, target, nil)
	require.NoError(t, err)
	return request
}

func TestM52GojaTimeoutAndBodyLimitHTTPMappings(t *testing.T) {
	t.Run("timeout", func(t *testing.T) {
		const source = `function process(input) { while (true) {} }`
		h := m52ProtocolHarness(t, true, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), m52GojaFactory(t, gojaprocessor.Config{
			ID: "m52-timeout", Source: source, Request: true, ExecutionTimeout: 100 * time.Millisecond,
		}))
		response := m52RoundTrip(t, h, true, http.MethodGet, "/timeout", "")
		require.Equal(t, http.StatusGatewayTimeout, response.StatusCode)
		require.Contains(t, m52ReadResponse(t, response), "processing timed out")
	})

	t.Run("body limit", func(t *testing.T) {
		const source = `function process(input) { return {kind:"continue"}; }`
		var calls atomic.Int32
		h := m52ProtocolHarness(t, false, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }), m52GojaFactory(t, gojaprocessor.Config{
			ID: "m52-body-limit", Source: source, Request: true,
			RequestBody: model.FullBuffered, RequestMaxBodyBytes: 4,
		}))
		response := m52RoundTrip(t, h, false, http.MethodPost, "/too-large", "12345")
		require.Equal(t, http.StatusRequestEntityTooLarge, response.StatusCode)
		require.Zero(t, calls.Load())
		_ = m52ReadResponse(t, response)
	})

	t.Run("output limit", func(t *testing.T) {
		const source = `function process(input) {
  if (input.phase === "response") return {kind:"response_change",response:{body:{encoding:"base64",data:"MTIzNDU="}}};
  return {kind:"continue"};
}`
		h := m52ProtocolHarness(t, true, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "origin") }), m52GojaFactory(t, gojaprocessor.Config{
			ID: "m52-output-limit", Source: source, Request: true, Response: true,
			MaxOutputBytes: 1024, MaxOutputBodyBytes: 4,
		}))
		response := m52RoundTrip(t, h, true, http.MethodGet, "/output-limit", "")
		require.Equal(t, http.StatusBadGateway, response.StatusCode)
		body := m52ReadResponse(t, response)
		require.NotContains(t, body, "12345")
		require.NotContains(t, body, "output limit")
	})

	t.Run("invalid result does not expose processor details", func(t *testing.T) {
		const source = `function process(input) { return {kind:"unknown-internal-value",debug:"private"}; }`
		h := m52ProtocolHarness(t, false, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("invalid request result reached upstream") }), m52GojaFactory(t, gojaprocessor.Config{
			ID: "m52-invalid-result", Source: source, Request: true,
		}))
		response := m52RoundTrip(t, h, false, http.MethodGet, "/invalid-result", "")
		require.Equal(t, http.StatusInternalServerError, response.StatusCode)
		body := m52ReadResponse(t, response)
		require.NotContains(t, body, "unknown-internal-value")
		require.NotContains(t, body, "private")
	})
}

func TestM52ResponseBodyTimeoutCancelsOnlyTheOwningRequest(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		name := "http11"
		if h2 {
			name = "http2"
		}
		t.Run(name, func(t *testing.T) {
			streamed := make(chan struct{})
			upstreamCanceled := make(chan struct{})
			upstreamDone := make(chan struct{})
			var upstreamCalls atomic.Int32
			release := make(chan struct{})
			var releaseOnce sync.Once
			releaseUpstream := func() { releaseOnce.Do(func() { close(release) }) }
			h := m52ProtocolHarness(t, h2, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				upstreamCalls.Add(1)
				if request.URL.Path != "/blocked" {
					_, _ = io.WriteString(w, "sibling-ok")
					return
				}
				defer close(upstreamDone)
				_, _ = io.WriteString(w, "partial")
				w.(http.Flusher).Flush()
				close(streamed)
				go func() {
					<-request.Context().Done()
					close(upstreamCanceled)
				}()
				// Deliberately ignore request cancellation until the test releases
				// this upstream handler. The proxy must still return its timeout.
				<-release
			}), m52GojaFactory(t, gojaprocessor.Config{
				ID: "m52-response-body-cancel", Source: `function process(input) { return {kind:"continue"}; }`,
				Response: true, ResponseBody: model.FullBuffered, ResponseMaxBodyBytes: 1 << 20,
				TotalTimeout: 150 * time.Millisecond,
			}))
			// Register after the harness cleanup so a failing assertion releases
			// the deliberately blocked upstream before httptest.Server.Close waits.
			t.Cleanup(releaseUpstream)

			type roundTripResult struct {
				response *http.Response
				err      error
			}
			request, err := http.NewRequest(http.MethodGet, "https://localhost/blocked", nil)
			require.NoError(t, err)
			result := make(chan roundTripResult, 1)
			go func() {
				var response *http.Response
				var roundTripErr error
				if h2 {
					response, roundTripErr = h.client.RoundTrip(request)
				} else {
					response, roundTripErr = h.wire.RoundTrip(request)
				}
				result <- roundTripResult{response: response, err: roundTripErr}
			}()
			select {
			case <-streamed:
			case <-time.After(3 * time.Second):
				t.Fatal("upstream did not start streaming the blocked response")
			}
			var response *http.Response
			select {
			case received := <-result:
				require.NoError(t, received.err)
				response = received.response
			case <-time.After(3 * time.Second):
				t.Fatal("response Body Close blocked the timed-out HTTP handler")
			}
			require.Equal(t, http.StatusGatewayTimeout, response.StatusCode)
			require.Contains(t, m52ReadResponse(t, response), "timed out")
			select {
			case <-upstreamCanceled:
			case <-time.After(3 * time.Second):
				t.Fatal("response body cancellation did not reach its upstream request")
			}
			if h2 {
				sibling := m52RoundTrip(t, h, true, http.MethodGet, "/sibling", "")
				require.Equal(t, "sibling-ok", m52ReadResponse(t, sibling), "canceling one stream must preserve its HTTP/2 sibling")
				require.EqualValues(t, 2, upstreamCalls.Load(), "each downstream stream must issue exactly one upstream exchange")
			} else {
				require.EqualValues(t, 1, upstreamCalls.Load(), "a response pipeline timeout must not retry the upstream exchange")
			}
			releaseUpstream()
			select {
			case <-upstreamDone:
			case <-time.After(3 * time.Second):
				t.Fatal("test upstream did not exit after release")
			}
		})
	}
}

type m52BlockedReadBody struct {
	entered  chan struct{}
	release  <-chan struct{}
	closed   chan struct{}
	readOnce sync.Once
	closeOne sync.Once
}

func (body *m52BlockedReadBody) Read(p []byte) (int, error) {
	body.readOnce.Do(func() { close(body.entered) })
	<-body.release
	return copy(p, "released"), io.EOF
}

func (body *m52BlockedReadBody) Close() error {
	body.closeOne.Do(func() { close(body.closed) })
	return nil
}

func TestM52NonCooperativeRequestReaderDoesNotHoldHTTPHandler(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		name := "http11"
		if h2 {
			name = "http2"
		}
		t.Run(name, func(t *testing.T) {
			entered := make(chan struct{})
			release := make(chan struct{})
			closed := make(chan struct{})
			var releaseOnce sync.Once
			releaseReader := func() { releaseOnce.Do(func() { close(release) }) }
			reader := &m52BlockedReadBody{entered: entered, release: release, closed: closed}
			var upstreamCalls atomic.Int32
			h := m52ProtocolHarness(t, h2, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				upstreamCalls.Add(1)
				_, _ = io.WriteString(w, request.URL.Path)
			}), m52GojaFactory(t, gojaprocessor.Config{
				ID:      "m52-blocked-request-reader",
				Source:  `function process(input) { return {kind:"continue"}; }`,
				Request: true, RequestBody: model.FullBuffered, RequestMaxBodyBytes: 1 << 20,
				TotalTimeout: 150 * time.Millisecond,
			}), func(config *Config) {
				config.RequestHook = func(request *http.Request) error {
					if request.URL.Path == "/blocked" {
						request.Body = reader
						request.ContentLength = -1
					}
					return nil
				}
			})
			// Release before httptest cleanup if an assertion fails while the Body
			// owner is still correctly retaining this deliberately blocked Reader.
			t.Cleanup(releaseReader)

			type roundTripResult struct {
				response *http.Response
				err      error
			}
			request, err := http.NewRequest(http.MethodGet, "https://localhost/blocked", nil)
			require.NoError(t, err)
			result := make(chan roundTripResult, 1)
			go func() {
				var response *http.Response
				var roundTripErr error
				if h2 {
					response, roundTripErr = h.client.RoundTrip(request)
				} else {
					response, roundTripErr = h.wire.RoundTrip(request)
				}
				result <- roundTripResult{response: response, err: roundTripErr}
			}()
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("RequestPhase did not start the blocked Body Reader")
			}
			var response *http.Response
			select {
			case received := <-result:
				require.NoError(t, received.err)
				response = received.response
			case <-time.After(3 * time.Second):
				t.Fatal("HTTP handler waited for a non-cooperative Reader after request timeout")
			}
			require.Equal(t, http.StatusGatewayTimeout, response.StatusCode)
			require.Contains(t, m52ReadResponse(t, response), "timed out")
			select {
			case <-closed:
				t.Fatal("logical timeout released the blocked Reader before Read returned")
			default:
			}
			if h2 {
				sibling := m52RoundTrip(t, h, true, http.MethodGet, "/sibling", "")
				require.Equal(t, "/sibling", m52ReadResponse(t, sibling), "one blocked HTTP/2 Body owner must not stall its sibling Stream")
			}
			wantCalls := int32(0)
			if h2 {
				wantCalls = 1
			}
			require.EqualValues(t, wantCalls, upstreamCalls.Load(), "the timed-out request must not reach the upstream")
			releaseReader()
			select {
			case <-closed:
			case <-time.After(3 * time.Second):
				t.Fatal("Body owner did not dispose the Reader after it physically returned")
			}
		})
	}
}

func TestCommitTrackingWriterRecognizesHTTPCommitBoundaries(t *testing.T) {
	t.Run("final headers commit without a body", func(t *testing.T) {
		for _, status := range []int{http.StatusOK, http.StatusNoContent, http.StatusNotModified} {
			recorder := httptest.NewRecorder()
			writer := &commitTrackingWriter{ResponseWriter: recorder}
			writer.WriteHeader(status)
			require.Truef(t, writer.Committed(), "status %d must commit even without a Body write", status)
			require.Equal(t, status, recorder.Code)
		}
	})

	t.Run("informational headers do not commit the final response", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		writer := &commitTrackingWriter{ResponseWriter: recorder}
		writer.WriteHeader(http.StatusEarlyHints)
		require.False(t, writer.Committed())
	})

	t.Run("empty Write and Flush commit implicitly", func(t *testing.T) {
		for _, commit := range []struct {
			name string
			call func(*commitTrackingWriter) error
		}{
			{name: "empty write", call: func(writer *commitTrackingWriter) error { _, err := writer.Write(nil); return err }},
			{name: "flush", call: func(writer *commitTrackingWriter) error { return writer.FlushError() }},
		} {
			t.Run(commit.name, func(t *testing.T) {
				recorder := httptest.NewRecorder()
				writer := &commitTrackingWriter{ResponseWriter: recorder}
				require.NoError(t, commit.call(writer))
				require.True(t, writer.Committed())
				require.Equal(t, http.StatusOK, recorder.Code)
				if commit.name == "flush" {
					require.True(t, recorder.Flushed)
				}
			})
		}
	})

	for _, commit := range []struct {
		name     string
		write    func(*commitTrackingWriter) error
		wantBody string
	}{
		{name: "WriteHeader without Body", write: func(writer *commitTrackingWriter) error { writer.WriteHeader(http.StatusOK); return nil }},
		{name: "partial Write", write: func(writer *commitTrackingWriter) error { _, err := writer.Write([]byte("partial")); return err }, wantBody: "partial"},
		{name: "Flush without Body", write: func(writer *commitTrackingWriter) error { return writer.FlushError() }},
	} {
		t.Run("failure after "+commit.name+" aborts instead of writing a second response", func(t *testing.T) {
			recorder := httptest.NewRecorder()
			writer := &commitTrackingWriter{ResponseWriter: recorder}
			require.NoError(t, commit.write(writer))
			request := httptest.NewRequest(http.MethodGet, "/", nil)
			var recovered any
			func() {
				defer func() { recovered = recover() }()
				writeProcessingFailure(writer, request, model.ErrInvalid, model.ResponsePhase)
			}()
			require.Equal(t, http.ErrAbortHandler, recovered)
			require.Equal(t, http.StatusOK, recorder.Code)
			require.Equal(t, commit.wantBody, recorder.Body.String())
		})
	}
}

type m52BlockedCloseBody struct {
	entered chan struct{}
	release <-chan struct{}
	closed  atomic.Int32
	once    sync.Once
}

func (*m52BlockedCloseBody) Read([]byte) (int, error) { return 0, io.EOF }
func (body *m52BlockedCloseBody) Close() error {
	body.closed.Add(1)
	body.once.Do(func() { close(body.entered) })
	<-body.release
	return nil
}

func TestM52ResponseBodyCloseReturnsBeforePhysicalDisposal(t *testing.T) {
	g := generation.New()
	require.NoError(t, g.Activate())
	connection, err := g.Bind()
	require.NoError(t, err)
	stream, err := connection.Transaction()
	require.NoError(t, err)
	ledger, err := model.NewLedger(-1, nil)
	require.NoError(t, err)
	lease := model.NewCopyLease(ledger)
	requestURL, err := model.ParseURL(lease, "https://localhost/", model.MITMHTTPS)
	require.NoError(t, err)
	requestHeaders, err := model.NewHeaderBlock(lease, nil)
	require.NoError(t, err)
	requestHead := model.RequestHead{Method: http.MethodGet, URL: requestURL, Authority: "localhost", Headers: requestHeaders}
	tx, err := model.NewTransaction(context.Background(), model.TransactionOptions{
		ID: "m52-response-close", Generation: g.ID(), Connection: model.ConnectionView{ID: "m52-connection"},
		OriginalIngress: requestHead, Request: requestHead, Ledger: ledger,
	})
	lease.Close()
	require.NoError(t, err)
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseBody := func() { releaseOnce.Do(func() { close(release) }) }
	body := &m52BlockedCloseBody{entered: make(chan struct{}), release: release}
	defer func() {
		releaseBody()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = tx.CloseContext(ctx)
		_ = stream.Close()
		_ = connection.Close()
		g.Retire()
		_ = g.WaitClosed(ctx)
	}()
	response := &http.Response{
		StatusCode: http.StatusOK, Header: make(http.Header), Trailer: make(http.Header),
		ContentLength: -1, Body: body, Request: httptest.NewRequest(http.MethodGet, "https://localhost/", nil),
	}
	require.NoError(t, enterUpstreamResponse(tx, response, stream, func() {}))
	require.Equal(t, http.NoBody, response.Body, "ReverseProxy must not close the raw source while the Transaction owns it")
	require.NoError(t, applyResponseTransaction(response, tx, http.MethodGet))

	closed := make(chan error, 1)
	go func() { closed <- response.Body.Close() }()
	select {
	case <-body.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("response Body owner did not begin physical disposal")
	}
	var closeBlocked bool
	select {
	case closeErr := <-closed:
		require.NoError(t, closeErr)
	case <-time.After(time.Second):
		closeBlocked = true
	}
	if closeBlocked {
		t.Fatal("HTTP Response.Body.Close waited for physical Body disposal")
	}
	select {
	case <-tx.BodyExecutionDone():
		t.Fatal("logical HTTP Body close forged physical ExecutionDone")
	default:
	}
	_ = stream.Close()
	_ = connection.Close()
	g.Retire()
	wait, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	err = g.WaitClosed(wait)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) || g.State() != generation.Retiring {
		t.Fatalf("Generation retired while response Body.Close was still running: state=%v err=%v", g.State(), err)
	}
	releaseBody()
	select {
	case <-tx.BodyExecutionDone():
	case <-time.After(3 * time.Second):
		t.Fatal("Body ExecutionDone did not follow physical disposal")
	}
	wait, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err = g.WaitClosed(wait); err != nil {
		t.Fatal(err)
	}
	if body.closed.Load() != 1 {
		t.Fatalf("source Close count = %d, want 1", body.closed.Load())
	}
}

func TestM52ProcessingFailureErrorMappings(t *testing.T) {
	processingError := func(kind model.ProcessingErrorKind, origin model.ProcessingErrorOrigin, phase model.Phase) error {
		return model.NewProcessingError(kind, origin, phase, "m52-mapping", "mapping-test", errors.New("private processor detail"))
	}
	tests := []struct {
		name  string
		err   error
		phase model.Phase
		want  int
	}{
		{name: "processor timeout", err: processingError(model.ProcessingErrorTimeout, model.ProcessingOriginProcessor, model.RequestPhase), phase: model.RequestPhase, want: http.StatusGatewayTimeout},
		{name: "context canceled", err: context.Canceled, phase: model.RequestPhase, want: 0},
		{name: "request body limit", err: processingError(model.ProcessingErrorBodyLimitExceeded, model.ProcessingOriginRequest, model.RequestPhase), phase: model.RequestPhase, want: http.StatusRequestEntityTooLarge},
		{name: "response body limit", err: processingError(model.ProcessingErrorBodyLimitExceeded, model.ProcessingOriginRequest, model.ResponsePhase), phase: model.ResponsePhase, want: http.StatusBadGateway},
		{name: "request output limit", err: processingError(model.ProcessingErrorOutputLimitExceeded, model.ProcessingOriginProcessor, model.RequestPhase), phase: model.RequestPhase, want: http.StatusRequestEntityTooLarge},
		{name: "response output limit", err: processingError(model.ProcessingErrorOutputLimitExceeded, model.ProcessingOriginProcessor, model.ResponsePhase), phase: model.ResponsePhase, want: http.StatusBadGateway},
		{name: "capacity exhausted", err: processingError(model.ProcessingErrorCapacityExhausted, model.ProcessingOriginProcessor, model.RequestPhase), phase: model.RequestPhase, want: http.StatusServiceUnavailable},
		{name: "invalid result", err: processingError(model.ProcessingErrorInvalidOutput, model.ProcessingOriginProcessor, model.RequestPhase), phase: model.RequestPhase, want: http.StatusInternalServerError},
		{name: "response processor failure", err: processingError(model.ProcessingErrorExecution, model.ProcessingOriginProcessor, model.ResponsePhase), phase: model.ResponsePhase, want: http.StatusBadGateway},
		{name: "upstream failure", err: processingError(model.ProcessingErrorUpstream, model.ProcessingOriginUpstream, model.ResponsePhase), phase: model.ResponsePhase, want: http.StatusBadGateway},
		{name: "irreversible I/O failure", err: processingError(model.ProcessingErrorIrreversibleIOFailure, model.ProcessingOriginUpstream, model.ResponsePhase), phase: model.ResponsePhase, want: http.StatusBadGateway},
		{name: "resource cleanup failure", err: processingError(model.ProcessingErrorCleanupFailure, model.ProcessingOriginConnection, model.RequestPhase), phase: model.RequestPhase, want: http.StatusServiceUnavailable},
		{name: "invalid protocol input", err: model.ErrInvalid, phase: model.RequestPhase, want: http.StatusBadRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.want, processingFailureStatus(test.err, test.phase))
		})
	}
}

func TestM52LegacyScriptPrecedesGojaWithoutDoubleExecution(t *testing.T) {
	legacy := m42Hooks(t, httphook.Config{Enable: true, Rules: []httphook.Rule{{
		Name: "legacy-request", Phase: httphook.RequestPhase,
		Match:  httphook.Match{Path: "/legacy"},
		Source: `({headers: Object.assign({}, input.headers, {"X-Legacy-Processor": ["ran"]})})`,
	}}})
	const source = `function process(input) {
  if (input.phase === "request") return {kind:"request_change",request:{headers:[{op:"set",name:"X-Goja-Processor",values:["ran"]}]}};
  return {kind:"continue"};
}`
	h := m52ProtocolHarness(t, false, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		_, _ = io.WriteString(w, request.Header.Get("X-Legacy-Processor")+"|"+request.Header.Get("X-Goja-Processor"))
	}), m52GojaFactory(t, gojaprocessor.Config{ID: "m52-priority", Source: source, Request: true}), func(config *Config) {
		config.ScriptHooks = legacy
	})
	response := m52RoundTrip(t, h, false, http.MethodGet, "/legacy", "")
	require.Equal(t, "ran|", m52ReadResponse(t, response), "the established legacy Script priority must win once for a matching request")
}

func TestM52GojaInvocationCapacityMapsToServiceUnavailable(t *testing.T) {
	const source = `function process(input) {
  if (input.request.url.indexOf("/hold") >= 0) while (true) {}
  return {kind:"continue"};
}`
	started := make(chan struct{})
	hook := func(config *Config) {
		previous := config.RequestHook
		config.RequestHook = func(request *http.Request) error {
			if err := previous(request); err != nil {
				return err
			}
			if request.URL.Path == "/hold" {
				close(started)
			}
			return nil
		}
	}
	h := m52ProtocolHarness(t, true, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), m52GojaFactory(t, gojaprocessor.Config{
		ID: "m52-capacity", Source: source, Request: true, Capacity: 1, ExecutionTimeout: 3 * time.Second,
	}), hook)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	firstRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://localhost/hold", nil)
	require.NoError(t, err)
	firstDone := make(chan error, 1)
	go func() {
		response, err := h.client.RoundTrip(firstRequest)
		if response != nil {
			_ = response.Body.Close()
		}
		firstDone <- err
	}()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("first HTTP/2 stream did not enter the production handler")
	}
	time.Sleep(75 * time.Millisecond)
	second := m52RoundTrip(t, h, true, http.MethodGet, "/capacity", "")
	require.Equal(t, http.StatusServiceUnavailable, second.StatusCode)
	require.Contains(t, m52ReadResponse(t, second), "capacity is unavailable")
	cancel()
	select {
	case err := <-firstDone:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(3 * time.Second):
		t.Fatal("canceling the held HTTP/2 stream did not release its Goja invocation")
	}
}

func benchmarkM52MITMOffClient(b *testing.B, h2 bool) (*http.Client, *atomic.Int32, func()) {
	b.Helper()
	originConnections := &atomic.Int32{}
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		_, _ = io.Copy(io.Discard, request.Body)
		_, _ = io.WriteString(w, "ok")
	}))
	origin.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			originConnections.Add(1)
		}
	}
	origin.EnableHTTP2 = h2
	origin.StartTLS()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		origin.Close()
		b.Fatal(err)
	}
	manager := NewManager(Config{Enabled: false})
	var relays sync.WaitGroup
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			inbound, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			relays.Add(1)
			go func(inbound net.Conn) {
				defer relays.Done()
				buffered := N.NewBufferedConn(inbound)
				outcome, dispatchErr := manager.Dispatch(context.Background(), buffered, &C.Metadata{
					NetWork: C.TCP, Type: C.TUNNEL, Host: "localhost", DstPort: 443,
				}, nil, nil)
				if dispatchErr != nil || outcome != DispatchUnmatched {
					_ = inbound.Close()
					return
				}
				upstream, dialErr := net.Dial("tcp", origin.Listener.Addr().String())
				if dialErr != nil {
					_ = inbound.Close()
					return
				}
				copied := make(chan struct{})
				go func() {
					_, _ = io.Copy(upstream, buffered)
					if tcp, ok := upstream.(*net.TCPConn); ok {
						_ = tcp.CloseWrite()
					}
					close(copied)
				}()
				_, _ = io.Copy(inbound, upstream)
				_ = inbound.Close()
				_ = upstream.Close()
				<-copied
			}(inbound)
		}
	}()
	base := origin.Client().Transport.(*http.Transport).Clone()
	base.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
	}
	base.ForceAttemptHTTP2 = h2
	if !h2 {
		base.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	}
	client := &http.Client{Transport: base}
	cleanup := func() {
		base.CloseIdleConnections()
		_ = listener.Close()
		<-acceptDone
		_ = manager.Close()
		relays.Wait()
		origin.Close()
	}
	return client, originConnections, cleanup
}

func BenchmarkM52ProductionHTTPProtocolPaths(b *testing.B) {
	for _, protocol := range []struct {
		name string
		h2   bool
	}{{name: "http11"}, {name: "http2", h2: true}} {
		b.Run(protocol.name, func(b *testing.B) {
			for _, mode := range []string{"mitm-off-native-relay", "mitm-on-no-processor", "mitm-on-goja"} {
				b.Run(mode, func(b *testing.B) {
					var client *http.Client
					var harness *h2Harness
					var originConnections *atomic.Int32
					var cleanup func()
					target := "https://localhost/benchmark"
					switch mode {
					case "mitm-off-native-relay":
						client, originConnections, cleanup = benchmarkM52MITMOffClient(b, protocol.h2)
						target = "https://example.com/benchmark"
					case "mitm-on-no-processor":
						harness = m52ProtocolHarness(b, protocol.h2, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }), nil)
						client = &http.Client{Transport: harness.wire}
					case "mitm-on-goja":
						factory := m52GojaFactory(b, gojaprocessor.Config{
							ID: "m52-benchmark", Source: `function process(input) { return {kind:"continue"}; }`, Request: true, Response: true,
						})
						harness = m52ProtocolHarness(b, protocol.h2, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }), factory)
						client = &http.Client{Transport: harness.wire}
					}
					if cleanup != nil {
						defer func() {
							b.StopTimer()
							cleanup()
						}()
					}
					request, err := http.NewRequest(http.MethodGet, target, nil)
					if err != nil {
						b.Fatal(err)
					}
					response, err := client.Do(request)
					if err != nil {
						b.Fatal(err)
					}
					if want := map[bool]int{false: 1, true: 2}[protocol.h2]; response.ProtoMajor != want {
						b.Fatalf("protocol = HTTP/%d, want HTTP/%d", response.ProtoMajor, want)
					}
					_, _ = io.Copy(io.Discard, response.Body)
					_ = response.Body.Close()
					connectionsAtWarmup := int32(0)
					if originConnections != nil {
						connectionsAtWarmup = originConnections.Load()
					} else if harness != nil {
						connectionsAtWarmup = harness.accepted.Load()
					}
					b.ReportAllocs()
					b.ResetTimer()
					for index := 0; index < b.N; index++ {
						request, err := http.NewRequest(http.MethodGet, target, nil)
						if err != nil {
							b.Fatal(err)
						}
						response, err := client.Do(request)
						if err != nil {
							b.Fatal(err)
						}
						_, _ = io.Copy(io.Discard, response.Body)
						if err := response.Body.Close(); err != nil {
							b.Fatal(err)
						}
					}
					if b.N > 0 {
						connectionsAfter := int32(0)
						if originConnections != nil {
							connectionsAfter = originConnections.Load()
						} else if harness != nil {
							connectionsAfter = harness.accepted.Load()
						}
						b.ReportMetric(float64(connectionsAfter-connectionsAtWarmup)/float64(b.N), "origin-conns/op")
					}
				})
			}
		})
	}
}

func BenchmarkM53ProductionHTTPBodySizes(b *testing.B) {
	protocols := []struct {
		name string
		h2   bool
	}{{name: "http11"}, {name: "http2", h2: true}}
	modes := []string{"mitm-off", "mitm-on-no-processor", "goja-continue", "goja-header", "goja-request-body", "goja-response-body"}
	sizes := []struct {
		name string
		n    int
	}{{name: "small-128b", n: 128}, {name: "medium-64k", n: 64 << 10}, {name: "near-budget", n: (1 << 20) - (16 << 10)}}
	for _, protocol := range protocols {
		b.Run(protocol.name, func(b *testing.B) {
			for _, mode := range modes {
				b.Run(mode, func(b *testing.B) {
					for _, size := range sizes {
						b.Run(size.name, func(b *testing.B) {
							payload := strings.Repeat("x", size.n)
							var upstreamRead atomic.Int64
							var upstreamReadErr atomic.Value
							echo := http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
								read, err := io.Copy(io.Discard, request.Body)
								upstreamRead.Store(read)
								if err != nil {
									upstreamReadErr.Store(err.Error())
									return
								}
								w.Header().Set("Content-Length", fmt.Sprint(len(payload)))
								_, _ = io.WriteString(w, payload)
							})
							target := "https://localhost/benchmark-body"
							var client *http.Client
							var harness *h2Harness
							var originConnections *atomic.Int32
							var cleanup func()
							switch mode {
							case "mitm-off":
								client, originConnections, cleanup = benchmarkM52MITMOffClient(b, protocol.h2)
								target = "https://example.com/benchmark-body"
							case "mitm-on-no-processor":
								harness = m52ProtocolHarness(b, protocol.h2, echo, nil)
								client = &http.Client{Transport: harness.wire}
							case "goja-continue":
								factory := m52GojaFactory(b, gojaprocessor.Config{
									ID: "m53-body-continue", Source: `function process(input) { return {kind:"continue"}; }`, Request: true, Response: true,
								})
								harness = m52ProtocolHarness(b, protocol.h2, echo, factory)
								client = &http.Client{Transport: harness.wire}
							case "goja-header":
								factory := m52GojaFactory(b, gojaprocessor.Config{
									ID: "m53-body-header", Source: `function process(input) { if (input.phase === "request") return {kind:"request_change",request:{headers:[{op:"set",name:"X-M53-Benchmark",values:["header"]}]}}; return {kind:"continue"}; }`, Request: true,
								})
								harness = m52ProtocolHarness(b, protocol.h2, echo, factory)
								client = &http.Client{Transport: harness.wire}
							case "goja-request-body":
								factory := m52GojaFactory(b, gojaprocessor.Config{
									ID: "m53-request-body", Source: `function process(input) { if (input.phase !== "request") return {kind:"continue"}; if (!input.body.available) throw new Error("body unavailable"); return {kind:"request_change",request:{body:{encoding:"base64",data:input.body.base64}}}; }`, Request: true,
									RequestBody: model.FullBuffered, RequestMaxBodyBytes: 1 << 20,
								})
								harness = m52ProtocolHarness(b, protocol.h2, echo, factory)
								client = &http.Client{Transport: harness.wire}
							case "goja-response-body":
								factory := m52GojaFactory(b, gojaprocessor.Config{
									ID: "m53-response-body", Source: `function process(input) { if (input.phase !== "response") return {kind:"continue"}; if (!input.body.available) throw new Error("body unavailable"); return {kind:"response_change",response:{body:{encoding:"base64",data:input.body.base64}}}; }`, Response: true,
									ResponseBody: model.FullBuffered, ResponseMaxBodyBytes: 1 << 20,
								})
								harness = m52ProtocolHarness(b, protocol.h2, echo, factory)
								client = &http.Client{Transport: harness.wire}
							}
							if cleanup != nil {
								defer func() { b.StopTimer(); cleanup() }()
							}
							send := func() (*http.Response, error) {
								request, err := http.NewRequest(http.MethodPost, target, strings.NewReader(payload))
								if err != nil {
									return nil, err
								}
								if harness != nil {
									return harness.wire.RoundTrip(request)
								}
								return client.Do(request)
							}
							consume := func(response *http.Response) error {
								if want := map[bool]int{false: 1, true: 2}[protocol.h2]; response.ProtoMajor != want {
									return errors.New("benchmark negotiated an unexpected downstream protocol")
								}
								n, err := io.Copy(io.Discard, response.Body)
								closeErr := response.Body.Close()
								if err != nil {
									return fmt.Errorf("response copy after %d bytes (content-length=%d, upstream-read=%d, upstream-read-error=%v): %w", n, response.ContentLength, upstreamRead.Load(), upstreamReadErr.Load(), err)
								}
								if closeErr != nil {
									return closeErr
								}
								wantLength := len(payload)
								if mode == "mitm-off" {
									wantLength = len("ok")
								}
								if n != int64(wantLength) {
									return fmt.Errorf("benchmark response length = %d, want %d (status=%d, content-length=%d, upstream-read=%d)", n, wantLength, response.StatusCode, response.ContentLength, upstreamRead.Load())
								}
								if harness != nil && upstreamRead.Load() != int64(size.n) {
									return fmt.Errorf("upstream read %d request bytes, want %d", upstreamRead.Load(), size.n)
								}
								return nil
							}
							response, err := send()
							if err != nil {
								b.Fatal(err)
							}
							if err := consume(response); err != nil {
								b.Fatal(err)
							}
							connectionsAtWarmup := int32(0)
							if harness != nil {
								connectionsAtWarmup = harness.accepted.Load()
							} else if originConnections != nil {
								connectionsAtWarmup = originConnections.Load()
							}
							b.ReportAllocs()
							b.ReportMetric(float64(size.n), "body-bytes/op")
							b.ResetTimer()
							for index := 0; index < b.N; index++ {
								response, err := send()
								if err != nil {
									b.Fatal(err)
								}
								if err := consume(response); err != nil {
									b.Fatal(err)
								}
							}
							if harness != nil && b.N > 0 {
								newConnections := harness.accepted.Load() - connectionsAtWarmup
								b.ReportMetric(float64(newConnections)/float64(b.N), "origin-conns/op")
							} else if originConnections != nil && b.N > 0 {
								newConnections := originConnections.Load() - connectionsAtWarmup
								b.ReportMetric(float64(newConnections)/float64(b.N), "origin-conns/op")
							}
						})
					}
				})
			}
		})
	}
}

func TestM52GojaHTTP2StreamCancellationAndConcurrentIsolation(t *testing.T) {
	const source = `function process(input) {
  if (input.phase === "request" && input.request.url.indexOf("/cancel") >= 0) while (true) {}
  if (input.phase === "request") return {kind:"request_change",request:{headers:[{op:"set",name:"X-Goja-Path",values:[input.request.url]}]}};
  return {kind:"continue"};
}`
	seen := make(chan string, 12)
	h := m52ProtocolHarness(t, true, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		seen <- request.Header.Get("X-Goja-Path")
		_, _ = io.WriteString(w, request.URL.Path)
	}), m52GojaFactory(t, gojaprocessor.Config{
		ID: "m52-h2-isolation", Source: source, Request: true, Response: true,
		ExecutionTimeout: 2 * time.Second, Capacity: 8,
	}))

	ctx, cancel := context.WithCancel(context.Background())
	canceledRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://localhost/cancel", nil)
	require.NoError(t, err)
	canceledDone := make(chan error, 1)
	go func() {
		response, err := h.client.RoundTrip(canceledRequest)
		if response != nil {
			_ = response.Body.Close()
		}
		canceledDone <- err
	}()
	time.Sleep(75 * time.Millisecond)
	cancel()
	select {
	case err := <-canceledDone:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(3 * time.Second):
		t.Fatal("canceled Goja invocation did not release its HTTP/2 stream")
	}

	const count = 8
	results := make(chan string, count)
	errs := make(chan error, count)
	for index := 0; index < count; index++ {
		go func(index int) {
			path := "/parallel/" + strings.Repeat("x", index+1)
			request, _ := http.NewRequest(http.MethodGet, "https://localhost"+path, nil)
			response, err := h.client.RoundTrip(request)
			if err != nil {
				errs <- err
				return
			}
			body, err := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if err != nil {
				errs <- err
				return
			}
			results <- string(body)
		}(index)
	}
	for index := 0; index < count; index++ {
		select {
		case err := <-errs:
			t.Fatal(err)
		case path := <-results:
			require.Contains(t, path, "/parallel/")
		}
	}
	observed := make(map[string]int)
	for index := 0; index < count; index++ {
		observed[<-seen]++
	}
	require.Len(t, observed, count, "each HTTP/2 stream must carry its own request snapshot")
}

func TestM52GojaHTTP2GenerationUpdateKeepsOldConnectionPinned(t *testing.T) {
	oldFactory := m52GojaFactory(t, gojaprocessor.Config{
		ID: "m52-generation-old",
		Source: `function process(input) {
  if (input.phase !== "request") return {kind:"continue"};
  if (input.request.url.indexOf("/hold") >= 0) while (true) {}
  return {kind:"request_change",request:{headers:[{op:"set",name:"X-Generation",values:["old"]}]}};
}`,
		Request: true, Response: true, Capacity: 8, ExecutionTimeout: time.Second,
	})
	oldUpstream := http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		_, _ = io.WriteString(w, request.Header.Get("X-Generation"))
	})
	h := m52ProtocolHarness(t, true, oldUpstream, oldFactory)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	holdRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://localhost/hold", nil)
	require.NoError(t, err)
	holdResult := make(chan struct {
		response *http.Response
		err      error
	}, 1)
	go func() {
		response, err := h.client.RoundTrip(holdRequest)
		holdResult <- struct {
			response *http.Response
			err      error
		}{response, err}
	}()
	time.Sleep(60 * time.Millisecond)
	select {
	case result := <-holdResult:
		if result.response != nil {
			_ = result.response.Body.Close()
		}
		t.Fatalf("old invocation unexpectedly finished before update: %v", result.err)
	default:
	}

	newConfig := h.manager.ConfigSnapshot()
	newConfig.ProcessorFactory = m52GojaFactory(t, gojaprocessor.Config{
		ID: "m52-generation-new",
		Source: `function process(input) {
  if (input.phase !== "request") return {kind:"continue"};
  return {kind:"request_change",request:{headers:[{op:"set",name:"X-Generation",values:["new"]}]}};
}`,
		Request: true, Response: true,
	})
	started := time.Now()
	require.NoError(t, h.manager.Update(newConfig))
	require.Less(t, time.Since(started), 250*time.Millisecond, "publishing a new Generation must not wait for the old Goja execution")

	oldConnectionResponse := m52RoundTrip(t, h, true, http.MethodGet, "/still-old", "")
	require.Equal(t, "old", m52ReadResponse(t, oldConnectionResponse))

	newConnection := newH2HarnessWithManager(t, h.manager, oldUpstream, false, true)
	newConnectionResponse := h2Request(t, newConnection, http.MethodGet, "/new", "")
	require.Equal(t, "new", m52ReadResponse(t, newConnectionResponse))

	select {
	case result := <-holdResult:
		if result.err != nil {
			t.Fatalf("old request ended without an HTTP response: %v", result.err)
		}
		require.Equal(t, http.StatusGatewayTimeout, result.response.StatusCode)
		_ = m52ReadResponse(t, result.response)
	case <-time.After(3 * time.Second):
		t.Fatal("old Generation invocation did not reach its execution timeout")
	}
}
