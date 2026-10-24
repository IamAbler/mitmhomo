package mitm

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"testing"
	"time"
)

type m2RoundTripperFunc func(*http.Request) (*http.Response, error)

func (roundTrip m2RoundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTrip(request)
}

type m2TestNetworkTimeout string

func (err m2TestNetworkTimeout) Error() string { return string(err) }
func (m2TestNetworkTimeout) Timeout() bool     { return true }
func (m2TestNetworkTimeout) Temporary() bool   { return true }

type m2TestGo120ResponseHeaderTimeout struct{}

func (m2TestGo120ResponseHeaderTimeout) Error() string {
	return "net/http: timeout awaiting response headers"
}
func (m2TestGo120ResponseHeaderTimeout) Timeout() bool { return true }
func (m2TestGo120ResponseHeaderTimeout) Temporary() bool {
	return true
}

func logM2TimeoutStatus(t *testing.T, scenario string, got, want int) {
	t.Helper()
	t.Logf("M2_TIMEOUT_STATUS scenario=%s got=%d want=%d", scenario, got, want)
}

func m2ProxyForRoundTripError(roundTripErr error, trackedWriter *commitTrackingWriter) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Transport: m2RoundTripperFunc(func(*http.Request) (*http.Response, error) {
			return nil, roundTripErr
		}),
		Rewrite:      func(*httputil.ProxyRequest) {},
		ErrorHandler: upstreamErrorHandler(trackedWriter, nil),
	}
}

func TestM2Go120ResponseHeaderTimeoutErrorCompatibility(t *testing.T) {
	var roundTripErr error = fmt.Errorf("wrapped by upstream adapter: %w", m2TestGo120ResponseHeaderTimeout{})
	if errors.Is(roundTripErr, context.DeadlineExceeded) {
		t.Fatal("Go 1.20 compatibility fixture unexpectedly matches context.DeadlineExceeded")
	}
	var networkErr net.Error
	if !errors.As(roundTripErr, &networkErr) || !networkErr.Timeout() {
		t.Fatalf("Go 1.20 compatibility fixture is not a timed out net.Error: %T: %v", roundTripErr, roundTripErr)
	}
	if !isRequestTimeoutError(roundTripErr, nil, nil, nil) {
		t.Fatal("Go 1.20 ResponseHeaderTimeout error was not classified as a request timeout")
	}
	wrappedErr := fmt.Errorf("wrapped by upstream adapter: %w", roundTripErr)
	if !isRequestTimeoutError(wrappedErr, nil, nil, nil) {
		t.Fatalf("wrapped Go 1.20 ResponseHeaderTimeout was not classified: %T: %v", wrappedErr, wrappedErr)
	}

	responseRecorder := httptest.NewRecorder()
	trackedWriter := &commitTrackingWriter{ResponseWriter: responseRecorder}
	requestContext, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	request := httptest.NewRequest(http.MethodGet, "http://upstream.test/", nil).WithContext(requestContext)
	m2ProxyForRoundTripError(roundTripErr, trackedWriter).ServeHTTP(trackedWriter, request)
	if responseRecorder.Code != http.StatusGatewayTimeout {
		t.Fatalf("production ErrorHandler status for wrapped Go 1.20 error = %d, want %d", responseRecorder.Code, http.StatusGatewayTimeout)
	}
	logM2TimeoutStatus(t, "go120_error_handler", responseRecorder.Code, http.StatusGatewayTimeout)

	canceledContext, cancelRequest := context.WithCancel(context.Background())
	cancelRequest()
	canceledRecorder := httptest.NewRecorder()
	canceledWriter := &commitTrackingWriter{ResponseWriter: canceledRecorder}
	canceledRequest := httptest.NewRequest(http.MethodGet, "http://upstream.test/", nil).WithContext(canceledContext)
	m2ProxyForRoundTripError(roundTripErr, canceledWriter).ServeHTTP(canceledWriter, canceledRequest)
	if canceledWriter.Committed() || canceledRecorder.Body.Len() != 0 {
		t.Fatalf("canceled request with a concurrent response timeout wrote an HTTP response: status=%d body=%q", canceledRecorder.Code, canceledRecorder.Body.String())
	}
	t.Logf("M2_TIMEOUT_CANCEL scenario=concurrent_response_timeout committed=%t body_bytes=%d", canceledWriter.Committed(), canceledRecorder.Body.Len())
}

func TestM2ResponseHeaderTimeoutIsClassifiedAsGatewayTimeout(t *testing.T) {
	started := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		started <- struct{}{}
		<-r.Context().Done()
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{ResponseHeaderTimeout: 150 * time.Millisecond}
	defer transport.CloseIdleConnections()

	_, roundTripErr := transport.RoundTrip(request)
	if roundTripErr == nil {
		t.Fatal("RoundTrip succeeded without upstream response headers")
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("request did not reach the local upstream")
	}
	if ctx.Err() != nil {
		t.Fatalf("request context expired before the independent response-header timeout: %v", ctx.Err())
	}
	var networkErr net.Error
	if !errors.As(roundTripErr, &networkErr) {
		t.Fatalf("response-header timeout is not a net.Error: %T: %v", roundTripErr, roundTripErr)
	}
	if !networkErr.Timeout() {
		t.Fatalf("response-header timeout Timeout() = false: %T: %v", roundTripErr, roundTripErr)
	}
	t.Logf("ResponseHeaderTimeout type=%T text=%q IsDeadlineExceeded=%t AsNetError=true Timeout=%t contextErr=%v cause=%v",
		roundTripErr, roundTripErr, errors.Is(roundTripErr, context.DeadlineExceeded), networkErr.Timeout(), ctx.Err(), context.Cause(ctx))
	for index, wrapped := 0, roundTripErr; wrapped != nil; index, wrapped = index+1, errors.Unwrap(wrapped) {
		t.Logf("error chain[%d]=%T %q", index, wrapped, wrapped)
	}

	if !isHTTP1ResponseHeaderTimeout(roundTripErr) {
		t.Fatalf("did not identify net/http ResponseHeaderTimeout error: %T: %v", roundTripErr, roundTripErr)
	}
	if !isRequestTimeoutError(roundTripErr, ctx.Err(), context.Cause(ctx), nil) {
		t.Fatal("ResponseHeaderTimeout was not classified as a request timeout")
	}
	wrappedErr := fmt.Errorf("wrapped by upstream adapter: %w", roundTripErr)
	if !isRequestTimeoutError(wrappedErr, nil, nil, nil) {
		t.Fatalf("wrapped ResponseHeaderTimeout was not classified: %T: %v", wrappedErr, wrappedErr)
	}
	if isRequestTimeoutError(wrappedErr, context.Canceled, context.Canceled, nil) {
		t.Fatal("a canceled request was classified as a timeout because its upstream error also timed out")
	}
}

func TestM2ResponseHeaderTimeoutReturns504ThroughProductionErrorHandler(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()

	transport := &http.Transport{ResponseHeaderTimeout: 150 * time.Millisecond}
	defer transport.CloseIdleConnections()
	var roundTripErr error
	responseRecorder := httptest.NewRecorder()
	trackedWriter := &commitTrackingWriter{ResponseWriter: responseRecorder}
	proxy := &httputil.ReverseProxy{
		Transport: m2RoundTripperFunc(func(request *http.Request) (*http.Response, error) {
			response, err := transport.RoundTrip(request)
			roundTripErr = err
			return response, err
		}),
		Rewrite:      func(*httputil.ProxyRequest) {},
		ErrorHandler: upstreamErrorHandler(trackedWriter, nil),
	}
	requestContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	request := httptest.NewRequest(http.MethodGet, server.URL, nil).WithContext(requestContext)
	proxy.ServeHTTP(trackedWriter, request)

	if !isHTTP1ResponseHeaderTimeout(roundTripErr) {
		t.Fatalf("proxy round trip error is not ResponseHeaderTimeout: %T: %v", roundTripErr, roundTripErr)
	}
	if responseRecorder.Code != http.StatusGatewayTimeout {
		t.Fatalf("production ErrorHandler status = %d, want %d (error %T: %v)", responseRecorder.Code, http.StatusGatewayTimeout, roundTripErr, roundTripErr)
	}
	logM2TimeoutStatus(t, "response_header_handler", responseRecorder.Code, http.StatusGatewayTimeout)
}

func TestM2RequestContextDeadlineRemainsGatewayTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{ResponseHeaderTimeout: time.Second}
	defer transport.CloseIdleConnections()
	var roundTripErr error
	responseRecorder := httptest.NewRecorder()
	trackedWriter := &commitTrackingWriter{ResponseWriter: responseRecorder}
	proxy := &httputil.ReverseProxy{
		Transport: m2RoundTripperFunc(func(request *http.Request) (*http.Response, error) {
			response, err := transport.RoundTrip(request)
			roundTripErr = err
			return response, err
		}),
		Rewrite:      func(*httputil.ProxyRequest) {},
		ErrorHandler: upstreamErrorHandler(trackedWriter, nil),
	}
	proxy.ServeHTTP(trackedWriter, request)
	if !errors.Is(roundTripErr, context.DeadlineExceeded) {
		t.Fatalf("RoundTrip error = %T: %v, want context deadline", roundTripErr, roundTripErr)
	}
	if !isRequestTimeoutError(roundTripErr, ctx.Err(), context.Cause(ctx), nil) {
		t.Fatalf("context deadline was not classified as a timeout: %T: %v", roundTripErr, roundTripErr)
	}
	if responseRecorder.Code != http.StatusGatewayTimeout {
		t.Fatalf("production ErrorHandler status for request deadline = %d, want %d", responseRecorder.Code, http.StatusGatewayTimeout)
	}
	logM2TimeoutStatus(t, "request_context_deadline", responseRecorder.Code, http.StatusGatewayTimeout)
}

func TestM2ActiveUpstreamRequestCancellationIsNotGatewayTimeout(t *testing.T) {
	started := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		started <- struct{}{}
		<-r.Context().Done()
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{ResponseHeaderTimeout: time.Second}
	defer transport.CloseIdleConnections()
	done := make(chan error, 1)
	go func() {
		_, roundTripErr := transport.RoundTrip(request)
		done <- roundTripErr
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("request did not reach the local upstream")
	}
	cancel()
	select {
	case roundTripErr := <-done:
		if !errors.Is(roundTripErr, context.Canceled) {
			t.Fatalf("RoundTrip error = %T: %v, want context.Canceled", roundTripErr, roundTripErr)
		}
		if isRequestTimeoutError(roundTripErr, ctx.Err(), context.Cause(ctx), nil) {
			t.Fatalf("active cancellation was classified as a timeout: %T: %v", roundTripErr, roundTripErr)
		}
		t.Log("M2_TIMEOUT_CANCEL scenario=active_upstream_roundtrip classified_timeout=false")
	case <-time.After(time.Second):
		t.Fatal("RoundTrip did not stop after context cancellation")
	}
}

func TestM2OrdinaryUpstreamErrorsAreNotGatewayTimeouts(t *testing.T) {
	t.Run("matching text without network timeout", func(t *testing.T) {
		err := errors.New("net/http: timeout awaiting response headers")
		if isHTTP1ResponseHeaderTimeout(err) {
			t.Fatal("matching text without net.Error matched HTTP/1 ResponseHeaderTimeout")
		}
		if isRequestTimeoutError(err, nil, nil, nil) {
			t.Fatal("matching text without net.Error was classified as a request timeout")
		}
	})

	t.Run("unrelated network timeout", func(t *testing.T) {
		err := m2TestNetworkTimeout("dial operation timed out")
		if isHTTP1ResponseHeaderTimeout(err) {
			t.Fatal("unrelated net.Error timeout matched HTTP/1 ResponseHeaderTimeout")
		}
		if isRequestTimeoutError(err, nil, nil, nil) {
			t.Fatal("unrelated network timeout was classified as an upstream response timeout")
		}
	})

	t.Run("connection refused", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		address := listener.Addr().String()
		if err := listener.Close(); err != nil {
			t.Fatal(err)
		}

		transport := &http.Transport{}
		defer transport.CloseIdleConnections()
		request, err := http.NewRequest(http.MethodGet, "http://"+address, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, roundTripErr := transport.RoundTrip(request)
		if roundTripErr == nil {
			t.Fatal("RoundTrip succeeded after the listener was closed")
		}
		if isRequestTimeoutError(roundTripErr, request.Context().Err(), context.Cause(request.Context()), nil) {
			t.Fatalf("connection refusal was classified as a timeout: %T: %v", roundTripErr, roundTripErr)
		}
	})

	t.Run("abrupt disconnect", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			hijacker, ok := w.(http.Hijacker)
			if !ok {
				t.Error("local HTTP server does not support hijacking")
				return
			}
			conn, _, err := hijacker.Hijack()
			if err != nil {
				t.Errorf("hijack upstream connection: %v", err)
				return
			}
			_ = conn.Close()
		}))
		defer server.Close()

		transport := &http.Transport{}
		defer transport.CloseIdleConnections()
		request, err := http.NewRequest(http.MethodGet, server.URL, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, roundTripErr := transport.RoundTrip(request)
		if roundTripErr == nil {
			t.Fatal("RoundTrip succeeded after the upstream closed the connection")
		}
		if isRequestTimeoutError(roundTripErr, request.Context().Err(), context.Cause(request.Context()), nil) {
			t.Fatalf("abrupt disconnect was classified as a timeout: %T: %v", roundTripErr, roundTripErr)
		}
	})
}
