package scriptapi

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/mitm/jsruntime"
)

func TestHTTPClientSupportsAllMethodsHeadersAndBodies(t *testing.T) {
	type observedRequest struct {
		method string
		body   string
		token  string
	}
	observed := make(chan observedRequest, 6)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		observed <- observedRequest{method: request.Method, body: string(body), token: request.Header.Get("X-Token")}
		_, _ = fmt.Fprintf(w, "ok:%s:%s", request.Method, string(body))
	}))
	defer server.Close()

	source := fmt.Sprintf(`
		var methods = ["get", "post", "put", "delete", "patch", "head"];
		var results = [];
		var index = 0;
		function next() {
			if (index === methods.length) { $done({results: results}); return; }
			var method = methods[index++];
			$httpClient[method]({url: %q, headers: {"X-Token": "ok"}, body: (method === "get" || method === "head") ? "" : "payload", timeout: 2000}, function(error, response, data) {
				if (error) { $done({error: error}); return; }
				results.push({method: method, status: response.statusCode, body: data});
				next();
			});
		}
		next();
	`, server.URL)
	result := runHostScript(t, source, HostConfig{Namespace: "methods", AllowPrivate: true, HTTPClients: testHTTPClientFactory(server.Client())})
	results := result.(map[string]any)["results"].([]any)
	if len(results) != 6 {
		t.Fatalf("results = %#v, want six HTTP callbacks", results)
	}
	wantMethods := []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"}
	for index, want := range wantMethods {
		request := <-observed
		if request.method != want || request.token != "ok" {
			t.Fatalf("request %d = %#v, want method %s and header", index, request, want)
		}
		if want == http.MethodGet || want == http.MethodHead {
			if request.body != "" {
				t.Fatalf("%s body = %q, want empty", want, request.body)
			}
		} else if request.body != "payload" {
			t.Fatalf("%s body = %q, want payload", want, request.body)
		}
	}
}

func TestHTTPClientTimeoutResponseLimitAndRedirectLimit(t *testing.T) {
	t.Run("timeout", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			time.Sleep(80 * time.Millisecond)
			_, _ = w.Write([]byte("late"))
		}))
		defer server.Close()
		source := fmt.Sprintf(`$httpClient.get({url: %q, timeout: 10}, function(error) { $done({error: error}); });`, server.URL)
		result := runHostScript(t, source, HostConfig{Namespace: "timeout", AllowPrivate: true, HTTPClients: testHTTPClientFactory(server.Client())})
		if !strings.Contains(result.(map[string]any)["error"].(string), "deadline") {
			t.Fatalf("timeout callback = %#v", result)
		}
	})

	t.Run("response body limit", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(strings.Repeat("x", maxHTTPBodyBytes+1)))
		}))
		defer server.Close()
		source := fmt.Sprintf(`$httpClient.get({url: %q}, function(error) { $done({error: error}); });`, server.URL)
		result := runHostScript(t, source, HostConfig{Namespace: "body-limit", AllowPrivate: true, HTTPClients: testHTTPClientFactory(server.Client())})
		if !strings.Contains(result.(map[string]any)["error"].(string), "exceeds 1 MiB") {
			t.Fatalf("oversized response callback = %#v", result)
		}
	})

	t.Run("redirect limit", func(t *testing.T) {
		var requests atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
			requests.Add(1)
			http.Redirect(w, request, "/redirect", http.StatusFound)
		}))
		defer server.Close()
		source := fmt.Sprintf(`$httpClient.get({url: %q}, function(error) { $done({error: error}); });`, server.URL)
		result := runHostScript(t, source, HostConfig{Namespace: "redirects", AllowPrivate: true, HTTPClients: testHTTPClientFactory(server.Client())})
		if !strings.Contains(result.(map[string]any)["error"].(string), "redirect limit") {
			t.Fatalf("redirect callback = %#v", result)
		}
		if requests.Load() > maxRedirects+1 {
			t.Fatalf("redirect request count = %d, limit is %d", requests.Load(), maxRedirects+1)
		}
	})
}

func TestHTTPClientPrivateAddressPolicyAndHeadersValidation(t *testing.T) {
	for _, target := range []string{"http://127.0.0.1/", "http://[2002:c0a8:0101::1]/"} {
		if _, _, err := buildHTTPRequest(context.Background(), http.MethodGet, map[string]any{"url": target}, false); err == nil {
			t.Fatalf("sensitive URL %q passed the default policy", target)
		}
	}
	if _, _, err := buildHTTPRequest(context.Background(), http.MethodGet, map[string]any{"url": "http://127.0.0.1/", "headers": map[string]any{"Connection": "keep-alive"}}, true); err == nil {
		t.Fatal("forbidden hop-by-hop header passed validation")
	}
	if _, _, err := buildHTTPRequest(context.Background(), http.MethodGet, map[string]any{"url": "http://127.0.0.1/"}, true); err != nil {
		t.Fatalf("explicit private-network opt-in rejected URL: %v", err)
	}
}

func TestHTTPTasksAfterDoneAreIgnored(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte("unexpected"))
	}))
	defer server.Close()
	source := fmt.Sprintf(`
		$done({value: "first"});
		$httpClient.get({url: %q}, function() { $done({value: "second"}); });
		console.log("continued");
	`, server.URL)
	result := runHostScript(t, source, HostConfig{Namespace: "done", AllowPrivate: true, HTTPClients: testHTTPClientFactory(server.Client())})
	if result.(map[string]any)["value"] != "first" {
		t.Fatalf("completion result = %#v, want first $done value", result)
	}
	if requests.Load() != 0 {
		t.Fatalf("post-done HTTP request count = %d, want 0", requests.Load())
	}
}

func TestHTTPClientParallelRequestsStayWithinSessionLimit(t *testing.T) {
	var active atomic.Int32
	var peak atomic.Int32
	var goroutinePeak atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		goroutines := int32(runtime.NumGoroutine())
		for observed := goroutinePeak.Load(); goroutines > observed; observed = goroutinePeak.Load() {
			if goroutinePeak.CompareAndSwap(observed, goroutines) {
				break
			}
		}
		current := active.Add(1)
		for observed := peak.Load(); current > observed; observed = peak.Load() {
			if peak.CompareAndSwap(observed, current) {
				break
			}
		}
		time.Sleep(25 * time.Millisecond)
		active.Add(-1)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()
	source := fmt.Sprintf(`
		var completed = 0;
		function done(error) { if (error) throw new Error(error); completed++; if (completed === 4) $done({completed: completed}); }
		for (var i = 0; i < 4; i++) $httpClient.get({url: %q}, done);
	`, server.URL)
	result := runHostScript(t, source, HostConfig{Namespace: "parallel", AllowPrivate: true, HTTPClients: testHTTPClientFactory(server.Client())})
	if result.(map[string]any)["completed"] != float64(4) {
		t.Fatalf("parallel callback result = %#v", result)
	}
	if peak.Load() < 2 || peak.Load() > 4 {
		t.Fatalf("observed parallel request peak = %d, want 2 through 4", peak.Load())
	}
	if active, globalPeak := HTTPTaskStats(); active != 0 || globalPeak > 8 {
		t.Fatalf("global HTTP task stats = active %d, peak %d; want active 0, peak <= 8", active, globalPeak)
	} else {
		t.Logf("M4.3 script HTTP Client task peak: %d (global limit %d), active server request peak: %d, observed goroutine peak: %d",
			globalPeak, cap(globalHTTPTasks), peak.Load(), goroutinePeak.Load())
	}
}

func TestHTTPRequestsCompleteAndTimeoutInterleavedInOneSession(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/timeout" {
			<-request.Context().Done()
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer server.Close()
	source := fmt.Sprintf(`
		var callbacks = 0, successes = 0, errors = 0;
		function complete(error, response, data) {
			callbacks++;
			if (error) errors++;
			else if (response.statusCode === 200 && data === "ok") successes++;
			if (callbacks === 4) $done({callbacks: callbacks, successes: successes, errors: errors});
		}
		$httpClient.get({url: %q, timeout: 1000}, complete);
		$httpClient.get({url: %q, timeout: 20}, complete);
		$httpClient.get({url: %q, timeout: 1000}, complete);
		$httpClient.get({url: %q, timeout: 20}, complete);
	`, server.URL+"/fast", server.URL+"/timeout", server.URL+"/fast", server.URL+"/timeout")
	before, _ := HTTPTaskStats()
	result := runHostScript(t, source, HostConfig{Namespace: "interleaved", AllowPrivate: true, HTTPClients: testHTTPClientFactory(server.Client())})
	values := result.(map[string]any)
	if values["callbacks"] != float64(4) || values["successes"] != float64(2) || values["errors"] != float64(2) {
		t.Fatalf("interleaved HTTP callbacks = %#v, want 4 total, 2 success, 2 timeout", values)
	}
	if active, _ := HTTPTaskStats(); active != before {
		t.Fatalf("active HTTP task count after interleaved completion = %d, want %d", active, before)
	}
}

func TestHostCloseCancelsActiveHTTPRequestAndReleasesResources(t *testing.T) {
	started := make(chan struct{})
	serverCanceled := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		close(started)
		<-request.Context().Done()
		close(serverCanceled)
	}))
	defer server.Close()

	cleanupCalls := atomic.Int32{}
	host, err := NewHost(HostConfig{
		Namespace:    "close-active",
		AllowPrivate: true,
		HTTPClients: func(bool) (*http.Client, func(), error) {
			return server.Client(), func() { cleanupCalls.Add(1) }, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	before, _ := HTTPTaskStats()
	session := &contractSession{}
	if err := callHostHTTP(host, session, server.URL); err != nil {
		t.Fatal(err)
	}
	workDone := make(chan error, 1)
	go func() {
		_, workErr := session.work(context.Background())
		workDone <- workErr
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("server did not observe the active HTTP request")
	}

	closeReturned := make(chan struct{})
	go func() {
		host.Close()
		close(closeReturned)
	}()
	select {
	case <-closeReturned:
	case <-time.After(time.Second):
		t.Fatal("Host.Close waited for the active network request")
	}
	host.Close()
	select {
	case <-serverCanceled:
	case <-time.After(time.Second):
		t.Fatal("Host.Close did not cancel the server request")
	}
	select {
	case err := <-workDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("active HTTP task error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("active HTTP task did not finish after Host.Close")
	}
	if active, _ := HTTPTaskStats(); active != before {
		t.Fatalf("active HTTP task count after Close = %d, want %d", active, before)
	}
	if cleanupCalls.Load() != 1 {
		t.Fatalf("HTTP client cleanup calls = %d, want exactly one", cleanupCalls.Load())
	}
	if err := callHostHTTP(host, &contractSession{}, server.URL); !errors.Is(err, ErrHostClosed) {
		t.Fatalf("request after Host.Close error = %v, want ErrHostClosed", err)
	}
}

func TestHostCloseAndHTTPTaskRegistrationRace(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("request ran after Host.Close won registration race")
	}))
	defer server.Close()
	host, err := NewHost(HostConfig{
		Namespace:    "close-register-race",
		AllowPrivate: true,
		HTTPClients:  testHTTPClientFactory(server.Client()),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	before, _ := HTTPTaskStats()
	session := &contractSession{}
	start := make(chan struct{})
	callResult := make(chan error, 1)
	closeResult := make(chan struct{})
	go func() {
		<-start
		callResult <- callHostHTTP(host, session, server.URL)
	}()
	go func() {
		<-start
		host.Close()
		close(closeResult)
	}()
	close(start)
	<-closeResult
	err = <-callResult
	if err == nil {
		if session.work == nil {
			t.Fatal("successful Schedule did not provide its task")
		}
		_, workErr := session.work(context.Background())
		if !errors.Is(workErr, context.Canceled) {
			t.Fatalf("task accepted before Close error = %v, want cancellation", workErr)
		}
	} else if !errors.Is(err, ErrHostClosed) {
		t.Fatalf("concurrent Schedule error = %v, want nil or ErrHostClosed", err)
	}
	if err := callHostHTTP(host, &contractSession{}, server.URL); !errors.Is(err, ErrHostClosed) {
		t.Fatalf("post-close Schedule error = %v, want ErrHostClosed", err)
	}
	if active, _ := HTTPTaskStats(); active != before {
		t.Fatalf("active HTTP task count after registration race = %d, want %d", active, before)
	}
}

func TestSessionCancellationRacesWithHTTPResponse(t *testing.T) {
	started := make(chan struct{})
	releaseResponse := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		close(started)
		select {
		case <-releaseResponse:
			_, _ = w.Write([]byte("ok"))
		case <-request.Context().Done():
		}
	}))
	defer server.Close()
	host, err := NewHost(HostConfig{Namespace: "session-response-race", AllowPrivate: true, HTTPClients: testHTTPClientFactory(server.Client())})
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	before, _ := HTTPTaskStats()
	session := &contractSession{}
	if err := callHostHTTP(host, session, server.URL); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	workDone := make(chan error, 1)
	go func() {
		_, workErr := session.work(ctx)
		workDone <- workErr
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("server did not observe the request")
	}
	gate := make(chan struct{})
	var race sync.WaitGroup
	race.Add(3)
	go func() { defer race.Done(); <-gate; close(releaseResponse) }()
	go func() { defer race.Done(); <-gate; cancel() }()
	go func() { defer race.Done(); <-gate; host.Close() }()
	close(gate)
	race.Wait()
	select {
	case err := <-workDone:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("racing task error = %v, want success or cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("HTTP task did not finish after response/cancel race")
	}
	if active, _ := HTTPTaskStats(); active != before {
		t.Fatalf("active HTTP task count after response/cancel race = %d, want %d", active, before)
	}
}

func TestAlreadyCanceledSessionDoesNotStartHTTPRequest(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte("unexpected"))
	}))
	defer server.Close()
	host, err := NewHost(HostConfig{Namespace: "already-canceled", AllowPrivate: true, HTTPClients: testHTTPClientFactory(server.Client())})
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	before, _ := HTTPTaskStats()
	session := &contractSession{}
	if err := callHostHTTP(host, session, server.URL); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := session.work(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("already-canceled session work error = %v, want context.Canceled", err)
	}
	if requests.Load() != 0 {
		t.Fatalf("requests started with an already-canceled session = %d, want 0", requests.Load())
	}
	if active, _ := HTTPTaskStats(); active != before {
		t.Fatalf("active HTTP task count after already-canceled session = %d, want %d", active, before)
	}
}

func TestHostCloseClosesResponseBodyAndIdleConnection(t *testing.T) {
	bodyRead := make(chan struct{})
	bodyClosed := make(chan struct{})
	var readOnce, closeOnce sync.Once
	client := &http.Client{Transport: testRoundTripper(func(request *http.Request) (*http.Response, error) {
		body := &blockingResponseBody{ctx: request.Context(), reading: bodyRead, closed: bodyClosed, readOnce: &readOnce, closeOnce: &closeOnce}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: body, Request: request}, nil
	})}
	cleanupCalls := atomic.Int32{}
	host, err := NewHost(HostConfig{
		Namespace:    "close-body",
		AllowPrivate: true,
		HTTPClients: func(bool) (*http.Client, func(), error) {
			return client, func() { cleanupCalls.Add(1) }, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	session := &contractSession{}
	if err := callHostHTTP(host, session, "http://example.com/"); err != nil {
		t.Fatal(err)
	}
	workDone := make(chan error, 1)
	go func() {
		_, workErr := session.work(context.Background())
		workDone <- workErr
	}()
	select {
	case <-bodyRead:
	case <-time.After(time.Second):
		t.Fatal("HTTP response body was not read")
	}
	host.Close()
	host.Close()
	select {
	case <-bodyClosed:
	case <-time.After(time.Second):
		t.Fatal("Host.Close did not release the response body")
	}
	select {
	case err := <-workDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("body read task error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("body read task did not exit")
	}
	if cleanupCalls.Load() != 1 {
		t.Fatalf("cleanup calls = %d, want exactly one after repeated Close", cleanupCalls.Load())
	}
}

func TestHostCloseClosesIdleHTTPConnection(t *testing.T) {
	closed := make(chan struct{}, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateClosed {
			select {
			case closed <- struct{}{}:
			default:
			}
		}
	}
	server.Start()
	defer server.Close()
	host, err := NewHost(HostConfig{Namespace: "close-idle-connection", AllowPrivate: true, HTTPClients: testHTTPClientFactory(server.Client())})
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	session := &contractSession{}
	if err := callHostHTTP(host, session, server.URL); err != nil {
		t.Fatal(err)
	}
	if _, err := session.work(context.Background()); err != nil {
		t.Fatal(err)
	}
	host.Close()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Host.Close did not release the idle HTTP connection")
	}
}

func TestHostCloseWithUnresponsiveTransportAndClosedRuntime(t *testing.T) {
	started := make(chan context.Context, 1)
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	bodyClosed := make(chan struct{})
	client := &http.Client{Transport: testRoundTripper(func(request *http.Request) (*http.Response, error) {
		started <- request.Context()
		// Deliberately ignore cancellation. The gate bounds this otherwise
		// unsupported transport so the test itself leaves no blocked worker.
		<-release
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Request: request,
			Body: &lateResponseBody{Reader: strings.NewReader("late"), closed: bodyClosed}}, nil
	})}
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	host, err := NewHost(HostConfig{Namespace: "late-worker", Store: store, HTTPClients: testHTTPClientFactory(client)})
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	rt, err := jsruntime.New(jsruntime.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()
	compiled, err := rt.Compile(`$httpClient.get({url: "http://example.com/"}, function() {
		$persistentStore.write("called", "callback"); $done();
	});`)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := HTTPTaskStats()
	runDone := make(chan error, 1)
	go func() {
		_, runErr := rt.RunSession(context.Background(), compiled, jsruntime.SessionOptions{
			Host: host, Bindings: Bindings(), Timeout: 3 * time.Second, MaxPendingTasks: 4,
		})
		runDone <- runErr
	}()
	var requestCtx context.Context
	select {
	case requestCtx = <-started:
	case <-time.After(time.Second):
		t.Fatal("transport did not start")
	}
	closeDone := make(chan struct{})
	go func() { host.Close(); host.Close(); close(closeDone) }()
	select {
	case <-closeDone:
	case <-time.After(time.Second):
		t.Fatal("Host.Close waited for the unresponsive transport")
	}
	if !errors.Is(requestCtx.Err(), context.Canceled) {
		t.Fatalf("request context after Close = %v", requestCtx.Err())
	}
	if err := rt.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case runErr := <-runDone:
		if !errors.Is(runErr, jsruntime.ErrClosed) {
			t.Fatalf("RunSession error = %v, want ErrClosed", runErr)
		}
	case <-time.After(time.Second):
		t.Fatal("Runtime waited for the unresponsive transport")
	}
	if active, _ := HTTPTaskStats(); active != before+1 {
		t.Fatalf("blocked transport active tasks = %d, want %d", active, before+1)
	}
	if err := callHostHTTP(host, &contractSession{}, "http://example.com/"); !errors.Is(err, ErrHostClosed) {
		t.Fatalf("post-close registration = %v, want ErrHostClosed", err)
	}
	unblock()
	select {
	case <-bodyClosed:
	case <-time.After(time.Second):
		t.Fatal("late response body was not closed")
	}
	deadline := time.Now().Add(time.Second)
	for {
		host.mu.Lock()
		remaining := len(host.tasks)
		host.mu.Unlock()
		active, _ := HTTPTaskStats()
		if remaining == 0 && active == before {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("late worker retained tasks=%d active=%d, baseline=%d", remaining, active, before)
		}
		time.Sleep(time.Millisecond)
	}
	if _, exists, err := store.Read("late-worker", "callback"); err != nil || exists {
		t.Fatalf("callback after Runtime exit: exists=%t err=%v", exists, err)
	}
}

type lateResponseBody struct {
	io.Reader
	closed chan struct{}
	once   sync.Once
}

func (body *lateResponseBody) Close() error {
	body.once.Do(func() { close(body.closed) })
	return nil
}

func callHostHTTP(host *Host, session *contractSession, target string) error {
	_, err := host.Call(context.Background(), session, jsruntime.HostCall{
		Name: "$httpClient.get", CallbackID: 1,
		Args: []any{map[string]any{"url": target}},
	})
	return err
}

type testRoundTripper func(*http.Request) (*http.Response, error)

func (roundTripper testRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTripper(request)
}

type blockingResponseBody struct {
	ctx       context.Context
	reading   chan struct{}
	closed    chan struct{}
	readOnce  *sync.Once
	closeOnce *sync.Once
}

func (body *blockingResponseBody) Read([]byte) (int, error) {
	body.readOnce.Do(func() { close(body.reading) })
	<-body.ctx.Done()
	return 0, body.ctx.Err()
}

func (body *blockingResponseBody) Close() error {
	body.closeOnce.Do(func() { close(body.closed) })
	return nil
}

func TestPersistentStoreNotificationEnvironmentAndLogContracts(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	logger := &testLogSink{}
	host, err := NewHost(HostConfig{Namespace: "rule", Store: store, Log: logger})
	if err != nil {
		t.Fatal(err)
	}
	if value, err := host.Call(context.Background(), nil, jsruntime.HostCall{Name: "$persistentStore.write", Args: []any{"value", "key"}}); err != nil || value != true {
		t.Fatalf("persistent write = %#v, %v", value, err)
	}
	if value, err := host.Call(context.Background(), nil, jsruntime.HostCall{Name: "$persistentStore.read", Args: []any{"key"}}); err != nil || value != "value" {
		t.Fatalf("persistent read = %#v, %v", value, err)
	}
	if value, err := host.Call(context.Background(), nil, jsruntime.HostCall{Name: "$notification.post", Args: []any{"title"}}); err != nil || value != false {
		t.Fatalf("unavailable notification = %#v, %v; want false", value, err)
	}
	if err := host.CallLogForTest(strings.Repeat("a", maxLogMessageBytes+100)); err != nil {
		t.Fatal(err)
	}
	if logger.length != maxLogMessageBytes {
		t.Fatalf("log message length = %d, want %d", logger.length, maxLogMessageBytes)
	}
	environment := Environment()
	if len(environment) != 2 || environment["platform"] == nil || environment["architecture"] == nil {
		t.Fatalf("unexpected environment fields: %#v", environment)
	}
}

type testLogSink struct{ length int }

func (sink *testLogSink) Log(_ string, message string) { sink.length = len(message) }

func (h *Host) CallLogForTest(message string) error {
	_, err := h.Call(context.Background(), nil, jsruntime.HostCall{Name: "console.log", Args: []any{message}})
	return err
}

func testHTTPClientFactory(client *http.Client) HTTPClientFactory {
	return func(bool) (*http.Client, func(), error) { return client, nil, nil }
}

func runHostScript(t *testing.T, source string, config HostConfig) any {
	t.Helper()
	runtime, err := jsruntime.New(jsruntime.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	host, err := NewHost(config)
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	compiled, err := runtime.Compile(source)
	if err != nil {
		t.Fatal(err)
	}
	result, err := runtime.RunSession(context.Background(), compiled, jsruntime.SessionOptions{
		Host: host, Bindings: Bindings(), Timeout: 3 * time.Second, MaxPendingTasks: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}
