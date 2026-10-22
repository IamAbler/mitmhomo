package mitm

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/mitm/httphook"
	"github.com/stretchr/testify/require"
)

func m42Hooks(t *testing.T, config httphook.Config) *httphook.Snapshot {
	t.Helper()
	snapshot, err := httphook.Compile(config)
	require.NoError(t, err)
	t.Cleanup(func() { _ = snapshot.Close() })
	return snapshot
}

func m42RequestResponseHooks(t *testing.T) *httphook.Snapshot {
	return m42Hooks(t, httphook.Config{Enable: true, Rules: []httphook.Rule{
		{
			Name: "request", Phase: httphook.RequestPhase,
			Match:  httphook.Match{Path: "/original", Methods: []string{http.MethodPost}},
			Source: `({url: input.url.replace("/original", "/scripted"), method: "PUT", headers: Object.assign({}, input.headers, {"X-Script": ["request"]}), body: input.body + "-request"})`,
		},
		{
			Name: "response", Phase: httphook.ResponsePhase,
			Match:  httphook.Match{Path: "/scripted", ResponseStatus: []int{200}},
			Source: `({status: 201, headers: Object.assign({}, input.headers, {"X-Script-Response": ["response"], "Content-Type": ["text/x-script"]}), body: input.body + "-response"})`,
		},
		{
			Name: "empty-response", Phase: httphook.ResponsePhase,
			Match:  httphook.Match{Path: "/empty", ResponseStatus: []int{204}},
			Source: `({headers: Object.assign({}, input.headers, {"X-Empty-Hook": ["yes"]})})`,
		},
		{
			Name: "head-response", Phase: httphook.ResponsePhase,
			Match:  httphook.Match{Path: "/head", ResponseStatus: []int{200}},
			Source: `({headers: Object.assign({}, input.headers, {"X-Head-Hook": ["yes"]}), body: "head representation"})`,
		},
		{
			Name: "not-modified-response", Phase: httphook.ResponsePhase,
			Match:  httphook.Match{Path: "/not-modified", ResponseStatus: []int{304}},
			Source: `({headers: Object.assign({}, input.headers, {"X-304-Hook": ["yes"]})})`,
		},
	}})
}

func TestM42RequestAndResponseHooksHTTP11AndHTTP2(t *testing.T) {
	for _, protocol := range []struct {
		name         string
		downstreamH2 bool
		upstreamALPN []string
	}{
		{name: "http11", upstreamALPN: []string{"http/1.1"}},
		{name: "http2", downstreamH2: true, upstreamALPN: []string{"h2"}},
	} {
		t.Run(protocol.name, func(t *testing.T) {
			hooks := m42RequestResponseHooks(t)
			upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/empty" {
					w.WriteHeader(http.StatusNoContent)
					return
				}
				if r.URL.Path == "/head" {
					w.Header().Set("Content-Length", "11")
					w.WriteHeader(http.StatusOK)
					return
				}
				if r.URL.Path == "/not-modified" {
					w.Header().Set("ETag", `"m42"`)
					w.WriteHeader(http.StatusNotModified)
					return
				}
				body, err := io.ReadAll(r.Body)
				if err != nil {
					http.Error(w, "read failed", http.StatusBadRequest)
					return
				}
				w.Header().Set("Content-Type", "text/plain")
				_, _ = fmt.Fprintf(w, "%s|%s|%s|%s", r.Method, r.URL.Path, r.Header.Get("X-Script"), body)
			})
			h := newProtocolHarness(t, nil, "localhost", 443, upstream, false, true, protocol.downstreamH2, protocol.upstreamALPN, func(c *Config) { c.ScriptHooks = hooks })
			request := m42NewRequest(t, http.MethodPost, "/original", "payload")
			response, err := h.wire.RoundTrip(request)
			require.NoError(t, err)
			body, err := io.ReadAll(response.Body)
			require.NoError(t, err)
			require.NoError(t, response.Body.Close())
			require.Equal(t, http.StatusCreated, response.StatusCode)
			require.Equal(t, "PUT|/scripted|request|payload-request-response", string(body))
			require.Equal(t, "response", response.Header.Get("X-Script-Response"))
			require.Equal(t, "text/x-script", response.Header.Get("Content-Type"))
			require.Equal(t, int64(len(body)), response.ContentLength)
			require.Equal(t, fmt.Sprint(len(body)), response.Header.Get("Content-Length"))
			require.Empty(t, response.Header.Get("Transfer-Encoding"))

			empty, err := h.wire.RoundTrip(m42NewRequest(t, http.MethodGet, "/empty", ""))
			require.NoError(t, err)
			emptyBody, err := io.ReadAll(empty.Body)
			require.NoError(t, err)
			require.NoError(t, empty.Body.Close())
			require.Equal(t, http.StatusNoContent, empty.StatusCode)
			require.Empty(t, emptyBody)
			require.Equal(t, "yes", empty.Header.Get("X-Empty-Hook"))
			require.Empty(t, empty.Header.Get("Content-Length"))
			require.Empty(t, empty.Header.Get("Transfer-Encoding"))

			head, err := h.wire.RoundTrip(m42NewRequest(t, http.MethodHead, "/head", ""))
			require.NoError(t, err)
			headBody, err := io.ReadAll(head.Body)
			require.NoError(t, err)
			require.NoError(t, head.Body.Close())
			require.Equal(t, http.StatusOK, head.StatusCode)
			require.Empty(t, headBody)
			require.Equal(t, "yes", head.Header.Get("X-Head-Hook"))
			require.Equal(t, int64(len("head representation")), head.ContentLength)

			notModified, err := h.wire.RoundTrip(m42NewRequest(t, http.MethodGet, "/not-modified", ""))
			require.NoError(t, err)
			notModifiedBody, err := io.ReadAll(notModified.Body)
			require.NoError(t, err)
			require.NoError(t, notModified.Body.Close())
			require.Equal(t, http.StatusNotModified, notModified.StatusCode)
			require.Empty(t, notModifiedBody)
			require.Equal(t, "yes", notModified.Header.Get("X-304-Hook"))
			require.Empty(t, notModified.Header.Get("Transfer-Encoding"))
		})
	}
}

func m42NewRequest(t *testing.T, method, path, body string) *http.Request {
	t.Helper()
	request, err := http.NewRequestWithContext(context.Background(), method, "https://localhost"+path, strings.NewReader(body))
	require.NoError(t, err)
	request.Header.Set("Content-Type", "text/plain")
	return request
}

func TestM42HTTP2MultiplexesConcurrentHookRequestsWithoutSharedScriptState(t *testing.T) {
	hooks := m42Hooks(t, httphook.Config{Enable: true, Rules: []httphook.Rule{{
		Name: "isolated", Phase: httphook.RequestPhase,
		Source: `var n = (typeof n === "undefined" ? 0 : n) + 1; ({headers: Object.assign({}, input.headers, {"X-Invocation": [String(n)]})})`,
	}}})
	var requests atomic.Int32
	h := newProtocolHarness(t, nil, "localhost", 443, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		body, _ := io.ReadAll(r.Body)
		_, _ = fmt.Fprintf(w, "%s|%s", r.Header.Get("X-Invocation"), body)
	}), false, true, true, []string{"h2"}, func(c *Config) { c.ScriptHooks = hooks })

	const workers = 8
	var wg sync.WaitGroup
	errCh := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := fmt.Sprintf("request-%d", i)
			response, err := h.wire.RoundTrip(m42NewRequest(t, http.MethodPost, "/parallel", id))
			if err != nil {
				errCh <- err
				return
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil {
				errCh <- err
				return
			}
			if !strings.Contains(string(body), id) {
				errCh <- fmt.Errorf("response %q lost its request body %q", body, id)
			}
			if response.Header.Get("X-Invocation") != "" && response.Header.Get("X-Invocation") != "1" {
				errCh <- fmt.Errorf("VM state leaked across requests: X-Invocation=%q", response.Header.Get("X-Invocation"))
			}
		}(i)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		require.NoError(t, err)
	}
	require.EqualValues(t, workers, requests.Load())
	require.EqualValues(t, workers, h.streams.Load())
}

func TestM42ScriptTimeoutAndInvalidOutputForwardOriginalMessage(t *testing.T) {
	hooks := m42Hooks(t, httphook.Config{Enable: true, Rules: []httphook.Rule{
		{Name: "timeout", Phase: httphook.RequestPhase, Match: httphook.Match{Path: "/timeout"}, Source: `while (true) {}`},
		{Name: "invalid", Phase: httphook.RequestPhase, Match: httphook.Match{Path: "/invalid"}, Source: `({headers: {"Content-Length": ["999"]}})`},
		{Name: "response-error", Phase: httphook.ResponsePhase, Match: httphook.Match{PathPrefix: "/", ResponseStatus: []int{200}}, Source: `throw new Error("response failure")`},
	}})
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(w, r.Body)
	})
	h := newProtocolHarness(t, nil, "localhost", 443, upstream, false, true, false, []string{"http/1.1"}, func(c *Config) { c.ScriptHooks = hooks })
	for _, path := range []string{"/timeout", "/invalid"} {
		response, err := h.wire.RoundTrip(m42NewRequest(t, http.MethodPost, path, "original"))
		require.NoError(t, err)
		body, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		require.NoError(t, response.Body.Close())
		require.Equal(t, http.StatusOK, response.StatusCode)
		require.Equal(t, "original", string(body))
	}
}

func TestM42CanceledScriptDoesNotForwardRequest(t *testing.T) {
	hooks := m42Hooks(t, httphook.Config{Enable: true, Rules: []httphook.Rule{{
		Name: "cancel", Phase: httphook.RequestPhase, Source: `while (true) {}`,
	}}})
	var upstreamRequests atomic.Int32
	h := newProtocolHarness(t, nil, "localhost", 443, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamRequests.Add(1)
		_, _ = io.Copy(w, r.Body)
	}), false, true, false, []string{"http/1.1"}, func(c *Config) { c.ScriptHooks = hooks })
	ctx, cancel := context.WithCancel(context.Background())
	timer := time.AfterFunc(30*time.Millisecond, cancel)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://localhost/cancel", strings.NewReader("body"))
	require.NoError(t, err)
	_, err = h.wire.RoundTrip(request)
	timer.Stop()
	cancel()
	require.Error(t, err)
	require.Eventually(t, func() bool { return upstreamRequests.Load() == 0 }, time.Second, 10*time.Millisecond)
}

func TestM42ConfiguredButUnmatchedHookDoesNotCreateRuntime(t *testing.T) {
	hooks := m42Hooks(t, httphook.Config{Enable: true, Rules: []httphook.Rule{{
		Name: "unmatched", Phase: httphook.RequestPhase, Match: httphook.Match{Path: "/script"}, Source: `({method: "PUT"})`,
	}}})
	h := newProtocolHarness(t, nil, "localhost", 443, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }), false, true, true, []string{"h2"}, func(c *Config) { c.ScriptHooks = hooks })
	response, err := h.wire.RoundTrip(m42NewRequest(t, http.MethodGet, "/other", ""))
	require.NoError(t, err)
	_, err = io.Copy(io.Discard, response.Body)
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())
	require.False(t, h.manager.loadSnapshot().config.ScriptHooks.RuntimeInitialized())
}

func TestM42HotReloadKeepsOldConnectionOnItsPinnedScriptGeneration(t *testing.T) {
	oldHooks := m42Hooks(t, httphook.Config{Enable: true, Rules: []httphook.Rule{{
		Name: "old", Phase: httphook.RequestPhase,
		Source: `({headers: Object.assign({}, input.headers, {"X-Generation": ["old"]})})`,
	}}})
	newHooks := m42Hooks(t, httphook.Config{Enable: true, Rules: []httphook.Rule{{
		Name: "new", Phase: httphook.RequestPhase,
		Source: `({headers: Object.assign({}, input.headers, {"X-Generation": ["new"]})})`,
	}}})
	ca, _ := makeTestAuthority(t)
	manager := NewManager(Config{Enabled: true, Ports: []uint16{443}, Domains: []string{"localhost"}, CA: ca, RequestTimeout: 5 * time.Second, IdleTimeout: 5 * time.Second, ScriptHooks: oldHooks})
	old := newH2HarnessWithManager(t, manager, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.Header.Get("X-Generation"))
	}), false, true)
	oldGeneration := manager.loadSnapshot()
	readValue := func(h *h2Harness) string {
		t.Helper()
		response := h2Request(t, h, http.MethodGet, "/generation", "")
		value, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		require.NoError(t, response.Body.Close())
		return string(value)
	}
	require.Equal(t, "old", readValue(old))
	require.True(t, oldGeneration.config.ScriptHooks.RuntimeInitialized())

	updated := manager.ConfigSnapshot()
	updatedHookClone := updated.ScriptHooks
	updated.ScriptHooks = newHooks
	manager.Update(updated)
	require.NoError(t, updatedHookClone.Close(), "the caller owns the clone returned by ConfigSnapshot")
	require.True(t, oldGeneration.config.ScriptHooks.RuntimeInitialized(), "an active TLS connection retains its old generation")
	require.Equal(t, "old", readValue(old))

	newer := newH2HarnessWithManager(t, manager, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.Header.Get("X-Generation"))
	}), false, true)
	require.Equal(t, "new", readValue(newer))
}

func TestM42ConfigSnapshotReturnsCallerOwnedHookClone(t *testing.T) {
	hooks := m42Hooks(t, httphook.Config{Enable: true, Rules: []httphook.Rule{{
		Name: "snapshot", Phase: httphook.RequestPhase, Source: `null`,
	}}})
	manager := NewManager(Config{Enabled: true, ScriptHooks: hooks})
	managerHooks := manager.loadSnapshot().config.ScriptHooks
	returned := manager.ConfigSnapshot()
	require.NotNil(t, returned.ScriptHooks)
	require.NotSame(t, managerHooks, returned.ScriptHooks)

	request, err := http.NewRequest(http.MethodGet, "https://example.test/", nil)
	require.NoError(t, err)
	_, err = returned.ScriptHooks.ApplyRequest(context.Background(), request)
	require.NoError(t, err)
	require.True(t, returned.ScriptHooks.RuntimeInitialized())
	require.False(t, managerHooks.RuntimeInitialized(), "the returned config has an independent Runtime")

	manager.Update(Config{Enabled: false})
	require.True(t, returned.ScriptHooks.RuntimeInitialized(), "retiring manager config does not close the caller's clone")
	require.NoError(t, returned.ScriptHooks.Close())
	require.False(t, returned.ScriptHooks.RuntimeInitialized())
}

func TestM42RapidReloadKeepsPinnedGenerationAndClosesRetiredRuntime(t *testing.T) {
	oldHooks := m42Hooks(t, httphook.Config{Enable: true, Rules: []httphook.Rule{{
		Name: "old", Phase: httphook.RequestPhase,
		Source: `({headers: Object.assign({}, input.headers, {"X-Generation": ["old"]})})`,
	}}})
	newHooks := m42Hooks(t, httphook.Config{Enable: true, Rules: []httphook.Rule{{
		Name: "new", Phase: httphook.RequestPhase,
		Source: `({headers: Object.assign({}, input.headers, {"X-Generation": ["new"]})})`,
	}}})
	manager := NewManager(Config{Enabled: true, ScriptHooks: oldHooks})
	old, releaseOld := manager.acquireSnapshot()
	var releaseOldOnce sync.Once
	defer releaseOldOnce.Do(releaseOld)

	apply := func(snapshot *httphook.Snapshot, want string) error {
		request, err := http.NewRequest(http.MethodGet, "https://example.test/", nil)
		if err != nil {
			return err
		}
		result, err := snapshot.ApplyRequest(context.Background(), request)
		if err != nil {
			return err
		}
		if result.Fallback != nil || result.Headers == nil || (*result.Headers).Get("X-Generation") != want {
			return fmt.Errorf("generation result = %#v, want %q", result, want)
		}
		return nil
	}
	require.NoError(t, apply(old.config.ScriptHooks, "old"))
	require.True(t, old.config.ScriptHooks.RuntimeInitialized())

	for i := 0; i < 64; i++ {
		manager.Update(Config{Enabled: true, ScriptHooks: newHooks})
	}
	require.EqualValues(t, 1, old.refs.Load(), "only the pinned connection reference keeps the old generation alive")
	require.True(t, old.config.ScriptHooks.RuntimeInitialized())

	current, releaseCurrent := manager.acquireSnapshot()
	var releaseCurrentOnce sync.Once
	defer releaseCurrentOnce.Do(releaseCurrent)
	require.NotSame(t, old, current)

	const workers = 4
	start := make(chan struct{})
	errCh := make(chan error, workers*2)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			errCh <- apply(old.config.ScriptHooks, "old")
		}()
		go func() {
			defer wg.Done()
			<-start
			errCh <- apply(current.config.ScriptHooks, "new")
		}()
	}
	close(start)
	wg.Wait()
	close(errCh)
	for err := range errCh {
		require.NoError(t, err)
	}

	releaseCurrentOnce.Do(releaseCurrent)
	manager.Update(Config{Enabled: false})
	require.False(t, current.config.ScriptHooks.RuntimeInitialized(), "the current Runtime closes after its final release")
	require.True(t, old.config.ScriptHooks.RuntimeInitialized(), "rapid reload cannot close a pinned generation")
	require.EqualValues(t, 1, old.refs.Load())

	releaseOldOnce.Do(releaseOld)
	require.Zero(t, old.refs.Load(), "retired generations release each reference exactly once")
	require.False(t, old.config.ScriptHooks.RuntimeInitialized(), "the old Runtime closes after the pinned connection ends")

	request, err := http.NewRequest(http.MethodGet, "https://example.test/", nil)
	require.NoError(t, err)
	closedResult, err := old.config.ScriptHooks.ApplyRequest(context.Background(), request)
	require.NoError(t, err)
	require.Error(t, closedResult.Fallback, "closed generations reject new script work")
	require.False(t, old.config.ScriptHooks.RuntimeInitialized(), "closed Runtime is not recreated")
}

func TestM42RetiredSnapshotClosesRuntimeAfterPinnedUse(t *testing.T) {
	hooks := m42Hooks(t, httphook.Config{Enable: true, Rules: []httphook.Rule{{
		Name: "active", Phase: httphook.RequestPhase, Source: `null`,
	}}})
	manager := NewManager(Config{Enabled: true, ScriptHooks: hooks})
	old, release := manager.acquireSnapshot()
	request, err := http.NewRequest(http.MethodGet, "https://example.test/", nil)
	require.NoError(t, err)
	_, err = old.config.ScriptHooks.ApplyRequest(context.Background(), request)
	require.NoError(t, err)
	require.True(t, old.config.ScriptHooks.RuntimeInitialized())

	manager.Update(Config{Enabled: true})
	require.True(t, old.config.ScriptHooks.RuntimeInitialized(), "retirement must wait for a pinned connection")
	release()
	require.False(t, old.config.ScriptHooks.RuntimeInitialized(), "the last release closes the generation Runtime")

	manager.Update(Config{Enabled: false, ScriptHooks: hooks})
	require.Nil(t, manager.loadSnapshot().config.ScriptHooks, "MITM-off updates do not retain JS hooks")
}
