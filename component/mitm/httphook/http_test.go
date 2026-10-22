package httphook

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/metacubex/mihomo/component/mitm/scriptapi"
	"github.com/stretchr/testify/require"
)

func TestSharedStoreSurvivesSnapshotRuntimeClose(t *testing.T) {
	directory := t.TempDir()
	store, err := scriptapi.SharedStore(directory)
	require.NoError(t, err)
	defer store.Close()
	base := testSnapshot(t, Config{Enable: true, Rules: []Rule{{
		Name: "shared-generations", Phase: RequestPhase, Mode: APIMode,
		Source: `$persistentStore.write($request.body, "key"); $done({body: $persistentStore.read("key")});`,
	}}})
	// Use the real production clone and API execution paths with isolated
	// storage so this test never writes to the application's data directory.
	old := base.CloneWithServices(Services{Store: store})
	require.NotNil(t, old)
	defer old.Close()
	next := old.Clone()
	require.NotNil(t, next)
	defer next.Close()
	require.Same(t, store, old.services.Store)
	require.Same(t, store, next.services.Store)
	oldRuntime, err := old.getRuntime()
	require.NoError(t, err)
	nextRuntime, err := next.getRuntime()
	require.NoError(t, err)
	require.NotSame(t, oldRuntime, nextRuntime)
	apply := func(snapshot *Snapshot, body string) {
		t.Helper()
		request := testRequest(t, http.MethodPost, "https://example.test/", body)
		defer request.Body.Close()
		result, err := snapshot.ApplyRequest(context.Background(), request)
		require.NoError(t, err)
		require.Nil(t, result.Fallback)
		require.True(t, result.Applied)
		value, exists, err := store.Read("shared-generations", "key")
		require.NoError(t, err)
		require.True(t, exists)
		require.Equal(t, body, value)
	}
	apply(old, "old")
	apply(next, "new-before-close")
	require.NoError(t, oldRuntime.Close())
	apply(next, "new-after-runtime-close")
	require.NoError(t, old.Close())
	apply(next, "new-after-snapshot-close")
	reopened, err := scriptapi.SharedStore(directory)
	require.NoError(t, err)
	require.Same(t, store, reopened)
}

func testSnapshot(t *testing.T, config Config) *Snapshot {
	t.Helper()
	snapshot, err := Compile(config)
	require.NoError(t, err)
	t.Cleanup(func() { _ = snapshot.Close() })
	return snapshot
}

func testRequest(t *testing.T, method, target, body string) *http.Request {
	t.Helper()
	request, err := http.NewRequest(method, target, strings.NewReader(body))
	require.NoError(t, err)
	request.Host = request.URL.Host
	request.Header.Set("X-Input", "before")
	return request
}

func TestRequestHookMutationAndPassthrough(t *testing.T) {
	snapshot := testSnapshot(t, Config{Enable: true, Rules: []Rule{{
		Name: "mutate", Phase: RequestPhase,
		Match:  Match{Domains: []string{"api.example.test"}, Path: "/old", Methods: []string{"POST"}},
		Source: `({url: input.url.replace("/old", "/new"), method: "PATCH", headers: Object.assign({}, input.headers, {"X-Hook": ["yes"]}), body: input.body + "-changed"})`,
	}}})
	request := testRequest(t, http.MethodPost, "https://api.example.test/old", "original")
	require.False(t, snapshot.RuntimeInitialized(), "a configured but unmatched rule must not create a Runtime")

	result, err := snapshot.ApplyRequest(context.Background(), request)
	require.NoError(t, err)
	require.True(t, result.Matched)
	require.True(t, result.Applied)
	require.Nil(t, result.Fallback)
	require.Equal(t, "PATCH", *result.Method)
	require.Equal(t, "/new", result.URL.Path)
	require.Equal(t, "api.example.test", *result.Host)
	require.Equal(t, []string{"yes"}, (*result.Headers)["X-Hook"])
	require.Equal(t, []byte("original-changed"), result.Body)
	require.True(t, result.BodyChanged)
	require.True(t, snapshot.RuntimeInitialized())

	// The hook consumed the body for inspection but left a complete replay for
	// the HTTP adapter to apply atomically.
	replayed, err := io.ReadAll(request.Body)
	require.NoError(t, err)
	require.Equal(t, "original", string(replayed))

	other := testRequest(t, http.MethodPost, "https://api.example.test/other", "untouched")
	noMatch, err := snapshot.ApplyRequest(context.Background(), other)
	require.NoError(t, err)
	require.False(t, noMatch.Matched)
	require.False(t, noMatch.Applied)
	replayed, err = io.ReadAll(other.Body)
	require.NoError(t, err)
	require.Equal(t, "untouched", string(replayed))
}

func TestAPIModeDoneMutatesRequestAndRejectsSecondCompletion(t *testing.T) {
	snapshot := testSnapshot(t, Config{Enable: true, Rules: []Rule{{
		Name: "api-request", Phase: RequestPhase, Mode: APIMode,
		Source: `$request.headers["X-API"] = ["yes"]; $done({method: "PATCH", headers: $request.headers, body: $request.body + "-api"}); $done({body: "second"});`,
	}}})
	request := testRequest(t, http.MethodPost, "https://api.example.test/path", "original")
	result, err := snapshot.ApplyRequest(context.Background(), request)
	require.NoError(t, err)
	require.True(t, result.Applied)
	require.Nil(t, result.Fallback)
	require.Equal(t, "PATCH", *result.Method)
	require.Equal(t, "yes", (*result.Headers).Get("X-API"))
	require.Equal(t, []byte("original-api"), result.Body)
}

func TestAPIModeDoneNoArgumentPassesThroughAndNoInputGlobal(t *testing.T) {
	snapshot := testSnapshot(t, Config{Enable: true, Rules: []Rule{{
		Name: "api-pass", Phase: RequestPhase, Mode: APIMode,
		Source: `if (typeof input !== "undefined") throw new Error("legacy input leaked"); $request.method; $done();`,
	}}})
	request := testRequest(t, http.MethodGet, "https://api.example.test/path", "body")
	result, err := snapshot.ApplyRequest(context.Background(), request)
	require.NoError(t, err)
	require.True(t, result.Matched)
	require.False(t, result.Applied)
	require.Nil(t, result.Fallback)
}

func TestAPIModeResponseReceivesRequestAndResponseAndUsesExistingValidation(t *testing.T) {
	snapshot := testSnapshot(t, Config{Enable: true, Rules: []Rule{{
		Name: "api-response", Phase: ResponsePhase, Mode: APIMode,
		Source: `if ($request.url !== "https://api.example.test/path") throw new Error("request missing"); $done({status: $response.status + 1, headers: $response.headers, body: $response.body + "!"});`,
	}}})
	request := testRequest(t, http.MethodGet, "https://api.example.test/path", "")
	response := &http.Response{StatusCode: http.StatusOK, Header: http.Header{"X-Input": []string{"before"}}, Body: io.NopCloser(strings.NewReader("response"))}
	result, err := snapshot.ApplyResponse(context.Background(), request, response)
	require.NoError(t, err)
	require.True(t, result.Applied)
	require.Equal(t, http.StatusCreated, *result.Status)
	require.Equal(t, []byte("response!"), result.Body)

	invalid := testSnapshot(t, Config{Enable: true, Rules: []Rule{{Name: "invalid", Phase: ResponsePhase, Mode: APIMode, Source: `$done({status: 101})`}}})
	invalidResponse := &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("original"))}
	invalidResult, err := invalid.ApplyResponse(context.Background(), request, invalidResponse)
	require.NoError(t, err)
	require.False(t, invalidResult.Applied)
	require.Error(t, invalidResult.Fallback)
	replayed, err := io.ReadAll(invalidResponse.Body)
	require.NoError(t, err)
	require.Equal(t, "original", string(replayed))
}

func TestAPIModeExceptionAfterDoneFallsBackToOriginal(t *testing.T) {
	snapshot := testSnapshot(t, Config{Enable: true, Rules: []Rule{{
		Name: "throw-after-done", Phase: RequestPhase, Mode: APIMode,
		Source: `$done({body: "changed"}); throw new Error("after done");`,
	}}})
	request := testRequest(t, http.MethodPost, "https://api.example.test/path", "original")
	result, err := snapshot.ApplyRequest(context.Background(), request)
	require.NoError(t, err)
	require.False(t, result.Applied)
	require.ErrorContains(t, result.Fallback, "after done")
}

func TestRequestHookBinaryBodyUsesBase64AndRuntimeStateIsIsolated(t *testing.T) {
	snapshot := testSnapshot(t, Config{Enable: true, Rules: []Rule{{
		Name: "binary", Phase: RequestPhase,
		Source: `var counter = (typeof counter === "undefined" ? 0 : counter) + 1; ({body_base64: input.body_base64 === "/wA=" ? (counter === 1 ? "AQID" : "BAUG") : "AA=="})`,
	}}})
	const workers = 4
	var wg sync.WaitGroup
	errCh := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			request, err := http.NewRequest(http.MethodPost, "https://binary.example.test/", strings.NewReader(string([]byte{0xff, 0x00})))
			if err != nil {
				errCh <- err
				return
			}
			result, err := snapshot.ApplyRequest(context.Background(), request)
			if err != nil {
				errCh <- err
				return
			}
			if result.Fallback != nil || !result.BodyChanged || string(result.Body) != string([]byte{1, 2, 3}) {
				errCh <- errors.New("binary body mutation failed")
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		require.NoError(t, err)
	}
}

func TestRequestHookFallbackRestoresOriginalBody(t *testing.T) {
	tests := []struct {
		name   string
		config Config
		body   string
		ctx    context.Context
		fatal  bool
	}{
		{name: "exception", config: Config{Enable: true, Rules: []Rule{{Name: "throws", Phase: RequestPhase, Source: `throw new Error("script failed")`}}}, body: "original"},
		{name: "illegal output", config: Config{Enable: true, Rules: []Rule{{Name: "bad", Phase: RequestPhase, Source: `({method: "not a method"})`}}}, body: "original"},
		{name: "oversized body", config: Config{Enable: true, MaxBodyBytes: 4, Rules: []Rule{{Name: "large", Phase: RequestPhase, Source: `({body: "changed"})`}}}, body: "original"},
		{name: "canceled", config: Config{Enable: true, Rules: []Rule{{Name: "cancel", Phase: RequestPhase, Source: `({body: "changed"})`}}}, body: "original", ctx: canceledContext(), fatal: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := testSnapshot(t, test.config)
			request := testRequest(t, http.MethodPost, "https://fallback.example.test/path", test.body)
			ctx := test.ctx
			if ctx == nil {
				ctx = context.Background()
			}
			result, err := snapshot.ApplyRequest(ctx, request)
			if test.fatal {
				require.ErrorIs(t, err, context.Canceled)
			} else {
				require.NoError(t, err)
				require.NotNil(t, result.Fallback)
				if test.name == "exception" {
					var fallbackError *FallbackError
					require.ErrorAs(t, result.Fallback, &fallbackError)
					require.Equal(t, "throws", fallbackError.Rule)
				}
			}
			replayed, readErr := io.ReadAll(request.Body)
			require.NoError(t, readErr)
			require.Equal(t, test.body, string(replayed))
		})
	}
}

func TestRequestHookNullResultAndBodyReadError(t *testing.T) {
	snapshot := testSnapshot(t, Config{Enable: true, Rules: []Rule{{Name: "pass", Phase: RequestPhase, Source: `null`}}})
	request := testRequest(t, http.MethodPost, "https://pass.example.test/", "original")
	result, err := snapshot.ApplyRequest(context.Background(), request)
	require.NoError(t, err)
	require.True(t, result.Matched)
	require.False(t, result.Applied)
	require.Nil(t, result.Fallback)
	replayed, err := io.ReadAll(request.Body)
	require.NoError(t, err)
	require.Equal(t, "original", string(replayed))

	readError := errors.New("injected body read failure")
	broken := testRequest(t, http.MethodPost, "https://pass.example.test/", "")
	broken.Body = &errorAfterPrefixBody{prefix: []byte("partial"), err: readError}
	_, err = snapshot.ApplyRequest(context.Background(), broken)
	require.ErrorIs(t, err, readError)
	replayed, err = io.ReadAll(broken.Body)
	require.ErrorIs(t, err, readError)
	require.Equal(t, "partial", string(replayed))
}

type errorAfterPrefixBody struct {
	prefix []byte
	done   bool
	err    error
}

func (b *errorAfterPrefixBody) Read(buffer []byte) (int, error) {
	if b.done {
		return 0, b.err
	}
	b.done = true
	return copy(buffer, b.prefix), nil
}

func (*errorAfterPrefixBody) Close() error { return nil }

type trackedReadCloser struct {
	reader     io.Reader
	closeErr   error
	closeCount int
}

func (b *trackedReadCloser) Read(buffer []byte) (int, error) { return b.reader.Read(buffer) }
func (b *trackedReadCloser) Close() error {
	b.closeCount++
	return b.closeErr
}

func TestRequestBodyOwnershipAndCloseCounts(t *testing.T) {
	for _, test := range []struct {
		name         string
		source       string
		wantApply    bool
		wantFallback bool
	}{
		{name: "unchanged", source: `null`},
		{name: "modified", source: `({body: input.body + "!"})`, wantApply: true},
		{name: "script fallback", source: `throw new Error("failed")`, wantFallback: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			snapshot := testSnapshot(t, Config{Enable: true, Rules: []Rule{{Name: "body", Phase: RequestPhase, Source: test.source}}})
			request := testRequest(t, http.MethodPost, "https://body.example.test/", "original")
			original := &trackedReadCloser{reader: strings.NewReader("original")}
			request.Body = original
			request.ContentLength = int64(len("original"))

			result, err := snapshot.ApplyRequest(context.Background(), request)
			require.NoError(t, err)
			require.Equal(t, 1, original.closeCount)
			require.Equal(t, test.wantApply, result.Applied)
			if test.wantFallback {
				require.Error(t, result.Fallback)
			}
			require.Equal(t, int64(len("original")), request.ContentLength)
			replay, err := request.GetBody()
			require.NoError(t, err)
			got, err := io.ReadAll(replay)
			require.NoError(t, err)
			require.NoError(t, replay.Close())
			require.Equal(t, "original", string(got))

			got, err = io.ReadAll(request.Body)
			require.NoError(t, err)
			require.Equal(t, "original", string(got))
			require.NoError(t, request.Body.Close())
			require.Equal(t, 1, original.closeCount, "closing the buffered body must not close the original twice")
		})
	}

	t.Run("empty body closes original", func(t *testing.T) {
		snapshot := testSnapshot(t, Config{Enable: true, Rules: []Rule{{Name: "empty", Phase: RequestPhase, Source: `null`}}})
		request := testRequest(t, http.MethodPost, "https://body.example.test/", "")
		original := &trackedReadCloser{reader: strings.NewReader("")}
		request.Body = original
		_, err := snapshot.ApplyRequest(context.Background(), request)
		require.NoError(t, err)
		require.Equal(t, 1, original.closeCount)
		require.NoError(t, request.Body.Close())
		require.Equal(t, 1, original.closeCount)
	})

	t.Run("external owner closes original", func(t *testing.T) {
		snapshot := testSnapshot(t, Config{Enable: true, Rules: []Rule{{Name: "external", Phase: RequestPhase, Source: `null`}}})
		request := testRequest(t, http.MethodPost, "https://body.example.test/", "original")
		original := &trackedReadCloser{reader: strings.NewReader("original")}
		request.Body = original
		_, err := snapshot.ApplyRequestWithExternalBodyOwner(context.Background(), request)
		require.NoError(t, err)
		require.Zero(t, original.closeCount)
		got, err := io.ReadAll(request.Body)
		require.NoError(t, err)
		require.Equal(t, "original", string(got))
		require.NoError(t, original.Close())
		require.NoError(t, request.Body.Close())
		require.Equal(t, 1, original.closeCount)
	})

	t.Run("oversize replays before one close", func(t *testing.T) {
		snapshot := testSnapshot(t, Config{Enable: true, MaxBodyBytes: 4, Rules: []Rule{{Name: "large", Phase: RequestPhase, Source: `null`}}})
		request := testRequest(t, http.MethodPost, "https://body.example.test/", "payload")
		original := &trackedReadCloser{reader: strings.NewReader("payload")}
		request.Body = original
		result, err := snapshot.ApplyRequest(context.Background(), request)
		require.NoError(t, err)
		require.Error(t, result.Fallback)
		require.Zero(t, original.closeCount, "the unconsumed suffix remains readable")
		got, err := io.ReadAll(request.Body)
		require.NoError(t, err)
		require.Equal(t, "payload", string(got))
		require.Zero(t, original.closeCount)
		require.NoError(t, request.Body.Close())
		require.NoError(t, request.Body.Close())
		require.Equal(t, 1, original.closeCount, "replay close is idempotent")
	})

	t.Run("read error replays prefix and closes once", func(t *testing.T) {
		snapshot := testSnapshot(t, Config{Enable: true, Rules: []Rule{{Name: "broken", Phase: RequestPhase, Source: `null`}}})
		readErr := errors.New("request read failed")
		request := testRequest(t, http.MethodPost, "https://body.example.test/", "")
		original := &trackedReadCloser{reader: &errorAfterPrefixBody{prefix: []byte("partial"), err: readErr}}
		request.Body = original
		_, err := snapshot.ApplyRequest(context.Background(), request)
		require.ErrorIs(t, err, readErr)
		require.Zero(t, original.closeCount, "do not close while replay still needs the original stream")
		got, err := io.ReadAll(request.Body)
		require.ErrorIs(t, err, readErr)
		require.Equal(t, "partial", string(got))
		require.NoError(t, request.Body.Close())
		require.Equal(t, 1, original.closeCount)
	})

	t.Run("close error keeps complete request bytes available", func(t *testing.T) {
		snapshot := testSnapshot(t, Config{Enable: true, Rules: []Rule{{Name: "close-error", Phase: RequestPhase, Source: `null`}}})
		closeErr := errors.New("request close failed")
		request := testRequest(t, http.MethodPost, "https://body.example.test/", "complete")
		original := &trackedReadCloser{reader: strings.NewReader("complete"), closeErr: closeErr}
		request.Body = original
		_, err := snapshot.ApplyRequest(context.Background(), request)
		require.ErrorIs(t, err, closeErr)
		require.Equal(t, 1, original.closeCount)
		got, err := io.ReadAll(request.Body)
		require.NoError(t, err)
		require.Equal(t, "complete", string(got), "a close error must not discard fully buffered request data")
	})
}

func canceledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func TestResponseHookMutationAndLimitFallback(t *testing.T) {
	snapshot := testSnapshot(t, Config{Enable: true, MaxBodyBytes: 8, Rules: []Rule{{
		Name: "response", Phase: ResponsePhase, Match: Match{ResponseStatus: []int{200}},
		Source: `({status: 201, headers: Object.assign({}, input.headers, {"X-Script": ["yes"]}), body: input.body + "!"})`,
	}}})
	request := testRequest(t, http.MethodGet, "https://api.example.test/path", "")
	response := &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"text/plain"}}, ContentLength: 4, Body: io.NopCloser(strings.NewReader("body"))}
	result, err := snapshot.ApplyResponse(context.Background(), request, response)
	require.NoError(t, err)
	require.True(t, result.Applied)
	require.Equal(t, 201, *result.Status)
	require.Equal(t, []string{"yes"}, (*result.Headers)["X-Script"])
	require.Equal(t, []byte("body!"), result.Body)
	require.True(t, result.BodyChanged)
	replayed, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	require.Equal(t, "body", string(replayed))

	oversized := testSnapshot(t, Config{Enable: true, MaxBodyBytes: 4, Rules: []Rule{{
		Name: "response-large", Phase: ResponsePhase, Source: `({body: "changed"})`,
	}}})
	largeResponse := &http.Response{StatusCode: 200, Header: make(http.Header), ContentLength: -1, Body: io.NopCloser(strings.NewReader("too large"))}
	largeResult, err := oversized.ApplyResponse(context.Background(), request, largeResponse)
	require.NoError(t, err)
	require.NotNil(t, largeResult.Fallback)
	require.False(t, oversized.RuntimeInitialized())
	replayed, err = io.ReadAll(largeResponse.Body)
	require.NoError(t, err)
	require.Equal(t, "too large", string(replayed))
}

func TestResponseHookBodyReadErrorTerminatesBeforeMutation(t *testing.T) {
	snapshot := testSnapshot(t, Config{Enable: true, Rules: []Rule{{
		Name: "read-error", Phase: ResponsePhase, Source: `({status: 201, body: "modified"})`,
	}}})
	request := testRequest(t, http.MethodGet, "https://api.example.test/", "")
	readError := errors.New("injected response body read failure")
	response := &http.Response{StatusCode: 200, Header: make(http.Header), Body: &errorAfterPrefixBody{prefix: []byte("partial"), err: readError}}
	_, err := snapshot.ApplyResponse(context.Background(), request, response)
	require.ErrorIs(t, err, readError)
	require.Equal(t, http.StatusOK, response.StatusCode)
	require.Equal(t, http.NoBody, response.Body, "a partial response cannot be safely replayed")
}

func TestResponseBodyCloseErrorsPreserveCompleteResponse(t *testing.T) {
	snapshot := testSnapshot(t, Config{Enable: true, Rules: []Rule{{
		Name: "close-error", Phase: ResponsePhase, Source: `({body: "changed"})`,
	}}})
	request := testRequest(t, http.MethodGet, "https://api.example.test/", "")
	closeErr := errors.New("upstream body close failed")
	original := &trackedReadCloser{reader: strings.NewReader("complete response"), closeErr: closeErr}
	response := &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: original, ContentLength: int64(len("complete response"))}

	result, err := snapshot.ApplyResponse(context.Background(), request, response)
	require.NoError(t, err, "a close error after full read must not discard the complete response")
	require.ErrorIs(t, result.Fallback, closeErr)
	require.False(t, result.Applied)
	require.False(t, snapshot.RuntimeInitialized(), "a close failure falls back before script execution")
	require.Equal(t, 1, original.closeCount)
	got, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	require.Equal(t, "complete response", string(got))
	require.NoError(t, response.Body.Close())
	require.Equal(t, 1, original.closeCount)
}

func TestResponseBodySuccessfulReadClosesSourceOnce(t *testing.T) {
	snapshot := testSnapshot(t, Config{Enable: true, Rules: []Rule{{Name: "pass", Phase: ResponsePhase, Source: `null`}}})
	request := testRequest(t, http.MethodGet, "https://api.example.test/", "")
	original := &trackedReadCloser{reader: strings.NewReader("complete")}
	response := &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: original, ContentLength: 8}

	result, err := snapshot.ApplyResponse(context.Background(), request, response)
	require.NoError(t, err)
	require.Nil(t, result.Fallback)
	require.Equal(t, 1, original.closeCount)
	got, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	require.Equal(t, "complete", string(got))
	require.NoError(t, response.Body.Close())
	require.Equal(t, 1, original.closeCount)
}

func TestResponseReadFailureClosesAndTerminatesIncompleteResponse(t *testing.T) {
	snapshot := testSnapshot(t, Config{Enable: true, Rules: []Rule{{Name: "read-error", Phase: ResponsePhase, Source: `null`}}})
	request := testRequest(t, http.MethodGet, "https://api.example.test/", "")
	readErr := errors.New("response read failed")
	closeErr := errors.New("response close failed")
	original := &trackedReadCloser{
		reader:   &errorAfterPrefixBody{prefix: []byte("partial"), err: readErr},
		closeErr: closeErr,
	}
	response := &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: original}

	_, err := snapshot.ApplyResponse(context.Background(), request, response)
	require.ErrorIs(t, err, readErr)
	require.ErrorIs(t, err, closeErr)
	require.Equal(t, 1, original.closeCount)
	require.Equal(t, http.NoBody, response.Body, "an incomplete response must not be exposed as a replayable original")
	got, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	require.Empty(t, got)
}

func TestResponseBodyLimitReplaysAndReportsCloseError(t *testing.T) {
	snapshot := testSnapshot(t, Config{Enable: true, MaxBodyBytes: 4, Rules: []Rule{{Name: "large", Phase: ResponsePhase, Source: `null`}}})
	request := testRequest(t, http.MethodGet, "https://api.example.test/", "")
	closeErr := errors.New("response body close failed")
	original := &trackedReadCloser{reader: strings.NewReader("oversized response"), closeErr: closeErr}
	response := &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: original}

	result, err := snapshot.ApplyResponse(context.Background(), request, response)
	require.NoError(t, err)
	require.Error(t, result.Fallback)
	require.False(t, snapshot.RuntimeInitialized())
	require.Zero(t, original.closeCount, "the original stream remains owned by the replay body")
	got, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	require.Equal(t, "oversized response", string(got))
	require.ErrorIs(t, response.Body.Close(), closeErr)
	require.ErrorIs(t, response.Body.Close(), closeErr)
	require.Equal(t, 1, original.closeCount, "replay body closes the source at most once")
}

func TestResponseScriptFailureRestoresCompleteOriginalBody(t *testing.T) {
	for _, test := range []struct {
		name   string
		source string
	}{
		{name: "exception", source: `throw new Error("response failed")`},
		{name: "timeout", source: `while (true) {}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			snapshot := testSnapshot(t, Config{Enable: true, Rules: []Rule{{Name: test.name, Phase: ResponsePhase, Source: test.source}}})
			request := testRequest(t, http.MethodGet, "https://api.example.test/", "")
			original := &trackedReadCloser{reader: strings.NewReader("original response")}
			response := &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: original}

			result, err := snapshot.ApplyResponse(context.Background(), request, response)
			require.NoError(t, err)
			require.Error(t, result.Fallback)
			require.Equal(t, 1, original.closeCount)
			got, err := io.ReadAll(response.Body)
			require.NoError(t, err)
			require.Equal(t, "original response", string(got))
			require.NoError(t, response.Body.Close())
			require.Equal(t, 1, original.closeCount)
		})
	}
}

func TestCompileValidatesRulesAndDisabledConfigDoesNotCreateRuntime(t *testing.T) {
	disabled, err := Compile(Config{Enable: false, Rules: []Rule{{Name: "ignored", Phase: "bad", Source: ""}}})
	require.NoError(t, err)
	require.Nil(t, disabled)

	_, err = Compile(Config{Enable: true, Rules: []Rule{{Name: "bad", Phase: RequestPhase, Match: Match{ResponseStatus: []int{201}}, Source: `null`}}})
	require.ErrorContains(t, err, "response-status")
	_, err = Compile(Config{Enable: true, Rules: []Rule{{Name: "bad", Phase: RequestPhase, Source: `null`, Match: Match{Path: "/x", PathPrefix: "/"}}}})
	require.ErrorContains(t, err, "mutually exclusive")

	snapshot := testSnapshot(t, Config{Enable: true, Rules: []Rule{{Name: "lazy", Phase: RequestPhase, Match: Match{Path: "/match"}, Source: `null`}}})
	request := testRequest(t, http.MethodGet, "https://lazy.example.test/miss", "")
	_, err = snapshot.ApplyRequest(context.Background(), request)
	require.NoError(t, err)
	require.False(t, snapshot.RuntimeInitialized())

	apiSnapshot := testSnapshot(t, Config{Enable: true, Rules: []Rule{{
		Name: "lazy-api", Phase: RequestPhase, Mode: APIMode,
		Match: Match{Path: "/match"}, Source: `$done();`,
	}}})
	apiRequest := testRequest(t, http.MethodGet, "https://lazy.example.test/miss", "")
	_, err = apiSnapshot.ApplyRequest(context.Background(), apiRequest)
	require.NoError(t, err)
	require.False(t, apiSnapshot.RuntimeInitialized(), "a configured but unmatched API rule must not create a Runtime")
}
