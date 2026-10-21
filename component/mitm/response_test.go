package mitm

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/metacubex/mihomo/component/mitm/rewrite"
	"github.com/stretchr/testify/require"
)

func TestM23ResponseBodyLifecycle(t *testing.T) {
	pipeline := compileM2Rules(t, rewrite.Rule{
		Name:     "replace",
		Match:    rewrite.Match{Path: "/replace"},
		Response: &rewrite.ResponseAction{Body: &rewrite.BodyReplacement{Replace: "static"}},
	})
	request := rewrite.RequestView{Method: http.MethodGet, URL: rewriteURL("https://example.test/replace")}

	t.Run("replacement closes without reading upstream body", func(t *testing.T) {
		old := &m2TrackedBody{}
		response := &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/plain"}}, Body: old, ContentLength: -1}
		require.NoError(t, applyResponseRewrite(context.Background(), request, response, pipeline, false, request.Method))
		require.Zero(t, old.reads.Load())
		require.EqualValues(t, 1, old.closed.Load())
		body, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		require.NoError(t, response.Body.Close())
		require.Equal(t, "static", string(body))
		require.EqualValues(t, len("static"), response.ContentLength)
		require.Equal(t, "6", response.Header.Get("Content-Length"))
		require.Empty(t, response.Header.Get("Content-Type"), "an unchanged upstream type is stale after replacement")
	})

	t.Run("unmatched response preserves streaming body", func(t *testing.T) {
		old := &m2TrackedBody{}
		response := &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: old, ContentLength: -1}
		request.URL = rewriteURL("https://example.test/other")
		require.NoError(t, applyResponseRewrite(context.Background(), request, response, pipeline, false, request.Method))
		require.Same(t, old, response.Body)
		require.Zero(t, old.reads.Load())
		require.Zero(t, old.closed.Load())
	})

	t.Run("HEAD replacement sets metadata but suppresses bytes", func(t *testing.T) {
		old := &m2TrackedBody{}
		response := &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: old, ContentLength: -1}
		request.Method = http.MethodHead
		request.URL = rewriteURL("https://example.test/replace")
		require.NoError(t, applyResponseRewrite(context.Background(), request, response, pipeline, false, http.MethodHead))
		require.EqualValues(t, 1, old.closed.Load())
		require.Equal(t, http.NoBody, response.Body)
		require.EqualValues(t, len("static"), response.ContentLength)
		require.Equal(t, "6", response.Header.Get("Content-Length"))
	})

	t.Run("original HEAD stays bodyless after method rewrite", func(t *testing.T) {
		old := &m2TrackedBody{}
		response := &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: old, ContentLength: -1}
		request.Method = http.MethodGet
		request.URL = rewriteURL("https://example.test/replace")
		require.NoError(t, applyResponseRewrite(context.Background(), request, response, pipeline, false, http.MethodHead))
		require.EqualValues(t, 1, old.closed.Load())
		require.Equal(t, http.NoBody, response.Body)
		require.Equal(t, "6", response.Header.Get("Content-Length"))
	})
}

func TestM23ResponseHeaderInjectionRejected(t *testing.T) {
	request := rewrite.RequestView{Method: http.MethodGet, URL: rewriteURL("https://example.test/")}
	response := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"X-Bad": {"safe\r\nX-Injected: yes"}},
		Body:       http.NoBody,
	}
	err := applyResponseRewrite(context.Background(), request, response, nil, true, request.Method)
	require.Error(t, err)
	require.NotContains(t, response.Header, "X-Injected")
}

func TestM23ExplicitContentTypeRewriteSurvivesReplacement(t *testing.T) {
	pipeline := compileM2Rules(t, rewrite.Rule{
		Name: "same-type",
		Response: &rewrite.ResponseAction{
			Headers: rewrite.HeaderAction{Set: map[string]string{"Content-Type": "text/plain"}},
			Body:    &rewrite.BodyReplacement{Replace: "replacement"},
		},
	})
	request := rewrite.RequestView{Method: http.MethodGet, URL: rewriteURL("https://example.test/")}
	response := &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/plain"}}, Body: http.NoBody, ContentLength: 0}
	require.NoError(t, applyResponseRewrite(context.Background(), request, response, pipeline, false, request.Method))
	require.Equal(t, "text/plain", response.Header.Get("Content-Type"))
}

func TestM23LaterHeaderRewriteWinsOverBodyContentType(t *testing.T) {
	pipeline := compileM2Rules(t,
		rewrite.Rule{Name: "body", Response: &rewrite.ResponseAction{Body: &rewrite.BodyReplacement{Replace: "replacement", ContentType: "application/body"}}},
		rewrite.Rule{Name: "later-header", Match: rewrite.Match{Headers: map[string]string{"Content-Type": "application/body"}}, Response: &rewrite.ResponseAction{Headers: rewrite.HeaderAction{Set: map[string]string{"Content-Type": "application/header"}}}},
	)
	request := rewrite.RequestView{Method: http.MethodGet, URL: rewriteURL("https://example.test/")}
	response := &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/plain"}}, Body: http.NoBody, ContentLength: 0}
	require.NoError(t, applyResponseRewrite(context.Background(), request, response, pipeline, false, request.Method))
	require.Equal(t, "application/header", response.Header.Get("Content-Type"))
}

func TestM23ResponseLengthConsistency(t *testing.T) {
	for _, trailers := range []bool{false, true} {
		t.Run(fmt.Sprint("trailers=", trailers), func(t *testing.T) {
			response := &http.Response{StatusCode: 200, Header: http.Header{"Content-Length": {"99"}}, ContentLength: 4, Body: http.NoBody}
			if trailers {
				response.Trailer = http.Header{"X-End": nil}
			}
			request := rewrite.RequestView{Method: "GET", URL: rewriteURL("https://example.test/")}
			require.Error(t, applyResponseRewrite(context.Background(), request, response, nil, true, "GET"))
		})
	}
	for _, length := range []string{"+4", "-1", "4, 5", "invalid"} {
		_, _, err := parseResponseContentLength(http.Header{"Content-Length": {length}})
		require.Error(t, err, length)
	}
}
