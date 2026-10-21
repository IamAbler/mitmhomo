package mitm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/textproto"
	"strconv"
	"strings"

	"github.com/metacubex/mihomo/component/mitm/rewrite"
)

func applyResponseRewrite(ctx context.Context, request rewrite.RequestView, response *http.Response, pipeline *rewrite.Snapshot, forceAdapter bool, downstreamMethod string) error {
	if response == nil {
		return errors.New("native outbound returned a nil response")
	}
	if response.StatusCode < http.StatusOK || response.StatusCode > 599 {
		return fmt.Errorf("unsupported informational or invalid upstream response status %d", response.StatusCode)
	}
	if response.Body == nil {
		response.Body = http.NoBody
	}
	if response.Header == nil {
		response.Header = make(http.Header)
	}

	result := rewrite.ResponseResult{
		Response: rewrite.ResponseView{
			StatusCode: response.StatusCode,
			Headers:    rewrite.HeaderMap(response.Header),
		},
		SuppressBody: request.Method == http.MethodHead || downstreamMethod == http.MethodHead || responseForbidsBody(response.StatusCode),
	}
	if pipeline != nil && pipeline.HasResponseRules() {
		var err error
		result, err = pipeline.ApplyResponse(ctx, request, result.Response)
		if err != nil {
			return fmt.Errorf("apply response rewrite: %w", err)
		}
	}
	// Wire semantics follow the client method, which may differ from the
	// rewritten outbound method. A HEAD upstream has no body to forward, but
	// a non-HEAD client may still receive an explicit static replacement.
	result.SuppressBody = downstreamMethod == http.MethodHead || responseForbidsBody(result.Response.StatusCode)
	if (request.Method == http.MethodHead || responseForbidsBody(response.StatusCode)) && result.Body == nil && !result.SuppressBody {
		// HEAD/304 lengths describe a representation, not an available stream.
		// A status rewrite must not turn that metadata into a promised body.
		response.ContentLength = 0
		result.Response.Headers = rewrite.HeaderMap(http.Header(result.Response.Headers).Clone())
		clearReplacedRepresentationHeaders(http.Header(result.Response.Headers))
		result.Response.Headers["Content-Length"] = []string{"0"}
		forceAdapter = true
	}
	if !result.Changed && !result.SuppressBody && !forceAdapter {
		return nil
	}
	return applyResponseResult(response, result, downstreamMethod)
}

func applyResponseResult(response *http.Response, result rewrite.ResponseResult, requestMethod string) error {
	if response == nil {
		return errors.New("cannot adapt a nil response")
	}
	status := result.Response.StatusCode
	if status < http.StatusOK || status > 599 {
		return fmt.Errorf("invalid rewritten response status %d", status)
	}
	if _, err := canonicalResponseHeader(rewrite.HeaderMap(response.Header)); err != nil {
		return err
	}
	header, err := canonicalResponseHeader(result.Response.Headers)
	if err != nil {
		return err
	}
	if err := validateResponseTrailers(response.Trailer); err != nil {
		return err
	}

	if result.Changed {
		response.StatusCode = status
		response.Status = responseStatus(status)
	}
	response.Header = header

	bodylessStatus := status == http.StatusNoContent || status == http.StatusResetContent || status == http.StatusNotModified
	suppressBody := result.SuppressBody || requestMethod == http.MethodHead || bodylessStatus
	if result.Body != nil && (status == http.StatusNoContent || status == http.StatusResetContent) {
		return fmt.Errorf("response body replacement conflicts with status %d", status)
	}
	if result.Body != nil && status == http.StatusPartialContent {
		// A full static representation has no valid upstream byte-range mapping.
		// Require an explicit status rewrite (typically 200), rather than emit a
		// 206 whose Content-Range was invalidated by the replacement.
		return errors.New("response body replacement requires a non-206 status")
	}

	if result.Body != nil {
		clearReplacedRepresentationHeaders(header)
		if result.ContentTypeModified {
			// A later response Header action deliberately chose or removed the type.
		} else if result.Body.ContentType != "" {
			header.Set("Content-Type", result.Body.ContentType)
		} else {
			header.Del("Content-Type")
		}
		response.ContentLength = int64(len(result.Body.Replace))
		header.Set("Content-Length", strconv.Itoa(len(result.Body.Replace)))
		response.Trailer = nil
		response.TransferEncoding = nil
		header.Del("Trailer")
		header.Del("Transfer-Encoding")
	} else if suppressBody {
		response.Trailer = nil
		response.TransferEncoding = nil
		header.Del("Trailer")
		header.Del("Transfer-Encoding")
	}

	nominatedTrailers := removeResponseHopByHopHeaders(header, response.Trailer)
	response.TransferEncoding = nil
	if err := normalizeResponseFraming(response, header, status, requestMethod, suppressBody); err != nil {
		return err
	}

	if result.Body != nil || suppressBody {
		oldBody := response.Body
		response.Body = http.NoBody
		if oldBody != nil && oldBody != http.NoBody {
			if err := oldBody.Close(); err != nil {
				return fmt.Errorf("close replaced upstream response body: %w", err)
			}
		}
		if result.Body != nil && !suppressBody {
			response.Body = replacementReader(result.Body.Replace)
		}
	} else if len(nominatedTrailers) > 0 && response.Body != nil && response.Body != http.NoBody {
		response.Body = &responseTrailerFilterBody{body: response.Body, trailers: response.Trailer, names: nominatedTrailers}
	}
	return nil
}

type responseTrailerFilterBody struct {
	body     io.ReadCloser
	trailers http.Header
	names    []string
	dropAll  bool
}

func (b *responseTrailerFilterBody) Read(p []byte) (int, error) {
	n, err := b.body.Read(p)
	if err != nil {
		if b.dropAll {
			for name := range b.trailers {
				delete(b.trailers, name)
			}
		}
		// The transport populates trailer values only when the upstream body
		// reaches EOF, so connection-nominated fields must be removed again here.
		for _, name := range b.names {
			b.trailers.Del(name)
		}
	}
	return n, err
}

func (b *responseTrailerFilterBody) Close() error { return b.body.Close() }

func canonicalResponseHeader(source rewrite.HeaderMap) (http.Header, error) {
	header := make(http.Header, len(source))
	for name, values := range source {
		if !validResponseHeaderName(name) {
			return nil, fmt.Errorf("invalid response header name %q", name)
		}
		canonical := textproto.CanonicalMIMEHeaderKey(name)
		for _, value := range values {
			if !validResponseHeaderValue(value) {
				return nil, fmt.Errorf("invalid value for response header %q", name)
			}
			header[canonical] = append(header[canonical], value)
		}
	}
	return header, nil
}

func validResponseHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c))) {
			return false
		}
	}
	return true
}

func validResponseHeaderValue(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] == 127 || value[i] < 32 && value[i] != '\t' {
			return false
		}
	}
	return true
}

func validateResponseTrailers(trailers http.Header) error {
	for name, values := range trailers {
		if !validResponseHeaderName(name) || forbiddenResponseTrailer(name) {
			return fmt.Errorf("invalid response trailer name %q", name)
		}
		for _, value := range values {
			if !validResponseHeaderValue(value) {
				return fmt.Errorf("invalid value for response trailer %q", name)
			}
		}
	}
	return nil
}

func forbiddenResponseTrailer(name string) bool {
	switch strings.ToLower(name) {
	case "content-length", "transfer-encoding", "trailer", "host", "connection", "keep-alive", "proxy-connection", "proxy-authenticate", "proxy-authorization", "proxy-authentication-info", "te", "upgrade":
		return true
	default:
		return false
	}
}

func removeResponseHopByHopHeaders(header http.Header, trailers ...http.Header) []string {
	nominated := responseConnectionFields(header)
	for _, field := range nominated {
		header.Del(field)
		for _, trailer := range trailers {
			trailer.Del(field)
		}
	}
	for _, name := range []string{
		"Connection", "Keep-Alive", "Proxy-Connection", "Proxy-Authenticate", "Proxy-Authorization",
		"Proxy-Authentication-Info", "TE", "Trailer", "Transfer-Encoding", "Upgrade",
	} {
		header.Del(name)
		for _, trailer := range trailers {
			trailer.Del(name)
		}
	}
	return nominated
}

func responseConnectionFields(header http.Header) []string {
	var fields []string
	for _, value := range header.Values("Connection") {
		for _, field := range strings.Split(value, ",") {
			field = strings.TrimSpace(field)
			if validResponseHeaderName(field) {
				fields = append(fields, field)
			}
		}
	}
	return fields
}

func clearReplacedRepresentationHeaders(header http.Header) {
	for _, name := range []string{
		"Content-Encoding", "Content-Language", "Content-Location", "Content-Range",
		"Content-MD5", "Digest", "Content-Digest", "Repr-Digest", "Accept-Ranges", "ETag",
		"Last-Modified", "Vary", "Content-Disposition",
	} {
		header.Del(name)
	}
}

func normalizeResponseFraming(response *http.Response, header http.Header, status int, requestMethod string, suppressBody bool) error {
	if status == http.StatusNoContent {
		header.Del("Content-Length")
		response.ContentLength = -1
		return nil
	}
	if status == http.StatusResetContent {
		header.Set("Content-Length", "0")
		response.ContentLength = 0
		return nil
	}

	if suppressBody {
		length, present, err := parseResponseContentLength(header)
		if err != nil {
			return err
		}
		if present {
			// Transport reports an empty 304 stream (ContentLength=0), while a
			// legal Content-Length header describes the selected representation.
			if status != http.StatusNotModified && response.ContentLength >= 0 && response.ContentLength != length {
				return fmt.Errorf("response Content-Length header %d conflicts with body length %d", length, response.ContentLength)
			}
			response.ContentLength = length
		} else if response.ContentLength >= 0 {
			header.Set("Content-Length", strconv.FormatInt(response.ContentLength, 10))
		} else {
			response.ContentLength = -1
		}
		return nil
	}

	length, present, err := parseResponseContentLength(header)
	if err != nil {
		return err
	}
	if response.ContentLength >= 0 {
		if present && length != response.ContentLength {
			return fmt.Errorf("response Content-Length header %d conflicts with body length %d", length, response.ContentLength)
		}
		header.Set("Content-Length", strconv.FormatInt(response.ContentLength, 10))
	} else if present {
		return errors.New("response has Content-Length but unknown body length")
	} else {
		header.Del("Content-Length")
	}
	if len(response.Trailer) > 0 {
		// Only a consistent length may be converted to chunked trailer framing.
		header.Del("Content-Length")
		response.ContentLength = -1
	}
	return nil
}

func parseResponseContentLength(header http.Header) (int64, bool, error) {
	values := header.Values("Content-Length")
	if len(values) == 0 {
		return 0, false, nil
	}
	var length int64 = -1
	for _, value := range values {
		for _, raw := range strings.Split(value, ",") {
			raw = strings.TrimSpace(raw)
			if raw == "" || strings.IndexFunc(raw, func(c rune) bool { return c < '0' || c > '9' }) >= 0 {
				return 0, false, fmt.Errorf("invalid response Content-Length %q", raw)
			}
			parsed, err := strconv.ParseInt(raw, 10, 64)
			if err != nil || parsed < 0 {
				return 0, false, fmt.Errorf("invalid response Content-Length %q", raw)
			}
			if length >= 0 && length != parsed {
				return 0, false, errors.New("conflicting response Content-Length values")
			}
			length = parsed
		}
	}
	return length, true, nil
}

func responseForbidsBody(status int) bool {
	return status == http.StatusNoContent || status == http.StatusResetContent || status == http.StatusNotModified
}

func responseStatus(status int) string {
	code := strconv.Itoa(status)
	if text := http.StatusText(status); text != "" {
		return code + " " + text
	}
	return code
}
