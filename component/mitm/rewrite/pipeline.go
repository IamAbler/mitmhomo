package rewrite

import (
	"context"
	"fmt"
	"strings"
)

var _ RequestPipeline = (*Snapshot)(nil)
var _ ResponsePipeline = (*Snapshot)(nil)

// HasRequestRules reports whether this snapshot contains request-phase actions.
// It lets HTTP adapters skip request conversion for response-only/empty rules.
func (s *Snapshot) HasRequestRules() bool {
	return s != nil && s.hasRequestRules
}

// ApplyRequest matches each rule against the progressively rewritten request.
// It never mutates the input; unchanged Headers remain borrowed from the caller.
func (s *Snapshot) ApplyRequest(ctx context.Context, request RequestView) (RequestResult, error) {
	result := RequestResult{Request: request}
	if err := ctx.Err(); err != nil {
		return RequestResult{}, err
	}
	if s == nil {
		return result, nil
	}
	headersOwned := false
	for _, rule := range s.rules {
		if err := ctx.Err(); err != nil {
			return RequestResult{}, err
		}
		if rule.request == nil && rule.terminal == nil {
			continue
		}
		if !rule.match.matches(result.Request, result.Request.Headers, 0) {
			continue
		}
		result.Changed = true
		if rule.terminal != nil {
			terminal := *rule.terminal
			terminal.Headers = cloneHeaders(terminal.Headers)
			return RequestResult{Request: request, Changed: true, Terminal: &terminal}, nil
		}
		a := rule.request
		if rule.target != nil {
			result.Request.URL = *rule.target
		}
		if a.Method != "" {
			result.Request.Method = a.Method
		}
		if !rule.requestHeaders.empty() {
			if !headersOwned {
				result.Request.Headers = cloneHeaders(result.Request.Headers)
				headersOwned = true
			}
			rule.requestHeaders.apply(result.Request.Headers)
		}
		if a.Body != nil {
			body := *a.Body
			result.Body = &body
		}
	}
	return result, nil
}

// ApplyResponse uses the final outbound request and progressively rewritten
// response headers/status. Final semantic validation precedes returning any intent.
// Adapters own framing, stream closure and enforcement of SuppressBody.
func (s *Snapshot) ApplyResponse(ctx context.Context, request RequestView, response ResponseView) (ResponseResult, error) {
	result := ResponseResult{Response: response}
	if err := ctx.Err(); err != nil {
		return ResponseResult{}, err
	}
	if !validStatus(response.StatusCode) {
		return ResponseResult{}, fmt.Errorf("response pipeline requires a final status, got %d", response.StatusCode)
	}
	if s == nil {
		return finalizeResponse(request, result)
	}
	headersOwned := false
	for _, rule := range s.rules {
		if err := ctx.Err(); err != nil {
			return ResponseResult{}, err
		}
		if rule.response == nil || !rule.match.matches(request, result.Response.Headers, result.Response.StatusCode) {
			continue
		}
		result.Changed = true
		a := rule.response
		if a.Status != 0 {
			result.Response.StatusCode = a.Status
		}
		if !rule.responseHeaders.empty() {
			if !headersOwned {
				result.Response.Headers = cloneHeaders(result.Response.Headers)
				headersOwned = true
			}
			rule.responseHeaders.apply(result.Response.Headers)
		}
		if a.Body != nil {
			body := *a.Body
			result.Body = &body
		}
	}
	return finalizeResponse(request, result)
}

// finalizeResponse validates the complete composition, never an intermediate status.
// Errors return no consumable partial result. HEAD replacement is deliberately
// unsupported until representation metadata can be derived by an adapter.
func finalizeResponse(request RequestView, result ResponseResult) (ResponseResult, error) {
	status := result.Response.StatusCode
	if result.Body != nil && (bodyless(status) || request.Method == "HEAD") {
		return ResponseResult{}, fmt.Errorf("body replacement conflicts with final status %d or request method %s", status, request.Method)
	}
	result.SuppressBody = bodyless(status) || request.Method == "HEAD"
	// Content-Type and validators can describe the selected representation even
	// without content. 304/HEAD length can describe the corresponding GET.
	// 204 forbids Content-Length; 205 permits only a zero content length.
	for name, values := range result.Response.Headers {
		if !strings.EqualFold(name, "Content-Length") {
			continue
		}
		remove := status == 204
		if status == 205 {
			for _, value := range values {
				if strings.TrimSpace(value) != "0" {
					remove = true
				}
			}
		}
		if remove {
			result.Response.Headers = cloneHeaders(result.Response.Headers)
			deleteHeader(result.Response.Headers, "Content-Length")
			result.Changed = true
			break
		}
	}
	return result, nil
}

func (m matcher) matches(request RequestView, headers HeaderMap, status int) bool {
	if len(m.domains) > 0 {
		host := strings.ToLower(strings.TrimSuffix(request.URL.Hostname(), "."))
		matched := false
		for _, domain := range m.domains {
			if host == domain || strings.HasPrefix(domain, "*.") && strings.HasSuffix(host, domain[1:]) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	path := request.URL.Path
	if path == "" {
		path = "/"
	}
	if m.path != "" && path != m.path || m.prefix != "" && !strings.HasPrefix(path, m.prefix) || m.regex != nil && !m.regex.MatchString(path) {
		return false
	}
	if len(m.methods) > 0 {
		found := false
		for _, method := range m.methods {
			if request.Method == method {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if len(m.statuses) > 0 {
		found := false
		for _, s := range m.statuses {
			if status == s {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	for _, p := range m.headers {
		found := false
		for k, values := range headers {
			if strings.EqualFold(k, p.name) {
				for _, value := range values {
					if value == p.value {
						found = true
						break
					}
				}
			}
		}
		if !found {
			return false
		}
	}
	return true
}
func cloneHeaders(headers HeaderMap) HeaderMap {
	result := make(HeaderMap, len(headers))
	for k, v := range headers {
		result[k] = append([]string(nil), v...)
	}
	return result
}
func (ops headerOps) empty() bool { return len(ops.set) == 0 && len(ops.remove) == 0 }
func (ops headerOps) apply(headers HeaderMap) {
	for _, name := range ops.remove {
		deleteHeader(headers, name)
	}
	for _, p := range ops.set {
		deleteHeader(headers, p.name)
		headers[p.name] = []string{p.value}
	}
}
func deleteHeader(headers HeaderMap, name string) {
	for k := range headers {
		if strings.EqualFold(k, name) {
			delete(headers, k)
		}
	}
}
