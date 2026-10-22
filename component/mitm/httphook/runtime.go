package httphook

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// FallbackError records a script failure for diagnostics after the original
// HTTP message has been restored. It is not a transport error.
type FallbackError struct {
	Rule  string
	Cause error
}

func (e *FallbackError) Error() string {
	if e == nil {
		return "HTTP script hook failed"
	}
	return fmt.Sprintf("rule %q: %v", e.Rule, e.Cause)
}

func (e *FallbackError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// RequestResult contains a fully validated mutation. A nil field means that
// script left that part unchanged. Body is meaningful only when BodyChanged.
type RequestResult struct {
	Matched     bool
	Applied     bool
	Fallback    error
	Method      *string
	URL         *url.URL
	Host        *string
	Headers     *http.Header
	Body        []byte
	BodyChanged bool
}

// ResponseResult contains a fully validated mutation. After a complete read,
// Snapshot.ApplyResponse leaves response.Body as a replayable copy, including
// when script execution falls back.
type ResponseResult struct {
	Matched     bool
	Applied     bool
	Fallback    error
	Status      *int
	Headers     *http.Header
	Body        []byte
	BodyChanged bool
}

func (s *Snapshot) matchingRule(phase Phase, request *http.Request, headers http.Header, status int) *compiledRule {
	if s == nil {
		return nil
	}
	for i := range s.rules {
		rule := &s.rules[i]
		if rule.phase == phase && rule.match.matches(request, headers, status) {
			return rule
		}
	}
	return nil
}

func (s *Snapshot) execute(ctx context.Context, rule *compiledRule, input any) (any, error) {
	runtime, err := s.getRuntime()
	if err != nil {
		return nil, err
	}
	return runtime.Run(ctx, rule.source, input)
}

func asOutput(value any, allowed ...string) (map[string]any, error) {
	output, ok := value.(map[string]any)
	if !ok || output == nil {
		return nil, fmt.Errorf("script result must be an object or null")
	}
	allowedKeys := make(map[string]struct{}, len(allowed))
	for _, key := range allowed {
		allowedKeys[key] = struct{}{}
	}
	for key := range output {
		if _, ok := allowedKeys[key]; !ok {
			return nil, fmt.Errorf("unknown script result field %q", key)
		}
	}
	return output, nil
}

func stringField(output map[string]any, name string) (*string, error) {
	value, exists := output[name]
	if !exists {
		return nil, nil
	}
	text, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("%s must be a string", name)
	}
	return &text, nil
}

func statusField(output map[string]any) (*int, error) {
	value, exists := output["status"]
	if !exists {
		return nil, nil
	}
	number, ok := value.(float64)
	if !ok || number != float64(int(number)) || number < 200 || number > 599 {
		return nil, fmt.Errorf("status must be an integer from 200 through 599")
	}
	status := int(number)
	return &status, nil
}

func requestInput(request *http.Request, body []byte) map[string]any {
	input := map[string]any{
		"url":     requestURL(request),
		"method":  request.Method,
		"headers": readRequestHeaders(request),
	}
	for key, value := range bodyInput(body) {
		input[key] = value
	}
	return input
}

func responseInput(request *http.Request, response *http.Response, body []byte) map[string]any {
	requestInput := map[string]any{
		"url":     requestURL(request),
		"method":  request.Method,
		"headers": readRequestHeaders(request),
	}
	input := map[string]any{
		"request": requestInput,
		"status":  response.StatusCode,
		"headers": readResponseHeaders(response),
	}
	for key, value := range bodyInput(body) {
		input[key] = value
	}
	return input
}

func parseRequestOutput(value any, request *http.Request, originalBody []byte, maxBody int) (RequestResult, error) {
	result := RequestResult{Matched: true}
	if value == nil {
		return result, nil
	}
	output, err := asOutput(value, "url", "method", "headers", "body", "body_base64")
	if err != nil {
		return result, err
	}
	result.Applied = true
	if method, err := stringField(output, "method"); err != nil {
		return result, err
	} else if method != nil {
		if !validToken(*method) || *method == http.MethodConnect || *method == "PRI" {
			return result, fmt.Errorf("method is invalid or unsupported")
		}
		result.Method = method
	}

	originalURL := requestURL(request)
	target := request.URL
	urlValue, err := stringField(output, "url")
	if err != nil {
		return result, err
	}
	urlChanged := urlValue != nil && *urlValue != originalURL
	if urlValue != nil {
		target, err = parseRequestURL(*urlValue)
		if err != nil {
			return result, err
		}
		result.URL = target
	}

	if rawHeaders, exists := output["headers"]; exists {
		headers, host, err := parseHeaders(rawHeaders, true)
		if err != nil {
			return result, err
		}
		result.Headers = &headers
		if host != "" {
			originalHost := request.Host
			if originalHost == "" {
				originalHost = request.URL.Host
			}
			if urlChanged {
				if sameAuthority(host, originalHost) {
					host = target.Host
				} else if !sameAuthority(host, target.Host) {
					return result, fmt.Errorf("Host header conflicts with URL authority")
				}
			} else if !sameAuthority(host, originalHost) {
				target = cloneURL(request.URL)
				target.Host = host
				result.URL = target
			}
			result.Host = &host
		} else if urlChanged {
			host := target.Host
			result.Host = &host
		}
	} else if urlChanged {
		host := target.Host
		result.Host = &host
	}
	if result.URL != nil {
		if _, err := parseRequestURL(result.URL.String()); err != nil {
			return result, err
		}
	}

	body, bodyChanged, err := parseBodyMutation(output, maxBody)
	if err != nil {
		return result, err
	}
	if bodyChanged {
		result.Body = body
		result.BodyChanged = !equalBytes(body, originalBody)
	}
	return result, nil
}

func parseResponseOutput(value any, originalBody []byte, maxBody int, currentStatus int) (ResponseResult, error) {
	result := ResponseResult{Matched: true}
	if value == nil {
		return result, nil
	}
	output, err := asOutput(value, "status", "headers", "body", "body_base64")
	if err != nil {
		return result, err
	}
	result.Applied = true
	result.Status, err = statusField(output)
	if err != nil {
		return result, err
	}
	if rawHeaders, exists := output["headers"]; exists {
		headers, _, err := parseHeaders(rawHeaders, false)
		if err != nil {
			return result, err
		}
		result.Headers = &headers
	}
	body, bodyChanged, err := parseBodyMutation(output, maxBody)
	if err != nil {
		return result, err
	}
	if bodyChanged {
		result.Body = body
		result.BodyChanged = !equalBytes(body, originalBody)
	}
	status := currentStatus
	if result.Status != nil {
		status = *result.Status
	}
	if result.BodyChanged && (status == http.StatusNoContent || status == http.StatusResetContent || status == http.StatusPartialContent) {
		return result, fmt.Errorf("body change conflicts with status %d", status)
	}
	return result, nil
}

func sameAuthority(a, b string) bool {
	parse := func(authority string) (string, string, error) {
		target, err := url.Parse("https://" + authority)
		if err != nil || target.Host == "" || target.User != nil || target.Path != "" {
			return "", "", fmt.Errorf("invalid authority")
		}
		port := target.Port()
		if port == "" {
			port = "443"
		}
		parsedPort, err := strconv.ParseUint(port, 10, 16)
		if err != nil || parsedPort == 0 {
			return "", "", fmt.Errorf("invalid authority port")
		}
		return strings.ToLower(strings.TrimSuffix(target.Hostname(), ".")), strconv.FormatUint(parsedPort, 10), nil
	}
	aHost, aPort, aErr := parse(a)
	bHost, bPort, bErr := parse(b)
	return aErr == nil && bErr == nil && aHost == bHost && aPort == bPort
}

func cloneURL(source *url.URL) *url.URL {
	if source == nil {
		return nil
	}
	cloned := *source
	return &cloned
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func fallback(rule *compiledRule, err error) error {
	if rule == nil || err == nil {
		return err
	}
	return &FallbackError{Rule: rule.name, Cause: err}
}
