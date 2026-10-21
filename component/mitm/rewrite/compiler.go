package rewrite

import (
	"fmt"
	"net/netip"
	"net/textproto"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

type headerPair struct{ name, value string }
type headerOps struct {
	set    []headerPair
	remove []string
}
type matcher struct {
	domains, methods []string
	path, prefix     string
	regex            *regexp.Regexp
	headers          []headerPair
	statuses         []int
}
type compiledRule struct {
	match                           matcher
	request                         *RequestAction
	response                        *ResponseAction
	target                          *url.URL
	requestHeaders, responseHeaders headerOps
	terminal                        *TerminalResponse
}

// Snapshot owns private compiled rules. It has no mutation API and is safe for
// concurrent use. Compile preserves configuration order, with no priority sort.
type Snapshot struct {
	rules            []compiledRule
	hasRequestRules  bool
	hasResponseRules bool
}

// Compile validates even disabled rules, but a disabled configuration does not
// compile or validate its contents (matching the optional M1 enable gate).
func Compile(config Config) (*Snapshot, error) {
	if !config.Enable {
		return &Snapshot{}, nil
	}
	per, total := config.MaxReplacementBodyBytes, config.MaxTotalReplacementBodyBytes
	if per == 0 {
		per = DefaultMaxReplacementBodyBytes
	}
	if total == 0 {
		total = DefaultMaxTotalReplacementBodyBytes
	}
	if per < 0 || total < 0 {
		return nil, fmt.Errorf("body limits must be positive")
	}
	s := &Snapshot{}
	names := make(map[string]bool)
	used := 0
	for i, rule := range config.Rules {
		if strings.TrimSpace(rule.Name) == "" || names[rule.Name] {
			return nil, fmt.Errorf("rules[%d]: missing or duplicate name %q", i, rule.Name)
		}
		names[rule.Name] = true
		compiled, size, err := compileRule(rule, per)
		if err != nil {
			return nil, fmt.Errorf("rule %q: %w", rule.Name, err)
		}
		if size > total-used {
			return nil, fmt.Errorf("rule %q: total replacement body limit exceeded", rule.Name)
		}
		used += size
		if rule.Enabled == nil || *rule.Enabled {
			s.rules = append(s.rules, compiled)
			if compiled.request != nil || compiled.terminal != nil {
				s.hasRequestRules = true
			}
			if compiled.response != nil {
				s.hasResponseRules = true
			}
		}
	}
	return s, nil
}

func compileRule(r Rule, limit int) (compiledRule, int, error) {
	var c compiledRule
	m, err := compileMatch(r.Match)
	if err != nil {
		return c, 0, err
	}
	c.match = m
	terminalCount := 0
	if r.Redirect != nil {
		terminalCount++
	}
	if r.LocalResponse != nil {
		terminalCount++
	}
	if terminalCount > 1 || (terminalCount != 0 && (r.Request != nil || r.Response != nil)) {
		return c, 0, fmt.Errorf("conflicting terminal actions")
	}
	if terminalCount == 0 && r.Request == nil && r.Response == nil {
		return c, 0, fmt.Errorf("rule has no action")
	}
	if len(m.statuses) > 0 && (r.Request != nil || terminalCount > 0) {
		return c, 0, fmt.Errorf("response-status requires response-only actions")
	}
	size := 0
	if r.Request != nil {
		a := *r.Request
		a.Headers = HeaderAction{} // runtime uses private, normalized operations
		if a.URL == "" && a.Method == "" && headerEmpty(r.Request.Headers) && a.Body == nil {
			return c, 0, fmt.Errorf("empty request action")
		}
		if a.URL != "" {
			c.target, err = validateTarget(a.URL)
			if err != nil {
				return c, 0, err
			}
		}
		if a.Method != "" && (!validToken(a.Method) || a.Method == "CONNECT" || a.Method == "PRI") {
			return c, 0, fmt.Errorf("invalid or unsupported method %q", a.Method)
		}
		c.requestHeaders, err = compileHeaders(r.Request.Headers)
		if err != nil {
			return c, 0, err
		}
		a.Body, err = compileBody(a.Body, limit)
		if err != nil {
			return c, 0, err
		}
		if a.Body != nil {
			size += len(a.Body.Replace)
		}
		c.request = &a
	}
	if r.Response != nil {
		a := *r.Response
		a.Headers = HeaderAction{}
		if a.Status == 0 && headerEmpty(r.Response.Headers) && a.Body == nil {
			return c, 0, fmt.Errorf("empty response action")
		}
		if a.Status != 0 && !validStatus(a.Status) {
			return c, 0, fmt.Errorf("invalid response status %d", a.Status)
		}
		if a.Body != nil && (a.Status == 204 || a.Status == 205) {
			return c, 0, fmt.Errorf("body conflicts with status %d", a.Status)
		}
		c.responseHeaders, err = compileHeaders(r.Response.Headers)
		if err != nil {
			return c, 0, err
		}
		a.Body, err = compileBody(a.Body, limit)
		if err != nil {
			return c, 0, err
		}
		if a.Body != nil {
			size += len(a.Body.Replace)
		}
		c.response = &a
	}
	if r.Redirect != nil {
		a := r.Redirect
		switch a.Status {
		case 301, 302, 303, 307, 308:
		default:
			return c, 0, fmt.Errorf("invalid redirect status %d", a.Status)
		}
		if err := validateLocation(a.Location); err != nil {
			return c, 0, err
		}
		c.terminal = &TerminalResponse{Decision: RedirectResponse, StatusCode: a.Status, Headers: HeaderMap{"Location": {a.Location}}}
	}
	if r.LocalResponse != nil {
		a := r.LocalResponse
		if !validStatus(a.Status) || (bodyless(a.Status) && a.Body != "") {
			return c, 0, fmt.Errorf("invalid local response status/body")
		}
		if len(a.Body) > limit || !utf8.ValidString(a.Body) {
			return c, 0, fmt.Errorf("invalid or oversized local response body")
		}
		ops, err := compileHeaders(HeaderAction{Set: a.Headers})
		if err != nil {
			return c, 0, err
		}
		headers := make(HeaderMap, len(ops.set))
		for _, p := range ops.set {
			headers[p.name] = []string{p.value}
		}
		c.terminal = &TerminalResponse{Decision: LocalResponseDecision, StatusCode: a.Status, Headers: headers, Body: a.Body}
		size += len(a.Body)
	}
	return c, size, nil
}

func compileMatch(m Match) (matcher, error) {
	c := matcher{path: m.Path, prefix: m.PathPrefix, methods: append([]string(nil), m.Methods...), statuses: append([]int(nil), m.ResponseStatus...)}
	n := 0
	for _, v := range []string{m.Path, m.PathPrefix, m.PathRegex} {
		if v != "" {
			n++
		}
	}
	if n > 1 {
		return c, fmt.Errorf("path match fields are mutually exclusive")
	}
	for _, p := range []string{m.Path, m.PathPrefix} {
		if p != "" && (!strings.HasPrefix(p, "/") || strings.ContainsAny(p, "\r\n\x00?#")) {
			return c, fmt.Errorf("invalid path %q", p)
		}
	}
	if m.PathRegex != "" {
		var err error
		c.regex, err = regexp.Compile(m.PathRegex)
		if err != nil {
			return c, fmt.Errorf("invalid path regex: %w", err)
		}
	}
	for _, domain := range m.Domains {
		d := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
		name := strings.TrimPrefix(d, "*.")
		_, ipErr := netip.ParseAddr(name)
		if !validDomain(name) || ipErr == nil {
			return c, fmt.Errorf("invalid domain %q", domain)
		}
		c.domains = append(c.domains, d)
	}
	for _, method := range c.methods {
		if !validToken(method) {
			return c, fmt.Errorf("invalid match method %q", method)
		}
	}
	for _, status := range c.statuses {
		if !validStatus(status) {
			return c, fmt.Errorf("invalid response-status %d", status)
		}
	}
	seen := map[string]bool{}
	for k, v := range m.Headers {
		if !validToken(k) || !validHeaderValue(v) {
			return c, fmt.Errorf("invalid header match %q", k)
		}
		k = textproto.CanonicalMIMEHeaderKey(k)
		if seen[k] {
			return c, fmt.Errorf("duplicate header match %q", k)
		}
		seen[k] = true
		c.headers = append(c.headers, headerPair{k, v})
	}
	sort.Slice(c.headers, func(i, j int) bool { return c.headers[i].name < c.headers[j].name })
	return c, nil
}

func compileHeaders(a HeaderAction) (headerOps, error) {
	var ops headerOps
	seen := map[string]bool{}
	for k, v := range a.Set {
		if err := validateHeader(k, v); err != nil {
			return ops, err
		}
		k = textproto.CanonicalMIMEHeaderKey(k)
		if seen[k] {
			return ops, fmt.Errorf("duplicate header operation %q", k)
		}
		seen[k] = true
		ops.set = append(ops.set, headerPair{k, v})
	}
	for _, k := range a.Remove {
		if err := validateHeader(k, ""); err != nil {
			return ops, err
		}
		k = textproto.CanonicalMIMEHeaderKey(k)
		if seen[k] {
			return ops, fmt.Errorf("conflicting header operation %q", k)
		}
		seen[k] = true
		ops.remove = append(ops.remove, k)
	}
	sort.Slice(ops.set, func(i, j int) bool { return ops.set[i].name < ops.set[j].name })
	return ops, nil
}

func compileBody(body *BodyReplacement, limit int) (*BodyReplacement, error) {
	if body == nil {
		return nil, nil
	}
	b := *body
	if len(b.Replace) > limit || !utf8.ValidString(b.Replace) {
		return nil, fmt.Errorf("invalid or oversized replacement body")
	}
	if !validHeaderValue(b.ContentType) {
		return nil, fmt.Errorf("invalid body content-type")
	}
	return &b, nil
}
func headerEmpty(h HeaderAction) bool { return len(h.Set) == 0 && len(h.Remove) == 0 }
func validStatus(status int) bool     { return status >= 200 && status <= 599 }

// Informational responses are not final pipeline inputs or action targets.
// 205 forbids content, while 204/304 also have special framing semantics.
func bodyless(status int) bool {
	return status >= 100 && status < 200 || status == 204 || status == 205 || status == 304
}
func validToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_"+"`"+"|~", rune(c))) {
			return false
		}
	}
	return true
}
func validHeaderValue(v string) bool {
	for i := 0; i < len(v); i++ {
		if v[i] == 127 || v[i] < 32 && v[i] != '\t' {
			return false
		}
	}
	return true
}
func validateHeader(k, v string) error {
	if !validToken(k) || !validHeaderValue(v) {
		return fmt.Errorf("invalid header %q", k)
	}
	switch strings.ToLower(k) {
	case "host", "content-length", "transfer-encoding", "connection", "proxy-connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "proxy-authentication-info", "te", "trailer", "upgrade":
		return fmt.Errorf("managed or hop-by-hop header %q is forbidden", k)
	}
	return nil
}
func validDomain(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
func validateTarget(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Opaque != "" || strings.Contains(raw, "#") || !validHeaderValue(raw) || strings.ContainsAny(raw, " \t\\") {
		// Configuration errors may reach logs/API callers. URLs can contain
		// credentials or query tokens; the caller already supplies the rule name.
		return nil, fmt.Errorf("invalid HTTPS rewrite URL")
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	ip, ipErr := netip.ParseAddr(host)
	if strings.HasPrefix(u.Host, "[") && (ipErr != nil || !ip.Is6() || ip.Zone() != "") {
		return nil, fmt.Errorf("invalid IPv6 authority")
	}
	if _, err := netip.ParseAddr(host); err != nil && !validDomain(host) {
		return nil, fmt.Errorf("invalid URL hostname %q", host)
	}
	if strings.HasSuffix(u.Host, ":") {
		return nil, fmt.Errorf("empty URL port")
	}
	if p := u.Port(); p != "" {
		n, err := strconv.ParseUint(p, 10, 16)
		if err != nil || n == 0 {
			return nil, fmt.Errorf("invalid URL port %q", p)
		}
	}
	// Colon-containing authorities must be bracketed IPv6, never bare IPv6.
	if strings.Contains(host, ":") && !strings.HasPrefix(u.Host, "[") {
		return nil, fmt.Errorf("IPv6 authority must be bracketed")
	}
	if _, err := url.QueryUnescape(u.RawQuery); err != nil {
		return nil, fmt.Errorf("invalid URL query encoding: %w", err)
	}
	return u, nil
}
func validateLocation(raw string) error {
	if raw == "" || !validHeaderValue(raw) || strings.ContainsAny(raw, " \t\\") {
		return fmt.Errorf("invalid redirect location")
	}
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Opaque != "" {
		return fmt.Errorf("invalid redirect location")
	}
	if _, err := url.QueryUnescape(u.RawQuery); err != nil {
		return fmt.Errorf("invalid redirect query encoding: %w", err)
	}
	if u.IsAbs() {
		// Fragments belong in client redirects, but not outbound rewrite URLs.
		u.Fragment, u.RawFragment = "", ""
		_, err = validateTarget(u.String())
		return err
	}
	if u.Host != "" || strings.HasPrefix(raw, "//") {
		return fmt.Errorf("network-path redirect is forbidden")
	}
	return nil
}
