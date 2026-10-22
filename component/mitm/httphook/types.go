// Package httphook implements bounded, engine-neutral HTTP script hooks for
// the MITM adapter. Scripts exchange JSON data and never receive net/http
// objects or proxy services.
package httphook

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"unicode/utf8"

	"github.com/metacubex/mihomo/component/mitm/jsruntime"
	"github.com/metacubex/mihomo/component/mitm/scriptapi"
	C "github.com/metacubex/mihomo/constant"
	domainname "github.com/metacubex/sing/common/metadata"
)

const (
	DefaultMaxBodyBytes = 256 << 10
	MaxBodyBytes        = 1 << 20
	maxSourceBytes      = 256 << 10
	maxConcurrentHooks  = 4
	maxScriptNameBytes  = 128
)

// Config is disabled unless Enable is true. Rules are evaluated in order; the
// first matching rule for a request or response phase runs once.
type Config struct {
	Enable               bool   `yaml:"enable" json:"enable"`
	MaxBodyBytes         int    `yaml:"max-body-bytes" json:"max-body-bytes"`
	ExecutionTimeout     int    `yaml:"execution-timeout" json:"execution-timeout"`
	AllowPrivateNetworks bool   `yaml:"allow-private-networks" json:"allow-private-networks"`
	Rules                []Rule `yaml:"rules" json:"rules"`
}

type Phase string

const (
	RequestPhase  Phase = "request"
	ResponsePhase Phase = "response"
)

// Rule contains inline JavaScript source. A source is compiled lazily the
// first time its rule matches a request.
type Rule struct {
	Name   string `yaml:"name" json:"name"`
	Phase  Phase  `yaml:"phase" json:"phase"`
	Mode   string `yaml:"mode" json:"mode"`
	Match  Match  `yaml:"match" json:"match"`
	Source string `yaml:"source" json:"source"`
}

const (
	LegacyMode = "legacy"
	APIMode    = "api"
)

type Services struct {
	Store         scriptapi.PersistentStore
	HTTPClients   scriptapi.HTTPClientFactory
	Log           scriptapi.LogSink
	Notifications scriptapi.Notifier
}

// Match deliberately supports only common HTTP predicates in this milestone.
// All configured fields must match.
type Match struct {
	Domains        []string          `yaml:"domains" json:"domains"`
	Methods        []string          `yaml:"methods" json:"methods"`
	Path           string            `yaml:"path" json:"path"`
	PathPrefix     string            `yaml:"path-prefix" json:"path-prefix"`
	Headers        map[string]string `yaml:"headers" json:"headers"`
	ResponseStatus []int             `yaml:"response-status" json:"response-status"`
}

type headerPredicate struct{ name, value string }

type compiledMatch struct {
	domains        []string
	methods        map[string]struct{}
	path           string
	pathPrefix     string
	headers        []headerPredicate
	responseStatus map[int]struct{}
}

type compiledRule struct {
	name   string
	phase  Phase
	mode   string
	match  compiledMatch
	source string
}

// Snapshot is immutable after Compile. Its Runtime is created only when a
// configured rule actually matches and is closed when its owning MITM
// configuration generation is retired.
type Snapshot struct {
	config Config
	rules  []compiledRule

	runtimeMu sync.Mutex
	runtime   *jsruntime.Runtime
	closed    bool
	active    atomic.Int32
	services  Services
}

// Compile validates and freezes configuration without creating a Runtime or
// VM. Disabled configuration produces no snapshot.
func Compile(config Config) (*Snapshot, error) {
	if !config.Enable {
		return nil, nil
	}
	if config.MaxBodyBytes == 0 {
		config.MaxBodyBytes = DefaultMaxBodyBytes
	}
	if config.MaxBodyBytes < 1 || config.MaxBodyBytes > MaxBodyBytes {
		return nil, fmt.Errorf("max-body-bytes must be between 1 and %d", MaxBodyBytes)
	}
	if config.ExecutionTimeout == 0 {
		config.ExecutionTimeout = 10
	}
	if config.ExecutionTimeout < 1 || config.ExecutionTimeout > 30 {
		return nil, fmt.Errorf("execution-timeout must be between 1 and 30 seconds")
	}
	if len(config.Rules) == 0 {
		return nil, fmt.Errorf("enabled HTTP script hooks require at least one rule")
	}

	config.Rules = cloneRules(config.Rules)
	snapshot := &Snapshot{config: config, rules: make([]compiledRule, 0, len(config.Rules))}
	names := make(map[string]struct{}, len(config.Rules))
	for i, rule := range config.Rules {
		if strings.TrimSpace(rule.Name) == "" {
			return nil, fmt.Errorf("rules[%d].name is required", i)
		}
		if len(rule.Name) > maxScriptNameBytes {
			return nil, fmt.Errorf("rules[%d].name is too long", i)
		}
		if _, exists := names[rule.Name]; exists {
			return nil, fmt.Errorf("rules[%d].name %q is duplicated", i, rule.Name)
		}
		names[rule.Name] = struct{}{}
		if rule.Mode == "" {
			rule.Mode = LegacyMode
		}
		if rule.Mode != LegacyMode && rule.Mode != APIMode {
			return nil, fmt.Errorf("rules[%d].mode must be legacy or api", i)
		}
		if rule.Phase != RequestPhase && rule.Phase != ResponsePhase {
			return nil, fmt.Errorf("rules[%d].phase must be request or response", i)
		}
		if strings.TrimSpace(rule.Source) == "" || len(rule.Source) > maxSourceBytes || !utf8.ValidString(rule.Source) {
			return nil, fmt.Errorf("rules[%d].source must be non-empty UTF-8 no larger than %d bytes", i, maxSourceBytes)
		}
		match, err := compileMatch(rule.Phase, rule.Match)
		if err != nil {
			return nil, fmt.Errorf("rules[%d].match: %w", i, err)
		}
		snapshot.rules = append(snapshot.rules, compiledRule{name: rule.Name, phase: rule.Phase, mode: rule.Mode, match: match, source: rule.Source})
		config.Rules[i].Mode = rule.Mode
	}
	for _, rule := range snapshot.rules {
		if rule.mode == APIMode {
			store, err := scriptapi.SharedStore(filepath.Join(C.Path.HomeDir(), "script-store"))
			if err != nil {
				return nil, fmt.Errorf("initialize persistent script storage: %w", err)
			}
			snapshot.services.Store = store
			break
		}
	}
	return snapshot, nil
}

func cloneRules(rules []Rule) []Rule {
	cloned := make([]Rule, len(rules))
	for i, rule := range rules {
		cloned[i] = rule
		cloned[i].Match.Domains = append([]string(nil), rule.Match.Domains...)
		cloned[i].Match.Methods = append([]string(nil), rule.Match.Methods...)
		cloned[i].Match.ResponseStatus = append([]int(nil), rule.Match.ResponseStatus...)
		if rule.Match.Headers != nil {
			cloned[i].Match.Headers = make(map[string]string, len(rule.Match.Headers))
			for name, value := range rule.Match.Headers {
				cloned[i].Match.Headers[name] = value
			}
		}
	}
	return cloned
}

// Clone makes a fresh generation with the same immutable source and matching
// rules. Runtime state is never shared across configuration generations.
func (s *Snapshot) Clone() *Snapshot {
	if s == nil {
		return nil
	}
	cloned, err := Compile(s.config)
	if err != nil {
		return nil
	}
	cloned.services = s.services
	return cloned
}

// CloneWithServices returns a fresh immutable generation with the supplied
// host services. Storage is shared by directory so config reloads retain data.
func (s *Snapshot) CloneWithServices(services Services) *Snapshot {
	cloned := s.Clone()
	if cloned == nil {
		return nil
	}
	if services.Store != nil {
		cloned.services.Store = services.Store
	}
	cloned.services.HTTPClients = services.HTTPClients
	if services.Log != nil {
		cloned.services.Log = services.Log
	}
	cloned.services.Notifications = services.Notifications
	return cloned
}

func (s *Snapshot) Close() error {
	if s == nil {
		return nil
	}
	s.runtimeMu.Lock()
	s.closed = true
	runtime := s.runtime
	s.runtime = nil
	s.runtimeMu.Unlock()
	if runtime != nil {
		return runtime.Close()
	}
	return nil
}

// RuntimeInitialized reports whether a matching rule has caused lazy Runtime
// construction. It is also useful for lifecycle diagnostics.
func (s *Snapshot) RuntimeInitialized() bool {
	if s == nil {
		return false
	}
	s.runtimeMu.Lock()
	defer s.runtimeMu.Unlock()
	return s.runtime != nil
}

func (s *Snapshot) getRuntime() (*jsruntime.Runtime, error) {
	s.runtimeMu.Lock()
	defer s.runtimeMu.Unlock()
	if s.closed {
		return nil, fmt.Errorf("HTTP script hook snapshot is closed")
	}
	if s.runtime != nil {
		return s.runtime, nil
	}
	config := jsruntime.DefaultConfig()
	config.MaxInputBytes = 8 << 20
	config.MaxOutputBytes = 4 << 20
	config.MaxConcurrent = 4
	config.CompileCacheEntries = 64
	runtime, err := jsruntime.New(config)
	if err != nil {
		return nil, err
	}
	s.runtime = runtime
	return runtime, nil
}

func (s *Snapshot) tryAcquire() bool {
	for {
		active := s.active.Load()
		if active >= maxConcurrentHooks {
			return false
		}
		if s.active.CompareAndSwap(active, active+1) {
			return true
		}
	}
}

func compileMatch(phase Phase, match Match) (compiledMatch, error) {
	compiled := compiledMatch{path: match.Path, pathPrefix: match.PathPrefix}
	if match.Path != "" && match.PathPrefix != "" {
		return compiled, fmt.Errorf("path and path-prefix are mutually exclusive")
	}
	for _, path := range []string{match.Path, match.PathPrefix} {
		if strings.ContainsAny(path, "\r\n\x00?#") || path != "" && !strings.HasPrefix(path, "/") {
			return compiled, fmt.Errorf("invalid path %q", path)
		}
	}
	for _, raw := range match.Domains {
		domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
		name := strings.TrimPrefix(domain, "*.")
		if name == "" || strings.Contains(strings.TrimPrefix(name, "*."), "*") || !domainname.IsDomainName(name) {
			return compiled, fmt.Errorf("invalid domain %q", raw)
		}
		compiled.domains = append(compiled.domains, domain)
	}
	if len(match.Methods) > 0 {
		compiled.methods = make(map[string]struct{}, len(match.Methods))
		for _, method := range match.Methods {
			if !validToken(method) {
				return compiled, fmt.Errorf("invalid method %q", method)
			}
			compiled.methods[method] = struct{}{}
		}
	}
	if phase == RequestPhase && len(match.ResponseStatus) > 0 {
		return compiled, fmt.Errorf("response-status is only valid for response rules")
	}
	if len(match.ResponseStatus) > 0 {
		compiled.responseStatus = make(map[int]struct{}, len(match.ResponseStatus))
		for _, status := range match.ResponseStatus {
			if status < 200 || status > 599 {
				return compiled, fmt.Errorf("invalid response status %d", status)
			}
			compiled.responseStatus[status] = struct{}{}
		}
	}
	seenHeaders := make(map[string]struct{}, len(match.Headers))
	for name, value := range match.Headers {
		if !validToken(name) || !validHeaderValue(value) {
			return compiled, fmt.Errorf("invalid header predicate %q", name)
		}
		canonical := http.CanonicalHeaderKey(name)
		if _, exists := seenHeaders[canonical]; exists {
			return compiled, fmt.Errorf("duplicate case-insensitive header predicate %q", name)
		}
		seenHeaders[canonical] = struct{}{}
		compiled.headers = append(compiled.headers, headerPredicate{name: canonical, value: value})
	}
	sort.Slice(compiled.headers, func(i, j int) bool { return compiled.headers[i].name < compiled.headers[j].name })
	return compiled, nil
}

func (m compiledMatch) matches(request *http.Request, headers http.Header, status int) bool {
	if request == nil || request.URL == nil {
		return false
	}
	host := strings.ToLower(strings.TrimSuffix(request.URL.Hostname(), "."))
	if len(m.domains) > 0 {
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
	if m.path != "" && request.URL.Path != m.path || m.pathPrefix != "" && !strings.HasPrefix(request.URL.Path, m.pathPrefix) {
		return false
	}
	if len(m.methods) > 0 {
		if _, ok := m.methods[request.Method]; !ok {
			return false
		}
	}
	if len(m.responseStatus) > 0 {
		if _, ok := m.responseStatus[status]; !ok {
			return false
		}
	}
	for _, predicate := range m.headers {
		found := false
		for name, values := range headers {
			if !strings.EqualFold(name, predicate.name) {
				continue
			}
			for _, value := range values {
				if value == predicate.value {
					found = true
					break
				}
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func validToken(value string) bool {
	if value == "" {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c))) {
			return false
		}
	}
	return true
}

func validHeaderValue(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] == 127 || value[i] < 32 && value[i] != '\t' || value[i] == '\r' || value[i] == '\n' {
			return false
		}
	}
	return true
}

func readRequestHeaders(request *http.Request) map[string][]string {
	headers := make(map[string][]string, len(request.Header)+1)
	for name, values := range request.Header {
		if managedHeader(name) {
			continue
		}
		headers[name] = append([]string(nil), values...)
	}
	if request.Host != "" {
		headers["Host"] = []string{request.Host}
	}
	return headers
}

func readResponseHeaders(response *http.Response) map[string][]string {
	headers := make(map[string][]string, len(response.Header))
	for name, values := range response.Header {
		if managedHeader(name) || strings.EqualFold(name, "Host") {
			continue
		}
		headers[name] = append([]string(nil), values...)
	}
	return headers
}

func managedHeader(name string) bool {
	switch strings.ToLower(name) {
	case "content-length", "transfer-encoding", "trailer", "connection", "keep-alive", "proxy-connection", "proxy-authenticate", "proxy-authorization", "proxy-authentication-info", "te", "upgrade":
		return true
	default:
		return false
	}
}

func parseHeaders(value any, allowHost bool) (http.Header, string, error) {
	entries, ok := value.(map[string]any)
	if !ok {
		return nil, "", fmt.Errorf("headers must be an object")
	}
	header := make(http.Header, len(entries))
	seen := make(map[string]struct{}, len(entries))
	host := ""
	for name, rawValues := range entries {
		if !validToken(name) {
			return nil, "", fmt.Errorf("invalid header name %q", name)
		}
		canonical := http.CanonicalHeaderKey(name)
		if _, ok := seen[canonical]; ok {
			return nil, "", fmt.Errorf("duplicate case-insensitive header %q", name)
		}
		seen[canonical] = struct{}{}
		if managedHeader(name) {
			return nil, "", fmt.Errorf("header %q is managed by HTTP framing", name)
		}
		var values []string
		switch raw := rawValues.(type) {
		case string:
			values = []string{raw}
		case []any:
			values = make([]string, 0, len(raw))
			for _, item := range raw {
				text, ok := item.(string)
				if !ok {
					return nil, "", fmt.Errorf("header %q values must be strings", name)
				}
				values = append(values, text)
			}
		default:
			return nil, "", fmt.Errorf("header %q must be a string or string array", name)
		}
		for _, item := range values {
			if !validHeaderValue(item) {
				return nil, "", fmt.Errorf("invalid value for header %q", name)
			}
		}
		if strings.EqualFold(name, "Host") {
			if !allowHost || len(values) != 1 || values[0] == "" {
				return nil, "", fmt.Errorf("Host must contain exactly one authority")
			}
			host = values[0]
			continue
		}
		header[canonical] = values
	}
	return header, host, nil
}

func bodyInput(body []byte) map[string]any {
	if utf8.Valid(body) {
		return map[string]any{"body": string(body)}
	}
	return map[string]any{"body_base64": base64.StdEncoding.EncodeToString(body)}
}

func parseBodyMutation(output map[string]any, maxBytes int) ([]byte, bool, error) {
	textValue, hasText := output["body"]
	base64Value, hasBase64 := output["body_base64"]
	if !hasText && !hasBase64 {
		return nil, false, nil
	}
	if hasText && hasBase64 {
		return nil, false, fmt.Errorf("body and body_base64 cannot both be set")
	}
	var body []byte
	if hasText {
		text, ok := textValue.(string)
		if !ok {
			return nil, false, fmt.Errorf("body must be a string")
		}
		body = []byte(text)
	} else {
		encoded, ok := base64Value.(string)
		if !ok {
			return nil, false, fmt.Errorf("body_base64 must be a string")
		}
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, false, fmt.Errorf("invalid body_base64: %w", err)
		}
		body = decoded
	}
	if len(body) > maxBytes {
		return nil, false, fmt.Errorf("body exceeds %d bytes", maxBytes)
	}
	return body, true, nil
}

func requestURL(request *http.Request) string {
	if request == nil || request.URL == nil {
		return ""
	}
	return request.URL.String()
}

func parseRequestURL(raw string) (*url.URL, error) {
	target, err := url.Parse(raw)
	if err != nil || target == nil || !target.IsAbs() || !strings.EqualFold(target.Scheme, "https") || target.Host == "" || target.User != nil || target.Opaque != "" || target.Fragment != "" || target.RawFragment != "" {
		return nil, fmt.Errorf("invalid absolute request URL")
	}
	if target.Hostname() == "" {
		return nil, fmt.Errorf("request URL authority has no hostname")
	}
	if port := target.Port(); port != "" {
		for _, digit := range port {
			if digit < '0' || digit > '9' {
				return nil, fmt.Errorf("request URL authority has an invalid port")
			}
		}
	}
	return target, nil
}
