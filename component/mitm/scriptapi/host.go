package scriptapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/textproto"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/metacubex/mihomo/common/contextutils"
	"github.com/metacubex/mihomo/component/mitm/scripthost"
)

const (
	maxHTTPBodyBytes       = 1 << 20
	maxHTTPHeaderBytes     = 32 << 10
	maxHTTPHeaders         = 64
	maxHTTPHeaderValueSize = 8 << 10
	maxHTTPTimeout         = 30 * time.Second
	defaultHTTPTimeout     = 5 * time.Second
	maxRedirects           = 3
	maxLogMessageBytes     = 4 << 10
	maxLogCalls            = 32
)

var ErrHostClosed = errors.New("script host is closed")

// HTTPClientFactory must return a client whose transport dials through the
// application's routing policy and enforces the private-address policy.
type HTTPClientFactory func(allowPrivate bool) (*http.Client, func(), error)

// LogSink receives bounded, already formatted script log messages.
type LogSink interface {
	Log(level, message string)
}

// Notifier is optional. A missing notifier makes notification.post return
// false rather than reporting a notification that was never delivered.
type Notifier interface {
	Post(context.Context, string, string, string) error
}

type HostConfig struct {
	Namespace     string
	Store         PersistentStore
	HTTPClients   HTTPClientFactory
	AllowPrivate  bool
	Log           LogSink
	Notifications Notifier
}

type Host struct {
	config      HostConfig
	client      *http.Client
	clientClose func()
	mu          sync.Mutex
	closed      bool
	tasks       map[*httpTask]struct{}
	closeOnce   sync.Once
	logCalls    atomic.Int32
}

type httpTask struct {
	host   *Host
	ctx    context.Context
	cancel context.CancelFunc
	once   sync.Once
}

func (task *httpTask) finish() {
	task.once.Do(func() {
		task.cancel()
		task.host.mu.Lock()
		delete(task.host.tasks, task)
		task.host.mu.Unlock()
		releaseGlobalHTTPTask()
	})
}

var _ scripthost.Host = (*Host)(nil)

var globalHTTPTasks = make(chan struct{}, 8)
var globalHTTPActive atomic.Int32
var globalHTTPPeak atomic.Int32

// HTTPTaskStats reports live and peak in-flight script HTTP operations.
func HTTPTaskStats() (active, peak int) {
	return int(globalHTTPActive.Load()), int(globalHTTPPeak.Load())
}

// NewHost creates one host instance for one isolated JavaScript VM.
func NewHost(config HostConfig) (*Host, error) {
	if config.Namespace == "" || len(config.Namespace) > maxStoreNamespace {
		return nil, ErrInvalidStoreInput
	}
	return &Host{config: config}, nil
}

func Bindings() []scripthost.Binding {
	return []scripthost.Binding{
		{Name: "$done", CallbackArg: -1},
		{Name: "$httpClient.get", Async: true, CallbackArg: 1},
		{Name: "$httpClient.post", Async: true, CallbackArg: 1},
		{Name: "$httpClient.put", Async: true, CallbackArg: 1},
		{Name: "$httpClient.delete", Async: true, CallbackArg: 1},
		{Name: "$httpClient.patch", Async: true, CallbackArg: 1},
		{Name: "$httpClient.head", Async: true, CallbackArg: 1},
		{Name: "$persistentStore.read", CallbackArg: -1},
		{Name: "$persistentStore.write", CallbackArg: -1},
		{Name: "$notification.post", CallbackArg: -1},
		{Name: "console.log", CallbackArg: -1},
		{Name: "console.info", CallbackArg: -1},
		{Name: "console.warn", CallbackArg: -1},
		{Name: "console.error", CallbackArg: -1},
	}
}

func Environment() map[string]any {
	return map[string]any{"platform": runtime.GOOS, "architecture": runtime.GOARCH}
}

func (h *Host) Call(ctx context.Context, session scripthost.Session, call scripthost.HostCall) (any, error) {
	switch call.Name {
	case "$done":
		if session == nil {
			return nil, errors.New("$done requires an active script session")
		}
		if session.IsDone() {
			return nil, nil
		}
		if len(call.Args) > 1 {
			return nil, errors.New("$done accepts zero or one argument")
		}
		if len(call.Args) == 0 || call.Args[0] == nil {
			session.Done(nil, false)
			return nil, nil
		}
		session.Done(call.Args[0], true)
		return nil, nil
	case "$persistentStore.read":
		if len(call.Args) != 1 {
			return nil, errors.New("$persistentStore.read requires one key")
		}
		key, ok := call.Args[0].(string)
		if !ok {
			return nil, errors.New("persistentStore key must be a string")
		}
		if h.config.Store == nil {
			return nil, errors.New("persistent storage is unavailable")
		}
		value, exists, err := h.config.Store.Read(h.config.Namespace, key)
		if err != nil {
			return nil, err
		}
		if !exists {
			return nil, nil
		}
		return value, nil
	case "$persistentStore.write":
		if len(call.Args) != 2 {
			return nil, errors.New("$persistentStore.write requires value and key")
		}
		value, valueOK := call.Args[0].(string)
		key, keyOK := call.Args[1].(string)
		if !valueOK || !keyOK {
			return nil, errors.New("persistentStore value and key must be strings")
		}
		if h.config.Store == nil {
			return nil, errors.New("persistent storage is unavailable")
		}
		if err := h.config.Store.Write(h.config.Namespace, key, value); err != nil {
			return nil, err
		}
		return true, nil
	case "$notification.post":
		if h.config.Notifications == nil {
			return false, nil
		}
		parts, err := stringArguments(call.Args, 3, "$notification.post")
		if err != nil {
			return nil, err
		}
		if err := h.config.Notifications.Post(ctx, parts[0], parts[1], parts[2]); err != nil {
			return false, err
		}
		return true, nil
	case "console.log", "console.info", "console.warn", "console.error":
		h.log(call.Name, call.Args)
		return nil, nil
	case "$httpClient.get", "$httpClient.post", "$httpClient.put", "$httpClient.delete", "$httpClient.patch", "$httpClient.head":
		return nil, h.scheduleHTTP(ctx, session, call)
	default:
		return nil, fmt.Errorf("unknown host API %q", call.Name)
	}
}

func (h *Host) scheduleHTTP(ctx context.Context, session scripthost.Session, call scripthost.HostCall) error {
	if session == nil {
		return errors.New("$httpClient requires an active script session")
	}
	if session.IsDone() {
		return nil
	}
	if len(call.Args) != 1 {
		return errors.New("$httpClient method requires an options object")
	}
	options, ok := call.Args[0].(map[string]any)
	if !ok || options == nil {
		return errors.New("$httpClient options must be an object")
	}
	method := strings.TrimPrefix(call.Name, "$httpClient.")
	method = strings.ToUpper(method)
	request, timeout, err := buildHTTPRequest(ctx, method, options, h.config.AllowPrivate)
	if err != nil {
		return err
	}
	select {
	case globalHTTPTasks <- struct{}{}:
	default:
		closeRequestBody(request)
		return errors.New("global HTTP task limit reached")
	}
	active := globalHTTPActive.Add(1)
	for peak := globalHTTPPeak.Load(); active > peak; peak = globalHTTPPeak.Load() {
		if globalHTTPPeak.CompareAndSwap(peak, active) {
			break
		}
	}
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		closeRequestBody(request)
		releaseGlobalHTTPTask()
		return ErrHostClosed
	}
	client, err := h.httpClientLocked()
	if err != nil {
		h.mu.Unlock()
		closeRequestBody(request)
		releaseGlobalHTTPTask()
		return err
	}
	taskCtx, taskCancel := context.WithCancel(context.Background())
	task := &httpTask{host: h, ctx: taskCtx, cancel: taskCancel}
	if h.tasks == nil {
		h.tasks = make(map[*httpTask]struct{})
	}
	h.tasks[task] = struct{}{}
	err = session.Schedule(call.CallbackID, func(sessionCtx context.Context) ([]any, error) {
		defer task.finish()
		defer closeRequestBody(request)
		if sessionCtx == nil {
			sessionCtx = context.Background()
		}
		if err := sessionCtx.Err(); err != nil {
			task.cancel()
			return nil, context.Cause(sessionCtx)
		}
		stopSession := contextutils.AfterFunc(sessionCtx, task.cancel)
		defer stopSession()
		requestCtx, cancel := context.WithTimeout(task.ctx, timeout)
		defer cancel()
		request = request.Clone(requestCtx)
		response, err := client.Do(request)
		if err != nil {
			return nil, err
		}
		defer response.Body.Close()
		body, err := io.ReadAll(io.LimitReader(response.Body, maxHTTPBodyBytes+1))
		if err != nil {
			return nil, err
		}
		if len(body) > maxHTTPBodyBytes {
			return nil, errors.New("HTTP response body exceeds 1 MiB")
		}
		headers, err := responseHeaders(response.Header)
		if err != nil {
			return nil, err
		}
		result := map[string]any{"statusCode": response.StatusCode, "headers": headers}
		data := string(body)
		if utf8.Valid(body) {
			result["body"] = data
		} else {
			encoded := base64.StdEncoding.EncodeToString(body)
			result["body_base64"] = encoded
			data = encoded
		}
		return []any{result, data}, nil
	})
	if err != nil {
		delete(h.tasks, task)
		task.cancel()
		h.mu.Unlock()
		closeRequestBody(request)
		releaseGlobalHTTPTask()
		return err
	}
	h.mu.Unlock()
	return nil
}

func closeRequestBody(request *http.Request) {
	if request != nil && request.Body != nil {
		_ = request.Body.Close()
	}
}

func releaseGlobalHTTPTask() {
	<-globalHTTPTasks
	globalHTTPActive.Add(-1)
}

func (h *Host) httpClientLocked() (*http.Client, error) {
	if h.client != nil {
		return h.client, nil
	}
	if h.config.HTTPClients == nil {
		return nil, errors.New("Mihomo routed HTTP client is unavailable")
	}
	client, cleanup, err := h.config.HTTPClients(h.config.AllowPrivate)
	if err != nil {
		if client != nil {
			client.CloseIdleConnections()
		}
		if cleanup != nil {
			cleanup()
		}
		return nil, err
	}
	if client == nil {
		if cleanup != nil {
			cleanup()
		}
		return nil, errors.New("HTTP client factory returned nil")
	}
	copyClient := *client
	previousRedirect := copyClient.CheckRedirect
	copyClient.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if len(via) > maxRedirects {
			return errors.New("HTTP redirect limit exceeded")
		}
		if err := validateURL(request.URL, h.config.AllowPrivate); err != nil {
			return err
		}
		if previousRedirect != nil {
			return previousRedirect(request, via)
		}
		return nil
	}
	h.clientClose = func() {
		copyClient.CloseIdleConnections()
		if cleanup != nil {
			cleanup()
		}
	}
	h.client = &copyClient
	return h.client, nil
}

// Close rejects later HTTP tasks, cancels registered tasks, and closes idle
// client connections. It does not wait for active requests; each task releases
// its body, host registration, and global permit when its context-aware HTTP
// operation returns.
func (h *Host) Close() {
	if h == nil {
		return
	}
	h.closeOnce.Do(func() {
		h.mu.Lock()
		h.closed = true
		for task := range h.tasks {
			task.cancel()
		}
		cleanup := h.clientClose
		h.client = nil
		h.clientClose = nil
		h.mu.Unlock()
		if cleanup != nil {
			cleanup()
		}
	})
}

func buildHTTPRequest(ctx context.Context, method string, options map[string]any, allowPrivate bool) (*http.Request, time.Duration, error) {
	for key := range options {
		if key != "url" && key != "headers" && key != "body" && key != "timeout" {
			return nil, 0, fmt.Errorf("unknown $httpClient option %q", key)
		}
	}
	rawURL, ok := options["url"].(string)
	if !ok {
		return nil, 0, errors.New("$httpClient url must be a string")
	}
	target, err := url.Parse(rawURL)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid $httpClient URL: %w", err)
	}
	if err := validateURL(target, allowPrivate); err != nil {
		return nil, 0, err
	}
	timeout := defaultHTTPTimeout
	if rawTimeout, exists := options["timeout"]; exists {
		number, ok := rawTimeout.(float64)
		if !ok || number != float64(int64(number)) || number < 1 || number > float64(maxHTTPTimeout/time.Millisecond) {
			return nil, 0, fmt.Errorf("$httpClient timeout must be an integer from 1 through %d milliseconds", maxHTTPTimeout/time.Millisecond)
		}
		timeout = time.Duration(number) * time.Millisecond
	}
	body := ""
	if rawBody, exists := options["body"]; exists {
		var ok bool
		body, ok = rawBody.(string)
		if !ok {
			return nil, 0, errors.New("$httpClient body must be a string")
		}
		if len(body) > maxHTTPBodyBytes {
			return nil, 0, errors.New("HTTP request body exceeds 1 MiB")
		}
	}
	request, err := http.NewRequestWithContext(ctx, method, target.String(), strings.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	if rawHeaders, exists := options["headers"]; exists {
		headers, err := parseHTTPHeaders(rawHeaders)
		if err != nil {
			return nil, 0, err
		}
		request.Header = headers
	}
	return request, timeout, nil
}

func validateURL(target *url.URL, allowPrivate bool) error {
	if target == nil || (target.Scheme != "http" && target.Scheme != "https") || target.Host == "" || target.User != nil || target.Fragment != "" {
		return errors.New("HTTP URL must be an absolute http or https URL without credentials or fragment")
	}
	host := strings.TrimSuffix(strings.ToLower(target.Hostname()), ".")
	if host == "" {
		return errors.New("HTTP URL hostname is empty")
	}
	if allowPrivate {
		return nil
	}
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") {
		return errors.New("HTTP target is not allowed by the public-address policy")
	}
	if ip, err := netip.ParseAddr(host); err == nil && !isPublicAddress(ip) {
		return errors.New("HTTP target is not allowed by the public-address policy")
	}
	return nil
}

func IsPublicAddress(ip netip.Addr) bool { return isPublicAddress(ip) }

func isPublicAddress(ip netip.Addr) bool {
	if !ip.IsValid() || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	if ip.Is4() {
		blocked := []netip.Prefix{
			netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("192.0.0.0/24"),
			netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("198.18.0.0/15"),
			netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("240.0.0.0/4"),
		}
		for _, prefix := range blocked {
			if prefix.Contains(ip) {
				return false
			}
		}
		return true
	}
	if !netip.MustParsePrefix("2000::/3").Contains(ip) || netip.MustParsePrefix("2001:db8::/32").Contains(ip) ||
		netip.MustParsePrefix("2001::/23").Contains(ip) || netip.MustParsePrefix("2002::/16").Contains(ip) {
		return false
	}
	return true
}

func parseHTTPHeaders(value any) (http.Header, error) {
	fields, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("$httpClient headers must be an object")
	}
	if len(fields) > maxHTTPHeaders {
		return nil, errors.New("too many HTTP request headers")
	}
	headers := make(http.Header, len(fields))
	total := 0
	for name, rawValue := range fields {
		canonical := textproto.CanonicalMIMEHeaderKey(name)
		if canonical == "" || !validHeaderName(name) || forbiddenHTTPHeader(canonical) {
			return nil, fmt.Errorf("invalid or forbidden HTTP header %q", name)
		}
		values, ok := rawValue.(string)
		list := []string{values}
		if !ok {
			array, isArray := rawValue.([]any)
			if !isArray || len(array) > 16 {
				return nil, fmt.Errorf("HTTP header %q must be a string or string array", name)
			}
			list = make([]string, len(array))
			for index, item := range array {
				list[index], ok = item.(string)
				if !ok {
					return nil, fmt.Errorf("HTTP header %q values must be strings", name)
				}
			}
		}
		for _, item := range list {
			if len(item) > maxHTTPHeaderValueSize || strings.ContainsAny(item, "\r\n\x00") {
				return nil, fmt.Errorf("HTTP header %q value is invalid or too long", name)
			}
			total += len(canonical) + len(item)
			if total > maxHTTPHeaderBytes {
				return nil, errors.New("HTTP request headers exceed 32 KiB")
			}
			headers.Add(canonical, item)
		}
	}
	return headers, nil
}

func responseHeaders(input http.Header) (map[string]any, error) {
	if len(input) > maxHTTPHeaders {
		return nil, errors.New("HTTP response has too many headers")
	}
	result := make(map[string]any, len(input))
	total := 0
	for name, values := range input {
		copied := append([]string(nil), values...)
		for _, value := range copied {
			total += len(name) + len(value)
			if len(value) > maxHTTPHeaderValueSize || total > maxHTTPHeaderBytes {
				return nil, errors.New("HTTP response headers exceed 32 KiB")
			}
		}
		result[name] = copied
	}
	return result, nil
}

func forbiddenHTTPHeader(name string) bool {
	switch strings.ToLower(name) {
	case "connection", "content-length", "keep-alive", "proxy-connection", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade", "host", "expect":
		return true
	default:
		return false
	}
}

func validHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for _, value := range name {
		if value <= 32 || value >= 127 || strings.ContainsRune("()<>@,;:\\\"/[]?={} \t", value) {
			return false
		}
	}
	return true
}

func stringArguments(args []any, count int, method string) ([]string, error) {
	if len(args) > count {
		return nil, fmt.Errorf("%s accepts at most %d arguments", method, count)
	}
	result := make([]string, count)
	for index, arg := range args {
		value, ok := arg.(string)
		if !ok {
			return nil, fmt.Errorf("%s arguments must be strings", method)
		}
		result[index] = value
	}
	return result, nil
}

func (h *Host) log(level string, args []any) {
	if h.config.Log == nil || h.logCalls.Add(1) > maxLogCalls {
		return
	}
	parts := make([]string, 0, len(args))
	for _, arg := range args {
		if value, ok := arg.(string); ok {
			parts = append(parts, value)
			continue
		}
		encoded, err := json.Marshal(arg)
		if err != nil {
			parts = append(parts, "<unprintable>")
		} else {
			parts = append(parts, string(encoded))
		}
	}
	message := strings.Join(parts, " ")
	if len(message) > maxLogMessageBytes {
		message = message[:maxLogMessageBytes]
		for !utf8.ValidString(message) {
			message = message[:len(message)-1]
		}
	}
	h.config.Log.Log(strings.TrimPrefix(level, "console."), message)
}
