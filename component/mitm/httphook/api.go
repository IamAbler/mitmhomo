package httphook

import (
	"context"
	"net/http"
	"time"

	"github.com/metacubex/mihomo/component/mitm/jsruntime"
	"github.com/metacubex/mihomo/component/mitm/scriptapi"
	"github.com/metacubex/mihomo/log"
)

func (s *Snapshot) executeAPI(ctx context.Context, rule *compiledRule, globals map[string]any) (any, error) {
	runtime, err := s.getRuntime()
	if err != nil {
		return nil, err
	}
	compiled, err := runtime.Compile(rule.source)
	if err != nil {
		return nil, err
	}
	logSink := s.services.Log
	if logSink == nil {
		logSink = scriptLogSink{}
	}
	globals["$environment"] = scriptapi.Environment()
	host, err := scriptapi.NewHost(scriptapi.HostConfig{
		Namespace:     rule.name,
		Store:         s.services.Store,
		HTTPClients:   s.services.HTTPClients,
		AllowPrivate:  s.config.AllowPrivateNetworks,
		Log:           logSink,
		Notifications: s.services.Notifications,
	})
	if err != nil {
		return nil, err
	}
	defer host.Close()
	return runtime.RunSession(ctx, compiled, jsruntime.SessionOptions{
		Globals:         globals,
		Bindings:        scriptapi.Bindings(),
		Host:            host,
		Timeout:         time.Duration(s.config.ExecutionTimeout) * time.Second,
		MaxPendingTasks: 4,
	})
}

func defaultScriptLog(level, message string) {
	switch level {
	case "warn", "error":
		log.Warnln("MITM JavaScript %s", message)
	case "info":
		log.Infoln("MITM JavaScript %s", message)
	default:
		log.Debugln("MITM JavaScript %s", message)
	}
}

type scriptLogSink struct{}

func (scriptLogSink) Log(level, message string) { defaultScriptLog(level, message) }

func apiRequestGlobals(request *http.Request, body []byte) map[string]any {
	return map[string]any{"$request": requestInput(request, body)}
}

func apiResponseGlobals(request *http.Request, response *http.Response, body []byte) map[string]any {
	requestValue := map[string]any{
		"url":     requestURL(request),
		"method":  request.Method,
		"headers": readRequestHeaders(request),
	}
	responseValue := map[string]any{
		"status":  response.StatusCode,
		"headers": readResponseHeaders(response),
	}
	for key, value := range bodyInput(body) {
		responseValue[key] = value
	}
	return map[string]any{"$request": requestValue, "$response": responseValue}
}
