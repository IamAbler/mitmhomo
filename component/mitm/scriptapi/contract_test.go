package scriptapi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/mitm/scripthost"
)

// contractSession exercises host behavior without creating a JavaScript VM.
// Engine adapters can reuse these host-level expectations independently.
type contractSession struct {
	done       bool
	result     any
	hasResult  bool
	callbackID uint64
	work       func(context.Context) ([]any, error)
}

func (s *contractSession) Done(value any, hasValue bool) bool {
	if s.done {
		return false
	}
	s.done, s.result, s.hasResult = true, value, hasValue
	return true
}

func (s *contractSession) IsDone() bool { return s.done }

func (s *contractSession) Schedule(callbackID uint64, work func(context.Context) ([]any, error)) error {
	s.callbackID, s.work = callbackID, work
	return nil
}

var _ scripthost.Session = (*contractSession)(nil)

func TestHostEngineNeutralDoneAndAsyncHTTPContract(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Contract", "ok")
		_, _ = fmt.Fprint(w, "body")
	}))
	defer server.Close()

	host, err := NewHost(HostConfig{
		Namespace:    "contract",
		AllowPrivate: true,
		HTTPClients: func(bool) (*http.Client, func(), error) {
			return server.Client(), nil, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	var api scripthost.Host = host

	session := &contractSession{}
	if _, err := api.Call(context.Background(), session, scripthost.HostCall{
		Name: "$done", Args: []any{"too", "many"},
	}); err == nil || session.done {
		t.Fatalf("invalid $done arguments = err %v, done %t; want error and incomplete session", err, session.done)
	}
	if _, err := api.Call(context.Background(), session, scripthost.HostCall{
		Name: "$done", Args: []any{map[string]any{"body": "first"}},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := api.Call(context.Background(), session, scripthost.HostCall{
		Name: "$done", Args: []any{map[string]any{"body": "second"}},
	}); err != nil {
		t.Fatal(err)
	}
	if !session.done || !session.hasResult || session.result.(map[string]any)["body"] != "first" {
		t.Fatalf("first completion contract = %#v", session)
	}

	session = &contractSession{}
	callContext, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = api.Call(callContext, session, scripthost.HostCall{
		Name: "$httpClient.get", CallbackID: 42,
		Args: []any{map[string]any{"url": server.URL, "timeout": float64(500)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if session.callbackID != 42 || session.work == nil {
		t.Fatalf("async scheduling contract: callback=%d work=%v", session.callbackID, session.work != nil)
	}
	results, err := session.work(callContext)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("HTTP completion args = %#v, want response and data", results)
	}
	response, ok := results[0].(map[string]any)
	if !ok || response["statusCode"] != http.StatusOK || response["body"] != "body" || results[1] != "body" {
		t.Fatalf("HTTP completion payload = %#v", results)
	}
}
