package rewrite

import (
	"context"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func view(raw string) RequestView {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	return RequestView{Method: "GET", URL: *u, Headers: HeaderMap{"x-old": {"one", "two"}}}
}
func compile(t *testing.T, rules ...Rule) *Snapshot {
	t.Helper()
	s, err := Compile(Config{Enable: true, Rules: rules})
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func basicRule() Rule { return Rule{Name: "basic", Request: &RequestAction{Method: "POST"}} }

func TestHasRequestRulesIsPrecomputedFromEnabledSnapshot(t *testing.T) {
	disabled := false
	cases := []struct {
		name   string
		config Config
		want   bool
	}{
		{name: "nil snapshot"},
		{name: "disabled config", config: Config{Rules: []Rule{basicRule()}}},
		{name: "empty snapshot", config: Config{Enable: true}},
		{name: "response only", config: Config{Enable: true, Rules: []Rule{{Name: "response", Response: &ResponseAction{Status: 204}}}}},
		{name: "disabled request rule", config: Config{Enable: true, Rules: []Rule{{Name: "disabled", Enabled: &disabled, Request: &RequestAction{Method: "POST"}}}}},
		{name: "request rule", config: Config{Enable: true, Rules: []Rule{basicRule()}}, want: true},
		{name: "terminal rule", config: Config{Enable: true, Rules: []Rule{{Name: "local", LocalResponse: &LocalResponse{Status: 200}}}}, want: true},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			var snapshot *Snapshot
			if test.name != "nil snapshot" {
				var err error
				snapshot, err = Compile(test.config)
				if err != nil {
					t.Fatal(err)
				}
			}
			if got := snapshot.HasRequestRules(); got != test.want {
				t.Fatalf("HasRequestRules() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestRequestOrderAndTermination(t *testing.T) {
	s := compile(t,
		Rule{Name: "move", Match: Match{Domains: []string{"a.example"}}, Request: &RequestAction{URL: "https://b.example/v2", Method: "POST", Headers: HeaderAction{Set: map[string]string{"X-Step": "one"}, Remove: []string{"X-Old"}}, Body: &BodyReplacement{Replace: "first"}}},
		Rule{Name: "match-updated", Match: Match{Domains: []string{"b.example"}, Path: "/v2", Methods: []string{"POST"}, Headers: map[string]string{"X-Step": "one"}}, Request: &RequestAction{Headers: HeaderAction{Set: map[string]string{"x-step": "two"}}, Body: &BodyReplacement{Replace: ""}}},
		Rule{Name: "local", Match: Match{Headers: map[string]string{"X-Step": "two"}}, LocalResponse: &LocalResponse{Status: 200, Body: "local", Headers: map[string]string{"X-Local": "yes"}}},
		Rule{Name: "must-not-run", Request: &RequestAction{Method: "DELETE"}},
	)
	input := view("https://a.example/v1")
	result, err := s.ApplyRequest(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Changed || !reflect.DeepEqual(result.Request, input) || result.Body != nil {
		t.Fatalf("unexpected result: %+v", result)
	}
	if result.Terminal == nil || result.Terminal.Decision != LocalResponseDecision || result.Terminal.Body != "local" {
		t.Fatalf("missing terminal result: %+v", result)
	}
	if input.Method != "GET" || input.URL.Host != "a.example" || len(input.Headers["x-old"]) != 2 || input.Headers["X-Step"] != nil {
		t.Fatal("input was mutated")
	}
	result.Terminal.Headers["X-Local"][0] = "mutated"
	again, _ := s.ApplyRequest(context.Background(), input)
	if again.Terminal.Headers["X-Local"][0] != "yes" || again.Body != nil || !reflect.DeepEqual(again.Request, input) {
		t.Fatal("result mutated compiled rules")
	}
}

func TestResponseOrderAndIsolation(t *testing.T) {
	s := compile(t,
		Rule{Name: "first", Match: Match{ResponseStatus: []int{404}}, Response: &ResponseAction{Status: 200, Headers: HeaderAction{Set: map[string]string{"X-Step": "one"}}, Body: &BodyReplacement{Replace: "first"}}},
		Rule{Name: "second", Match: Match{Domains: []string{"b.example"}, ResponseStatus: []int{200}, Headers: map[string]string{"x-step": "one"}}, Response: &ResponseAction{Headers: HeaderAction{Set: map[string]string{"x-step": "two"}, Remove: []string{"x-old"}}, Body: &BodyReplacement{Replace: "second", ContentType: "text/plain"}}},
	)
	input := ResponseView{StatusCode: 404, Headers: HeaderMap{"x-old": {"old"}}}
	result, err := s.ApplyResponse(context.Background(), view("https://b.example/v2"), input)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Changed || result.Response.StatusCode != 200 || result.Body.Replace != "second" || result.Response.Headers["X-Step"][0] != "two" || result.Response.Headers["x-old"] != nil {
		t.Fatalf("unexpected response: %+v", result)
	}
	if input.StatusCode != 404 || input.Headers["x-old"][0] != "old" {
		t.Fatal("input mutated")
	}
	result.Body.Replace = "bad"
	result.Response.Headers["X-Step"][0] = "bad"
	again, _ := s.ApplyResponse(context.Background(), view("https://b.example/v2"), input)
	if again.Body.Replace != "second" || again.Response.Headers["X-Step"][0] != "two" {
		t.Fatal("response result leaked into snapshot")
	}
}

func TestMatchers(t *testing.T) {
	cases := []struct {
		name        string
		match       Match
		url, method string
		headers     HeaderMap
		want        bool
	}{
		{name: "exact normalized", match: Match{Domains: []string{"EXAMPLE.com."}}, url: "https://EXAMPLE.COM.:8443/a", want: true},
		{name: "wildcard", match: Match{Domains: []string{"*.example.com"}}, url: "https://a.b.example.com/", want: true},
		{name: "wildcard apex", match: Match{Domains: []string{"*.example.com"}}, url: "https://example.com/", want: false},
		{name: "suffix boundary", match: Match{Domains: []string{"*.example.com"}}, url: "https://evil-example.com/", want: false},
		{name: "domain OR", match: Match{Domains: []string{"a.example", "b.example"}}, url: "https://b.example/", want: true},
		{name: "decoded exact", match: Match{Path: "/a b"}, url: "https://a.example/a%20b?x=y", want: true},
		{name: "prefix", match: Match{PathPrefix: "/v1/"}, url: "https://a.example/v1/item", want: true},
		{name: "regex", match: Match{PathRegex: "^/v[12]/[0-9]+$"}, url: "https://a.example/v2/123", want: true},
		{name: "method OR", match: Match{Methods: []string{"GET", "POST"}}, method: "POST", want: true},
		{name: "method case", match: Match{Methods: []string{"GET"}}, method: "get", want: false},
		{name: "AND", match: Match{Domains: []string{"a.example"}, Path: "/yes", Methods: []string{"POST"}}, url: "https://a.example/no", method: "POST", want: false},
		{name: "header case", match: Match{Headers: map[string]string{"x-TEST": "two"}}, headers: HeaderMap{"X-Test": {"one", "two"}}, want: true},
		{name: "missing not empty", match: Match{Headers: map[string]string{"X-Test": ""}}, want: false},
		{name: "empty field", match: Match{Headers: map[string]string{"X-Test": ""}}, headers: HeaderMap{"X-Test": {""}}, want: true},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			raw := test.url
			if raw == "" {
				raw = "https://a.example/"
			}
			request := view(raw)
			if test.method != "" {
				request.Method = test.method
			}
			request.Headers = test.headers
			s := compile(t, Rule{Name: "match", Match: test.match, Request: &RequestAction{Method: "PATCH"}})
			result, err := s.ApplyRequest(context.Background(), request)
			if err != nil {
				t.Fatal(err)
			}
			if result.Changed != test.want {
				t.Fatalf("match=%v, want %v", result.Changed, test.want)
			}
		})
	}
}

func TestInvalidRules(t *testing.T) {
	cases := map[string]func(*Rule){
		"empty name":           func(r *Rule) { r.Name = "" },
		"no action":            func(r *Rule) { r.Request = nil },
		"empty action":         func(r *Rule) { r.Request = &RequestAction{} },
		"path conflict":        func(r *Rule) { r.Match = Match{Path: "/a", PathPrefix: "/"} },
		"invalid path":         func(r *Rule) { r.Match.Path = "relative" },
		"invalid regex":        func(r *Rule) { r.Match.PathRegex = "[" },
		"invalid domain":       func(r *Rule) { r.Match.Domains = []string{"*evil.example"} },
		"IP domain":            func(r *Rule) { r.Match.Domains = []string{"127.0.0.1"} },
		"invalid match method": func(r *Rule) { r.Match.Methods = []string{"bad method"} },
		"invalid method":       func(r *Rule) { r.Request.Method = "BAD\nMETHOD" },
		"CONNECT":              func(r *Rule) { r.Request.Method = "CONNECT" },
		"header injection":     func(r *Rule) { r.Request.Headers.Set = map[string]string{"X-Test": "yes\r\nInjected: bad"} },
		"bad header name":      func(r *Rule) { r.Request.Headers.Set = map[string]string{"Bad Header": "yes"} },
		"duplicate header":     func(r *Rule) { r.Request.Headers.Set = map[string]string{"X-Test": "one", "x-test": "two"} },
		"conflicting headers": func(r *Rule) {
			r.Request.Headers = HeaderAction{Set: map[string]string{"X-Test": "yes"}, Remove: []string{"x-test"}}
		},
		"bad content type":        func(r *Rule) { r.Request.Body = &BodyReplacement{ContentType: "bad\x00type"} },
		"invalid UTF8":            func(r *Rule) { r.Request.Body = &BodyReplacement{Replace: string([]byte{255})} },
		"invalid response status": func(r *Rule) { r.Request = nil; r.Response = &ResponseAction{Status: 600} },
		"invalid match status": func(r *Rule) {
			r.Request = nil
			r.Response = &ResponseAction{Status: 200}
			r.Match.ResponseStatus = []int{99}
		},
		"bodyless status": func(r *Rule) {
			r.Request = nil
			r.Response = &ResponseAction{Status: 204, Body: &BodyReplacement{Replace: "x"}}
		},
		"response condition request": func(r *Rule) { r.Match.ResponseStatus = []int{200} },
		"terminal conflict":          func(r *Rule) { r.Redirect = &Redirect{Status: 302, Location: "/"} },
		"two terminals": func(r *Rule) {
			r.Request = nil
			r.Redirect = &Redirect{Status: 302, Location: "/"}
			r.LocalResponse = &LocalResponse{Status: 200}
		},
		"bad redirect status": func(r *Rule) { r.Request = nil; r.Redirect = &Redirect{Status: 200, Location: "/"} },
		"local informational": func(r *Rule) { r.Request = nil; r.LocalResponse = &LocalResponse{Status: 100} },
		"local bodyless":      func(r *Rule) { r.Request = nil; r.LocalResponse = &LocalResponse{Status: 304, Body: "bad"} },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			r := basicRule()
			change(&r)
			if _, err := Compile(Config{Enable: true, Rules: []Rule{r}}); err == nil {
				t.Fatal("invalid rule accepted")
			}
		})
	}
	for _, name := range []string{"Host", "Content-Length", "Transfer-Encoding", "Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "TE", "Trailer", "Upgrade"} {
		t.Run(name, func(t *testing.T) {
			r := basicRule()
			r.Request.Headers.Remove = []string{name}
			if _, err := Compile(Config{Enable: true, Rules: []Rule{r}}); err == nil {
				t.Fatal("managed header accepted")
			}
		})
	}
	for _, name := range []string{"Content-Length", "Transfer-Encoding", "Trailer", "Connection", "Upgrade"} {
		t.Run("terminal managed header "+name, func(t *testing.T) {
			_, err := Compile(Config{Enable: true, Rules: []Rule{{
				Name: "local", LocalResponse: &LocalResponse{Status: 200, Headers: map[string]string{name: "unsafe"}},
			}}})
			if err == nil {
				t.Fatalf("terminal response accepted managed header %q", name)
			}
		})
	}
	for _, raw := range []string{"http://a.example/", "/relative", "https://user:pass@a.example/", "https://a.example:0/", "https://a.example:65536/", "https://a.example:/", "https://a.example/#fragment", "https://a.example/#", "https://[example.com]/", "https://::1/", "https://bad_host/", "https://a.example/?bad=%zz", "https://a.example/\r\n"} {
		t.Run(raw, func(t *testing.T) {
			r := basicRule()
			r.Request.URL = raw
			if _, err := Compile(Config{Enable: true, Rules: []Rule{r}}); err == nil {
				t.Fatal("invalid URL accepted")
			}
		})
	}
	for _, raw := range []string{"", "//other.example/", "http://other.example/", "javascript:alert(1)", "/new?bad=%zz", "/bad\r\nLocation: x"} {
		t.Run("redirect "+raw, func(t *testing.T) {
			_, err := Compile(Config{Enable: true, Rules: []Rule{{Name: "redirect", Redirect: &Redirect{Status: 302, Location: raw}}}})
			if err == nil {
				t.Fatal("invalid redirect accepted")
			}
		})
	}
}

func TestLimitsDisabledAndImmutability(t *testing.T) {
	disabled := false
	r := basicRule()
	r.Enabled = &disabled
	r.Request.Body = &BodyReplacement{Replace: "1234"}
	for _, c := range []Config{
		{Enable: true, MaxReplacementBodyBytes: -1},
		{Enable: true, MaxTotalReplacementBodyBytes: -1},
		{Enable: true, MaxReplacementBodyBytes: 3, Rules: []Rule{r}},
		{Enable: true, MaxTotalReplacementBodyBytes: 3, Rules: []Rule{r}},
		{Enable: true, Rules: []Rule{r, r}},
	} {
		if _, err := Compile(c); err == nil {
			t.Fatal("invalid configuration accepted")
		}
	}
	r.Request.Method = "bad method"
	if _, err := Compile(Config{Enable: true, Rules: []Rule{r}}); err == nil {
		t.Fatal("disabled rule bypassed validation")
	}
	if _, err := Compile(Config{Rules: []Rule{r}, MaxReplacementBodyBytes: -1}); err != nil {
		t.Fatal("disabled config should be inactive")
	}
	r = basicRule()
	r.Match = Match{Domains: []string{"a.example"}, Methods: []string{"GET"}}
	r.Request.Headers.Set = map[string]string{"X-Value": "before"}
	r.Request.Body = &BodyReplacement{Replace: "before"}
	s := compile(t, r)
	r.Match.Domains[0] = "changed"
	r.Match.Methods[0] = "DELETE"
	r.Request.Headers.Set["X-Value"] = "after"
	r.Request.Body.Replace = "after"
	r.Request.Method = "DELETE"
	result, _ := s.ApplyRequest(context.Background(), view("https://a.example/"))
	if result.Request.Method != "POST" || result.Request.Headers["X-Value"][0] != "before" || result.Body.Replace != "before" {
		t.Fatal("compile retained mutable config")
	}
}

func TestRedirectAndEmptyReplacement(t *testing.T) {
	for _, location := range []string{"/new", "../new", "https://other.example/new", "https://[::1]:8443/new"} {
		s := compile(t, Rule{Name: "redirect", Redirect: &Redirect{Status: 308, Location: location}})
		r, err := s.ApplyRequest(context.Background(), view("https://a.example/"))
		if err != nil || r.Terminal == nil || r.Terminal.Headers["Location"][0] != location || r.Terminal.Decision != RedirectResponse {
			t.Fatalf("redirect failed: %+v %v", r, err)
		}
	}
	s := compile(t, Rule{Name: "empty", Request: &RequestAction{Body: &BodyReplacement{}}})
	result, _ := s.ApplyRequest(context.Background(), view("https://a.example/"))
	if result.Body == nil || result.Body.Replace != "" {
		t.Fatal("empty replacement lost")
	}
}

func TestConcurrentSnapshotAndCancellation(t *testing.T) {
	s := compile(t, Rule{Name: "both", Request: &RequestAction{Headers: HeaderAction{Set: map[string]string{"X-Test": "value"}}, Body: &BodyReplacement{Replace: "body"}}, Response: &ResponseAction{Headers: HeaderAction{Set: map[string]string{"X-Test": "response"}}, Body: &BodyReplacement{Replace: "response"}}})
	input := view("https://a.example/")
	var group sync.WaitGroup
	for i := 0; i < 32; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for j := 0; j < 100; j++ {
				r, err := s.ApplyRequest(context.Background(), input)
				if err != nil || r.Body.Replace != "body" {
					t.Error("request isolation failed")
					return
				}
				r.Body.Replace = "private"
				r.Request.Headers["X-Test"][0] = "private"
				response, err := s.ApplyResponse(context.Background(), input, ResponseView{StatusCode: 200})
				if err != nil || response.Body.Replace != "response" {
					t.Error("response isolation failed")
					return
				}
				response.Body.Replace = "private"
				response.Response.Headers["X-Test"][0] = "private"
			}
		}()
	}
	group.Wait()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.ApplyRequest(ctx, input); err != context.Canceled {
		t.Fatalf("request cancellation: %v", err)
	}
	if _, err := s.ApplyResponse(ctx, input, ResponseView{}); err != context.Canceled {
		t.Fatalf("response cancellation: %v", err)
	}
}

func TestUnmatchedNoAllocation(t *testing.T) {
	s := compile(t, Rule{Name: "miss", Match: Match{Domains: []string{"other.example"}}, Request: &RequestAction{Method: "POST"}, Response: &ResponseAction{Status: 201}})
	input := view("https://a.example/")
	response := ResponseView{StatusCode: 200, Headers: input.Headers}
	if n := testing.AllocsPerRun(1000, func() {
		r, err := s.ApplyRequest(context.Background(), input)
		if err != nil || r.Changed || r.Body != nil || r.Terminal != nil {
			panic("bad no-match result")
		}
	}); n != 0 {
		t.Fatalf("unmatched request allocations: %v", n)
	}
	if n := testing.AllocsPerRun(1000, func() {
		r, err := s.ApplyResponse(context.Background(), input, response)
		if err != nil || r.Changed {
			panic("bad no-match response")
		}
	}); n != 0 {
		t.Fatalf("unmatched response allocations: %v", n)
	}
	r, _ := s.ApplyRequest(context.Background(), input)
	if !reflect.DeepEqual(input, r.Request) {
		t.Fatal("unmatched request changed")
	}
	var empty *Snapshot
	if r, err := empty.ApplyRequest(context.Background(), input); err != nil || r.Changed {
		t.Fatal("nil snapshot not identity")
	}
}

func BenchmarkUnmatched(b *testing.B) {
	s, err := Compile(Config{Enable: true, Rules: []Rule{{Name: "miss", Match: Match{Domains: []string{"other.example"}}, Request: &RequestAction{Body: &BodyReplacement{Replace: strings.Repeat("x", 1024)}}}}})
	if err != nil {
		b.Fatal(err)
	}
	request := view("https://a.example/")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = s.ApplyRequest(context.Background(), request)
	}
}

func TestDisabledRulesAndAggregateLimits(t *testing.T) {
	disabled := false
	rules := []Rule{
		{Name: "disabled", Enabled: &disabled, Request: &RequestAction{Method: "DELETE"}},
		{Name: "request", Request: &RequestAction{Body: &BodyReplacement{Replace: "abc"}}},
		{Name: "response", Response: &ResponseAction{Body: &BodyReplacement{Replace: "def"}}},
	}
	if _, err := Compile(Config{Enable: true, MaxTotalReplacementBodyBytes: 5, Rules: rules}); err == nil {
		t.Fatal("aggregate payload limit ignored")
	}
	s, err := Compile(Config{Enable: true, MaxReplacementBodyBytes: 3, MaxTotalReplacementBodyBytes: 6, Rules: rules})
	if err != nil {
		t.Fatal(err)
	}
	result, err := s.ApplyRequest(context.Background(), view("https://a.example/"))
	if err != nil || result.Request.Method != "GET" || result.Body.Replace != "abc" {
		t.Fatal("disabled rule executed or boundary payload rejected")
	}
	tooLarge := Rule{Name: "large", LocalResponse: &LocalResponse{Status: 200, Body: strings.Repeat("x", DefaultMaxReplacementBodyBytes+1)}}
	if _, err := Compile(Config{Enable: true, Rules: []Rule{tooLarge}}); err == nil {
		t.Fatal("default local payload limit ignored")
	}
}

func TestHeaderCopyOnWriteAndRedirectFragment(t *testing.T) {
	s := compile(t, Rule{Name: "headers", Request: &RequestAction{Headers: HeaderAction{Set: map[string]string{"X-Test": "new"}, Remove: []string{"x-remove"}}}})
	input := view("https://a.example/")
	input.Headers["x-test"] = []string{"old"}
	input.Headers["X-TEST"] = []string{"duplicate"}
	input.Headers["X-Remove"] = []string{"remove"}
	result, _ := s.ApplyRequest(context.Background(), input)
	result.Request.Headers["x-old"][0] = "private"
	if len(result.Request.Headers) != 2 || result.Request.Headers["X-Test"][0] != "new" || input.Headers["x-old"][0] != "one" || input.Headers["x-test"][0] != "old" {
		t.Fatal("header update was not case insensitive and isolated")
	}
	redirect := compile(t, Rule{Name: "fragment", Redirect: &Redirect{Status: 302, Location: "https://b.example/new#section"}})
	terminal, err := redirect.ApplyRequest(context.Background(), input)
	if err != nil || terminal.Terminal.Headers["Location"][0] != "https://b.example/new#section" {
		t.Fatalf("valid redirect fragment lost: %+v %v", terminal, err)
	}
}
