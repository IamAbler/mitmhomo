package rewrite

import (
	"context"
	"fmt"
	"reflect"
	"sync"
	"testing"
)

func TestTerminalComposition(t *testing.T) {
	for _, redirect := range []bool{false, true} {
		t.Run(fmt.Sprint(redirect), func(t *testing.T) {
			terminal := Rule{Name: "terminal", Match: Match{Methods: []string{"POST"}, Headers: map[string]string{"X-Step": "yes"}}}
			if redirect {
				terminal.Redirect = &Redirect{Status: 307, Location: "/target"}
			} else {
				terminal.LocalResponse = &LocalResponse{Status: 201, Body: "local", Headers: map[string]string{"X-Local": "yes"}}
			}
			rules := []Rule{
				{Name: "before", Request: &RequestAction{Method: "POST", URL: "https://b.example/", Headers: HeaderAction{Set: map[string]string{"X-Step": "yes"}}, Body: &BodyReplacement{Replace: "upstream"}}},
				terminal,
				{Name: "after", LocalResponse: &LocalResponse{Status: 500, Body: "must not run"}},
			}
			s := compile(t, rules...)
			// Mutating source configuration after compilation must not affect terminal.
			if terminal.LocalResponse != nil {
				terminal.LocalResponse.Headers["X-Local"] = "bad"
				terminal.LocalResponse.Body = "bad"
			}
			input := view("https://a.example/")
			var wg sync.WaitGroup
			for i := 0; i < 16; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for j := 0; j < 30; j++ {
						r, err := s.ApplyRequest(context.Background(), input)
						if err != nil || r.Terminal == nil || r.Body != nil || !reflect.DeepEqual(r.Request, input) || !r.Changed {
							t.Errorf("terminal result: %+v %v", r, err)
							return
						}
						if redirect {
							if r.Terminal.StatusCode != 307 || r.Terminal.Headers["Location"][0] != "/target" {
								t.Error("redirect changed")
							}
							r.Terminal.Headers["Location"][0] = "private"
						} else {
							if r.Terminal.StatusCode != 201 || r.Terminal.Body != "local" || r.Terminal.Headers["X-Local"][0] != "yes" {
								t.Error("local changed")
							}
							r.Terminal.Headers["X-Local"][0] = "private"
						}
					}
				}()
			}
			wg.Wait()
			// A terminal before an ordinary action must stop that action as well.
			terminal.Match = Match{}
			first := compile(t, terminal, rules[0])
			r, err := first.ApplyRequest(context.Background(), input)
			if err != nil || r.Body != nil || !reflect.DeepEqual(r.Request, input) {
				t.Fatalf("terminal first: %+v %v", r, err)
			}
		})
	}
}

func TestResponseComposition(t *testing.T) {
	for _, status := range []int{200, 201, 204, 205, 304} {
		for _, reverse := range []bool{false, true} {
			for _, method := range []string{"GET", "HEAD"} {
				t.Run(fmt.Sprintf("%d/%t/%s", status, reverse, method), func(t *testing.T) {
					rules := []Rule{{Name: "body", Response: &ResponseAction{Body: &BodyReplacement{Replace: "payload"}}}, {Name: "status", Response: &ResponseAction{Status: status}}}
					if reverse {
						rules[0], rules[1] = rules[1], rules[0]
					}
					s := compile(t, rules...)
					request := view("https://a.example/")
					request.Method = method
					r, err := s.ApplyResponse(context.Background(), request, ResponseView{StatusCode: 200})
					conflict := bodyless(status) || method == "HEAD"
					if conflict {
						if err == nil || !reflect.DeepEqual(r, ResponseResult{}) {
							t.Fatalf("expected atomic error: %+v %v", r, err)
						}
						return
					}
					if err != nil || r.Body == nil || r.Body.Replace != "payload" || r.Response.StatusCode != status || r.SuppressBody {
						t.Fatalf("result: %+v %v", r, err)
					}
				})
			}
		}
	}
	// Intermediate bodyless status may be superseded before final validation.
	s := compile(t, Rule{Name: "body", Response: &ResponseAction{Body: &BodyReplacement{}}}, Rule{Name: "empty", Response: &ResponseAction{Status: 204}}, Rule{Name: "restore", Response: &ResponseAction{Status: 200}})
	r, err := s.ApplyResponse(context.Background(), view("https://a.example/"), ResponseView{StatusCode: 200})
	if err != nil || r.Body == nil || r.SuppressBody {
		t.Fatalf("final status not used: %+v %v", r, err)
	}
}

func TestResponseBodyBoundary(t *testing.T) {
	for _, status := range []int{100, 101, 103, 200, 204, 205, 304} {
		for _, method := range []string{"GET", "HEAD"} {
			for _, length := range []string{"0", "17"} {
				t.Run(fmt.Sprintf("%d/%s/%s", status, method, length), func(t *testing.T) {
					input := ResponseView{StatusCode: status, Headers: HeaderMap{"content-length": {length}, "Content-Type": {"text/plain"}, "ETag": {"tag"}}}
					req := view("https://a.example/")
					req.Method = method
					for _, s := range []*Snapshot{nil, compile(t, Rule{Name: "miss", Match: Match{Domains: []string{"other.example"}}, Response: &ResponseAction{Status: 200}})} {
						r, err := s.ApplyResponse(context.Background(), req, input)
						if status < 200 {
							if err == nil || !reflect.DeepEqual(r, ResponseResult{}) {
								t.Fatal("informational response accepted")
							}
							continue
						}
						if err != nil || r.SuppressBody != (bodyless(status) || method == "HEAD") {
							t.Fatalf("boundary: %+v %v", r, err)
						}
						remove := status == 204 || status == 205 && length != "0"
						if (r.Response.Headers["content-length"] == nil) != remove || r.Response.Headers["Content-Type"][0] != "text/plain" || r.Response.Headers["ETag"][0] != "tag" {
							t.Fatalf("metadata: %+v", r)
						}
						if input.Headers["content-length"][0] != length {
							t.Fatal("input mutated")
						}
					}
				})
			}
		}
	}
}

func TestConcurrentResponseComposition(t *testing.T) {
	body := &BodyReplacement{Replace: "snapshot"}
	action := &ResponseAction{Body: body}
	s := compile(t, Rule{Name: "body", Response: action}, Rule{Name: "status", Response: &ResponseAction{Status: 204}}, Rule{Name: "recover", Match: Match{Methods: []string{"GET"}, ResponseStatus: []int{204}}, Response: &ResponseAction{Status: 200}})
	body.Replace = "mutated config"
	action.Status = 500
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				req := view("https://a.example/")
				r, err := s.ApplyResponse(context.Background(), req, ResponseView{StatusCode: 201})
				if err != nil || r.Body == nil || r.Body.Replace != "snapshot" || r.Response.StatusCode != 200 {
					t.Errorf("shared snapshot: %+v %v", r, err)
					return
				}
				r.Body.Replace = "private result"
				req.Method = "POST"
				r, err = s.ApplyResponse(context.Background(), req, ResponseView{StatusCode: 201})
				if err == nil || !reflect.DeepEqual(r, ResponseResult{}) {
					t.Error("partial result escaped")
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestCompileResponseBodyBoundaries(t *testing.T) {
	for _, status := range []int{100, 101, 103, 204, 205, 304} {
		for _, payload := range []string{"", "content"} {
			t.Run(fmt.Sprintf("%d/%s", status, payload), func(t *testing.T) {
				_, err := Compile(Config{Enable: true, Rules: []Rule{{Name: "conflict", Response: &ResponseAction{Status: status, Body: &BodyReplacement{Replace: payload}}}}})
				if err == nil {
					t.Fatal("status/body combination accepted")
				}
			})
		}
		if status < 200 {
			_, err := Compile(Config{Enable: true, Rules: []Rule{{Name: "informational", Response: &ResponseAction{Status: status}}}})
			if err == nil {
				t.Fatal("informational target accepted")
			}
		}
	}
}
