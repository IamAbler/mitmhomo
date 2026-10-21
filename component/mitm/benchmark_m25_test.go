package mitm

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/component/mitm/rewrite"
)

// Isolates rule evaluation and protocol adaptation; excludes socket/TLS costs.
func BenchmarkM25ResponseAdapter(b *testing.B) {
	for _, kind := range []string{"empty", "header", "body-1K", "body-1M", "rules-100"} {
		b.Run(kind, func(b *testing.B) {
			config := rewrite.Config{Enable: true}
			switch kind {
			case "header":
				config.Rules = []rewrite.Rule{{Name: "header", Response: &rewrite.ResponseAction{Headers: rewrite.HeaderAction{Set: map[string]string{"X-Test": "yes"}}}}}
			case "body-1K", "body-1M":
				n := 1024
				if kind == "body-1M" {
					n = 1 << 20
				}
				config.Rules = []rewrite.Rule{{Name: "body", Response: &rewrite.ResponseAction{Body: &rewrite.BodyReplacement{Replace: strings.Repeat("x", n)}}}}
			case "rules-100":
				for i := 0; i < 100; i++ {
					config.Rules = append(config.Rules, rewrite.Rule{Name: fmt.Sprint(i), Match: rewrite.Match{Path: fmt.Sprint("/miss", i)}, Response: &rewrite.ResponseAction{Status: 201}})
				}
			}
			pipeline, err := rewrite.Compile(config)
			if err != nil {
				b.Fatal(err)
			}
			target, _ := url.Parse("https://example.com/test")
			request := rewrite.RequestView{Method: "GET", URL: *target}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				response := &http.Response{StatusCode: 200, Header: http.Header{"Content-Length": []string{"0"}}, ContentLength: 0, Body: http.NoBody}
				if err := applyResponseRewrite(context.Background(), request, response, pipeline, false, "GET"); err != nil {
					b.Fatal(err)
				}
				if _, err := io.Copy(io.Discard, response.Body); err != nil {
					b.Fatal(err)
				}
				_ = response.Body.Close()
			}
		})
	}
}

func BenchmarkM25CertificateCache(b *testing.B) {
	ca, _ := makeTestAuthority(b)
	if _, err := ca.serverCertificate("cache.example"); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := ca.serverCertificate("cache.example"); err != nil {
				b.Error(err)
			}
		}
	})
}
