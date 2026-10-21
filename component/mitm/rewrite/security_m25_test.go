package rewrite

import (
	"strings"
	"testing"
)

func TestM25InvalidURLDoesNotDiscloseCredentials(t *testing.T) {
	for _, target := range []string{"https://user:password@example.com/?token=secret", "http://example.com/?token=secret", "https://example.com/path#secret"} {
		_, err := Compile(Config{Enable: true, Rules: []Rule{{Name: "private-target", Request: &RequestAction{URL: target}}}})
		if err == nil {
			t.Fatal("invalid URL accepted")
		}
		for _, secret := range []string{"password", "secret", target} {
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("configuration error disclosed URL data: %v", err)
			}
		}
		if !strings.Contains(err.Error(), "private-target") {
			t.Fatal("error lost the rule location")
		}
	}
}
