package config

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/mitm"
	"github.com/metacubex/mihomo/component/mitm/rewrite"
	C "github.com/metacubex/mihomo/constant"
)

const rewriteYAML = `mitm:
  rewrite:
    enable: true
    rules:
      - name: move
        match:
          domains: [a.example]
          path-prefix: /v1/
          methods: [GET]
        request:
          url: https://b.example/v2
          method: POST
          headers:
            set:
              X-Stage: one
            remove: [X-Old]
          body:
            replace: '{"name":"new"}'
            content-type: application/json
      - name: stop
        match:
          domains: [b.example]
          methods: [POST]
        local-response:
          status: 200
          headers:
            Content-Type: text/plain
          body: local
`

func TestRewriteYAMLAndConfigurationOrder(t *testing.T) {
	raw, err := UnmarshalRawConfig([]byte(rewriteYAML))
	if err != nil {
		t.Fatal(err)
	}
	s, err := parseMITMRewrite(raw.MITM.Rewrite)
	if err != nil {
		t.Fatal(err)
	}
	target, _ := url.Parse("https://a.example/v1/items")
	result, err := s.ApplyRequest(context.Background(), rewrite.RequestView{URL: *target, Method: "GET"})
	if err != nil || result.Request.Method != "GET" || result.Request.URL != *target || result.Request.Headers != nil || result.Terminal == nil || result.Terminal.Body != "local" || result.Body != nil {
		t.Fatalf("unexpected parsed rules: %+v %v", result, err)
	}
}

func TestRewriteYAMLRejectsInvalidFieldsAndTypes(t *testing.T) {
	for _, test := range []struct{ name, from, to string }{
		{"unknown field", "enable: true", "enabled: true"},
		{"priority unsupported", "name: move", "name: move\n        priority: 100"},
		{"unknown action", "method: POST", "methd: POST"},
		{"wrong type", "methods: [GET]", "methods: GET"},
		{"duplicate field", "name: move", "name: move\n        name: duplicate"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := UnmarshalRawConfig([]byte(strings.Replace(rewriteYAML, test.from, test.to, 1)))
			if err == nil {
				t.Fatal("invalid YAML accepted")
			}
		})
	}
}

func TestRewriteYAMLRejectsInvalidActions(t *testing.T) {
	for _, test := range []struct{ name, from, to string }{
		{"URL", "https://b.example/v2", "http://b.example/v2"},
		{"header", "X-Stage: one", "Content-Length: one"},
		{"terminal framing header", "Content-Type: text/plain", "Content-Type: text/plain\n            Content-Length: 20"},
		{"terminal transfer encoding", "Content-Type: text/plain", "Content-Type: text/plain\n            Transfer-Encoding: chunked"},
		{"terminal trailer", "Content-Type: text/plain", "Content-Type: text/plain\n            Trailer: X-End"},
		{"status", "status: 200", "status: 600"},
		{"method", "method: POST", "method: bad method"},
		{"path regex", "path-prefix: /v1/", "path-regex: '['"},
		{"conflicting terminal", "body: local", "body: local\n        redirect:\n          status: 302\n          location: /new"},
		{"disabled invalid still checked", "name: move", "name: move\n        enabled: false\n        redirect:\n          status: 302\n          location: /new"},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw, err := UnmarshalRawConfig([]byte(strings.Replace(rewriteYAML, test.from, test.to, 1)))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := parseMITMRewrite(raw.MITM.Rewrite); err == nil {
				t.Fatal("invalid rule accepted")
			}
		})
	}
}

func TestRewriteDisableAndLimits(t *testing.T) {
	raw, err := UnmarshalRawConfig([]byte(rewriteYAML))
	if err != nil {
		t.Fatal(err)
	}
	raw.MITM.Rewrite.MaxReplacementBodyBytes = 1
	if _, err := parseMITMRewrite(raw.MITM.Rewrite); err == nil {
		t.Fatal("oversized replacement accepted")
	}
	raw.MITM.Rewrite.Enable = false
	if _, err := parseMITMRewrite(raw.MITM.Rewrite); err != nil {
		t.Fatal(err)
	}
	raw.MITM.Rewrite.Enable = true
	parsed, err := parseMITM(raw.MITM)
	if err != nil || parsed.Enabled || parsed.Rewrite != nil {
		t.Fatalf("disabled MITM compiled rewrite: %+v %v", parsed, err)
	}
	// With M1 enabled, malformed rewrite must fail before any CA file access.
	raw.MITM.Enable = true
	raw.MITM.Domains = []string{"a.example"}
	if _, err := parseMITM(raw.MITM); err == nil || !strings.Contains(err.Error(), "mitm.rewrite") {
		t.Fatalf("expected rewrite validation error before CA load: %v", err)
	}
}

func TestMITMRetainsParsedRewriteInConnectionSnapshot(t *testing.T) {
	oldHome := C.Path.HomeDir()
	home := t.TempDir()
	C.SetHomeDir(home)
	t.Cleanup(func() { C.SetHomeDir(oldHome) })
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "M2 test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "ca.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "ca.key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
	raw, err := UnmarshalRawConfig([]byte(rewriteYAML))
	if err != nil {
		t.Fatal(err)
	}
	raw.MITM.Enable = true
	raw.MITM.Domains = []string{"a.example"}
	raw.MITM.CACertificate = "ca.pem"
	raw.MITM.CAPrivateKey = "ca.key"
	parsed, err := parseMITM(raw.MITM)
	if err != nil {
		t.Fatal(err)
	}
	manager := mitm.NewManager(*parsed)
	pinned := manager.ConfigSnapshot()
	if pinned.Rewrite == nil || pinned.RequestHook != nil || pinned.ResponseHook != nil {
		t.Fatal("snapshot lost rewrite or unexpectedly wired HTTP hooks")
	}
	// Failed parsing must not publish a partial generation or poison the active
	// immutable snapshot. The executor only receives successfully parsed Configs.
	raw.MITM.Rewrite.Rules[0].Request.Method = "BAD METHOD"
	if _, err := parseMITM(raw.MITM); err == nil {
		t.Fatal("invalid reload unexpectedly parsed")
	}
	if manager.ConfigSnapshot().Rewrite != pinned.Rewrite {
		t.Fatal("failed reload changed the active snapshot")
	}
	raw.MITM.Rewrite.Rules[0].Request.Method = "DELETE"
	manager.Update(mitm.Config{})
	target, _ := url.Parse("https://a.example/v1/items")
	result, err := pinned.Rewrite.ApplyRequest(context.Background(), rewrite.RequestView{URL: *target, Method: "GET"})
	if err != nil || result.Request.Method != "GET" || result.Request.URL != *target || result.Body != nil || result.Terminal == nil || result.Terminal.Body != "local" {
		t.Fatalf("pinned snapshot changed: %+v %v", result, err)
	}
	if manager.ConfigSnapshot().Rewrite != nil {
		t.Fatal("new config retained old rules")
	}
}

func TestRewriteYAMLPreservesExternalAnchorsAndMerges(t *testing.T) {
	const input = `template: &template
  enable: true
  rules:
    - name: anchored
      request:
        method: POST
mitm:
  rewrite:
    <<: *template
`
	raw, err := UnmarshalRawConfig([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	s, err := parseMITMRewrite(raw.MITM.Rewrite)
	if err != nil {
		t.Fatal(err)
	}
	result, err := s.ApplyRequest(context.Background(), rewrite.RequestView{Method: "GET"})
	if err != nil || result.Request.Method != "POST" {
		t.Fatalf("external anchor lost: %+v %v", result, err)
	}
	if _, err := UnmarshalRawConfig([]byte(strings.Replace(input, "method: POST", "unknown: POST", 1))); err == nil {
		t.Fatal("unknown field in external anchor accepted")
	}
}
