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
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/mitm"
	"github.com/metacubex/mihomo/component/mitm/processing/model"
	C "github.com/metacubex/mihomo/constant"
	"github.com/stretchr/testify/require"
)

func writeMITMTestCA(t *testing.T, directory string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(52),
		Subject:               pkix.Name{CommonName: "MITM Goja test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(directory, "mitm-ca.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(directory, "mitm-ca-key.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600))
}

func TestMITMGojaYAMLBuildsGenerationProcessor(t *testing.T) {
	oldHome := C.Path.HomeDir()
	configHome := t.TempDir()
	C.SetHomeDir(configHome)
	t.Cleanup(func() { C.SetHomeDir(oldHome) })
	writeMITMTestCA(t, configHome)

	const rawYAML = `mitm:
  enable: true
  domains: [api.example.test]
  ca-cert: mitm-ca.pem
  ca-key: mitm-ca-key.pem
  goja-processor:
    enable: true
    id: example-http
    request: true
    response: true
    request-body: full-buffered
    request-max-body-bytes: 65536
    response-body: none
    execution-timeout: 2
    capacity: 8
    source: |
      function process(input) {
        if (input.phase === "request") return {kind:"request_change",request:{headers:[{op:"set",name:"X-Processed",values:["goja"]}]}};
        return {kind:"response_change",response:{headers:[{op:"set",name:"X-Response-Processed",values:["goja"]}]}};
      }
`
	raw, err := UnmarshalRawConfig([]byte(rawYAML))
	require.NoError(t, err)
	parsed, err := parseMITM(raw.MITM)
	require.NoError(t, err)
	require.True(t, parsed.Enabled)
	require.NotNil(t, parsed.ProcessorFactory)
	entries, err := parsed.ProcessorFactory()
	require.NoError(t, err)
	require.Len(t, entries, 1)
	descriptor := entries[0].Processor.Describe()
	require.Equal(t, "goja", descriptor.Backend)
	require.True(t, descriptor.Request)
	require.True(t, descriptor.Response)
	require.Equal(t, model.FullBuffered, descriptor.RequestNeeds.Body)
	require.EqualValues(t, 65536, descriptor.RequestNeeds.MaxBodyBytes)
	require.Equal(t, model.None, descriptor.ResponseNeeds.Body)
	require.NoError(t, entries[0].Processor.Close())
	require.NoError(t, entries[0].Processor.WaitClosed(context.Background()))
}

func TestMITMGojaYAMLIsStrictAndDefaultOff(t *testing.T) {
	unknown, err := UnmarshalRawConfig([]byte(`mitm:
  goja-processor:
    enable: true
    typo-field: true
`))
	require.Nil(t, unknown)
	require.ErrorContains(t, err, "mitm.goja-processor")
	require.ErrorContains(t, err, "unknown field")

	disabled, err := parseMITM(RawMITM{GojaProcessor: RawGoja{Enable: true, ID: "ignored"}})
	require.NoError(t, err)
	require.False(t, disabled.Enabled)
	require.Nil(t, disabled.ProcessorFactory)

	bad := RawMITM{
		Enable:        true,
		Domains:       []string{"api.example.test"},
		CACertificate: "missing.pem",
		CAPrivateKey:  "missing.key",
		GojaProcessor: RawGoja{Enable: true, ID: "bad-body", Request: true, Source: `function process(input) { return {kind:"continue"}; }`, RequestBody: "stream"},
	}
	_, err = parseMITM(bad)
	require.ErrorContains(t, err, "mitm.goja-processor")
	require.ErrorContains(t, err, "request-body must be none or full-buffered")
}

func TestMITMGojaSourceCompileFailureDoesNotPublishCandidate(t *testing.T) {
	oldHome := C.Path.HomeDir()
	configHome := t.TempDir()
	C.SetHomeDir(configHome)
	t.Cleanup(func() { C.SetHomeDir(oldHome) })
	writeMITMTestCA(t, configHome)

	raw, err := UnmarshalRawConfig([]byte(`mitm:
  enable: true
  domains: [api.example.test]
  ca-cert: mitm-ca.pem
  ca-key: mitm-ca-key.pem
  goja-processor:
    enable: true
    id: broken
    request: true
    source: |
      function process(input) {
`))
	require.NoError(t, err)
	parsed, err := parseMITM(raw.MITM)
	require.NoError(t, err, "Goja compilation is deferred to candidate construction before publication")
	validFactory, err := parseMITMGoja(RawGoja{
		Enable: true, ID: "healthy", Request: true,
		Source: `function process(input) { return {kind:"continue"}; }`,
	})
	require.NoError(t, err)
	manager := mitm.NewManager(mitm.Config{Enabled: true, ProcessorFactory: validFactory})
	previous := manager.Generation()
	require.NotNil(t, previous)
	err = manager.Update(mitm.Config{Enabled: true, ProcessorFactory: parsed.ProcessorFactory})
	require.Error(t, err, "Factory.Build must compile the program before a Generation can be published")
	require.Same(t, previous, manager.Generation(), "a compile failure must keep the active Generation")
	_ = manager.Close()
}
