package config

import (
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

	C "github.com/metacubex/mihomo/constant"
	"github.com/stretchr/testify/require"
)

func TestParseMITMDefaultsDisabledWithoutLoadingCA(t *testing.T) {
	parsed, err := parseMITM(RawMITM{CACertificate: "does-not-exist.pem", CAPrivateKey: "does-not-exist.key"})
	require.NoError(t, err)
	require.False(t, parsed.Enabled)
	require.Nil(t, parsed.CA)
}

func TestParseMITMValidatesRulesPortsAndTimeoutsBeforeCA(t *testing.T) {
	base := RawMITM{Enable: true, CACertificate: "missing.pem", CAPrivateKey: "missing.key"}

	_, err := parseMITM(base)
	require.ErrorContains(t, err, "domains")

	base.Domains = []string{"127.0.0.1"}
	_, err = parseMITM(base)
	require.ErrorContains(t, err, "invalid MITM domain")

	base.Domains = []string{"example.test"}
	base.Ports = []string{"65536"}
	_, err = parseMITM(base)
	require.ErrorContains(t, err, "port")

	base.Ports = []string{"443"}
	base.RequestTimeout = 3601
	_, err = parseMITM(base)
	require.ErrorContains(t, err, "request-timeout")
}

func TestParseMITMLoadsCAAndAppliesSafeDefaults(t *testing.T) {
	oldHome := C.Path.HomeDir()
	configHome := t.TempDir()
	C.SetHomeDir(configHome)
	t.Cleanup(func() { C.SetHomeDir(oldHome) })

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(10),
		Subject:               pkix.Name{CommonName: "MITM test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId:          []byte{1, 3, 3, 7},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(configHome, "mitm-ca.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(configHome, "mitm-ca-key.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600))

	parsed, err := parseMITM(RawMITM{
		Enable:        true,
		Domains:       []string{"Example.test", "*.sub.example.test"},
		CACertificate: "mitm-ca.pem",
		CAPrivateKey:  "mitm-ca-key.pem",
	})
	require.NoError(t, err)
	require.True(t, parsed.Enabled)
	require.NotNil(t, parsed.CA)
	require.Equal(t, []string{"example.test", "*.sub.example.test"}, parsed.Domains)
	require.Equal(t, uint16(443), parsed.PortRanges[0].Start)
	require.Equal(t, uint16(443), parsed.PortRanges[0].End)
	require.Equal(t, 2*time.Second, parsed.ClientHelloTimeout)
	require.Equal(t, 10*time.Second, parsed.HandshakeTimeout)
	require.Equal(t, 120*time.Second, parsed.RequestTimeout)
	require.Equal(t, 60*time.Second, parsed.IdleTimeout)

	ranged, err := parseMITM(RawMITM{
		Enable:        true,
		Domains:       []string{"*.example.test"},
		Ports:         []string{"443", "8443-8445"},
		CACertificate: "mitm-ca.pem",
		CAPrivateKey:  "mitm-ca-key.pem",
	})
	require.NoError(t, err)
	require.Equal(t, []uint16{443, 8443}, []uint16{ranged.PortRanges[0].Start, ranged.PortRanges[1].Start})
	require.Equal(t, uint16(8445), ranged.PortRanges[1].End)
}
