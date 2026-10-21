package mitm

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
	"runtime"
	"sync"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/stretchr/testify/require"
)

func TestLoadCertificateAuthorityChecksPrivateKeyPermissionsAndLeafCache(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix private-key mode bits are not available on Windows")
	}
	oldHome := C.Path.HomeDir()
	configHome := t.TempDir()
	C.SetHomeDir(configHome)
	t.Cleanup(func() { C.SetHomeDir(oldHome) })

	ca, _ := makeTestAuthority(t)
	certificatePath := filepath.Join(configHome, "ca.pem")
	keyPath := filepath.Join(configHome, "ca-key.pem")
	require.NoError(t, os.WriteFile(certificatePath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.certificate.Certificate[0]}), 0o644))
	keyDER, err := x509.MarshalPKCS8PrivateKey(ca.signer)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o644))

	_, err = LoadCertificateAuthority("ca.pem", "ca-key.pem")
	require.ErrorContains(t, err, "permissions")
	require.NoError(t, os.Chmod(keyPath, 0o600))
	loaded, err := LoadCertificateAuthority("ca.pem", "ca-key.pem")
	require.NoError(t, err)

	first, err := loaded.serverCertificate("localhost")
	require.NoError(t, err)
	second, err := loaded.serverCertificate("LOCALHOST.")
	require.NoError(t, err)
	require.Equal(t, first.Leaf.SerialNumber, second.Leaf.SerialNumber, "normalized names must hit the same cached leaf")
	require.Equal(t, []string{"localhost"}, first.Leaf.DNSNames)
	require.Equal(t, x509.ExtKeyUsageServerAuth, first.Leaf.ExtKeyUsage[0])
	require.NotSame(t, loaded.signer, first.PrivateKey, "the client-facing certificate must contain only the generated leaf key")
	first.Certificate[0][0] ^= 0xff
	third, err := loaded.serverCertificate("localhost")
	require.NoError(t, err)
	require.NotEqual(t, first.Certificate[0][0], third.Certificate[0][0], "returned certificates must not expose mutable cached DER")

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			certificate, err := loaded.serverCertificate("parallel.example")
			if err != nil || certificate.Leaf == nil {
				t.Errorf("concurrent leaf issuance failed: %v", err)
			}
		}()
	}
	wg.Wait()
}

func TestLoadCertificateAuthorityRejectsNonCA(t *testing.T) {
	oldHome := C.Path.HomeDir()
	configHome := t.TempDir()
	C.SetHomeDir(configHome)
	t.Cleanup(func() { C.SetHomeDir(oldHome) })

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "not a CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(configHome, "cert.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(configHome, "key.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600))
	_, err = LoadCertificateAuthority("cert.pem", "key.pem")
	require.ErrorContains(t, err, "must be a valid CA")
}

func TestLoadCertificateAuthorityRejectsMismatchedKeyAndExpiredCA(t *testing.T) {
	oldHome := C.Path.HomeDir()
	configHome := t.TempDir()
	C.SetHomeDir(configHome)
	t.Cleanup(func() { C.SetHomeDir(oldHome) })
	writePair := func(certificateDER []byte, privateKey any) {
		t.Helper()
		keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(configHome, "cert.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}), 0o644))
		require.NoError(t, os.WriteFile(filepath.Join(configHome, "key.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600))
	}

	firstCA, _ := makeTestAuthority(t)
	secondCA, _ := makeTestAuthority(t)
	writePair(firstCA.certificate.Certificate[0], secondCA.signer)
	_, err := LoadCertificateAuthority("cert.pem", "key.pem")
	require.ErrorContains(t, err, "private key does not match public key")

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	now := time.Now()
	expiredTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(33),
		Subject:               pkix.Name{CommonName: "expired test CA"},
		NotBefore:             now.Add(-48 * time.Hour),
		NotAfter:              now.Add(-24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, expiredTemplate, expiredTemplate, &key.PublicKey, key)
	require.NoError(t, err)
	writePair(der, key)
	_, err = LoadCertificateAuthority("cert.pem", "key.pem")
	require.ErrorContains(t, err, "not currently valid")
}
