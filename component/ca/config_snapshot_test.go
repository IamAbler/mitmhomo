package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCertPoolSnapshotSurvivesUpdates(t *testing.T) {
	mutex.Lock()
	original := globalCertPool
	globalCertPool = x509.NewCertPool()
	mutex.Unlock()
	defer func() { mutex.Lock(); globalCertPool = original; mutex.Unlock() }()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cert := &x509.Certificate{SerialNumber: big.NewInt(34), Subject: pkix.Name{CommonName: "snapshot.example"}, DNSNames: []string{"snapshot.example"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	old := GetCertPoolSnapshot()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			if e := AddCertificate(string(der)); e != nil {
				t.Error(e)
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			GetCertPoolSnapshot()
		}
	}()
	wg.Wait()
	_, err = leaf.Verify(x509.VerifyOptions{Roots: old, DNSName: "snapshot.example"})
	require.Error(t, err, "existing connection cannot inherit newly trusted roots")
	_, err = leaf.Verify(x509.VerifyOptions{Roots: GetCertPoolSnapshot(), DNSName: "snapshot.example"})
	require.NoError(t, err, "new connection observes trust update")
}
