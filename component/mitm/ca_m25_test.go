package mitm

import (
	"crypto/x509"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestM25CAValidityAtIssuanceAndCacheHit(t *testing.T) {
	for _, cached := range []bool{false, true} {
		t.Run(fmt.Sprint(cached), func(t *testing.T) {
			ca, _ := makeTestAuthority(t)
			if cached {
				_, err := ca.serverCertificate("valid.example")
				require.NoError(t, err)
			}
			// Simulate a CA reaching expiry after configuration was loaded.
			ca.leaf.NotAfter = time.Now().Add(-time.Second)
			_, err := ca.serverCertificate("valid.example")
			require.ErrorContains(t, err, "not currently valid")
		})
	}
}

func TestM25CertificateBoundsAndConcurrentEviction(t *testing.T) {
	ca, roots := makeTestAuthority(t)
	ca.leaf.NotBefore = time.Now().Add(-time.Minute).Truncate(time.Second)
	ca.leaf.NotAfter = time.Now().Add(time.Hour)
	certificate, err := ca.serverCertificate("bounds.example")
	require.NoError(t, err)
	require.False(t, certificate.Leaf.NotBefore.Before(ca.leaf.NotBefore))
	require.False(t, certificate.Leaf.NotAfter.After(ca.leaf.NotAfter))
	require.Positive(t, certificate.Leaf.SerialNumber.Sign())
	_, err = certificate.Leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "bounds.example"})
	require.NoError(t, err)
	var workers sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		workers.Add(1)
		go func(worker int) {
			defer workers.Done()
			for i := 0; i < 80; i++ {
				_, err := ca.serverCertificate(fmt.Sprintf("h%d-%d.example", worker, i))
				if err != nil {
					t.Error(err)
					return
				}
			}
		}(worker)
	}
	workers.Wait()
	require.Len(t, ca.cache, maxLeafCertificates)
	require.Equal(t, maxLeafCertificates, ca.lru.Len())
	_, exists := ca.cache["bounds.example"]
	require.False(t, exists)
}
