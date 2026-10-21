package mitm

import (
	"container/list"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	C "github.com/metacubex/mihomo/constant"
	domainname "github.com/metacubex/sing/common/metadata"
)

const (
	maxLeafCertificates = 256
	leafCertificateAge  = 24 * time.Hour
)

// CertificateAuthority keeps the configured CA key private to this package
// and signs a bounded cache of short-lived server certificates.
type CertificateAuthority struct {
	certificate tls.Certificate
	leaf        *x509.Certificate
	signer      crypto.Signer

	mu    sync.Mutex
	cache map[string]*list.Element
	lru   *list.List
}

type leafCertificate struct {
	host        string
	certificate tls.Certificate
}

// LoadCertificateAuthority loads and validates a CA certificate and private
// key. Relative paths resolve under Mihomo's configuration directory.
func LoadCertificateAuthority(certificatePath, privateKeyPath string) (*CertificateAuthority, error) {
	if certificatePath == "" || privateKeyPath == "" {
		return nil, errors.New("MITM CA certificate and private key paths are required")
	}
	certificatePath, _, err := resolveCAFile(certificatePath)
	if err != nil {
		return nil, fmt.Errorf("load MITM CA certificate: %w", err)
	}
	privateKeyPath, keyInfo, err := resolveCAFile(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load MITM CA private key: %w", err)
	}
	if runtime.GOOS != "windows" && keyInfo.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("MITM CA private key permissions must not grant group or other access: %s", privateKeyPath)
	}

	certificatePEM, err := os.ReadFile(certificatePath)
	if err != nil {
		return nil, fmt.Errorf("read MITM CA certificate: %w", err)
	}
	privateKeyPEM, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read MITM CA private key: %w", err)
	}
	certificate, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse MITM CA key pair: %w", err)
	}
	if len(certificate.Certificate) == 0 {
		return nil, errors.New("MITM CA certificate chain is empty")
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse MITM CA certificate: %w", err)
	}
	if !leaf.IsCA || !leaf.BasicConstraintsValid || leaf.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, errors.New("MITM CA certificate must be a valid CA with certificate-signing usage")
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return nil, errors.New("MITM CA certificate is not currently valid")
	}
	signer, ok := certificate.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("MITM CA private key does not implement crypto.Signer")
	}
	certificate.Leaf = leaf

	return &CertificateAuthority{
		certificate: certificate,
		leaf:        leaf,
		signer:      signer,
		cache:       make(map[string]*list.Element),
		lru:         list.New(),
	}, nil
}

func resolveCAFile(path string) (string, os.FileInfo, error) {
	resolved := C.Path.Resolve(path)
	if !C.Path.IsSafePath(resolved) {
		return "", nil, C.Path.ErrNotSafePath(resolved)
	}
	realPath, err := filepath.EvalSymlinks(resolved)
	if err != nil {
		return "", nil, err
	}
	if !C.Path.IsSafePath(realPath) {
		return "", nil, C.Path.ErrNotSafePath(realPath)
	}
	info, err := os.Stat(realPath)
	if err != nil {
		return "", nil, err
	}
	if !info.Mode().IsRegular() {
		return "", nil, errors.New("path is not a regular file")
	}
	return realPath, info, nil
}

func (ca *CertificateAuthority) serverCertificate(serverName string) (tls.Certificate, error) {
	if ca == nil || ca.signer == nil {
		return tls.Certificate{}, errors.New("MITM certificate authority is unavailable")
	}
	serverName = normalizeDomain(serverName)
	if _, err := netip.ParseAddr(serverName); serverName == "" || err == nil || !domainname.IsDomainName(serverName) {
		return tls.Certificate{}, fmt.Errorf("invalid MITM server name %q", serverName)
	}

	ca.mu.Lock()
	defer ca.mu.Unlock()
	if element := ca.cache[serverName]; element != nil {
		entry := element.Value.(*leafCertificate)
		if entry.certificate.Leaf != nil && time.Until(entry.certificate.Leaf.NotAfter) > time.Minute {
			ca.lru.MoveToFront(element)
			return cloneTLSCertificate(entry.certificate), nil
		}
		ca.lru.Remove(element)
		delete(ca.cache, serverName)
	}

	certificate, err := ca.issueServerCertificate(serverName)
	if err != nil {
		return tls.Certificate{}, err
	}
	entry := &leafCertificate{host: serverName, certificate: certificate}
	ca.cache[serverName] = ca.lru.PushFront(entry)
	if ca.lru.Len() > maxLeafCertificates {
		oldest := ca.lru.Back()
		delete(ca.cache, oldest.Value.(*leafCertificate).host)
		ca.lru.Remove(oldest)
	}
	return cloneTLSCertificate(certificate), nil
}

func (ca *CertificateAuthority) issueServerCertificate(serverName string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate MITM leaf key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate MITM leaf serial: %w", err)
	}
	now := time.Now()
	notAfter := now.Add(leafCertificateAge)
	if notAfter.After(ca.leaf.NotAfter) {
		notAfter = ca.leaf.NotAfter
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: serverName},
		DNSNames:              []string{serverName},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		AuthorityKeyId:        ca.leaf.SubjectKeyId,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, template, ca.leaf, &key.PublicKey, ca.signer)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("sign MITM leaf certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parse MITM leaf certificate: %w", err)
	}
	chain := make([][]byte, 0, len(ca.certificate.Certificate))
	chain = append(chain, leafDER)
	for _, cert := range ca.certificate.Certificate[1:] {
		chain = append(chain, append([]byte(nil), cert...))
	}
	return tls.Certificate{Certificate: chain, PrivateKey: key, Leaf: leaf}, nil
}

func cloneTLSCertificate(certificate tls.Certificate) tls.Certificate {
	clone := certificate
	clone.Certificate = make([][]byte, len(certificate.Certificate))
	for i, der := range certificate.Certificate {
		clone.Certificate[i] = append([]byte(nil), der...)
	}
	clone.OCSPStaple = append([]byte(nil), certificate.OCSPStaple...)
	clone.SupportedSignatureAlgorithms = append([]tls.SignatureScheme(nil), certificate.SupportedSignatureAlgorithms...)
	clone.SignedCertificateTimestamps = make([][]byte, len(certificate.SignedCertificateTimestamps))
	for i, sct := range certificate.SignedCertificateTimestamps {
		clone.SignedCertificateTimestamps[i] = append([]byte(nil), sct...)
	}
	return clone
}
