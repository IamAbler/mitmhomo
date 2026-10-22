package tunnel_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	N "github.com/metacubex/mihomo/common/net"
	mihomoCA "github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/mitm"
	"github.com/metacubex/mihomo/component/mitm/rewrite"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/component/trie"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel"
	"github.com/metacubex/mihomo/tunnel/statistic"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
)

// Real DIRECT and HTTP CONNECT adapters, native rule selection and Tracker,
// verified TLS, and a real H2 origin. No substitute MITM native dialer.
func TestM33NativeH2DirectProxyAndRouteChanges(t *testing.T) {
	oldMode, oldProxies, oldProviders := tunnel.Mode(), tunnel.Proxies(), tunnel.Providers()
	oldRules, oldRuleProviders := tunnel.Rules(), tunnel.RuleProviders()
	oldHosts := resolver.DefaultHosts
	t.Cleanup(func() {
		tunnel.SetMode(oldMode)
		tunnel.UpdateProxies(oldProxies, oldProviders)
		tunnel.UpdateRules(oldRules, nil, oldRuleProviders)
		resolver.DefaultHosts = oldHosts
		mihomoCA.ResetCertificate()
	})
	tunnel.SetMode(tunnel.Rule)
	resolver.DefaultHosts = resolver.NewHosts(trie.New[resolver.HostValue]())
	var upstreamCalls, connects atomic.Int32
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		require.Equal(t, 2, r.ProtoMajor)
		require.Equal(t, "h2", r.TLS.NegotiatedProtocol)
		require.Equal(t, "/rewritten", r.URL.Path)
		b, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		fmt.Fprintf(w, "%s:%s", r.Method, b)
	}))
	upstream.EnableHTTP2 = true
	upstream.StartTLS()
	t.Cleanup(upstream.Close)
	leaf := upstream.Certificate()
	mihomoCA.ResetCertificate()
	require.NoError(t, mihomoCA.AddCertificate(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}))))
	target := upstream.Listener.Addr().String()
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "CONNECT" || r.Host != target {
			http.Error(w, "wrong target", 400)
			return
		}
		connects.Add(1)
		remote, err := net.Dial("tcp", target)
		if err != nil {
			http.Error(w, "dial", 502)
			return
		}
		defer remote.Close()
		client, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer client.Close()
		rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
		rw.Flush()
		done := make(chan struct{})
		go func() { io.Copy(remote, rw); remote.Close(); close(done) }()
		io.Copy(client, remote)
		client.Close()
		<-done
	}))
	t.Cleanup(proxyServer.Close)
	host, portString, err := net.SplitHostPort(proxyServer.Listener.Addr().String())
	require.NoError(t, err)
	port, err := strconv.Atoi(portString)
	require.NoError(t, err)
	httpProxy, err := outbound.NewHttp(outbound.HttpOption{Name: "M33_PROXY", Server: host, Port: port})
	require.NoError(t, err)
	tunnel.UpdateProxies(map[string]C.Proxy{"DIRECT": adapter.NewProxy(outbound.NewDirect()), "M33_PROXY": adapter.NewProxy(httpProxy)}, nil)
	pipeline, err := rewrite.Compile(rewrite.Config{Enable: true, Rules: []rewrite.Rule{{Name: "target", Request: &rewrite.RequestAction{URL: "https://" + target + "/rewritten"}}}})
	require.NoError(t, err)
	authority, roots := loadM33TestCA(t)
	manager := mitm.NewManager(mitm.Config{Enabled: true, Ports: []uint16{443}, Domains: []string{"localhost"}, CA: authority, Rewrite: pipeline, HandshakeTimeout: time.Second, RequestTimeout: 4 * time.Second, IdleTimeout: time.Second})
	serverRaw, clientRaw := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan m33DispatchResult, 1)
	go func() {
		outcome, err := manager.Dispatch(ctx, N.NewBufferedConn(serverRaw), &C.Metadata{NetWork: C.TCP, Type: C.TUNNEL, Host: "localhost", DstPort: 443, SrcIP: netip.MustParseAddr("192.0.2.33"), SrcPort: 43333}, nil, tunnel.Tunnel.DialTCPWithTLSHandshake)
		done <- m33DispatchResult{outcome: outcome, err: err}
	}()
	secure := tls.Client(clientRaw, &tls.Config{RootCAs: roots, ServerName: "localhost", NextProtos: []string{"h2"}, MinVersion: tls.VersionTLS12})
	require.NoError(t, secure.HandshakeContext(ctx))
	cc, err := (&http2.Transport{}).NewClientConn(secure)
	require.NoError(t, err)
	t.Cleanup(func() {
		defer cancel()
		cc.Close()
		select {
		case result := <-done:
			require.NoError(t, result.err)
		case <-time.After(3 * time.Second):
			t.Error("dispatcher leaked")
		}
	})
	for i, route := range []string{"DIRECT", "M33_PROXY", "DIRECT"} {
		// No active requests while mutating these native globals; pool bypass is
		// tested on the SAME downstream connection and SAME rewritten origin.
		tunnel.UpdateRules([]C.Rule{m33RouteRule{adapter: route}}, nil, nil)
		cfg := manager.ConfigSnapshot()
		manager.Update(cfg)
		req, err := http.NewRequest("POST", "https://localhost/old", io.NopCloser(strings.NewReader("payload")))
		require.NoError(t, err)
		response, err := cc.RoundTrip(req)
		require.NoError(t, err)
		require.Equal(t, 200, response.StatusCode)
		body, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		require.NoError(t, response.Body.Close())
		require.Equal(t, "POST:payload", string(body))
		require.Eventually(t, func() bool {
			found := false
			statistic.DefaultManager.Range(func(tracker statistic.Tracker) bool {
				found = found || tracker.Info().Metadata.SrcPort == 43333
				return !found
			})
			return !found
		}, 3*time.Second, 5*time.Millisecond)
		require.EqualValues(t, i+1, upstreamCalls.Load())
	}
	require.EqualValues(t, 1, connects.Load(), "only the PROXY request may use the CONNECT relay")
}

func loadM33TestCA(t *testing.T) (*mitm.CertificateAuthority, *x509.CertPool) {
	t.Helper()
	oldHome := C.Path.HomeDir()
	configHome := t.TempDir()
	C.SetHomeDir(configHome)
	t.Cleanup(func() { C.SetHomeDir(oldHome) })
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(99),
		Subject:               pkix.Name{CommonName: "M1 hook test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId:          []byte{9, 9, 9},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(configHome, "ca.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(configHome, "ca-key.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600))
	manager, err := mitm.LoadCertificateAuthority("ca.pem", "ca-key.pem")
	require.NoError(t, err)
	root, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(root)
	return manager, roots
}

type m33DispatchResult struct {
	outcome mitm.DispatchOutcome
	err     error
}
type m33RouteRule struct{ adapter string }

func (r m33RouteRule) RuleType() C.RuleType                                { return C.Domain }
func (r m33RouteRule) Match(*C.Metadata, C.RuleMatchHelper) (bool, string) { return true, r.adapter }
func (r m33RouteRule) Adapter() string                                     { return r.adapter }
func (r m33RouteRule) Payload() string                                     { return "" }
func (r m33RouteRule) ProviderNames() []string                             { return nil }
