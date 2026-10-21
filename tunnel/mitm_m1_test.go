package tunnel

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	mihomoCA "github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/mitm"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/component/sniffer"
	"github.com/metacubex/mihomo/component/trie"
	C "github.com/metacubex/mihomo/constant"
	icontext "github.com/metacubex/mihomo/context"
	"github.com/metacubex/mihomo/tunnel/statistic"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

type m1RouteRule struct {
	host    string
	adapter string
}

func (r m1RouteRule) RuleType() C.RuleType { return C.Domain }
func (r m1RouteRule) Match(metadata *C.Metadata, _ C.RuleMatchHelper) (bool, string) {
	return metadata.Host == r.host, r.adapter
}
func (r m1RouteRule) Adapter() string       { return r.adapter }
func (r m1RouteRule) Payload() string       { return r.host }
func (m1RouteRule) ProviderNames() []string { return nil }

type m1DNSResolveRule struct {
	host    string
	adapter string
}

func (r m1DNSResolveRule) RuleType() C.RuleType { return C.Domain }
func (r m1DNSResolveRule) Match(_ *C.Metadata, helper C.RuleMatchHelper) (bool, string) {
	helper.ResolveIP()
	return true, r.adapter
}
func (r m1DNSResolveRule) Adapter() string       { return r.adapter }
func (r m1DNSResolveRule) Payload() string       { return r.host }
func (m1DNSResolveRule) ProviderNames() []string { return nil }

type m1BlockingResolver struct {
	started   chan struct{}
	canceled  chan error
	startOnce sync.Once
}

func (resolver *m1BlockingResolver) LookupIP(ctx context.Context, _ string) ([]netip.Addr, error) {
	resolver.startOnce.Do(func() { close(resolver.started) })
	<-ctx.Done()
	resolver.canceled <- ctx.Err()
	return nil, ctx.Err()
}
func (resolver *m1BlockingResolver) LookupIPv4(ctx context.Context, host string) ([]netip.Addr, error) {
	return resolver.LookupIP(ctx, host)
}
func (resolver *m1BlockingResolver) LookupIPv6(ctx context.Context, host string) ([]netip.Addr, error) {
	return resolver.LookupIP(ctx, host)
}
func (*m1BlockingResolver) ResolveECH(context.Context, string) ([]byte, error) {
	return nil, errors.New("not implemented")
}
func (*m1BlockingResolver) ExchangeContext(context.Context, *dns.Msg) (*dns.Msg, error) {
	return nil, errors.New("not implemented")
}
func (*m1BlockingResolver) Invalid() bool    { return true }
func (*m1BlockingResolver) ClearCache()      {}
func (*m1BlockingResolver) ResetConnection() {}

type m1NativeProxy struct {
	C.Proxy
	mu             sync.Mutex
	name           string
	conn           C.Conn
	metadata       *C.Metadata
	calls          int
	onDial         func(context.Context) (C.Conn, error)
	onDialMetadata func(context.Context, *C.Metadata) (C.Conn, error)
}

func (p *m1NativeProxy) Name() string                   { return p.name }
func (*m1NativeProxy) Type() C.AdapterType              { return C.Vmess }
func (*m1NativeProxy) Unwrap(*C.Metadata, bool) C.Proxy { return nil }
func (p *m1NativeProxy) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	p.mu.Lock()
	p.calls++
	p.metadata = metadata.Clone()
	p.mu.Unlock()
	if p.onDialMetadata != nil {
		return p.onDialMetadata(ctx, metadata)
	}
	if p.onDial != nil {
		return p.onDial(ctx)
	}
	return p.conn, nil
}

func (p *m1NativeProxy) snapshot() (int, *C.Metadata) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.metadata == nil {
		return p.calls, nil
	}
	return p.calls, p.metadata.Clone()
}

func TestPrepareMITMOriginRecoversMissingFakeIPOnlyOnCopy(t *testing.T) {
	oldMapper, oldHosts := resolver.DefaultHostMapper, resolver.DefaultHosts
	t.Cleanup(func() {
		resolver.DefaultHostMapper = oldMapper
		resolver.DefaultHosts = oldHosts
	})
	fakeIP := netip.MustParseAddr("198.18.0.88")
	resolver.DefaultHostMapper = &testHostMapper{
		mapping:     true,
		fakeIPRange: netip.MustParsePrefix("198.18.0.1/16"),
		fakeIPs:     map[netip.Addr]bool{},
		hosts:       map[netip.Addr]string{},
	}
	resolver.DefaultHosts = resolver.NewHosts(trie.New[resolver.HostValue]())
	metadata := &C.Metadata{NetWork: C.TCP, Type: C.TUNNEL, DstIP: fakeIP, DstPort: 443}
	prepared, err := prepareMITMOrigin(metadata, &sniffer.TLSClientHelloInfo{ServerName: "allowed.example"})
	require.NoError(t, err)
	require.Equal(t, "allowed.example", prepared.Host)
	require.False(t, prepared.DstIP.IsValid(), "the fake address must never become an upstream destination")
	require.Equal(t, C.DNSNormal, prepared.DNSMode)
	require.Equal(t, fakeIP, metadata.DstIP, "preparation must not rewrite the inbound Metadata")
	require.Empty(t, metadata.Host)

	_, err = prepareMITMOrigin(metadata, &sniffer.TLSClientHelloInfo{})
	require.ErrorContains(t, err, "requires Metadata and SNI")
}

func TestMITMDialTCPUsesNativeRulesEarlyWriteAndStatistics(t *testing.T) {
	oldMode, oldProxies, oldRules, oldSubRules, oldHosts := mode, proxies, rules, subRules, resolver.DefaultHosts
	t.Cleanup(func() {
		mode, proxies, rules, subRules, resolver.DefaultHosts = oldMode, oldProxies, oldRules, oldSubRules, oldHosts
	})
	resolver.DefaultHosts = resolver.NewHosts(trie.New[resolver.HostValue]())
	const host = "mitm-m1-native-rule.example"
	remoteSide, remotePeer := net.Pipe()
	t.Cleanup(func() { _ = remotePeer.Close() })
	remote := &earlyCaptureConn{
		ExtendedConn:  N.NewExtendedConn(remoteSide),
		host:          host,
		needHandshake: true,
		writes:        make(chan earlyWrite, 1),
	}
	selected := &m1NativeProxy{name: "MITM_RULE_PROXY", conn: remote}
	direct := &m1NativeProxy{name: "DIRECT"}
	mode = Rule
	proxies = map[string]C.Proxy{"MITM_RULE_PROXY": selected, "DIRECT": direct}
	rules = []C.Rule{m1RouteRule{host: host, adapter: "MITM_RULE_PROXY"}}
	subRules = nil

	metadata := &C.Metadata{NetWork: C.TCP, Type: C.TUNNEL, Host: host, DstPort: 443}
	conn, err := Tunnel.DialTCPWithTLSHandshake(context.Background(), metadata, func(_ context.Context, conn net.Conn) (net.Conn, error) {
		_, err := conn.Write([]byte("upstream TLS ClientHello"))
		return conn, err
	})
	require.NoError(t, err)
	require.True(t, N.NeedHandshake(conn), "the tracked native connection must preserve the EarlyConn signal")
	selectedCalls, selectedMetadata := selected.snapshot()
	directCalls, _ := direct.snapshot()
	require.Equal(t, 1, selectedCalls)
	require.Zero(t, directCalls)
	require.Equal(t, host, selectedMetadata.Host)
	require.Equal(t, uint16(443), selectedMetadata.DstPort)

	select {
	case firstWrite := <-remote.writes:
		require.Equal(t, "upstream TLS ClientHello", string(firstWrite.data))
		require.True(t, firstWrite.tracked, "the early first write must pass through the native tracker")
	case <-time.After(time.Second):
		t.Fatal("the first upstream TLS write was not delivered")
	}
	require.NoError(t, conn.Close())
	found := false
	statistic.DefaultManager.Range(func(tracker statistic.Tracker) bool {
		found = found || tracker.Info().Metadata.Host == host
		return !found
	})
	require.False(t, found, "closing an outbound request connection must release its statistics tracker")
}

func TestMITMDialTCPRetriesEarlyTLSHandshakeAndCleansFailedTracker(t *testing.T) {
	oldMode, oldProxies, oldRules, oldSubRules, oldHosts := mode, proxies, rules, subRules, resolver.DefaultHosts
	t.Cleanup(func() {
		mode, proxies, rules, subRules, resolver.DefaultHosts = oldMode, oldProxies, oldRules, oldSubRules, oldHosts
	})
	resolver.DefaultHosts = resolver.NewHosts(trie.New[resolver.HostValue]())
	const host = "mitm-m1-early-retry.example"
	failedSide, failedPeer := net.Pipe()
	defer failedPeer.Close()
	goodSide, goodPeer := net.Pipe()
	defer goodPeer.Close()
	good := &earlyCaptureConn{
		ExtendedConn:  N.NewExtendedConn(goodSide),
		host:          host,
		needHandshake: true,
		writes:        make(chan earlyWrite, 1),
	}
	var dials atomic.Int32
	proxy := &m1NativeProxy{name: "EARLY_RETRY_PROXY", onDial: func(context.Context) (C.Conn, error) {
		if dials.Add(1) == 1 {
			return &m1FailingEarlyNativeConn{m1PlainNativeConn: &m1PlainNativeConn{ExtendedConn: N.NewExtendedConn(failedSide)}}, nil
		}
		leaked := false
		statistic.DefaultManager.Range(func(tracker statistic.Tracker) bool {
			leaked = leaked || tracker.Info().Metadata.Host == host
			return !leaked
		})
		require.False(t, leaked, "a failed EarlyConn attempt must unregister its tracker before retry")
		return good, nil
	}}
	mode = Direct
	proxies = map[string]C.Proxy{"DIRECT": proxy}
	rules, subRules = nil, nil

	metadata := &C.Metadata{NetWork: C.TCP, Type: C.TUNNEL, Host: host, DstPort: 443}
	conn, err := Tunnel.DialTCPWithTLSHandshake(context.Background(), metadata, func(_ context.Context, conn net.Conn) (net.Conn, error) {
		_, err := conn.Write([]byte("upstream TLS ClientHello"))
		return conn, err
	})
	require.NoError(t, err)
	require.EqualValues(t, 2, dials.Load(), "an EarlyConn first-write failure must use Mihomo's retry path")
	select {
	case firstWrite := <-good.writes:
		require.Equal(t, "upstream TLS ClientHello", string(firstWrite.data))
		require.True(t, firstWrite.tracked)
	case <-time.After(time.Second):
		t.Fatal("retried EarlyConn did not receive the upstream TLS ClientHello")
	}
	require.NoError(t, conn.Close())
	found := false
	statistic.DefaultManager.Range(func(tracker statistic.Tracker) bool {
		found = found || tracker.Info().Metadata.Host == host
		return !found
	})
	require.False(t, found, "closing the successful retry must unregister its tracker")
}

func TestMITMDialTCPCancellationReachesNativeProxy(t *testing.T) {
	oldMode, oldProxies, oldRules, oldSubRules, oldHosts := mode, proxies, rules, subRules, resolver.DefaultHosts
	t.Cleanup(func() {
		mode, proxies, rules, subRules, resolver.DefaultHosts = oldMode, oldProxies, oldRules, oldSubRules, oldHosts
	})
	resolver.DefaultHosts = resolver.NewHosts(trie.New[resolver.HostValue]())
	started := make(chan struct{})
	proxy := &m1NativeProxy{name: "CANCEL_PROXY", onDial: func(ctx context.Context) (C.Conn, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	mode = Direct
	proxies = map[string]C.Proxy{"DIRECT": proxy}
	rules, subRules = nil, nil
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := Tunnel.DialTCP(ctx, &C.Metadata{NetWork: C.TCP, Type: C.TUNNEL, Host: "cancel.example", DstPort: 443})
		result <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("native outbound proxy was not called")
	}
	cancel()
	select {
	case err := <-result:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("native outbound dial did not stop after context cancellation")
	}
}

func TestMITMDialTCPContextCancellationReachesDNSAndNativeDial(t *testing.T) {
	oldMode, oldProxies, oldRules, oldSubRules := mode, proxies, rules, subRules
	oldHosts, oldResolver, oldSystemResolver := resolver.DefaultHosts, resolver.DefaultResolver, resolver.SystemResolver
	t.Cleanup(func() {
		mode, proxies, rules, subRules = oldMode, oldProxies, oldRules, oldSubRules
		resolver.DefaultHosts, resolver.DefaultResolver, resolver.SystemResolver = oldHosts, oldResolver, oldSystemResolver
	})
	resolver.DefaultHosts = resolver.NewHosts(trie.New[resolver.HostValue]())
	dnsStarted := make(chan struct{})
	dnsCanceled := make(chan error, 1)
	resolver.DefaultResolver = &m1BlockingResolver{started: dnsStarted, canceled: dnsCanceled}
	proxyStarted := make(chan struct{})
	proxy := &m1NativeProxy{name: "DNS_CANCEL_PROXY", onDial: func(ctx context.Context) (C.Conn, error) {
		close(proxyStarted)
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	mode = Rule
	proxies = map[string]C.Proxy{"DNS_CANCEL_PROXY": proxy}
	rules, subRules = []C.Rule{m1DNSResolveRule{host: "dns-cancel.example", adapter: "DNS_CANCEL_PROXY"}}, nil

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := Tunnel.DialTCP(ctx, &C.Metadata{NetWork: C.TCP, Type: C.TUNNEL, Host: "dns-cancel.example", DstPort: 443})
		result <- err
	}()
	select {
	case <-dnsStarted:
	case <-time.After(time.Second):
		t.Fatal("native route selection did not reach DNS resolution")
	}
	cancel()
	select {
	case err := <-dnsCanceled:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("DNS resolution did not observe context cancellation")
	}
	select {
	case <-proxyStarted:
	case <-time.After(time.Second):
		t.Fatal("native route selection did not propagate to the proxy dial")
	}
	select {
	case err := <-result:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("cancelled DNS and native dial did not return")
	}
}

type m1PlainNativeConn struct{ N.ExtendedConn }

func (*m1PlainNativeConn) Chains() C.Chain               { return C.Chain{"DIRECT"} }
func (*m1PlainNativeConn) ProviderChains() C.Chain       { return nil }
func (*m1PlainNativeConn) AppendToChains(C.ProxyAdapter) {}
func (*m1PlainNativeConn) RemoteDestination() string     { return "localhost:443" }

type m1EarlyNativeConn struct {
	*m1PlainNativeConn
	host   string
	writes chan earlyWrite
	once   sync.Once
}

func (*m1EarlyNativeConn) NeedHandshake() bool { return true }

func (conn *m1EarlyNativeConn) Write(data []byte) (int, error) {
	conn.once.Do(func() {
		tracked := false
		statistic.DefaultManager.Range(func(tracker statistic.Tracker) bool {
			if tracker.Info().Metadata.Host == conn.host {
				tracked = true
				return false
			}
			return true
		})
		conn.writes <- earlyWrite{data: append([]byte(nil), data...), tracked: tracked}
	})
	return conn.m1PlainNativeConn.Write(data)
}

type m1FailingEarlyNativeConn struct{ *m1PlainNativeConn }

func (*m1FailingEarlyNativeConn) NeedHandshake() bool { return true }
func (*m1FailingEarlyNativeConn) Write([]byte) (int, error) {
	return 0, errors.New("simulated EarlyConn first-write failure")
}

type m1EarlyFirstWriteErrorConn struct {
	*m1PlainNativeConn
	writes     chan []byte
	afterWrite func()
}

func (*m1EarlyFirstWriteErrorConn) NeedHandshake() bool { return true }

func (conn *m1EarlyFirstWriteErrorConn) Write(data []byte) (int, error) {
	conn.writes <- append([]byte(nil), data...)
	n, err := conn.m1PlainNativeConn.Write(data)
	if err != nil {
		return n, err
	}
	if conn.afterWrite != nil {
		conn.afterWrite()
	}
	return n, errors.New("injected EarlyConn ClientHello write failure")
}

type m1StalledTLSUpstream struct {
	listener net.Listener
	hello    chan struct{}
	closed   chan struct{}
	mu       sync.Mutex
	peer     net.Conn
}

func newM1StalledTLSUpstream(t *testing.T) *m1StalledTLSUpstream {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	upstream := &m1StalledTLSUpstream{
		listener: listener,
		hello:    make(chan struct{}),
		closed:   make(chan struct{}),
	}
	go func() {
		defer close(upstream.closed)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		upstream.mu.Lock()
		upstream.peer = conn
		upstream.mu.Unlock()
		defer conn.Close()
		var header [5]byte
		if _, err := io.ReadFull(conn, header[:]); err != nil || header[0] != 0x16 {
			return
		}
		body := make([]byte, int(binary.BigEndian.Uint16(header[3:])))
		if _, err := io.ReadFull(conn, body); err != nil {
			return
		}
		close(upstream.hello)
		_, _ = io.Copy(io.Discard, conn)
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		upstream.mu.Lock()
		peer := upstream.peer
		upstream.mu.Unlock()
		if peer != nil {
			_ = peer.Close()
		}
	})
	return upstream
}

func (upstream *m1StalledTLSUpstream) waitForHello(t *testing.T) {
	t.Helper()
	select {
	case <-upstream.hello:
	case <-time.After(3 * time.Second):
		t.Fatal("local upstream did not receive a TLS ClientHello")
	}
}

func (upstream *m1StalledTLSUpstream) waitForClose(t *testing.T) {
	t.Helper()
	select {
	case <-upstream.closed:
	case <-time.After(3 * time.Second):
		t.Fatal("local upstream did not observe the client socket close")
	}
}

var m1TrackerSourcePort atomic.Uint32

func configureM1DirectNativeProxy(t *testing.T, proxy *m1NativeProxy) *C.Metadata {
	t.Helper()
	oldMode, oldProxies, oldRules, oldSubRules, oldHosts := mode, proxies, rules, subRules, resolver.DefaultHosts
	t.Cleanup(func() {
		mode, proxies, rules, subRules, resolver.DefaultHosts = oldMode, oldProxies, oldRules, oldSubRules, oldHosts
	})
	resolver.DefaultHosts = resolver.NewHosts(trie.New[resolver.HostValue]())
	mode = Direct
	proxies = map[string]C.Proxy{"DIRECT": proxy}
	rules, subRules = nil, nil
	sourcePort := uint16(10000 + m1TrackerSourcePort.Add(1)%50000)
	return &C.Metadata{NetWork: C.TCP, Type: C.TUNNEL, Host: "localhost", DstPort: 443, SrcPort: sourcePort}
}

func requireM1TrackerRemoved(t *testing.T, metadata *C.Metadata) {
	t.Helper()
	found := false
	statistic.DefaultManager.Range(func(tracker statistic.Tracker) bool {
		tracked := tracker.Info().Metadata
		found = found || (tracked.Host == metadata.Host && tracked.SrcPort == metadata.SrcPort)
		return !found
	})
	require.False(t, found, "the MITM native Tracker must be removed after connection failure or close")
}

func requireM1TrackerPresent(t *testing.T, metadata *C.Metadata) {
	t.Helper()
	found := false
	statistic.DefaultManager.Range(func(tracker statistic.Tracker) bool {
		tracked := tracker.Info().Metadata
		found = found || (tracked.Host == metadata.Host && tracked.SrcPort == metadata.SrcPort)
		return !found
	})
	require.True(t, found, "the active MITM native connection must have a Tracker")
}

type m1HandshakeCapture struct {
	nativeDial chan context.Context
	handshake  chan context.Context
	result     chan error
}

func newM1HandshakeCapture() (*m1HandshakeCapture, mitm.NativeDialContext) {
	return newM1HandshakeCaptureWithBuffer(1)
}

func newM1HandshakeCaptureWithBuffer(buffer int) (*m1HandshakeCapture, mitm.NativeDialContext) {
	capture := &m1HandshakeCapture{
		nativeDial: make(chan context.Context, buffer),
		handshake:  make(chan context.Context, buffer),
		result:     make(chan error, buffer),
	}
	dial := func(ctx context.Context, metadata *C.Metadata, handshake mitm.NativeTLSHandshake) (net.Conn, error) {
		capture.nativeDial <- ctx
		wrappedHandshake := func(ctx context.Context, conn net.Conn) (net.Conn, error) {
			capture.handshake <- ctx
			secureConn, err := handshake(ctx, conn)
			capture.result <- err
			return secureConn, err
		}
		return Tunnel.DialTCPWithTLSHandshake(ctx, metadata, wrappedHandshake)
	}
	return capture, dial
}

type m1HTTPDispatchResult struct {
	outcome mitm.DispatchOutcome
	err     error
}

func startM1HTTPDispatch(t *testing.T, manager *mitm.Manager, roots *x509.CertPool, ctx context.Context, metadata *C.Metadata, dial mitm.NativeDialContext) (*tls.Conn, <-chan m1HTTPDispatchResult) {
	return startM1HTTPDispatchForServerName(t, manager, roots, ctx, metadata, dial, "localhost")
}

func startM1HTTPDispatchForServerName(t *testing.T, manager *mitm.Manager, roots *x509.CertPool, ctx context.Context, metadata *C.Metadata, dial mitm.NativeDialContext, serverName string) (*tls.Conn, <-chan m1HTTPDispatchResult) {
	t.Helper()
	serverRaw, clientRaw := net.Pipe()
	if dial == nil {
		dial = func(ctx context.Context, metadata *C.Metadata, handshake mitm.NativeTLSHandshake) (net.Conn, error) {
			return Tunnel.DialTCPWithTLSHandshake(ctx, metadata, handshake)
		}
	}
	dispatchDone := make(chan m1HTTPDispatchResult, 1)
	go func() {
		outcome, err := manager.Dispatch(ctx, N.NewBufferedConn(serverRaw), metadata, nil, dial)
		dispatchDone <- m1HTTPDispatchResult{outcome: outcome, err: err}
	}()
	client := tls.Client(clientRaw, &tls.Config{RootCAs: roots, ServerName: serverName, NextProtos: []string{"http/1.1"}})
	_ = client.SetDeadline(time.Now().Add(8 * time.Second))
	t.Cleanup(func() { _ = client.Close() })
	require.NoError(t, client.Handshake())
	return client, dispatchDone
}

type m1BlockingCloseConn struct {
	net.Conn
	closeStarted chan struct{}
	allowClose   chan struct{}
	closeCalls   atomic.Int32
}

type m1GateWriteConn struct {
	net.Conn
	writeStarted chan struct{}
	release      <-chan struct{}
	writeOnce    sync.Once
}

func (conn *m1GateWriteConn) Write(data []byte) (int, error) {
	conn.writeOnce.Do(func() {
		close(conn.writeStarted)
		<-conn.release
	})
	return conn.Conn.Write(data)
}

func (conn *m1BlockingCloseConn) Close() error {
	conn.closeCalls.Add(1)
	select {
	case conn.closeStarted <- struct{}{}:
	default:
	}
	<-conn.allowClose
	return conn.Conn.Close()
}

func loadTunnelTestCA(t *testing.T) (*mitm.CertificateAuthority, *x509.CertPool) {
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

func TestHandleTCPConnMITMIndependentOfSnifferAndPreservesFallbackBytes(t *testing.T) {
	t.Run("matching SNI is terminated with the global sniffer disabled", func(t *testing.T) {
		oldStatus, oldDispatcher, oldSniffing := Status(), snifferDispatcher, sniffingEnable
		t.Cleanup(func() {
			status.Store(oldStatus)
			snifferDispatcher, sniffingEnable = oldDispatcher, oldSniffing
			UpdateMITMManager(nil)
		})
		status.Store(Running)
		snifferDispatcher, sniffingEnable = nil, false
		ca, roots := loadTunnelTestCA(t)
		UpdateMITMManager(mitm.NewManager(mitm.Config{Enabled: true, Ports: []uint16{443}, Domains: []string{"localhost"}, CA: ca}))
		serverRaw, clientRaw := net.Pipe()
		serverConn := N.NewBufferedConn(serverRaw)
		metadata := &C.Metadata{NetWork: C.TCP, Type: C.TUNNEL, Host: "localhost", DstPort: 443}
		done := make(chan struct{})
		go func() {
			handleTCPConn(icontext.NewConnContext(serverConn, metadata))
			close(done)
		}()
		client := tls.Client(clientRaw, &tls.Config{RootCAs: roots, ServerName: "localhost", NextProtos: []string{"http/1.1"}})
		_ = client.SetDeadline(time.Now().Add(5 * time.Second))
		require.NoError(t, client.Handshake())
		require.Equal(t, "http/1.1", client.ConnectionState().NegotiatedProtocol)
		require.Equal(t, "localhost", metadata.Host)
		_ = client.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("MITM hook did not release a client that closed after TLS handshake")
		}
	})

	t.Run("unmatched SNI follows native relay with all peeked bytes", func(t *testing.T) {
		oldStatus, oldDispatcher, oldSniffing, oldMode, oldProxies := Status(), snifferDispatcher, sniffingEnable, mode, proxies
		t.Cleanup(func() {
			status.Store(oldStatus)
			snifferDispatcher, sniffingEnable = oldDispatcher, oldSniffing
			mode, proxies = oldMode, oldProxies
			UpdateMITMManager(nil)
		})
		status.Store(Running)
		snifferDispatcher, sniffingEnable = nil, false
		remoteSide, remotePeer := net.Pipe()
		defer remotePeer.Close()
		remote := &m1PlainNativeConn{ExtendedConn: N.NewExtendedConn(remoteSide)}
		proxy := &m1NativeProxy{name: "DIRECT", conn: remote}
		mode = Direct
		proxies = map[string]C.Proxy{"DIRECT": proxy}
		UpdateMITMManager(mitm.NewManager(mitm.Config{Enabled: true, Ports: []uint16{443}, Domains: []string{"allowed.example"}}))
		serverRaw, clientRaw := net.Pipe()
		serverConn := N.NewBufferedConn(serverRaw)
		metadata := &C.Metadata{NetWork: C.TCP, Type: C.TUNNEL, Host: "allowed.example", DstPort: 443}
		done := make(chan struct{})
		go func() {
			handleTCPConn(icontext.NewConnContext(serverConn, metadata))
			close(done)
		}()
		client := tls.Client(clientRaw, &tls.Config{ServerName: "other.example", NextProtos: []string{"http/1.1"}})
		_ = client.SetDeadline(time.Now().Add(5 * time.Second))
		clientHandshake := make(chan error, 1)
		go func() { clientHandshake <- client.Handshake() }()
		_ = remotePeer.SetReadDeadline(time.Now().Add(5 * time.Second))
		var recordHeader [5]byte
		_, err := io.ReadFull(remotePeer, recordHeader[:])
		require.NoError(t, err)
		require.Equal(t, byte(0x16), recordHeader[0], "native relay must start with the original TLS record")
		payload := make([]byte, int(binary.BigEndian.Uint16(recordHeader[3:])))
		_, err = io.ReadFull(remotePeer, payload)
		require.NoError(t, err)
		require.Contains(t, string(payload), "other.example", "the ClientHello SNI must survive the MITM inspection Peek")
		require.Equal(t, "allowed.example", metadata.Host, "SNI mismatch must not rewrite inbound Metadata")
		_ = client.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("native relay did not release after the client disconnected")
		}
		<-clientHandshake
	})
}

func TestHandleTCPConnMatchedMITMFailureDoesNotFallBack(t *testing.T) {
	oldStatus, oldDispatcher, oldSniffing, oldMode, oldProxies := Status(), snifferDispatcher, sniffingEnable, mode, proxies
	t.Cleanup(func() {
		status.Store(oldStatus)
		snifferDispatcher, sniffingEnable = oldDispatcher, oldSniffing
		mode, proxies = oldMode, oldProxies
		UpdateMITMManager(nil)
	})
	status.Store(Running)
	snifferDispatcher, sniffingEnable = nil, false
	native := &m1NativeProxy{name: "DIRECT"}
	mode = Direct
	proxies = map[string]C.Proxy{"DIRECT": native}
	UpdateMITMManager(mitm.NewManager(mitm.Config{Enabled: true, Ports: []uint16{443}, Domains: []string{"allowed.example"}}))

	serverRaw, clientRaw := net.Pipe()
	serverConn := N.NewBufferedConn(serverRaw)
	done := make(chan struct{})
	go func() {
		handleTCPConn(icontext.NewConnContext(serverConn, &C.Metadata{NetWork: C.TCP, Type: C.TUNNEL, Host: "allowed.example", DstPort: 443}))
		close(done)
	}()
	client := tls.Client(clientRaw, &tls.Config{ServerName: "allowed.example", NextProtos: []string{"http/1.1"}})
	handshake := make(chan error, 1)
	go func() { handshake <- client.Handshake() }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("matched MITM failure did not release the inbound connection")
	}
	require.Error(t, <-handshake)
	dials, _ := native.snapshot()
	require.Zero(t, dials, "a matched MITM failure must not continue into native TCP routing")
	_ = client.Close()
}

func TestHandleTCPConnMITMUsesNativeRuleDialAndCleansTracker(t *testing.T) {
	oldStatus, oldDispatcher, oldSniffing, oldMode, oldProxies, oldRules, oldSubRules := Status(), snifferDispatcher, sniffingEnable, mode, proxies, rules, subRules
	t.Cleanup(func() {
		status.Store(oldStatus)
		snifferDispatcher, sniffingEnable = oldDispatcher, oldSniffing
		mode, proxies, rules, subRules = oldMode, oldProxies, oldRules, oldSubRules
		UpdateMITMManager(nil)
	})
	status.Store(Running)
	snifferDispatcher, sniffingEnable = nil, false
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "local upstream")
	}))
	defer upstream.Close()
	mihomoCA.ResetCertificate()
	defer mihomoCA.ResetCertificate()
	upstreamLeaf := upstream.TLS.Certificates[0].Leaf
	if upstreamLeaf == nil {
		var err error
		upstreamLeaf, err = x509.ParseCertificate(upstream.TLS.Certificates[0].Certificate[0])
		require.NoError(t, err)
	}
	require.NoError(t, mihomoCA.AddCertificate(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstreamLeaf.Raw}))))
	_, err := upstreamLeaf.Verify(x509.VerifyOptions{Roots: mihomoCA.GetCertPool(), DNSName: "example.com"})
	require.NoError(t, err, "Mihomo's custom trust pool must accept the local upstream certificate for its configured name")
	upstreamAddress := upstream.Listener.Addr().String()
	firstUpstreamWrite := make(chan earlyWrite, 1)
	proxy := &m1NativeProxy{name: "MITM_TEST_PROXY", onDial: func(ctx context.Context) (C.Conn, error) {
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", upstreamAddress)
		if err != nil {
			return nil, err
		}
		return &m1EarlyNativeConn{
			m1PlainNativeConn: &m1PlainNativeConn{ExtendedConn: N.NewExtendedConn(conn)},
			host:              "example.com",
			writes:            firstUpstreamWrite,
		}, nil
	}}
	direct := &m1NativeProxy{name: "DIRECT"}
	mode = Rule
	proxies = map[string]C.Proxy{"MITM_TEST_PROXY": proxy, "DIRECT": direct}
	rules = []C.Rule{m1RouteRule{host: "example.com", adapter: "MITM_TEST_PROXY"}}
	subRules = nil

	ca, roots := loadTunnelTestCA(t)
	UpdateMITMManager(mitm.NewManager(mitm.Config{
		Enabled:           true,
		Ports:             []uint16{443},
		Domains:           []string{"example.com"},
		CA:                ca,
		HandshakeTimeout:  3 * time.Second,
		ReadHeaderTimeout: 3 * time.Second,
		RequestTimeout:    3 * time.Second,
		IdleTimeout:       3 * time.Second,
	}))
	serverRaw, clientRaw := net.Pipe()
	serverConn := N.NewBufferedConn(serverRaw)
	metadata := &C.Metadata{NetWork: C.TCP, Type: C.TUNNEL, Host: "example.com", DstPort: 443, SrcIP: netip.MustParseAddr("192.0.2.19"), SrcPort: 45678}
	done := make(chan struct{})
	go func() {
		handleTCPConn(icontext.NewConnContext(serverConn, metadata))
		close(done)
	}()
	client := tls.Client(clientRaw, &tls.Config{RootCAs: roots, ServerName: "example.com", NextProtos: []string{"http/1.1"}})
	_ = client.SetDeadline(time.Now().Add(8 * time.Second))
	require.NoError(t, client.Handshake())
	_, err = io.WriteString(client, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	require.NoError(t, err)
	response, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: http.MethodGet})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.StatusCode, "the local upstream certificate is trusted through Mihomo's existing custom trust pool")
	responseBody, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	require.Equal(t, "local upstream", string(responseBody))
	_ = response.Body.Close()
	select {
	case firstWrite := <-firstUpstreamWrite:
		require.GreaterOrEqual(t, len(firstWrite.data), 5)
		require.Equal(t, byte(0x16), firstWrite.data[0], "the first write on an EarlyConn must be the upstream TLS ClientHello")
		require.True(t, firstWrite.tracked, "the EarlyConn TLS ClientHello must pass through the initialized native tracker")
	case <-time.After(time.Second):
		t.Fatal("upstream TLS handshake did not write through the EarlyConn")
	}
	proxyCalls, proxyMetadata := proxy.snapshot()
	directCalls, _ := direct.snapshot()
	require.Equal(t, 1, proxyCalls, "the configured Mihomo rule must choose this native Proxy.DialContext")
	require.Zero(t, directCalls)
	require.Equal(t, "example.com", proxyMetadata.Host)
	_ = client.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("native-route MITM connection did not release")
	}
	trackerExists := false
	statistic.DefaultManager.Range(func(tracker statistic.Tracker) bool {
		trackerExists = trackerExists || (tracker.Info().Metadata.Host == "example.com" && tracker.Info().Metadata.SrcPort == 45678)
		return !trackerExists
	})
	require.False(t, trackerExists, "failed upstream TLS verification must close and unregister its native tracker")
}

func TestMITMHTTPTransportTLSHandshakeTimeoutClosesNativeSocketAndTracker(t *testing.T) {
	ca, roots := loadTunnelTestCA(t)
	upstream := newM1StalledTLSUpstream(t)
	proxy := &m1NativeProxy{name: "TLS_HANDSHAKE_TIMEOUT_PROXY", onDial: func(ctx context.Context) (C.Conn, error) {
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", upstream.listener.Addr().String())
		if err != nil {
			return nil, err
		}
		return &m1PlainNativeConn{ExtendedConn: N.NewExtendedConn(conn)}, nil
	}}
	metadata := configureM1DirectNativeProxy(t, proxy)
	manager := mitm.NewManager(mitm.Config{
		Enabled:           true,
		Ports:             []uint16{443},
		Domains:           []string{"localhost"},
		CA:                ca,
		HandshakeTimeout:  250 * time.Millisecond,
		ReadHeaderTimeout: 3 * time.Second,
		RequestTimeout:    4 * time.Second,
		IdleTimeout:       3 * time.Second,
	})
	client, dispatchDone := startM1HTTPDispatch(t, manager, roots, context.Background(), metadata, nil)
	started := time.Now()
	_, err := io.WriteString(client, "GET /timeout HTTP/1.1\r\nHost: localhost\r\n\r\n")
	require.NoError(t, err)
	upstream.waitForHello(t)
	response, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: http.MethodGet})
	require.NoError(t, err)
	require.Equal(t, http.StatusGatewayTimeout, response.StatusCode)
	require.Less(t, time.Since(started), 2*time.Second, "the shorter TLS handshake timeout must win over the HTTP request timeout")
	_, err = io.Copy(io.Discard, response.Body)
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())
	upstream.waitForClose(t)
	requireM1TrackerRemoved(t, metadata)
	_ = client.Close()
	select {
	case result := <-dispatchDone:
		require.Equal(t, mitm.DispatchIntercepted, result.outcome)
		require.NoError(t, result.err)
	case <-time.After(3 * time.Second):
		t.Fatal("HTTP server did not finish after the client closed")
	}
}

func TestMITMHTTPUpstreamTLSContextCancellationClosesNativeSocketAndTracker(t *testing.T) {
	ca, roots := loadTunnelTestCA(t)
	upstream := newM1StalledTLSUpstream(t)
	proxy := &m1NativeProxy{name: "TLS_HANDSHAKE_CANCEL_PROXY", onDial: func(ctx context.Context) (C.Conn, error) {
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", upstream.listener.Addr().String())
		if err != nil {
			return nil, err
		}
		return &m1PlainNativeConn{ExtendedConn: N.NewExtendedConn(conn)}, nil
	}}
	metadata := configureM1DirectNativeProxy(t, proxy)
	requestCtxReady := make(chan context.Context, 1)
	manager := mitm.NewManager(mitm.Config{
		Enabled:           true,
		Ports:             []uint16{443},
		Domains:           []string{"localhost"},
		CA:                ca,
		HandshakeTimeout:  5 * time.Second,
		ReadHeaderTimeout: 6 * time.Second,
		RequestTimeout:    7 * time.Second,
		IdleTimeout:       6 * time.Second,
		RequestHook: func(request *http.Request) error {
			requestCtxReady <- request.Context()
			return nil
		},
	})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	nativeDialCtxReady := make(chan context.Context, 1)
	handshakeCtxReady := make(chan context.Context, 1)
	handshakeDone := make(chan error, 1)
	dial := func(ctx context.Context, metadata *C.Metadata, handshake mitm.NativeTLSHandshake) (net.Conn, error) {
		nativeDialCtxReady <- ctx
		wrappedHandshake := func(ctx context.Context, conn net.Conn) (net.Conn, error) {
			handshakeCtxReady <- ctx
			secureConn, err := handshake(ctx, conn)
			handshakeDone <- err
			return secureConn, err
		}
		return Tunnel.DialTCPWithTLSHandshake(ctx, metadata, wrappedHandshake)
	}
	client, dispatchDone := startM1HTTPDispatch(t, manager, roots, ctx, metadata, dial)
	_, err := io.WriteString(client, "GET /cancel HTTP/1.1\r\nHost: localhost\r\n\r\n")
	require.NoError(t, err)
	upstream.waitForHello(t)
	var upstreamHandshakeCtx context.Context
	select {
	case upstreamHandshakeCtx = <-handshakeCtxReady:
	case <-time.After(3 * time.Second):
		t.Fatal("the native TLS handshake callback was not entered")
	}
	var nativeDialCtx context.Context
	select {
	case nativeDialCtx = <-nativeDialCtxReady:
	case <-time.After(3 * time.Second):
		t.Fatal("the native DialTLSContext callback was not entered")
	}
	var requestCtx context.Context
	select {
	case requestCtx = <-requestCtxReady:
	case <-time.After(3 * time.Second):
		t.Fatal("the HTTP request hook did not receive its Context")
	}
	cancel()
	select {
	case <-ctx.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("test cancellation was not delivered to its parent Context")
	}
	select {
	case <-requestCtx.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("HTTP request Context did not inherit Dispatcher cancellation")
	}
	select {
	case <-nativeDialCtx.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("external cancellation did not reach the HTTP Transport dial Context")
	}
	select {
	case <-upstreamHandshakeCtx.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("external cancellation did not reach the actual TLS handshake Context")
	}
	select {
	case err := <-handshakeDone:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(3 * time.Second):
		t.Fatal("TLS HandshakeContext did not return after external cancellation")
	}
	upstream.waitForClose(t)
	requireM1TrackerRemoved(t, metadata)
	select {
	case result := <-dispatchDone:
		require.Equal(t, mitm.DispatchFailed, result.outcome)
		require.ErrorIs(t, result.err, context.Canceled)
	case <-time.After(3 * time.Second):
		t.Fatal("external Context cancellation did not stop the HTTP/TLS lifecycle")
	}
	_ = client.Close()
}

func TestMITMHTTPTransportRequestCancellationClosesNativeSocketAndTracker(t *testing.T) {
	ca, roots := loadTunnelTestCA(t)
	upstream := newM1StalledTLSUpstream(t)
	proxy := &m1NativeProxy{name: "TLS_REQUEST_CANCEL_PROXY", onDial: func(ctx context.Context) (C.Conn, error) {
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", upstream.listener.Addr().String())
		if err != nil {
			return nil, err
		}
		return &m1PlainNativeConn{ExtendedConn: N.NewExtendedConn(conn)}, nil
	}}
	metadata := configureM1DirectNativeProxy(t, proxy)
	requestCtxReady := make(chan context.Context, 1)
	manager := mitm.NewManager(mitm.Config{
		Enabled:           true,
		Ports:             []uint16{443},
		Domains:           []string{"localhost"},
		CA:                ca,
		HandshakeTimeout:  5 * time.Second,
		ReadHeaderTimeout: 6 * time.Second,
		RequestTimeout:    7 * time.Second,
		IdleTimeout:       6 * time.Second,
		RequestHook: func(request *http.Request) error {
			requestCtxReady <- request.Context()
			return nil
		},
	})
	capture, dial := newM1HandshakeCapture()
	client, dispatchDone := startM1HTTPDispatch(t, manager, roots, context.Background(), metadata, dial)
	_, err := io.WriteString(client, "GET /client-cancel HTTP/1.1\r\nHost: localhost\r\n\r\n")
	require.NoError(t, err)
	upstream.waitForHello(t)

	var requestCtx, nativeDialCtx, handshakeCtx context.Context
	select {
	case requestCtx = <-requestCtxReady:
	case <-time.After(3 * time.Second):
		t.Fatal("the HTTP request hook did not receive the request Context")
	}
	select {
	case nativeDialCtx = <-capture.nativeDial:
	case <-time.After(3 * time.Second):
		t.Fatal("the real HTTP Transport did not invoke the native dial callback")
	}
	select {
	case handshakeCtx = <-capture.handshake:
	case <-time.After(3 * time.Second):
		t.Fatal("the native outbound TLS handshake did not start")
	}

	// Closing the downstream HTTP client cancels the server's per-request
	// Context while the upstream TLS server is still waiting for a handshake.
	require.NoError(t, client.Close())
	for name, ctx := range map[string]context.Context{
		"HTTP request":           requestCtx,
		"Transport dial":         nativeDialCtx,
		"upstream TLS handshake": handshakeCtx,
	} {
		select {
		case <-ctx.Done():
		case <-time.After(3 * time.Second):
			t.Fatalf("client request cancellation did not reach the %s Context", name)
		}
	}
	select {
	case err := <-capture.result:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(3 * time.Second):
		t.Fatal("TLS HandshakeContext did not stop after the client canceled its request")
	}
	upstream.waitForClose(t)
	requireM1TrackerRemoved(t, metadata)
	select {
	case result := <-dispatchDone:
		require.Equal(t, mitm.DispatchIntercepted, result.outcome)
		require.NoError(t, result.err)
	case <-time.After(3 * time.Second):
		t.Fatal("request cancellation left the MITM HTTP server running")
	}
}

func TestMITMHTTPTransportKeepAliveRequestsUseTheirOwnContexts(t *testing.T) {
	ca, roots := loadTunnelTestCA(t)
	var upstreamRequests atomic.Int32
	firstUpstreamClosed := make(chan struct{}, 1)
	firstUpstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamRequests.Add(1)
		_, _ = io.WriteString(w, "ok")
	}))
	firstUpstream.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateClosed {
			select {
			case firstUpstreamClosed <- struct{}{}:
			default:
			}
		}
	}
	firstUpstream.StartTLS()
	t.Cleanup(firstUpstream.Close)
	firstCertificate := firstUpstream.TLS.Certificates[0].Certificate[0]
	mihomoCA.ResetCertificate()
	require.NoError(t, mihomoCA.AddCertificate(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: firstCertificate}))))
	t.Cleanup(mihomoCA.ResetCertificate)
	stalledUpstream := newM1StalledTLSUpstream(t)
	var dials atomic.Int32
	proxy := &m1NativeProxy{name: "TLS_KEEPALIVE_CONTEXT_PROXY", onDial: func(ctx context.Context) (C.Conn, error) {
		address := firstUpstream.Listener.Addr().String()
		if dials.Add(1) == 2 {
			address = stalledUpstream.listener.Addr().String()
		}
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
		if err != nil {
			return nil, err
		}
		return &m1PlainNativeConn{ExtendedConn: N.NewExtendedConn(conn)}, nil
	}}
	metadata := configureM1DirectNativeProxy(t, proxy)
	metadata.Host = "example.com"
	requestContexts := make(chan context.Context, 2)
	manager := mitm.NewManager(mitm.Config{
		Enabled:           true,
		Ports:             []uint16{443},
		Domains:           []string{"example.com"},
		CA:                ca,
		HandshakeTimeout:  5 * time.Second,
		ReadHeaderTimeout: 6 * time.Second,
		RequestTimeout:    7 * time.Second,
		IdleTimeout:       6 * time.Second,
		RequestHook: func(request *http.Request) error {
			requestContexts <- request.Context()
			return nil
		},
	})
	capture, dial := newM1HandshakeCaptureWithBuffer(2)
	client, dispatchDone := startM1HTTPDispatchForServerName(t, manager, roots, context.Background(), metadata, dial, "example.com")
	reader := bufio.NewReader(client)
	_, err := io.WriteString(client, "GET /first HTTP/1.1\r\nHost: example.com\r\n\r\n")
	require.NoError(t, err)
	firstResponse, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, firstResponse.StatusCode)
	firstBody, err := io.ReadAll(firstResponse.Body)
	require.NoError(t, err)
	require.Equal(t, "ok", string(firstBody))
	require.NoError(t, firstResponse.Body.Close())
	require.EqualValues(t, 1, upstreamRequests.Load())

	var firstRequestCtx, firstDialCtx, firstHandshakeCtx context.Context
	select {
	case firstRequestCtx = <-requestContexts:
	case <-time.After(3 * time.Second):
		t.Fatal("the first HTTP request Context was not observed")
	}
	select {
	case firstDialCtx = <-capture.nativeDial:
	case <-time.After(3 * time.Second):
		t.Fatal("the first request did not use the HTTP Transport dial callback")
	}
	select {
	case firstHandshakeCtx = <-capture.handshake:
	case <-time.After(3 * time.Second):
		t.Fatal("the first native TLS handshake was not observed")
	}
	select {
	case err := <-capture.result:
		require.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("the first upstream TLS handshake did not finish")
	}
	select {
	case <-firstRequestCtx.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("the completed first request Context was not canceled")
	}
	require.ErrorIs(t, firstDialCtx.Err(), context.Canceled)
	require.ErrorIs(t, firstHandshakeCtx.Err(), context.Canceled)
	select {
	case <-firstUpstreamClosed:
	case <-time.After(3 * time.Second):
		t.Fatal("the first upstream connection did not close after its response completed")
	}
	requireM1TrackerRemoved(t, metadata)

	// The same inbound HTTP/1.1 TLS connection remains open. Its second request
	// must start with a fresh live Context, not inherit the completed first one.
	_, err = io.WriteString(client, "GET /second HTTP/1.1\r\nHost: example.com\r\n\r\n")
	require.NoError(t, err)
	stalledUpstream.waitForHello(t)
	var secondRequestCtx, secondDialCtx, secondHandshakeCtx context.Context
	select {
	case secondRequestCtx = <-requestContexts:
	case <-time.After(3 * time.Second):
		t.Fatal("the second HTTP request Context was not observed")
	}
	select {
	case secondDialCtx = <-capture.nativeDial:
	case <-time.After(3 * time.Second):
		t.Fatal("the second request did not use the HTTP Transport dial callback")
	}
	select {
	case secondHandshakeCtx = <-capture.handshake:
	case <-time.After(3 * time.Second):
		t.Fatal("the second native TLS handshake was not observed")
	}
	require.NotEqual(t, firstRequestCtx, secondRequestCtx, "HTTP keep-alive requests must have distinct request Contexts")
	require.ErrorIs(t, firstRequestCtx.Err(), context.Canceled)
	require.NoError(t, secondRequestCtx.Err())
	require.NoError(t, secondDialCtx.Err())
	require.NoError(t, secondHandshakeCtx.Err())
	require.EqualValues(t, 2, dials.Load(), "each request must create a separate upstream TLS connection")
	requireM1TrackerPresent(t, metadata)

	require.NoError(t, client.Close())
	for name, ctx := range map[string]context.Context{
		"second HTTP request":   secondRequestCtx,
		"second Transport dial": secondDialCtx,
		"second TLS handshake":  secondHandshakeCtx,
	} {
		select {
		case <-ctx.Done():
		case <-time.After(3 * time.Second):
			t.Fatalf("client close did not cancel the %s Context", name)
		}
	}
	select {
	case err := <-capture.result:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(3 * time.Second):
		t.Fatal("the second upstream TLS handshake did not stop after cancellation")
	}
	stalledUpstream.waitForClose(t)
	requireM1TrackerRemoved(t, metadata)
	select {
	case result := <-dispatchDone:
		require.Equal(t, mitm.DispatchIntercepted, result.outcome)
		require.NoError(t, result.err)
	case <-time.After(3 * time.Second):
		t.Fatal("the Keep-Alive HTTP connection did not finish after cancellation")
	}
}

func TestMITMHTTPTransportConcurrentRequestCancellationDoesNotMixContexts(t *testing.T) {
	ca, roots := loadTunnelTestCA(t)
	upstreamOne := newM1StalledTLSUpstream(t)
	upstreamTwo := newM1StalledTLSUpstream(t)
	addresses := make(map[uint16]string)
	proxy := &m1NativeProxy{name: "TLS_CONCURRENT_CONTEXT_PROXY"}
	proxy.onDialMetadata = func(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
		address, ok := addresses[metadata.SrcPort]
		if !ok {
			return nil, fmt.Errorf("missing test upstream for source port %d", metadata.SrcPort)
		}
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
		if err != nil {
			return nil, err
		}
		return &m1PlainNativeConn{ExtendedConn: N.NewExtendedConn(conn)}, nil
	}
	metadataOne := configureM1DirectNativeProxy(t, proxy)
	metadataTwo := metadataOne.Clone()
	metadataTwo.SrcPort++
	addresses[metadataOne.SrcPort] = upstreamOne.listener.Addr().String()
	addresses[metadataTwo.SrcPort] = upstreamTwo.listener.Addr().String()
	requestContexts := make(chan struct {
		path string
		ctx  context.Context
	}, 2)
	manager := mitm.NewManager(mitm.Config{
		Enabled:           true,
		Ports:             []uint16{443},
		Domains:           []string{"localhost"},
		CA:                ca,
		HandshakeTimeout:  5 * time.Second,
		ReadHeaderTimeout: 6 * time.Second,
		RequestTimeout:    7 * time.Second,
		IdleTimeout:       6 * time.Second,
		RequestHook: func(request *http.Request) error {
			requestContexts <- struct {
				path string
				ctx  context.Context
			}{path: request.URL.Path, ctx: request.Context()}
			return nil
		},
	})
	captureOne, dialOne := newM1HandshakeCapture()
	clientOne, dispatchOne := startM1HTTPDispatch(t, manager, roots, context.Background(), metadataOne, dialOne)
	_, err := io.WriteString(clientOne, "GET /one HTTP/1.1\r\nHost: localhost\r\n\r\n")
	require.NoError(t, err)
	upstreamOne.waitForHello(t)
	requestOne := <-requestContexts
	require.Equal(t, "/one", requestOne.path)
	dialCtxOne := <-captureOne.nativeDial
	handshakeCtxOne := <-captureOne.handshake

	captureTwo, dialTwo := newM1HandshakeCapture()
	clientTwo, dispatchTwo := startM1HTTPDispatch(t, manager, roots, context.Background(), metadataTwo, dialTwo)
	_, err = io.WriteString(clientTwo, "GET /two HTTP/1.1\r\nHost: localhost\r\n\r\n")
	require.NoError(t, err)
	upstreamTwo.waitForHello(t)
	requestTwo := <-requestContexts
	require.Equal(t, "/two", requestTwo.path)
	dialCtxTwo := <-captureTwo.nativeDial
	handshakeCtxTwo := <-captureTwo.handshake
	require.NotEqual(t, requestOne.ctx, requestTwo.ctx, "concurrent clients must have separate server request Contexts")
	require.NoError(t, requestTwo.ctx.Err())
	require.NoError(t, dialCtxTwo.Err())
	require.NoError(t, handshakeCtxTwo.Err())

	// Cancel the first request while the second remains stalled in its own TLS
	// handshake. The second request and Tracker must remain live until it is
	// independently canceled.
	require.NoError(t, clientOne.Close())
	for name, ctx := range map[string]context.Context{
		"first HTTP request":   requestOne.ctx,
		"first Transport dial": dialCtxOne,
		"first TLS handshake":  handshakeCtxOne,
	} {
		select {
		case <-ctx.Done():
		case <-time.After(3 * time.Second):
			t.Fatalf("first client cancellation did not reach the %s Context", name)
		}
	}
	select {
	case err := <-captureOne.result:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(3 * time.Second):
		t.Fatal("the first upstream TLS handshake did not stop")
	}
	upstreamOne.waitForClose(t)
	requireM1TrackerRemoved(t, metadataOne)
	requireM1TrackerPresent(t, metadataTwo)
	require.NoError(t, requestTwo.ctx.Err(), "canceling the first client must not cancel the second request")
	require.NoError(t, dialCtxTwo.Err())
	require.NoError(t, handshakeCtxTwo.Err())

	require.NoError(t, clientTwo.Close())
	for name, ctx := range map[string]context.Context{
		"second HTTP request":   requestTwo.ctx,
		"second Transport dial": dialCtxTwo,
		"second TLS handshake":  handshakeCtxTwo,
	} {
		select {
		case <-ctx.Done():
		case <-time.After(3 * time.Second):
			t.Fatalf("second client cancellation did not reach the %s Context", name)
		}
	}
	select {
	case err := <-captureTwo.result:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(3 * time.Second):
		t.Fatal("the second upstream TLS handshake did not stop")
	}
	upstreamTwo.waitForClose(t)
	requireM1TrackerRemoved(t, metadataTwo)
	for name, done := range map[string]<-chan m1HTTPDispatchResult{"first": dispatchOne, "second": dispatchTwo} {
		select {
		case result := <-done:
			require.Equal(t, mitm.DispatchIntercepted, result.outcome, "%s dispatcher outcome", name)
			require.NoError(t, result.err, "%s dispatcher error", name)
		case <-time.After(3 * time.Second):
			t.Fatalf("%s canceled HTTP connection left its dispatcher running", name)
		}
	}
}

func TestMITMHTTPTransportDeadlineCancellationAndHandshakeCompletionRace(t *testing.T) {
	ca, roots := loadTunnelTestCA(t)
	probe := httptest.NewTLSServer(http.NotFoundHandler())
	upstreamCertificate := probe.TLS.Certificates[0]
	probeTransport := probe.Client().Transport.(*http.Transport)
	upstreamRoots := probeTransport.TLSClientConfig.RootCAs.Clone()
	probe.Close()
	require.NotNil(t, upstreamRoots)
	mihomoCA.ResetCertificate()
	require.NoError(t, mihomoCA.AddCertificate(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstreamCertificate.Certificate[0]}))))
	t.Cleanup(mihomoCA.ResetCertificate)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	writeStarted := make(chan struct{})
	releaseWrite := make(chan struct{})
	var releaseWriteOnce sync.Once
	release := func() { releaseWriteOnce.Do(func() { close(releaseWrite) }) }
	t.Cleanup(release)
	serverHandshake := make(chan error, 1)
	serverFinished := make(chan struct{})
	var peerMu sync.Mutex
	var peer net.Conn
	go func() {
		defer close(serverFinished)
		raw, err := listener.Accept()
		if err != nil {
			return
		}
		peerMu.Lock()
		peer = raw
		peerMu.Unlock()
		gated := &m1GateWriteConn{Conn: raw, writeStarted: writeStarted, release: releaseWrite}
		secure := tls.Server(gated, &tls.Config{Certificates: []tls.Certificate{upstreamCertificate}})
		handshakeErr := secure.Handshake()
		serverHandshake <- handshakeErr
		if handshakeErr == nil {
			request, err := http.ReadRequest(bufio.NewReader(secure))
			if err == nil {
				_, _ = io.Copy(io.Discard, request.Body)
				_ = request.Body.Close()
				_, _ = io.WriteString(secure, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
			}
		}
		_ = secure.Close()
	}()
	t.Cleanup(func() {
		release()
		_ = listener.Close()
		peerMu.Lock()
		if peer != nil {
			_ = peer.Close()
		}
		peerMu.Unlock()
		select {
		case <-serverFinished:
		case <-time.After(3 * time.Second):
			t.Errorf("racing local TLS server goroutine did not exit")
		}
	})

	proxy := &m1NativeProxy{name: "TLS_TIMEOUT_CANCEL_HANDSHAKE_RACE_PROXY", onDial: func(ctx context.Context) (C.Conn, error) {
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
		if err != nil {
			return nil, err
		}
		return &m1PlainNativeConn{ExtendedConn: N.NewExtendedConn(conn)}, nil
	}}
	metadata := configureM1DirectNativeProxy(t, proxy)
	metadata.Host = "example.com"
	manager := mitm.NewManager(mitm.Config{
		Enabled:           true,
		Ports:             []uint16{443},
		Domains:           []string{"example.com"},
		CA:                ca,
		HandshakeTimeout:  250 * time.Millisecond,
		ReadHeaderTimeout: time.Second,
		RequestTimeout:    2 * time.Second,
		IdleTimeout:       time.Second,
	})
	capture, dial := newM1HandshakeCapture()
	client, dispatchDone := startM1HTTPDispatchForServerName(t, manager, roots, context.Background(), metadata, dial, "example.com")
	_, err = io.WriteString(client, "GET /race HTTP/1.1\r\nHost: example.com\r\n\r\n")
	require.NoError(t, err)
	var handshakeCtx context.Context
	select {
	case handshakeCtx = <-capture.handshake:
	case <-time.After(3 * time.Second):
		t.Fatal("the HTTP Transport did not reach the native TLS handshake")
	}
	select {
	case <-writeStarted:
	case <-time.After(3 * time.Second):
		t.Fatal("the upstream TLS server did not reach its handshake response")
	}
	requireM1TrackerPresent(t, metadata)
	deadline, ok := handshakeCtx.Deadline()
	require.True(t, ok, "upstream TLS handshake must have a deadline")

	// Release the upstream ServerHello and close the HTTP client at the
	// handshake deadline. The TLS handshake timeout fires at the same boundary.
	racingStart := make(chan struct{})
	deadlineTimer := time.AfterFunc(time.Until(deadline), func() { close(racingStart) })
	t.Cleanup(func() { deadlineTimer.Stop() })
	clientClosed := make(chan error, 1)
	go func() {
		<-racingStart
		clientClosed <- client.Close()
	}()
	go func() {
		<-racingStart
		release()
	}()
	select {
	case <-racingStart:
	case <-time.After(3 * time.Second):
		t.Fatal("the handshake deadline did not trigger the race barrier")
	}
	select {
	case <-clientClosed:
	case <-time.After(3 * time.Second):
		t.Fatal("closing the HTTP client deadlocked against TLS completion")
	}
	select {
	case <-capture.result:
	case <-time.After(3 * time.Second):
		t.Fatal("TLS handshake did not return after timeout/cancel/completion race")
	}
	select {
	case <-serverHandshake:
	case <-time.After(3 * time.Second):
		t.Fatal("upstream TLS server handshake did not return")
	}
	select {
	case <-serverFinished:
	case <-time.After(3 * time.Second):
		t.Fatal("upstream TLS server goroutine did not exit")
	}
	select {
	case result := <-dispatchDone:
		require.Equal(t, mitm.DispatchIntercepted, result.outcome)
		require.NoError(t, result.err)
	case <-time.After(3 * time.Second):
		t.Fatal("the MITM Dispatcher deadlocked after timeout/cancel/handshake race")
	}
	requireM1TrackerRemoved(t, metadata)
}

func TestMITMDialEarlyTLSWriteFailureRetriesWithFreshLocalSocket(t *testing.T) {
	probe := httptest.NewTLSServer(http.NotFoundHandler())
	certificate := probe.TLS.Certificates[0]
	probeTransport := probe.Client().Transport.(*http.Transport)
	roots := probeTransport.TLSClientConfig.RootCAs.Clone()
	probe.Close()
	require.NotNil(t, roots)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	firstHello := make(chan []byte, 1)
	firstRemote := make(chan string, 1)
	firstHandshakeDone := make(chan error, 1)
	secondRemote := make(chan string, 1)
	serverDone := make(chan error, 1)
	serverFinished := make(chan struct{})
	t.Cleanup(func() {
		_ = listener.Close()
		select {
		case <-serverFinished:
		case <-time.After(3 * time.Second):
			t.Errorf("local TLS retry server goroutine did not exit")
		}
	})
	go func() {
		defer close(serverFinished)
		firstRaw, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		firstRemote <- firstRaw.RemoteAddr().String()
		firstConn := N.NewBufferedConn(firstRaw)
		firstRecord, err := firstConn.Peek(5)
		if err != nil {
			_ = firstRaw.Close()
			serverDone <- err
			return
		}
		firstHello <- append([]byte(nil), firstRecord...)
		firstTLS := tls.Server(firstConn, &tls.Config{Certificates: []tls.Certificate{certificate}})
		firstErr := firstTLS.Handshake()
		firstHandshakeDone <- firstErr
		_ = firstTLS.Close()

		secondRaw, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		secondRemote <- secondRaw.RemoteAddr().String()
		secondTLS := tls.Server(secondRaw, &tls.Config{Certificates: []tls.Certificate{certificate}})
		if err := secondTLS.Handshake(); err != nil {
			_ = secondTLS.Close()
			serverDone <- err
			return
		}
		request, err := http.ReadRequest(bufio.NewReader(secondTLS))
		if err != nil {
			_ = secondTLS.Close()
			serverDone <- err
			return
		}
		_, _ = io.Copy(io.Discard, request.Body)
		_ = request.Body.Close()
		_, err = io.WriteString(secondTLS, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
		_ = secondTLS.Close()
		serverDone <- err
	}()

	firstWrite := make(chan []byte, 1)
	secondWrite := make(chan earlyWrite, 1)
	var dialNumber atomic.Int32
	proxy := &m1NativeProxy{name: "EARLY_TLS_SOCKET_RETRY_PROXY", onDial: func(ctx context.Context) (C.Conn, error) {
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
		if err != nil {
			return nil, err
		}
		switch dialNumber.Add(1) {
		case 1:
			return &m1EarlyFirstWriteErrorConn{
				m1PlainNativeConn: &m1PlainNativeConn{ExtendedConn: N.NewExtendedConn(conn)},
				writes:            firstWrite,
			}, nil
		default:
			return &m1EarlyNativeConn{
				m1PlainNativeConn: &m1PlainNativeConn{ExtendedConn: N.NewExtendedConn(conn)},
				host:              "localhost",
				writes:            secondWrite,
			}, nil
		}
	}}
	metadata := configureM1DirectNativeProxy(t, proxy)
	handshake := func(ctx context.Context, conn net.Conn) (net.Conn, error) {
		tlsConn := tls.Client(conn, &tls.Config{ServerName: "example.com", RootCAs: roots, MinVersion: tls.VersionTLS12})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		return tlsConn, nil
	}
	conn, err := Tunnel.DialTCPWithTLSHandshake(context.Background(), metadata, handshake)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	require.EqualValues(t, 2, dialNumber.Load(), "the retry must open a second TCP socket")
	select {
	case hello := <-firstWrite:
		require.GreaterOrEqual(t, len(hello), 5)
		require.Equal(t, byte(0x16), hello[0], "the failed EarlyConn write must contain a TLS ClientHello record")
	case <-time.After(3 * time.Second):
		t.Fatal("the first real TCP connection did not receive a ClientHello write")
	}
	select {
	case first := <-firstHello:
		require.Equal(t, byte(0x16), first[0])
	case <-time.After(3 * time.Second):
		t.Fatal("the first local TLS server did not receive the failed ClientHello")
	}
	select {
	case err := <-firstHandshakeDone:
		require.Error(t, err, "the failed first TLS connection must not complete a handshake")
	case <-time.After(3 * time.Second):
		t.Fatal("the first TLS server handshake did not observe the failed socket")
	}
	select {
	case write := <-secondWrite:
		require.GreaterOrEqual(t, len(write.data), 5)
		require.Equal(t, byte(0x16), write.data[0])
		require.True(t, write.tracked, "the retried ClientHello must pass through its initialized Tracker")
	case <-time.After(3 * time.Second):
		t.Fatal("the retry did not send its ClientHello over the new EarlyConn")
	}
	select {
	case remote := <-secondRemote:
		// The server sees a different ephemeral source port after retrying.
		first := <-firstRemote
		proxyCalls, _ := proxy.snapshot()
		require.Equal(t, 2, proxyCalls)
		require.NotEmpty(t, remote)
		require.NotEqual(t, first, remote, "the retry must use a fresh TCP socket")
	case <-time.After(3 * time.Second):
		t.Fatal("the retry did not establish a second TCP connection")
	}
	_, err = io.WriteString(conn, "GET /retry HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
	require.NoError(t, err)
	response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.StatusCode)
	responseBody, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	require.Equal(t, "ok", string(responseBody))
	require.NoError(t, response.Body.Close())
	select {
	case err := <-serverDone:
		require.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("the second local TLS server connection did not finish")
	}
	require.NoError(t, conn.Close())
	requireM1TrackerRemoved(t, metadata)
}

func TestMITMDialEarlyTLSRetryCancellationDoesNotRedial(t *testing.T) {
	upstream := newM1StalledTLSUpstream(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	writes := make(chan []byte, 1)
	var dials atomic.Int32
	proxy := &m1NativeProxy{name: "EARLY_TLS_RETRY_CANCEL_PROXY", onDial: func(ctx context.Context) (C.Conn, error) {
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", upstream.listener.Addr().String())
		if err != nil {
			return nil, err
		}
		dials.Add(1)
		return &m1EarlyFirstWriteErrorConn{
			m1PlainNativeConn: &m1PlainNativeConn{ExtendedConn: N.NewExtendedConn(conn)},
			writes:            writes,
			afterWrite:        cancel,
		}, nil
	}}
	metadata := configureM1DirectNativeProxy(t, proxy)
	_, err := Tunnel.DialTCPWithTLSHandshake(ctx, metadata, func(ctx context.Context, conn net.Conn) (net.Conn, error) {
		tlsConn := tls.Client(conn, &tls.Config{ServerName: "localhost"})
		return nil, tlsConn.HandshakeContext(ctx)
	})
	require.ErrorIs(t, err, context.Canceled)
	select {
	case hello := <-writes:
		require.GreaterOrEqual(t, len(hello), 5)
		require.Equal(t, byte(0x16), hello[0])
	case <-time.After(3 * time.Second):
		t.Fatal("the canceled retry did not attempt its first TLS ClientHello write")
	}
	upstream.waitForHello(t)
	upstream.waitForClose(t)
	require.EqualValues(t, 1, dials.Load(), "a canceled retry must not start another native dial")
	requireM1TrackerRemoved(t, metadata)
}

func TestMITMDialTLSHandshakeCloseAndCancellationRaceReleasesTracker(t *testing.T) {
	upstream := newM1StalledTLSUpstream(t)
	blockingClose := &m1BlockingCloseConn{closeStarted: make(chan struct{}, 4), allowClose: make(chan struct{})}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(blockingClose.allowClose) }) }
	t.Cleanup(release)
	proxy := &m1NativeProxy{name: "TLS_CLOSE_CANCEL_RACE_PROXY", onDial: func(ctx context.Context) (C.Conn, error) {
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", upstream.listener.Addr().String())
		if err != nil {
			return nil, err
		}
		blockingClose.Conn = conn
		return &m1PlainNativeConn{ExtendedConn: N.NewExtendedConn(blockingClose)}, nil
	}}
	metadata := configureM1DirectNativeProxy(t, proxy)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	trackedConnReady := make(chan net.Conn, 1)
	handshakeReturned := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		_, err := Tunnel.DialTCPWithTLSHandshake(ctx, metadata, func(ctx context.Context, conn net.Conn) (net.Conn, error) {
			trackedConnReady <- conn
			tlsConn := tls.Client(conn, &tls.Config{ServerName: "localhost"})
			err := tlsConn.HandshakeContext(ctx)
			close(handshakeReturned)
			return nil, err
		})
		result <- err
	}()
	var trackedConn net.Conn
	select {
	case trackedConn = <-trackedConnReady:
	case <-time.After(3 * time.Second):
		t.Fatal("native dial did not enter the upstream TLS handshake")
	}
	upstream.waitForHello(t)
	start := make(chan struct{})
	closeResult := make(chan error, 1)
	go func() {
		<-start
		closeResult <- trackedConn.Close()
	}()
	close(start)
	select {
	case <-blockingClose.closeStarted:
	case <-time.After(3 * time.Second):
		t.Fatal("explicit close did not reach the local TCP socket")
	}
	// Cancel while the first real socket Close is still in progress. TLS
	// cancellation and Tunnel's cleanup may both call Tracker.Close here.
	cancel()
	release()
	select {
	case err := <-closeResult:
		require.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("concurrent connection close deadlocked")
	}
	select {
	case <-handshakeReturned:
	case <-time.After(3 * time.Second):
		t.Fatal("Context cancellation did not release the TLS handshake")
	}
	select {
	case err := <-result:
		require.Error(t, err, "the interrupted TLS handshake must return an error")
	case <-time.After(3 * time.Second):
		t.Fatal("TLS handshake and context cancellation deadlocked")
	}
	upstream.waitForClose(t)
	require.Equal(t, int32(1), blockingClose.closeCalls.Load(), "concurrent Tracker.Close calls must close the native socket only once")
	requireM1TrackerRemoved(t, metadata)
}

func TestSnapshotMITMMetadataSkipsDisabledClone(t *testing.T) {
	metadata := &C.Metadata{NetWork: C.TCP, Type: C.TUNNEL, Host: "disabled.example", DstPort: 443}
	disabled := mitm.NewManager(mitm.Config{Enabled: false, Ports: []uint16{443}})
	for name, manager := range map[string]*mitm.Manager{"nil manager": nil, "disabled manager": disabled} {
		t.Run(name, func(t *testing.T) {
			var snapshot *C.Metadata
			var inspect bool
			allocs := testing.AllocsPerRun(100, func() {
				snapshot, inspect = snapshotMITMMetadata(manager, metadata)
			})
			require.Zero(t, allocs, "disabled MITM must not allocate a Metadata clone")
			require.Nil(t, snapshot)
			require.False(t, inspect)
		})
	}

	enabled := mitm.NewManager(mitm.Config{Enabled: true, Ports: []uint16{443}})
	snapshot, inspect := snapshotMITMMetadata(enabled, metadata)
	require.True(t, inspect)
	require.NotNil(t, snapshot)
	require.NotSame(t, metadata, snapshot)
}

//go:noinline
func benchmarkMITMDisabledPointerGate() bool {
	manager := mitmDispatcher.Load()
	_, inspect := snapshotMITMMetadata(manager, &C.Metadata{DstPort: 443})
	return inspect
}

func BenchmarkMITMDisabledPointerGate(b *testing.B) {
	oldManager := mitmDispatcher.Load()
	UpdateMITMManager(nil)
	defer UpdateMITMManager(oldManager)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if benchmarkMITMDisabledPointerGate() {
			b.Fatal("MITM must remain disabled in this benchmark")
		}
	}
}
