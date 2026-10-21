package tunnel

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/component/trie"
	C "github.com/metacubex/mihomo/constant"
	icontext "github.com/metacubex/mihomo/context"
	"github.com/metacubex/mihomo/tunnel/statistic"
	"github.com/stretchr/testify/require"
)

type testHostMapper struct {
	mapping     bool
	fakeIPRange netip.Prefix
	fakeIPs     map[netip.Addr]bool
	hosts       map[netip.Addr]string
}

func (m *testHostMapper) FakeIPEnabled() bool              { return true }
func (m *testHostMapper) MappingEnabled() bool             { return m.mapping }
func (m *testHostMapper) IsFakeIP(ip netip.Addr) bool      { return m.fakeIPRange.Contains(ip) }
func (*testHostMapper) IsFakeBroadcastIP(netip.Addr) bool  { return false }
func (m *testHostMapper) IsExistFakeIP(ip netip.Addr) bool { return m.fakeIPs[ip] }
func (m *testHostMapper) FindHostByIP(ip netip.Addr) (string, bool) {
	host, ok := m.hosts[ip]
	return host, ok
}
func (*testHostMapper) FlushFakeIP() error                { return nil }
func (*testHostMapper) InsertHostByIP(netip.Addr, string) {}
func (*testHostMapper) StoreFakePoolState()               {}

func TestPreHandleMetadataNormalAndFakeIPCases(t *testing.T) {
	oldMapper, oldHosts := resolver.DefaultHostMapper, resolver.DefaultHosts
	t.Cleanup(func() {
		resolver.DefaultHostMapper = oldMapper
		resolver.DefaultHosts = oldHosts
	})
	resolver.DefaultHosts = resolver.NewHosts(trie.New[resolver.HostValue]())

	fakeIP := netip.MustParseAddr("198.18.0.7")
	realIP := netip.MustParseAddr("203.0.113.7")
	mapper := &testHostMapper{
		mapping:     true,
		fakeIPRange: netip.MustParsePrefix("198.18.0.1/16"),
		fakeIPs:     map[netip.Addr]bool{fakeIP: true},
		hosts: map[netip.Addr]string{
			fakeIP: "mapped.example",
			realIP: "redir.example",
		},
	}
	resolver.DefaultHostMapper = mapper

	t.Run("normal domain", func(t *testing.T) {
		metadata := &C.Metadata{Host: "origin.example"}
		require.NoError(t, preHandleMetadata(metadata))
		require.Equal(t, "origin.example", metadata.Host)
	})

	t.Run("normal target IP with mapping enabled", func(t *testing.T) {
		metadata := &C.Metadata{DstIP: realIP}
		require.NoError(t, preHandleMetadata(metadata))
		require.Equal(t, "redir.example", metadata.Host)
		require.Equal(t, realIP, metadata.DstIP)
		require.Equal(t, C.DNSMapping, metadata.DNSMode)
	})

	t.Run("Fake-IP mapping exists", func(t *testing.T) {
		metadata := &C.Metadata{DstIP: fakeIP}
		require.NoError(t, preHandleMetadata(metadata))
		require.Equal(t, "mapped.example", metadata.Host)
		require.False(t, metadata.DstIP.IsValid(), "mapped Fake-IP must not be dialed as a real destination")
		require.Equal(t, C.DNSFakeIP, metadata.DNSMode)
	})

	t.Run("Fake-IP mapping missing returns the native error", func(t *testing.T) {
		missingIP := netip.MustParseAddr("198.18.0.8")
		metadata := &C.Metadata{DstIP: missingIP}
		err := preHandleMetadata(metadata)
		require.ErrorContains(t, err, "fake DNS record")
		require.True(t, metadata.Valid(), "pre-handle failure does not make valid input invalid")
	})

	t.Run("mapping disabled leaves normal IP unchanged", func(t *testing.T) {
		mapper.mapping = false
		metadata := &C.Metadata{DstIP: netip.MustParseAddr("192.0.2.1")}
		require.NoError(t, preHandleMetadata(metadata))
		require.Equal(t, netip.MustParseAddr("192.0.2.1"), metadata.DstIP)
		require.Empty(t, metadata.Host)
	})
}

type selectionOnlyProxy struct{ C.Proxy }

func TestResolveMetadataCanBeReusedWithoutReenteringTunnel(t *testing.T) {
	oldMode, oldProxies := mode, proxies
	t.Cleanup(func() {
		mode, proxies = oldMode, oldProxies
	})
	proxy := &selectionOnlyProxy{}
	mode = Direct
	proxies = map[string]C.Proxy{"DIRECT": proxy}

	metadata := &C.Metadata{Host: "origin.example", Type: C.TUNNEL}
	selected, rule, err := resolveMetadata(metadata)
	require.NoError(t, err)
	require.Same(t, proxy, selected)
	require.Nil(t, rule)

	metadata.SpecialProxy = "missing"
	selected, _, err = resolveMetadata(metadata)
	require.ErrorContains(t, err, "proxy missing not found")
	require.Nil(t, selected)
}

func TestResolveMetadataAppliesDefaultHostResolution(t *testing.T) {
	oldMode, oldProxies, oldHosts := mode, proxies, resolver.DefaultHosts
	t.Cleanup(func() {
		mode, proxies = oldMode, oldProxies
		resolver.DefaultHosts = oldHosts
	})
	tree := trie.New[resolver.HostValue]()
	value, err := resolver.NewHostValue([]string{"192.0.2.15"})
	require.NoError(t, err)
	require.NoError(t, tree.Insert("resolved.example", value))
	resolver.DefaultHosts = resolver.NewHosts(tree)
	proxy := &selectionOnlyProxy{}
	mode = Direct
	proxies = map[string]C.Proxy{"DIRECT": proxy}

	metadata := &C.Metadata{Host: "resolved.example", Type: C.TUNNEL}
	selected, _, err := resolveMetadata(metadata)
	require.NoError(t, err)
	require.Same(t, proxy, selected)
	require.Equal(t, netip.MustParseAddr("192.0.2.15"), metadata.DstIP, "resolveMetadata mutates the request metadata with a hosts result")
}

func TestRetryPropagatesContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	proxy := &cancelDialProxy{cancel: cancel}
	var reported error
	_, err := retry(ctx, func(ctx context.Context) (C.Conn, error) {
		return proxy.DialContext(ctx, &C.Metadata{})
	}, func(err error) {
		reported = err
	})
	require.ErrorIs(t, err, context.Canceled)
	require.ErrorIs(t, reported, context.Canceled)
	require.Equal(t, 1, proxy.calls, "canceled context must stop retrying")
}

type cancelDialProxy struct {
	C.Proxy
	cancel context.CancelFunc
	calls  int
}

func (p *cancelDialProxy) DialContext(ctx context.Context, _ *C.Metadata) (C.Conn, error) {
	p.calls++
	p.cancel()
	return nil, ctx.Err()
}

type fixedInputConn struct {
	data   []byte
	closed bool
}

func (c *fixedInputConn) Read(p []byte) (int, error) {
	if len(c.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, c.data)
	c.data = c.data[n:]
	return n, nil
}
func (*fixedInputConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *fixedInputConn) Close() error                   { c.closed = true; return nil }
func (*fixedInputConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (*fixedInputConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (*fixedInputConn) SetDeadline(time.Time) error      { return nil }
func (*fixedInputConn) SetReadDeadline(time.Time) error  { return nil }
func (*fixedInputConn) SetWriteDeadline(time.Time) error { return nil }

type earlyCaptureConn struct {
	N.ExtendedConn
	host          string
	needHandshake bool
	writes        chan earlyWrite
}

type earlyWrite struct {
	data    []byte
	tracked bool
}

func (c *earlyCaptureConn) NeedHandshake() bool { return c.needHandshake }
func (c *earlyCaptureConn) Write(data []byte) (int, error) {
	tracked := false
	statistic.DefaultManager.Range(func(tracker statistic.Tracker) bool {
		if tracker.Info().Metadata.Host == c.host {
			tracked = true
			return false
		}
		return true
	})
	c.writes <- earlyWrite{data: bytes.Clone(data), tracked: tracked}
	return len(data), nil
}
func (*earlyCaptureConn) Chains() C.Chain               { return C.Chain{"EARLY"} }
func (*earlyCaptureConn) ProviderChains() C.Chain       { return nil }
func (*earlyCaptureConn) AppendToChains(C.ProxyAdapter) {}
func (*earlyCaptureConn) RemoteDestination() string     { return "origin.example:443" }

type earlyTestProxy struct {
	C.Proxy
	conn C.Conn
}

func (p *earlyTestProxy) DialContext(context.Context, *C.Metadata) (C.Conn, error) {
	return p.conn, nil
}

func TestHandleTCPConnWritesNeedHandshakeFirstPacketBeforeTracking(t *testing.T) {
	oldMode, oldProxies := mode, proxies
	oldStatus, oldDispatcher, oldSniffing := Status(), snifferDispatcher, sniffingEnable
	t.Cleanup(func() {
		mode, proxies = oldMode, oldProxies
		status.Store(oldStatus)
		snifferDispatcher, sniffingEnable = oldDispatcher, oldSniffing
	})
	status.Store(Running)
	mode = Direct
	snifferDispatcher, sniffingEnable = nil, false

	const host = "mitm-m0-first-flight.example"
	remoteSide, remotePeer := net.Pipe()
	defer remotePeer.Close()
	remote := &earlyCaptureConn{
		ExtendedConn:  N.NewExtendedConn(remoteSide),
		host:          host,
		needHandshake: true,
		writes:        make(chan earlyWrite, 2),
	}
	proxies = map[string]C.Proxy{"DIRECT": &earlyTestProxy{conn: remote}}

	inbound := &fixedInputConn{data: []byte("client-first-flight")}
	defer inbound.Close()
	done := make(chan struct{})
	go func() {
		handleTCPConn(icontext.NewConnContext(inbound, &C.Metadata{
			NetWork: C.TCP,
			Type:    C.TUNNEL,
			Host:    host,
			DstPort: 443,
		}))
		close(done)
	}()

	select {
	case write := <-remote.writes:
		require.Equal(t, "client-first-flight", string(write.data))
		require.False(t, write.tracked, "NeedHandshake consumes the first packet before NewTCPTracker registers the connection")
	case <-time.After(time.Second):
		t.Fatal("early outbound handshake did not receive the client's buffered first packet")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("TCP handler did not release the connection")
	}
	require.True(t, inbound.closed)
	found := false
	statistic.DefaultManager.Range(func(tracker statistic.Tracker) bool {
		if tracker.Info().Metadata.Host == host {
			found = true
			return false
		}
		return true
	})
	require.False(t, found, "tracker must be removed after the relayed connection closes")
}

func TestHandleTCPConnRelaysPeekedBytesWithoutNeedHandshake(t *testing.T) {
	oldMode, oldProxies := mode, proxies
	oldStatus, oldDispatcher, oldSniffing := Status(), snifferDispatcher, sniffingEnable
	t.Cleanup(func() {
		mode, proxies = oldMode, oldProxies
		status.Store(oldStatus)
		snifferDispatcher, sniffingEnable = oldDispatcher, oldSniffing
	})
	status.Store(Running)
	mode = Direct
	snifferDispatcher, sniffingEnable = nil, false

	const host = "mitm-m0-relay-first-flight.example"
	remoteSide, remotePeer := net.Pipe()
	defer remotePeer.Close()
	remote := &earlyCaptureConn{
		ExtendedConn: N.NewExtendedConn(remoteSide),
		host:         host,
		writes:       make(chan earlyWrite, 2),
	}
	proxies = map[string]C.Proxy{"DIRECT": &earlyTestProxy{conn: remote}}

	inbound := &fixedInputConn{data: []byte("native-relay-first-flight")}
	defer inbound.Close()
	done := make(chan struct{})
	go func() {
		handleTCPConn(icontext.NewConnContext(inbound, &C.Metadata{
			NetWork: C.TCP,
			Type:    C.TUNNEL,
			Host:    host,
			DstPort: 443,
		}))
		close(done)
	}()

	select {
	case write := <-remote.writes:
		require.Equal(t, "native-relay-first-flight", string(write.data))
		require.True(t, write.tracked, "ordinary relay writes happen after the native tracker is registered")
	case <-time.After(time.Second):
		t.Fatal("native relay did not receive the buffered first packet")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("TCP handler did not release the connection")
	}
	require.True(t, inbound.closed)
}

func TestPreHandleFailureIsReturnedForHookHandling(t *testing.T) {
	oldMapper := resolver.DefaultHostMapper
	t.Cleanup(func() { resolver.DefaultHostMapper = oldMapper })
	resolver.DefaultHostMapper = &testHostMapper{
		mapping:     true,
		fakeIPRange: netip.MustParsePrefix("198.18.0.1/16"),
		fakeIPs:     map[netip.Addr]bool{netip.MustParseAddr("198.18.0.9"): true},
		hosts:       map[netip.Addr]string{},
	}
	metadata := &C.Metadata{DstIP: netip.MustParseAddr("198.18.0.9")}
	err := preHandleMetadata(metadata)
	require.Error(t, err)
	require.True(t, metadata.Valid())
}
