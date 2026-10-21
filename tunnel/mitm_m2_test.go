package tunnel

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	mihomoCA "github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/mitm"
	"github.com/metacubex/mihomo/component/mitm/rewrite"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/component/trie"
	C "github.com/metacubex/mihomo/constant"
	icontext "github.com/metacubex/mihomo/context"
	"github.com/metacubex/mihomo/tunnel/statistic"
	"github.com/stretchr/testify/require"
)

type m2NativeRequest struct {
	method string
	path   string
	host   string
	sni    string
	header http.Header
	body   string
}

func TestM2RequestRewriteUsesNativeRuleAndVerifiedTLS(t *testing.T) {
	oldStatus, oldDispatcher, oldSniffing := Status(), snifferDispatcher, sniffingEnable
	oldManager, oldMode := mitmDispatcher.Load(), mode
	oldProxies, oldRules, oldSubRules, oldHosts := proxies, rules, subRules, resolver.DefaultHosts
	t.Cleanup(func() {
		status.Store(oldStatus)
		snifferDispatcher, sniffingEnable = oldDispatcher, oldSniffing
		mode, proxies, rules, subRules = oldMode, oldProxies, oldRules, oldSubRules
		resolver.DefaultHosts = oldHosts
		UpdateMITMManager(oldManager)
		mihomoCA.ResetCertificate()
	})
	status.Store(Running)
	snifferDispatcher, sniffingEnable = nil, false
	resolver.DefaultHosts = resolver.NewHosts(trie.New[resolver.HostValue]())
	mode = Rule

	observed := make(chan m2NativeRequest, 1)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "body read", http.StatusInternalServerError)
			return
		}
		observed <- m2NativeRequest{
			method: r.Method,
			path:   r.URL.RequestURI(),
			host:   r.Host,
			sni:    r.TLS.ServerName,
			header: r.Header.Clone(),
			body:   string(body),
		}
		_, _ = io.WriteString(w, "native-m2-ok")
	}))
	t.Cleanup(upstream.Close)
	upstreamLeaf := upstream.TLS.Certificates[0].Leaf
	if upstreamLeaf == nil {
		var err error
		upstreamLeaf, err = x509.ParseCertificate(upstream.TLS.Certificates[0].Certificate[0])
		require.NoError(t, err)
	}
	mihomoCA.ResetCertificate()
	require.NoError(t, mihomoCA.AddCertificate(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstreamLeaf.Raw}))))
	_, err := upstreamLeaf.Verify(x509.VerifyOptions{Roots: mihomoCA.GetCertPool(), DNSName: "example.com"})
	require.NoError(t, err, "the upstream certificate must validate for the rewritten target")

	upstreamAddress := upstream.Listener.Addr().String()
	selected := &m1NativeProxy{name: "M2_REWRITE_PROXY", onDialMetadata: func(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", upstreamAddress)
		if err != nil {
			return nil, err
		}
		return &m1PlainNativeConn{ExtendedConn: N.NewExtendedConn(conn)}, nil
	}}
	direct := &m1NativeProxy{name: "DIRECT"}
	proxies = map[string]C.Proxy{"M2_REWRITE_PROXY": selected, "DIRECT": direct}
	rules = []C.Rule{
		m1RouteRule{host: "example.com", adapter: "M2_REWRITE_PROXY"},
		m1RouteRule{host: "origin.example", adapter: "DIRECT"},
	}
	subRules = nil

	pipeline, err := rewrite.Compile(rewrite.Config{Enable: true, Rules: []rewrite.Rule{{
		Name:  "route-rewritten-target",
		Match: rewrite.Match{Path: "/old", Methods: []string{http.MethodPost}},
		Request: &rewrite.RequestAction{
			URL:     "https://example.com/new?source=m2",
			Method:  http.MethodPatch,
			Headers: rewrite.HeaderAction{Set: map[string]string{"X-M2-Rewrite": "active"}},
			Body:    &rewrite.BodyReplacement{Replace: "rewritten-body", ContentType: "text/plain"},
		},
	}}})
	require.NoError(t, err)
	ca, roots := loadTunnelTestCA(t)
	UpdateMITMManager(mitm.NewManager(mitm.Config{
		Enabled:           true,
		Ports:             []uint16{443},
		Domains:           []string{"origin.example"},
		CA:                ca,
		HandshakeTimeout:  3 * time.Second,
		ReadHeaderTimeout: 3 * time.Second,
		RequestTimeout:    4 * time.Second,
		IdleTimeout:       3 * time.Second,
		Rewrite:           pipeline,
	}))

	metadata := &C.Metadata{
		NetWork: C.TCP, Type: C.TUNNEL,
		Host: "origin.example", DstPort: 443,
		SrcIP: netip.MustParseAddr("192.0.2.29"), SrcPort: 45991,
	}
	serverRaw, clientRaw := net.Pipe()
	dispatchDone := make(chan struct{})
	go func() {
		handleTCPConn(icontext.NewConnContext(N.NewBufferedConn(serverRaw), metadata))
		close(dispatchDone)
	}()
	client := tls.Client(clientRaw, &tls.Config{RootCAs: roots, ServerName: "origin.example", NextProtos: []string{"http/1.1"}})
	_ = client.SetDeadline(time.Now().Add(10 * time.Second))
	require.NoError(t, client.Handshake())
	_, err = io.WriteString(client, "POST /old HTTP/1.1\r\nHost: origin.example\r\nContent-Length: 3\r\nX-Old: value\r\n\r\nold")
	require.NoError(t, err)
	response, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: http.MethodPost})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.StatusCode)
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())
	require.Equal(t, "native-m2-ok", string(body))

	select {
	case request := <-observed:
		require.Equal(t, http.MethodPatch, request.method)
		require.Equal(t, "/new?source=m2", request.path)
		require.Equal(t, "example.com:443", request.host)
		require.Equal(t, "example.com", request.sni)
		require.Equal(t, "active", request.header.Get("X-M2-Rewrite"))
		require.Equal(t, "rewritten-body", request.body)
	case <-time.After(3 * time.Second):
		t.Fatal("rewritten request never reached the verified native TLS upstream")
	}

	proxyCalls, targetMetadata := selected.snapshot()
	directCalls, _ := direct.snapshot()
	require.Equal(t, 1, proxyCalls, "the rewritten target must be routed through Mihomo's native rules")
	require.Zero(t, directCalls, "the original TLS authority must not determine the rewritten upstream route")
	require.Equal(t, "example.com", targetMetadata.Host)
	require.Equal(t, uint16(443), targetMetadata.DstPort)
	require.True(t, targetMetadata.SrcPort == metadata.SrcPort)

	_ = client.Close()
	select {
	case <-dispatchDone:
	case <-time.After(5 * time.Second):
		t.Fatal("native Rewrite connection did not close")
	}
	require.Eventually(t, func() bool {
		found := false
		statistic.DefaultManager.Range(func(tracker statistic.Tracker) bool {
			info := tracker.Info().Metadata
			found = found || info.Host == "example.com" && info.SrcPort == metadata.SrcPort
			return !found
		})
		return !found
	}, 3*time.Second, 10*time.Millisecond)
}

func TestM2ExplicitIPTargetDoesNotInheritFakeIPOrDNSMapping(t *testing.T) {
	oldMode, oldProxies, oldRules, oldSubRules, oldHosts, oldMapper := mode, proxies, rules, subRules, resolver.DefaultHosts, resolver.DefaultHostMapper
	t.Cleanup(func() {
		mode, proxies, rules, subRules = oldMode, oldProxies, oldRules, oldSubRules
		resolver.DefaultHosts, resolver.DefaultHostMapper = oldHosts, oldMapper
	})
	resolver.DefaultHosts = resolver.NewHosts(trie.New[resolver.HostValue]())
	fakeIP := netip.MustParseAddr("198.18.0.88")
	realIP := netip.MustParseAddr("203.0.113.88")
	resolver.DefaultHostMapper = &testHostMapper{
		mapping:     true,
		fakeIPRange: netip.MustParsePrefix("198.18.0.1/16"),
		fakeIPs:     map[netip.Addr]bool{fakeIP: true},
		hosts: map[netip.Addr]string{
			fakeIP: "stale-origin.example",
			realIP: "stale-origin.example",
		},
	}
	for _, destination := range []netip.Addr{fakeIP, realIP} {
		t.Run(destination.String(), func(t *testing.T) {
			remote, peer := net.Pipe()
			t.Cleanup(func() { _ = peer.Close() })
			proxy := &m1NativeProxy{
				name: "DIRECT",
				conn: &m1PlainNativeConn{ExtendedConn: N.NewExtendedConn(remote)},
			}
			mode = Direct
			proxies = map[string]C.Proxy{"DIRECT": proxy}
			rules, subRules = nil, nil

			metadata := &C.Metadata{NetWork: C.TCP, Type: C.TUNNEL, DstIP: destination, DstPort: 443}
			conn, err := Tunnel.DialTCP(context.Background(), metadata)
			require.NoError(t, err)
			defer conn.Close()
			calls, selected := proxy.snapshot()
			require.Equal(t, 1, calls)
			require.Empty(t, selected.Host, "an explicit IP URL target must remain an IP rather than reverse-map to the inbound host")
			require.Equal(t, destination, selected.DstIP)
			require.Equal(t, C.DNSNormal, selected.DNSMode)
		})
	}
}

func TestM2DomainTargetStillRunsNativeHostsPreprocessing(t *testing.T) {
	oldMapper, oldHosts := resolver.DefaultHostMapper, resolver.DefaultHosts
	t.Cleanup(func() {
		resolver.DefaultHostMapper, resolver.DefaultHosts = oldMapper, oldHosts
	})
	resolver.DefaultHostMapper = &testHostMapper{mapping: true}
	tree := trie.New[resolver.HostValue]()
	value, err := resolver.NewHostValueByDomain("canonical.example")
	require.NoError(t, err)
	require.NoError(t, tree.Insert("alias.example", value))
	resolver.DefaultHosts = resolver.NewHosts(tree)

	metadata := &C.Metadata{Host: "alias.example", DstIP: netip.MustParseAddr("198.18.0.99"), DNSMode: C.DNSNormal}
	require.NoError(t, preHandleMITMMetadata(metadata))
	require.Equal(t, "canonical.example", metadata.Host, "domain URL targets still use normal DefaultHosts preprocessing")
}

func TestM2TerminalRequestSkipsTunnelNativeOutbound(t *testing.T) {
	oldStatus, oldDispatcher, oldSniffing := Status(), snifferDispatcher, sniffingEnable
	oldManager, oldMode := mitmDispatcher.Load(), mode
	oldProxies, oldRules, oldSubRules, oldHosts := proxies, rules, subRules, resolver.DefaultHosts
	t.Cleanup(func() {
		status.Store(oldStatus)
		snifferDispatcher, sniffingEnable = oldDispatcher, oldSniffing
		mode, proxies, rules, subRules = oldMode, oldProxies, oldRules, oldSubRules
		resolver.DefaultHosts = oldHosts
		UpdateMITMManager(oldManager)
	})
	status.Store(Running)
	snifferDispatcher, sniffingEnable = nil, false
	resolver.DefaultHosts = resolver.NewHosts(trie.New[resolver.HostValue]())
	mode = Direct
	proxy := &m1NativeProxy{name: "DIRECT"}
	proxies = map[string]C.Proxy{"DIRECT": proxy}
	rules, subRules = nil, nil

	pipeline, err := rewrite.Compile(rewrite.Config{Enable: true, Rules: []rewrite.Rule{{
		Name: "local-response", Match: rewrite.Match{Path: "/local"},
		LocalResponse: &rewrite.LocalResponse{Status: http.StatusCreated, Body: "local-only", Headers: map[string]string{"X-Local": "yes"}},
	}}})
	require.NoError(t, err)
	ca, roots := loadTunnelTestCA(t)
	UpdateMITMManager(mitm.NewManager(mitm.Config{
		Enabled: true, Ports: []uint16{443}, Domains: []string{"origin.example"}, CA: ca,
		RequestTimeout: 3 * time.Second, Rewrite: pipeline,
	}))
	serverRaw, clientRaw := net.Pipe()
	dispatchDone := make(chan struct{})
	go func() {
		handleTCPConn(icontext.NewConnContext(N.NewBufferedConn(serverRaw), &C.Metadata{
			NetWork: C.TCP, Type: C.TUNNEL, Host: "origin.example", DstPort: 443,
		}))
		close(dispatchDone)
	}()
	client := tls.Client(clientRaw, &tls.Config{RootCAs: roots, ServerName: "origin.example", NextProtos: []string{"http/1.1"}})
	_ = client.SetDeadline(time.Now().Add(8 * time.Second))
	require.NoError(t, client.Handshake())
	_, err = io.WriteString(client, "GET /local HTTP/1.1\r\nHost: origin.example\r\n\r\n")
	require.NoError(t, err)
	response, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: http.MethodGet})
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, response.StatusCode)
	require.Equal(t, "yes", response.Header.Get("X-Local"))
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())
	require.Equal(t, "local-only", string(body))
	proxyCalls, _ := proxy.snapshot()
	require.Zero(t, proxyCalls, "terminal handling must not invoke Proxy.DialContext")
	_ = client.Close()
	select {
	case <-dispatchDone:
	case <-time.After(5 * time.Second):
		t.Fatal("terminal request left the client TLS connection active")
	}
}
