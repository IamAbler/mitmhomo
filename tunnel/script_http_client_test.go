package tunnel

import (
	"context"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"testing"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/component/trie"
	C "github.com/metacubex/mihomo/constant"
	"github.com/stretchr/testify/require"
)

func TestScriptHTTPClientUsesNativeRouteAndPinnedResolvedIP(t *testing.T) {
	oldMode, oldProxies, oldRules, oldSubRules, oldHosts := mode, proxies, rules, subRules, resolver.DefaultHosts
	t.Cleanup(func() {
		mode, proxies, rules, subRules, resolver.DefaultHosts = oldMode, oldProxies, oldRules, oldSubRules, oldHosts
	})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		_, _ = io.WriteString(w, request.Host)
	}))
	defer server.Close()
	serverAddress := server.Listener.Addr().String()
	_, portText, err := net.SplitHostPort(serverAddress)
	require.NoError(t, err)

	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	host := "example.com"
	ip := netip.MustParseAddr("127.0.0.1")
	tree := trie.New[resolver.HostValue]()
	value, err := resolver.NewHostValue([]string{ip.String()})
	require.NoError(t, err)
	require.NoError(t, tree.Insert(host, value))
	resolver.DefaultHosts = resolver.NewHosts(tree)

	writes := make(chan earlyWrite, 1)
	selected := &m1NativeProxy{name: "SCRIPT_HTTP_PROXY", onDialMetadata: func(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", serverAddress)
		if err != nil {
			return nil, err
		}
		return &m1EarlyNativeConn{
			m1PlainNativeConn: &m1PlainNativeConn{ExtendedConn: N.NewExtendedConn(conn)},
			host:              host,
			writes:            writes,
		}, nil
	}}
	direct := &m1NativeProxy{name: "DIRECT"}
	mode = Rule
	proxies = map[string]C.Proxy{"SCRIPT_HTTP_PROXY": selected, "DIRECT": direct}
	rules = []C.Rule{m1RouteRule{host: host, adapter: "SCRIPT_HTTP_PROXY"}}
	subRules = nil

	client, closeClient, err := newScriptHTTPClientFactory(true, roots)
	require.NoError(t, err)
	defer closeClient()
	requestCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, "https://"+net.JoinHostPort(host, portText)+"/", nil)
	require.NoError(t, err)
	response, err := client.Do(request)
	require.NoError(t, err)
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())
	require.Equal(t, net.JoinHostPort(host, portText), string(body))

	select {
	case write := <-writes:
		require.GreaterOrEqual(t, len(write.data), 5)
		require.Equal(t, byte(0x16), write.data[0], "the EarlyConn first write must be the upstream TLS ClientHello")
		require.True(t, write.tracked, "the TLS ClientHello must be tracked by the selected native route")
	case <-time.After(time.Second):
		t.Fatal("upstream TLS handshake did not traverse the EarlyConn route")
	}
	selectedCalls, metadata := selected.snapshot()
	directCalls, _ := direct.snapshot()
	require.Equal(t, 1, selectedCalls)
	require.Zero(t, directCalls)
	require.Empty(t, metadata.Host, "the dialed address is pinned after domain-rule selection")
	require.Equal(t, ip, metadata.DstIP)
	require.Equal(t, uint16(mustPort(t, portText)), metadata.DstPort)
}

func mustPort(t *testing.T, value string) uint64 {
	t.Helper()
	port, err := strconv.ParseUint(value, 10, 16)
	require.NoError(t, err)
	return port
}
