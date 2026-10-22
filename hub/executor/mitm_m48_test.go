package executor_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/mitm/httphook"
	"github.com/metacubex/mihomo/component/mitm/processing/generation"
	"github.com/metacubex/mihomo/config"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/tunnel"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
)

func TestM48RealConfigPublication(t *testing.T) {
	if os.Getenv("M48_CONFIG_CHILD") != "1" {
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestM48RealConfigPublication$", "-test.v", "-test.timeout=40s")
		cmd.Env = append(os.Environ(), "M48_CONFIG_CHILD=1")
		out, e := cmd.CombinedOutput()
		require.NoError(t, e, "%s", out)
		t.Log(string(out))
		return
	}
	home := t.TempDir()
	C.SetHomeDir(home)
	roots := m35ExecutorCA(t, home)
	yaml := func(version string, enabled bool) []byte {
		return []byte(fmt.Sprintf(`mode: direct
log-level: silent
find-process-mode: off
geo-auto-update: false
profile: {store-selected: false}
dns: {enable: false}
tun: {enable: false, auto-route: false, dns-mode: disabled}
ntp: {enable: false}
iptables: {enable: false}
mitm:
  enable: %t
  domains: [localhost]
  ca-cert: ca.pem
  ca-key: ca-key.pem
  rewrite:
    enable: true
    rules:
      - name: local
        local-response:
          status: 200
          body: %s
`, enabled, version))
	}
	apply := func(version string, enabled bool) *generation.Generation {
		cfg, e := config.Parse(yaml(version, enabled))
		require.NoError(t, e)
		require.NoError(t, hub.ApplyConfig(cfg))
		return tunnel.MITMGeneration()
	}
	old := apply("old", true)
	require.NotNil(t, old)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	type client struct {
		rt   http.RoundTripper
		raw  net.Conn
		done chan struct{}
	}
	clients := []*client{}
	defer func() {
		for _, c := range clients {
			c.raw.Close()
		}
		apply("off", false)
	}()
	start := func(h2 bool) *client {
		server, raw := net.Pipe()
		c := &client{raw: raw, done: make(chan struct{})}
		clients = append(clients, c)
		go func() {
			defer close(c.done)
			tunnel.Tunnel.HandleTCPConn(server, &C.Metadata{NetWork: C.TCP, Type: C.TUNNEL, Host: "localhost", DstPort: 443, SrcIP: netip.MustParseAddr("192.0.2.48"), SrcPort: 44800})
		}()
		protocols := []string{"http/1.1"}
		if h2 {
			protocols = []string{"h2"}
		}
		secure := tls.Client(raw, &tls.Config{RootCAs: roots, ServerName: "localhost", NextProtos: protocols, MinVersion: tls.VersionTLS12})
		require.NoError(t, secure.HandshakeContext(ctx))
		if h2 {
			var e error
			c.rt, e = (&http2.Transport{}).NewClientConn(secure)
			require.NoError(t, e)
		} else {
			c.rt = &http.Transport{TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}, DialTLSContext: func(context.Context, string, string) (net.Conn, error) { return secure, nil }}
		}
		return c
	}
	send := func(c *client, want string) {
		r, e := http.NewRequestWithContext(ctx, "GET", "https://localhost/", nil)
		require.NoError(t, e)
		resp, e := c.rt.RoundTrip(r)
		require.NoError(t, e)
		data, e := io.ReadAll(resp.Body)
		require.NoError(t, e)
		require.NoError(t, resp.Body.Close())
		require.Equal(t, want, string(data))
	}
	h1, h2 := start(false), start(true)
	send(h1, "old")
	send(h2, "old")
	second := apply("second", true)
	require.Equal(t, generation.Retiring, old.State())
	send(h1, "old")
	send(h2, "old")
	fresh := start(true)
	send(fresh, "second")
	third := apply("third", true)
	send(h2, "old")
	send(fresh, "second")
	newest := start(true)
	send(newest, "third")
	// Parse failure and production candidate failure both leave the active pointer.
	_, e := config.Parse([]byte("mitm: {enable: true, domains: ['bad*domain']}"))
	require.Error(t, e)
	require.Same(t, third, tunnel.MITMGeneration())
	invalid, e := config.Parse(yaml("invalid", true))
	require.NoError(t, e)
	invalid.MITM.CA = nil
	require.Error(t, hub.ApplyConfig(invalid))
	require.Same(t, third, tunnel.MITMGeneration())
	send(newest, "third")
	invalid, e = config.Parse(yaml("invalid-script", true))
	require.NoError(t, e)
	invalid.MITM.ScriptHooks, e = httphook.Compile(httphook.Config{Enable: true, Rules: []httphook.Rule{{Name: "syntax", Phase: httphook.RequestPhase, Source: "function {"}}})
	require.NoError(t, e)
	require.Error(t, hub.ApplyConfig(invalid))
	require.Same(t, third, tunnel.MITMGeneration())
	require.NoError(t, invalid.MITM.ScriptHooks.Close())
	require.Nil(t, apply("off", false))
	send(h2, "old")
	send(newest, "third")
	fourth := apply("fourth", true)
	send(start(true), "fourth")
	require.NotEqual(t, third.ID(), fourth.ID())
	// Two real ApplyConfig calls serialize the entire Executor mutation path.
	configs := make([]*config.Config, 2)
	for i := range configs {
		configs[i], e = config.Parse(yaml(fmt.Sprintf("parallel%d", i), true))
		require.NoError(t, e)
	}
	gate := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for _, cfg := range configs {
		wg.Add(1)
		go func(cfg *config.Config) { defer wg.Done(); <-gate; errs <- executor.ApplyConfig(cfg, true) }(cfg)
	}
	close(gate)
	wg.Wait()
	require.NoError(t, <-errs)
	require.NoError(t, <-errs)
	apply("off", false)
	for _, c := range clients {
		require.NoError(t, c.raw.Close())
		select {
		case <-c.done:
		case <-ctx.Done():
			t.Fatal("connection did not drain")
		}
	}
	for _, g := range []*generation.Generation{old, second, third, fourth} {
		require.NoError(t, g.WaitClosed(ctx))
		require.Equal(t, generation.Closed, g.State())
	}
	t.Log("Parse -> hub.ApplyConfig -> executor.ApplyConfig -> Tunnel; H1/H2 pinned; rollback, disable/re-enable, concurrent ApplyConfig, explicit drain PASS")
}
