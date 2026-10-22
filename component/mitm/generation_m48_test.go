package mitm

import (
	"context"
	"crypto/tls"
	"fmt"
	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/mitm/processing/generation"
	"github.com/stretchr/testify/require"
)

func TestM48RetiredManagerKeepsProtocolConnection(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(map[bool]string{false: "h1-keepalive", true: "h2-new-stream"}[h2], func(t *testing.T) {
			h := newProtocolHarness(t, nil, "localhost", 443, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("old")) }), false, true, h2, []string{"http/1.1"})
			old := h.manager.Generation()
			request := func() {
				r, e := http.NewRequest("GET", "https://localhost/check", nil)
				require.NoError(t, e)
				resp, e := h.wire.RoundTrip(r)
				require.NoError(t, e)
				data, e := io.ReadAll(resp.Body)
				require.NoError(t, e)
				require.NoError(t, resp.Body.Close())
				require.Equal(t, "old", string(data))
			}
			request()
			require.NoError(t, h.manager.Close())
			require.Equal(t, generation.Retiring, old.State())
			require.Nil(t, h.manager.Bind(443))
			request()
			require.Equal(t, generation.Retiring, old.State())
			require.NoError(t, h.raw.Close())
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			require.NoError(t, old.WaitClosed(ctx))
			require.Equal(t, generation.Closed, old.State())
		})
	}
}
func TestM48ConnectionBindAndClose(t *testing.T) {
	m := NewManager(Config{Enabled: true, Ports: []uint16{443}})
	old := m.Generation()
	c := m.Bind(443)
	require.NotNil(t, c)
	require.NoError(t, m.Close())
	require.Nil(t, m.Bind(443))
	require.Equal(t, generation.Retiring, old.State())
	c.Close()
	c.Close()
	require.Equal(t, generation.Closed, old.State())
	m.Close()
}

func TestM48HandshakeFailureReleasesGeneration(t *testing.T) {
	authority, _ := makeTestAuthority(t)
	m := NewManager(Config{Enabled: true, Ports: []uint16{443}, Domains: []string{"localhost"}, CA: authority, HandshakeTimeout: time.Second})
	g := m.Generation()
	binding := m.Bind(443)
	require.NotNil(t, binding)
	server, client := net.Pipe()
	defer client.Close()
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, e := binding.Dispatch(ctx, N.NewBufferedConn(server), &C.Metadata{NetWork: C.TCP, Type: C.TUNNEL, Host: "localhost", DstPort: 443}, nil, func(context.Context, *C.Metadata, NativeTLSHandshake) (net.Conn, error) {
			return nil, fmt.Errorf("unexpected dial")
		})
		done <- e
	}()
	secure := tls.Client(client, &tls.Config{ServerName: "localhost", MinVersion: tls.VersionTLS12})
	require.Error(t, secure.HandshakeContext(ctx))
	client.Close()
	m.Close()
	select {
	case e := <-done:
		require.Error(t, e)
	case <-ctx.Done():
		t.Fatal("dispatcher retained")
	}
	require.NoError(t, g.WaitClosed(ctx))
	require.Equal(t, generation.Closed, g.State())
}
