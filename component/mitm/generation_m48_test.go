package mitm

import (
	"context"
	"io"
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
