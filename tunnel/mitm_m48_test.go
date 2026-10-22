package tunnel

import (
	"sync"
	"testing"

	"github.com/metacubex/mihomo/component/mitm"
	"github.com/metacubex/mihomo/component/mitm/processing/generation"
	"github.com/stretchr/testify/require"
)

func TestM48TunnelPublishBindRace(t *testing.T) {
	require.Nil(t, mitmDispatcher.Load())
	defer UpdateMITMManager(nil)
	for round := 0; round < 100; round++ {
		first := mitm.NewManager(mitm.Config{Enabled: true, Ports: []uint16{443}})
		second := mitm.NewManager(mitm.Config{Enabled: true, Ports: []uint16{443}})
		third := mitm.NewManager(mitm.Config{Enabled: true, Ports: []uint16{443}})
		generations := []*generation.Generation{first.Generation(), second.Generation(), third.Generation()}
		UpdateMITMManager(first)
		gate := make(chan struct{})
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-gate
				c := bindMITMConnection(443)
				if c != nil {
					c.Close()
					c.Close()
				}
			}()
		}
		for _, m := range []*mitm.Manager{second, third} {
			wg.Add(1)
			go func(m *mitm.Manager) { defer wg.Done(); <-gate; UpdateMITMManager(m) }(m)
		}
		close(gate)
		wg.Wait()
		UpdateMITMManager(nil)
		for _, g := range generations {
			require.Equal(t, generation.Closed, g.State())
			_, e := g.Bind()
			require.Error(t, e)
		}
	}
}
