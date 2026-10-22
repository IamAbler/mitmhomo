package mitm

import (
	"context"
	"sync"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/mitm/processing/generation"
	"github.com/metacubex/mihomo/component/sniffer"
	C "github.com/metacubex/mihomo/constant"
)

// Connection is a one-shot connection capability. Bind must occur inside the
// publisher's pointer lock. Dispatch retains the snapshot across TLS, H1
// keep-alive and all H2 streams, including streams opened after retirement.
type Connection struct {
	manager  *Manager
	snapshot *configSnapshot
	lease    *generation.Lease
	release  func()
	once     sync.Once
}

func (m *Manager) Bind(port uint16) *Connection {
	s, lease, release := m.acquireConnectionSnapshot()
	if s == nil || !s.config.Enabled || !portAllowed(s, port) {
		release()
		return nil
	}
	return &Connection{manager: m, snapshot: s, lease: lease, release: release}
}
func (c *Connection) Close() error {
	if c != nil {
		c.once.Do(c.release)
	}
	return nil
}
func (c *Connection) Dispatch(ctx context.Context, conn *N.BufferedConn, metadata *C.Metadata, prepare func(*sniffer.TLSClientHelloInfo) (*C.Metadata, error), dial NativeDialContext) (DispatchOutcome, error) {
	defer c.Close()
	return c.manager.dispatchSnapshot(ctx, conn, metadata, prepare, dial, c.snapshot, c.lease)
}
