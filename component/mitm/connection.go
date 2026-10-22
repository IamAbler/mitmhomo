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
	manager            *Manager
	snapshot           *configSnapshot
	lease              *generation.Lease
	release            func()
	once               sync.Once
	mu                 sync.Mutex
	closed, dispatched bool
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
		c.mu.Lock()
		c.closed = true
		c.mu.Unlock()
		c.once.Do(c.release)
	}
	return nil
}
func (c *Connection) Dispatch(ctx context.Context, conn *N.BufferedConn, metadata *C.Metadata, prepare func(*sniffer.TLSClientHelloInfo) (*C.Metadata, error), dial NativeDialContext) (DispatchOutcome, error) {
	c.mu.Lock()
	if c.closed || c.dispatched {
		c.mu.Unlock()
		return DispatchFailed, generation.ErrUnavailable
	}
	c.dispatched = true
	serving, err := c.lease.Transaction()
	c.mu.Unlock()
	if err != nil {
		return DispatchFailed, err
	}
	defer serving.Close()
	defer c.Close()
	return c.manager.dispatchSnapshot(ctx, conn, metadata, prepare, dial, c.snapshot, serving)
}

// ProcessingRunnerFromContext provides the immutable connection plan to an
// HTTP adapter. It does not run or replace legacy Script/Rewrite processing.
// The capability is valid only while the handler's stream lease is open.
type processingContextKey struct{}

func ProcessingRunnerFromContext(ctx context.Context) (*generation.BoundRunner, bool) {
	runner, ok := ctx.Value(processingContextKey{}).(*generation.BoundRunner)
	return runner, ok
}
