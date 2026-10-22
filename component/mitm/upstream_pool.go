package mitm

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"sync"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"golang.org/x/net/http2"
)

// upstreamTarget is an address and security partition, NOT a hostname pool.
// TLS policy, inbound metadata and rewrite snapshot are immutable within owner.
// Host header is deliberately independent of URL/SNI, as in M3.3.
type upstreamTarget struct {
	scheme, host, serverName string
	port                     uint16
	ip                       netip.Addr
	security                 *tls.Config
}

// upstreamIdentity binds a target to exactly one native dial/route lease. The
// actual proxy and chain live on that socket's Native Tracker. We never resolve
// a new route and attach it to an existing lease, even after config reload.
// A new dial gets a new lease; there is no cross-owner or cross-origin lookup.
type upstreamIdentity struct {
	target                     upstreamTarget
	owner                      *upstreamManager
	lease                      uint64
	alpn                       string
	outbound, chain, providers string
}

func identityForUpstream(key upstreamTarget, owner *upstreamManager, lease uint64, secure *tls.Conn) upstreamIdentity {
	id := upstreamIdentity{target: key, owner: owner, lease: lease, alpn: secure.ConnectionState().NegotiatedProtocol}
	if native, ok := secure.NetConn().(C.Connection); ok {
		// Names alone cannot identify a dynamic adapter generation. The lease
		// remains the authoritative identity; chain values describe that lease.
		chain := append(C.Chain(nil), native.Chains()...)
		providers := append(C.Chain(nil), native.ProviderChains()...)
		id.outbound = chain.Last()
		encoded, _ := json.Marshal(chain)
		id.chain = string(encoded)
		encoded, _ = json.Marshal(providers)
		id.providers = string(encoded)
	}
	return id
}

type upstreamEntry struct {
	identity upstreamIdentity
	cc       *http2.ClientConn
	secure   *tls.Conn
}

type upstreamPending struct{ done chan struct{} }

// One manager belongs to one downstream H2 TLS connection/snapshot. Locks
// protect lookup/publication only, never dialing, HTTP or body I/O.
type upstreamManager struct {
	ctx       context.Context
	cancel    context.CancelFunc
	mu        sync.Mutex
	closed    bool
	nextLease uint64
	current   map[upstreamTarget]*upstreamEntry
	all       map[upstreamIdentity]*upstreamEntry
	pending   map[upstreamTarget]*upstreamPending
	done      chan struct{}
}

func newUpstreamManager(ctx context.Context, idle time.Duration) *upstreamManager {
	ctx, cancel := context.WithCancel(ctx)
	m := &upstreamManager{ctx: ctx, cancel: cancel, current: make(map[upstreamTarget]*upstreamEntry), all: make(map[upstreamIdentity]*upstreamEntry), pending: make(map[upstreamTarget]*upstreamPending), done: make(chan struct{})}
	go func() {
		defer close(m.done)
		tick := time.NewTicker(positiveDuration(idle, time.Minute))
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				m.closeConnections()
				return
			case <-tick.C:
				m.mu.Lock()
				m.pruneLocked()
				m.mu.Unlock()
			}
		}
	}()
	return m
}

func (m *upstreamManager) pruneLocked() {
	for identity, e := range m.all {
		if e.cc.State().Closed {
			delete(m.all, identity)
			if m.current[e.identity.target] == e {
				delete(m.current, e.identity.target)
			}
		}
	}
}

func (m *upstreamManager) closeConnections() {
	m.mu.Lock()
	m.closed = true
	entries := m.all
	pending := make([]*upstreamPending, 0, len(m.pending))
	for _, p := range m.pending {
		pending = append(pending, p)
	}
	m.all = make(map[upstreamIdentity]*upstreamEntry)
	m.current = make(map[upstreamTarget]*upstreamEntry)
	m.mu.Unlock()
	for _, e := range entries {
		// Abort the tracked native socket first. TLS Close may try to write
		// close_notify to a peer that is no longer reading; forced shutdown
		// must not wait for that write or race HTTP/2 write deadlines.
		_ = e.secure.NetConn().Close()
		_ = e.cc.Close()
	}
	for _, p := range pending {
		<-p.done
	}
}

func (m *upstreamManager) Close() { m.cancel(); <-m.done }

// publish transfers an initialized H2 connection from its creator to the pool.
// Validation and registration share one critical section: a rejected entry is
// never visible to lookups or shutdown, and remains the creator's responsibility.
// A nil entry validates an exclusive H1 handoff without adding it to the pool.
func (m *upstreamManager) publish(ctx context.Context, e *upstreamEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if m.closed || m.ctx.Err() != nil {
		return errors.New("upstream manager closed")
	}
	if e != nil {
		state := e.cc.State()
		// CanTakeNewRequest alone permits a never-used, already-closed
		// ClientConn so that x/net can report its initial connection error.
		if state.Closed || state.Closing || !e.cc.CanTakeNewRequest() {
			return errors.New("new upstream HTTP/2 connection unavailable")
		}
		m.current[e.identity.target] = e
		m.all[e.identity] = e
	}
	return nil
}

// acquire selects a connection for a single RoundTrip. Pending dial cancellation belongs
// to its initiating request; waiters can create a replacement before sending
// any HTTP bytes. This is not request replay. H1 sockets are never published.
func (m *upstreamManager) acquire(req *http.Request, rt *nativeRoundTripper) (*http2.ClientConn, *tls.Conn, error) {
	key := upstreamTarget{scheme: req.URL.Scheme, host: rt.target.Host, port: rt.target.DstPort, ip: rt.target.DstIP, serverName: req.URL.Hostname(), security: rt.tlsConfig}
	for {
		if err := req.Context().Err(); err != nil {
			return nil, nil, err
		}
		m.mu.Lock()
		m.pruneLocked()
		if m.closed || m.ctx.Err() != nil {
			m.mu.Unlock()
			return nil, nil, errors.New("upstream manager closed")
		}
		if e := m.current[key]; e != nil {
			state := e.cc.State()
			if !state.Closed && !state.Closing && e.cc.CanTakeNewRequest() {
				m.mu.Unlock()
				return e.cc, nil, nil
			}
			// GOAWAY drains active streams. Keep ownership until they finish; never
			// close that socket just because it cannot accept another stream.
			delete(m.current, key)
		}
		if p := m.pending[key]; p != nil {
			m.mu.Unlock()
			select {
			case <-p.done:
				continue
			case <-req.Context().Done():
				return nil, nil, req.Context().Err()
			case <-m.ctx.Done():
				return nil, nil, errors.New("upstream manager closed")
			}
		}
		p := &upstreamPending{done: make(chan struct{})}
		m.pending[key] = p
		m.nextLease++
		lease := m.nextLease
		m.mu.Unlock()

		dialCtx, cancel := context.WithTimeout(req.Context(), rt.handshakeTimeout)
		stop := closeOnContextDone(m.ctx, cancel)
		secure, err := rt.dialTLS(dialCtx, req.URL.Hostname())
		var cc *http2.ClientConn
		if err == nil {
			// NewClientConn writes the preface/settings. A peer that stops
			// reading must not keep initialization alive after downstream close.
			stopInit := closeOnContextDone(dialCtx, func() { _ = secure.NetConn().Close() })
			if secure.ConnectionState().NegotiatedProtocol == "h2" {
				cc, err = rt.h2Transport().NewClientConn(secure)
			}
			stopInit()
			if err == nil {
				err = dialCtx.Err()
			}
		}
		stop()
		cancel()
		if err == nil {
			var e *upstreamEntry
			if cc != nil {
				e = &upstreamEntry{identity: identityForUpstream(key, m, lease, secure), cc: cc, secure: secure}
			}
			err = m.publish(req.Context(), e)
		}
		if err != nil {
			if secure != nil {
				_ = secure.NetConn().Close()
			}
			if cc != nil {
				_ = cc.Close()
			} else if secure != nil {
				_ = secure.Close()
			}
		}
		m.mu.Lock()
		delete(m.pending, key)
		close(p.done)
		m.mu.Unlock()
		if err != nil {
			return nil, nil, err
		}
		if cc != nil {
			return cc, nil, nil
		}
		return nil, secure, nil
	}
}
