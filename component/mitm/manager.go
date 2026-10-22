// Package mitm contains the optional HTTPS interception engine. Tunnel owns
// the dispatcher hook; this package owns TLS termination and HTTP/1.1 handling.
package mitm

import (
	"crypto/x509"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/mitm/httphook"
	"github.com/metacubex/mihomo/component/mitm/rewrite"
	"github.com/metacubex/mihomo/component/sniffer"
	C "github.com/metacubex/mihomo/constant"
	domainname "github.com/metacubex/sing/common/metadata"
)

const maxClientHelloSize = 64 * 1024

var ErrClientHelloTooLarge = errors.New("client hello exceeds inspection limit")

// PortRange describes an inclusive target TCP port range.
type PortRange struct {
	Start uint16
	End   uint16
}

// Config is immutable after it is published by Manager. Domains accepts exact
// names and *.suffix patterns; an empty CA is valid only for parser-only tests
// and can never complete a TLS interception.
type Config struct {
	Enabled            bool
	Ports              []uint16
	PortRanges         []PortRange
	Domains            []string
	CA                 *CertificateAuthority
	ClientHelloTimeout time.Duration
	HandshakeTimeout   time.Duration
	ReadHeaderTimeout  time.Duration
	RequestTimeout     time.Duration
	IdleTimeout        time.Duration
	RequestHook        RequestHook
	ResponseHook       ResponseHook
	ScriptHooks        *httphook.Snapshot
	// Rewrite is immutable after publication and fixed for each intercepted TLS
	// connection. The HTTP adapter applies its request and response stages.
	Rewrite *rewrite.Snapshot
	// upstreamRootCAs is an internal test seam. Production leaves it nil so
	// the standard platform roots are used and certificate verification stays on.
	upstreamRootCAs *x509.CertPool
}

type configSnapshot struct {
	config       Config
	ports        map[uint16]struct{}
	portRanges   []PortRange
	domains      map[string]struct{}
	wildcardHost []string
	refs         atomic.Int64
	retired      atomic.Bool
	closeOnce    sync.Once
}

// Manager publishes immutable configuration snapshots. A nil or disabled
// snapshot makes ShouldInspect return without touching the connection.
type Manager struct {
	snapshot atomic.Pointer[configSnapshot]
}

func NewManager(config Config) *Manager {
	manager := &Manager{}
	manager.Update(config)
	return manager
}

func (m *Manager) Update(config Config) {
	if m == nil {
		return
	}
	snapshot := &configSnapshot{
		config: Config{
			Enabled:            config.Enabled,
			Ports:              append([]uint16(nil), config.Ports...),
			PortRanges:         append([]PortRange(nil), config.PortRanges...),
			Domains:            append([]string(nil), config.Domains...),
			CA:                 config.CA,
			ClientHelloTimeout: config.ClientHelloTimeout,
			HandshakeTimeout:   config.HandshakeTimeout,
			ReadHeaderTimeout:  config.ReadHeaderTimeout,
			RequestTimeout:     config.RequestTimeout,
			IdleTimeout:        config.IdleTimeout,
			RequestHook:        config.RequestHook,
			ResponseHook:       config.ResponseHook,
			ScriptHooks:        cloneScriptHooks(config.Enabled, config.ScriptHooks),
			Rewrite:            config.Rewrite,
			upstreamRootCAs:    config.upstreamRootCAs,
		},
		ports:      make(map[uint16]struct{}, len(config.Ports)),
		portRanges: append([]PortRange(nil), config.PortRanges...),
		domains:    make(map[string]struct{}, len(config.Domains)),
	}
	for _, port := range config.Ports {
		if port != 0 {
			snapshot.ports[port] = struct{}{}
		}
	}
	for _, domain := range config.Domains {
		domain = normalizeDomain(domain)
		if strings.HasPrefix(domain, "*.") {
			suffix := strings.TrimPrefix(domain, "*.")
			if domainname.IsDomainName(suffix) {
				snapshot.wildcardHost = append(snapshot.wildcardHost, suffix)
			}
			continue
		}
		if _, err := netip.ParseAddr(domain); err != nil && domainname.IsDomainName(domain) {
			snapshot.domains[domain] = struct{}{}
		}
	}
	snapshot.refs.Store(1) // Manager ownership, released on the next Update.
	previous := m.snapshot.Swap(snapshot)
	if previous != nil {
		previous.retire()
	}
}

func cloneScriptHooks(enabled bool, hooks *httphook.Snapshot) *httphook.Snapshot {
	if !enabled || hooks == nil {
		return nil
	}
	return hooks.Clone()
}

func (s *configSnapshot) tryAcquire() bool {
	if s == nil {
		return false
	}
	for {
		if s.retired.Load() {
			return false
		}
		refs := s.refs.Load()
		if refs <= 0 {
			return false
		}
		if !s.refs.CompareAndSwap(refs, refs+1) {
			continue
		}
		if !s.retired.Load() {
			return true
		}
		s.release()
		return false
	}
}

func (s *configSnapshot) release() {
	if s == nil {
		return
	}
	if s.refs.Add(-1) == 0 {
		s.closeOnce.Do(func() {
			if s.config.ScriptHooks != nil {
				_ = s.config.ScriptHooks.Close()
			}
		})
	}
}

func (s *configSnapshot) retire() {
	if s != nil && s.retired.CompareAndSwap(false, true) {
		s.release() // Manager ownership.
	}
}

// ConfigSnapshot returns a detached configuration copy. If ScriptHooks is
// non-nil, the returned value owns a cloned Snapshot; callers that retain or
// execute it must close that Snapshot when it is no longer needed. Update
// clones the supplied hooks, so the caller retains ownership of its input.
func (m *Manager) ConfigSnapshot() Config {
	if m == nil {
		return Config{}
	}
	snapshot := m.snapshot.Load()
	if snapshot == nil {
		return Config{}
	}
	return Config{
		Enabled:            snapshot.config.Enabled,
		Ports:              append([]uint16(nil), snapshot.config.Ports...),
		PortRanges:         append([]PortRange(nil), snapshot.config.PortRanges...),
		Domains:            append([]string(nil), snapshot.config.Domains...),
		CA:                 snapshot.config.CA,
		ClientHelloTimeout: snapshot.config.ClientHelloTimeout,
		HandshakeTimeout:   snapshot.config.HandshakeTimeout,
		ReadHeaderTimeout:  snapshot.config.ReadHeaderTimeout,
		RequestTimeout:     snapshot.config.RequestTimeout,
		IdleTimeout:        snapshot.config.IdleTimeout,
		RequestHook:        snapshot.config.RequestHook,
		ResponseHook:       snapshot.config.ResponseHook,
		ScriptHooks:        snapshot.config.ScriptHooks.Clone(),
		Rewrite:            snapshot.config.Rewrite,
		upstreamRootCAs:    snapshot.config.upstreamRootCAs,
	}
}

func (m *Manager) ShouldInspect(port uint16) bool {
	snapshot := m.loadSnapshot()
	if snapshot == nil || !snapshot.config.Enabled {
		return false
	}
	if _, ok := snapshot.ports[port]; ok {
		return true
	}
	for _, portRange := range snapshot.portRanges {
		if port >= portRange.Start && port <= portRange.End {
			return true
		}
	}
	return false
}

func (m *Manager) loadSnapshot() *configSnapshot {
	if m == nil {
		return nil
	}
	return m.snapshot.Load()
}

func (m *Manager) acquireSnapshot() (*configSnapshot, func()) {
	if m == nil {
		return nil, func() {}
	}
	for {
		snapshot := m.snapshot.Load()
		if snapshot == nil {
			return nil, func() {}
		}
		if snapshot.tryAcquire() {
			return snapshot, snapshot.release
		}
	}
}

// InspectClientHello only reads when the manager is enabled for this port.
// Peek data remains in BufferedConn for tls.Server or the original relay.
func (m *Manager) InspectClientHello(conn *N.BufferedConn, port uint16, timeout time.Duration) (info *sniffer.TLSClientHelloInfo, inspected bool, err error) {
	if !m.ShouldInspect(port) {
		return nil, false, nil
	}
	return inspectClientHello(conn, timeout)
}

func inspectClientHello(conn *N.BufferedConn, timeout time.Duration) (info *sniffer.TLSClientHelloInfo, inspected bool, err error) {
	if conn == nil {
		return nil, true, errors.New("nil buffered connection")
	}
	if timeout <= 0 {
		timeout = time.Second
	}
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, true, err
	}
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()

	want := 5 // TLS record header
	for {
		if want > maxClientHelloSize {
			return nil, true, ErrClientHelloTooLarge
		}
		conn.Grow(want)
		_, peekErr := conn.Peek(want)
		available := conn.Buffered()
		if available > 0 {
			data, _ := conn.Peek(available)
			info, err = sniffer.SniffTLSInfo(data)
			if err == nil {
				return info, true, nil
			}
			if !errors.Is(err, sniffer.ErrNoClue) {
				return nil, true, err
			}
		}
		if peekErr != nil {
			return nil, true, peekErr
		}
		want = available + 1
	}
}

// CanIntercept only accepts a complete non-ECH ClientHello with a configured
// SNI. A supplied target domain must agree with SNI; IP-only targets may use
// SNI as the HTTP origin in the dispatcher.
func (m *Manager) CanIntercept(metadata *C.Metadata, hello *sniffer.TLSClientHelloInfo) bool {
	return canIntercept(m.loadSnapshot(), metadata, hello)
}

func canIntercept(snapshot *configSnapshot, metadata *C.Metadata, hello *sniffer.TLSClientHelloInfo) bool {
	if metadata == nil || hello == nil || !metadata.Valid() || hello.HasECH || hello.ServerName == "" {
		return false
	}
	if _, err := netip.ParseAddr(hello.ServerName); err == nil || !domainname.IsDomainName(hello.ServerName) {
		return false
	}
	if snapshot == nil || !snapshot.config.Enabled || !portAllowed(snapshot, metadata.DstPort) {
		return false
	}
	if metadata.Host != "" {
		if _, err := netip.ParseAddr(metadata.Host); err != nil && normalizeDomain(metadata.Host) != normalizeDomain(hello.ServerName) {
			return false
		}
	}
	return domainAllowed(snapshot, hello.ServerName)
}

func portAllowed(snapshot *configSnapshot, port uint16) bool {
	if _, ok := snapshot.ports[port]; ok {
		return true
	}
	for _, portRange := range snapshot.portRanges {
		if port >= portRange.Start && port <= portRange.End {
			return true
		}
	}
	return false
}

func domainAllowed(snapshot *configSnapshot, domain string) bool {
	domain = normalizeDomain(domain)
	if _, ok := snapshot.domains[domain]; ok {
		return true
	}
	for _, suffix := range snapshot.wildcardHost {
		if strings.HasSuffix(domain, "."+suffix) {
			return true
		}
	}
	return false
}

func normalizeDomain(domain string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
}
