package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	stdatomic "sync/atomic"
	"time"

	"github.com/metacubex/mihomo/common/atomic"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/loopback"
	"github.com/metacubex/mihomo/component/mitm"
	"github.com/metacubex/mihomo/component/nat"
	"github.com/metacubex/mihomo/component/process"
	"github.com/metacubex/mihomo/component/proxydialer"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/component/slowdown"
	"github.com/metacubex/mihomo/component/sniffer"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/constant/features"
	P "github.com/metacubex/mihomo/constant/provider"
	icontext "github.com/metacubex/mihomo/context"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/tunnel/statistic"

	"golang.org/x/exp/slices"
)

const (
	queueCapacity  = 64  // chan capacity tcpQueue and udpQueue
	senderCapacity = 128 // chan capacity of PacketSender
)

var (
	status        = atomic.NewInt32Enum(Suspend)
	udpInit       sync.Once
	udpQueues     []chan C.PacketAdapter
	natTable      = nat.New()
	rules         []C.Rule
	listeners     = make(map[string]C.InboundListener)
	subRules      map[string][]C.Rule
	proxies       = make(map[string]C.Proxy)
	providers     map[string]P.ProxyProvider
	ruleProviders map[string]P.RuleProvider
	configMux     sync.RWMutex

	// for compatibility, lazy init
	tcpQueue  chan C.ConnContext
	tcpInOnce sync.Once
	udpQueue  chan C.PacketAdapter
	udpInOnce sync.Once

	// Outbound Rule
	mode = Rule

	// default timeout for UDP session
	udpTimeout = 60 * time.Second

	findProcessMode = atomic.NewInt32Enum(process.FindProcessStrict)

	snifferDispatcher *sniffer.Dispatcher
	sniffingEnable    = false
	mitmDispatcher    stdatomic.Pointer[mitm.Manager]
	mitmPublishMu     sync.Mutex

	ruleUpdateCallback = utils.NewCallback[P.RuleProvider]()
)

type tunnel struct{}

var Tunnel = tunnel{}
var _ C.Tunnel = Tunnel
var _ P.Tunnel = Tunnel
var _ proxydialer.Tunnel = Tunnel

func (t tunnel) HandleTCPConn(conn net.Conn, metadata *C.Metadata) {
	connCtx := icontext.NewConnContext(conn, metadata)
	handleTCPConn(connCtx)
}

// UpdateMITMManager atomically publishes the active optional dispatcher.
// A nil manager disables MITM without adding reads to native TCP handling.
func UpdateMITMManager(manager *mitm.Manager) {
	mitmPublishMu.Lock()
	old := mitmDispatcher.Swap(manager)
	mitmPublishMu.Unlock()
	if old != nil && old != manager {
		_ = old.Close()
	}
}

// DialTCP reuses Mihomo's native metadata preprocessing, rule selection,
// retry, proxy dialing, and statistics path for one MITM HTTP request.
func (t tunnel) DialTCP(ctx context.Context, metadata *C.Metadata) (net.Conn, error) {
	return t.dialMITMNativeTCP(ctx, metadata, nil)
}

// DialTCPWithTLSHandshake lets the MITM HTTP transport complete upstream TLS
// inside the native retry path when a proxy returns an EarlyConn. For ordinary
// connections the handshake is completed after the native TCP dial succeeds.
func (t tunnel) DialTCPWithTLSHandshake(ctx context.Context, metadata *C.Metadata, handshake mitm.NativeTLSHandshake) (net.Conn, error) {
	if handshake == nil {
		return nil, errors.New("MITM upstream TLS handshake is unavailable")
	}
	return t.dialMITMNativeTCP(ctx, metadata, handshake)
}

func (t tunnel) dialMITMNativeTCP(ctx context.Context, metadata *C.Metadata, handshake mitm.NativeTLSHandshake) (net.Conn, error) {
	return t.dialMITMNativeTCPWithPinnedIP(ctx, metadata, handshake, netip.Addr{})
}

func (t tunnel) dialMITMNativeTCPWithPinnedIP(ctx context.Context, metadata *C.Metadata, handshake mitm.NativeTLSHandshake, pinnedIP netip.Addr) (net.Conn, error) {
	if metadata == nil || !metadata.Valid() {
		return nil, errors.New("MITM outbound Metadata is invalid")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	dialCtx, cancel := context.WithTimeout(ctx, C.DefaultTCPTimeout)
	defer cancel()

	prepared := metadata.Clone()
	fixMetadata(prepared)
	if err := preHandleMITMMetadata(prepared); err != nil {
		return nil, fmt.Errorf("MITM outbound Metadata preprocessing: %w", err)
	}
	proxy, rule, err := resolveMetadataContext(dialCtx, prepared)
	if err != nil {
		return nil, fmt.Errorf("MITM outbound route selection: %w", err)
	}
	if proxy == nil {
		return nil, errors.New("MITM outbound route selected no proxy")
	}
	dialMetadata := nativeDialMetadata(prepared)
	if pinnedIP.IsValid() {
		dialMetadata = dialMetadata.Clone()
		dialMetadata.Host = ""
		dialMetadata.DstIP = pinnedIP.Unmap()
		dialMetadata.DNSMode = C.DNSNormal
		dialMetadata.RawDstAddr = nil
		dialMetadata.DstGeoIP = nil
		dialMetadata.DstIPASN = ""
	}
	type dialResult struct {
		remote  C.Conn
		tracked C.Conn
		conn    net.Conn
	}
	result, err := retry(dialCtx, func(attemptCtx context.Context) (dialResult, error) {
		remoteConn, err := proxy.DialContext(attemptCtx, dialMetadata)
		if err != nil {
			return dialResult{}, err
		}
		if handshake == nil || !N.NeedHandshake(remoteConn) {
			return dialResult{remote: remoteConn}, nil
		}

		// Native handleTCPConn primes an EarlyConn with the client's first
		// bytes before installing its tracker. MITM has no inbound payload to
		// reuse: the upstream TLS ClientHello is the correct first write, so
		// complete that handshake under retry with tracking already active.
		tracked := statistic.NewTCPTracker(remoteConn, statistic.DefaultManager, prepared, rule, 0, 0, true)
		secureConn, handshakeErr := handshake(attemptCtx, tracked)
		if handshakeErr != nil {
			_ = tracked.Close()
			return dialResult{}, fmt.Errorf("MITM upstream TLS handshake: %w", handshakeErr)
		}
		if secureConn == nil {
			_ = tracked.Close()
			return dialResult{}, errors.New("MITM upstream TLS handshake returned a nil connection")
		}
		return dialResult{tracked: tracked, conn: secureConn}, nil
	}, func(dialErr error) {
		logMetadataErr(prepared, rule, proxy, dialErr)
	})
	if err != nil {
		return nil, err
	}
	if result.tracked != nil {
		logMetadata(prepared, rule, result.tracked)
		return result.conn, nil
	}
	if result.remote == nil {
		return nil, errors.New("MITM native outbound returned no connection")
	}
	logMetadata(prepared, rule, result.remote)
	tracked := statistic.NewTCPTracker(result.remote, statistic.DefaultManager, prepared, rule, 0, 0, true)
	if handshake == nil {
		return tracked, nil
	}
	secureConn, err := handshake(dialCtx, tracked)
	if err != nil {
		_ = tracked.Close()
		return nil, fmt.Errorf("MITM upstream TLS handshake: %w", err)
	}
	if secureConn == nil {
		_ = tracked.Close()
		return nil, errors.New("MITM upstream TLS handshake returned a nil connection")
	}
	return secureConn, nil
}

func initUDP() {
	numUDPWorkers := 4
	if num := runtime.GOMAXPROCS(0); num > numUDPWorkers {
		numUDPWorkers = num
	}

	udpQueues = make([]chan C.PacketAdapter, numUDPWorkers)
	for i := 0; i < numUDPWorkers; i++ {
		queue := make(chan C.PacketAdapter, queueCapacity)
		udpQueues[i] = queue
		go processUDP(queue)
	}
}

func (t tunnel) HandleUDPPacket(packet C.UDPPacket, metadata *C.Metadata) {
	udpInit.Do(initUDP)

	packetAdapter := C.NewPacketAdapter(packet, metadata)
	key := packetAdapter.Key()

	hash := utils.MapHash(key)
	queueNo := uint(hash) % uint(len(udpQueues))

	select {
	case udpQueues[queueNo] <- packetAdapter:
	default:
		packet.Drop()
	}
}

func (t tunnel) NatTable() C.NatTable {
	return natTable
}

func (t tunnel) Proxies() map[string]C.Proxy {
	return proxies
}

func (t tunnel) Providers() map[string]P.ProxyProvider {
	return providers
}

func (t tunnel) RuleProviders() map[string]P.RuleProvider {
	return ruleProviders
}

func (t tunnel) RuleUpdateCallback() *utils.Callback[P.RuleProvider] {
	return ruleUpdateCallback
}

func OnSuspend() {
	status.Store(Suspend)
}

func OnInnerLoading() {
	status.Store(Inner)
}

func OnRunning() {
	status.Store(Running)
}

func Status() TunnelStatus {
	return status.Load()
}

func SetSniffing(b bool) {
	if snifferDispatcher.Enable() {
		configMux.Lock()
		sniffingEnable = b
		configMux.Unlock()
	}
}

func IsSniffing() bool {
	return sniffingEnable
}

// TCPIn return fan-in queue
// Deprecated: using Tunnel instead
func TCPIn() chan<- C.ConnContext {
	tcpInOnce.Do(func() {
		tcpQueue = make(chan C.ConnContext, queueCapacity)
		go func() {
			for connCtx := range tcpQueue {
				go handleTCPConn(connCtx)
			}
		}()
	})
	return tcpQueue
}

// UDPIn return fan-in udp queue
// Deprecated: using Tunnel instead
func UDPIn() chan<- C.PacketAdapter {
	udpInOnce.Do(func() {
		udpQueue = make(chan C.PacketAdapter, queueCapacity)
		go func() {
			for packet := range udpQueue {
				Tunnel.HandleUDPPacket(packet, packet.Metadata())
			}
		}()
	})
	return udpQueue
}

// NatTable return nat table
func NatTable() C.NatTable {
	return natTable
}

// Rules return all rules
func Rules() []C.Rule {
	return rules
}

func Listeners() map[string]C.InboundListener {
	return listeners
}

// UpdateRules handle update rules
func UpdateRules(newRules []C.Rule, newSubRule map[string][]C.Rule, rp map[string]P.RuleProvider) {
	configMux.Lock()
	rules = newRules
	ruleProviders = rp
	subRules = newSubRule
	configMux.Unlock()
}

// Proxies return all proxies
func Proxies() map[string]C.Proxy {
	return proxies
}

// Providers return all compatible providers
func Providers() map[string]P.ProxyProvider {
	return providers
}

// RuleProviders return all loaded rule providers
func RuleProviders() map[string]P.RuleProvider {
	return ruleProviders
}

// UpdateProxies handle update proxies
func UpdateProxies(newProxies map[string]C.Proxy, newProviders map[string]P.ProxyProvider) {
	configMux.Lock()
	proxies = newProxies
	providers = newProviders
	configMux.Unlock()
}

func UpdateListeners(newListeners map[string]C.InboundListener) {
	configMux.Lock()
	defer configMux.Unlock()
	listeners = newListeners
}

func UpdateSniffer(dispatcher *sniffer.Dispatcher) {
	configMux.Lock()
	snifferDispatcher = dispatcher
	sniffingEnable = dispatcher.Enable()
	configMux.Unlock()
}

// Mode return current mode
func Mode() TunnelMode {
	return mode
}

// SetMode change the mode of tunnel
func SetMode(m TunnelMode) {
	mode = m
}

func FindProcessMode() process.FindProcessMode {
	return findProcessMode.Load()
}

// SetFindProcessMode replace SetAlwaysFindProcess
// always find process info if legacyAlways = true or mode.Always() = true, may be increase many memory
func SetFindProcessMode(mode process.FindProcessMode) {
	findProcessMode.Store(mode)
}

func isHandle(t C.Type) bool {
	status := status.Load()
	return status == Running || (status == Inner && t == C.INNER)
}

func fixMetadata(metadata *C.Metadata) {
	// first unmap dstIP
	metadata.DstIP = metadata.DstIP.Unmap()
	// handle IP string on host
	if ip, err := netip.ParseAddr(metadata.Host); err == nil {
		metadata.DstIP = ip.Unmap()
		metadata.Host = ""
	}
}

func nativeDialMetadata(metadata *C.Metadata) *C.Metadata {
	dialMetadata := metadata
	if metadata != nil && len(metadata.Host) > 0 {
		if node, ok := resolver.DefaultHosts.Search(metadata.Host, false); ok {
			if dstIP, _ := node.RandIP(); !resolver.IsFakeIP(dstIP) {
				metadata.DstIP = dstIP
				metadata.DNSMode = C.DNSHosts
				dialMetadata = dialMetadata.Pure()
			}
		}
	}
	return dialMetadata
}

func needLookupIP(metadata *C.Metadata) bool {
	return resolver.MappingEnabled() && metadata.Host == "" && metadata.DstIP.IsValid()
}

func preHandleMetadata(metadata *C.Metadata) error {
	return preHandleMetadataWithExplicitIP(metadata, false)
}

// preHandleMITMMetadata keeps an explicit IP URL target from being reverse
// mapped to a hostname associated with the inbound connection. Domain targets
// still pass through the normal Hosts and mapping preprocessing path.
func preHandleMITMMetadata(metadata *C.Metadata) error {
	if metadata == nil {
		return errors.New("MITM outbound Metadata is nil")
	}
	preserveExplicitIP := metadata.Host == "" && metadata.DstIP.IsValid()
	return preHandleMetadataWithExplicitIP(metadata, preserveExplicitIP)
}

func preHandleMetadataWithExplicitIP(metadata *C.Metadata, preserveExplicitIP bool) error {
	if metadata == nil {
		return errors.New("Metadata is nil")
	}
	// preprocess enhanced-mode metadata
	if needLookupIP(metadata) {
		if !preserveExplicitIP {
			host, exist := resolver.FindHostByIP(metadata.DstIP)
			if exist {
				metadata.Host = host
				metadata.DNSMode = C.DNSMapping
				if resolver.IsFakeIP(metadata.DstIP) {
					// only clear dstIP if it is confirmed to be a fake IP
					metadata.DstIP = netip.Addr{}
					metadata.DNSMode = C.DNSFakeIP
				} else if node, ok := resolver.DefaultHosts.Search(host, false); ok {
					// redir-host should lookup the hosts
					metadata.DstIP, _ = node.RandIP()
				} else if node != nil && node.IsDomain {
					metadata.Host = node.Domain
				}
			} else if resolver.IsFakeIP(metadata.DstIP) {
				return fmt.Errorf("fake DNS record %s missing", metadata.DstIP)
			}
		}
	} else if node, ok := resolver.DefaultHosts.Search(metadata.Host, true); ok {
		// try use domain mapping
		metadata.Host = node.Domain
	}

	return nil
}

func prepareMITMOrigin(metadata *C.Metadata, hello *sniffer.TLSClientHelloInfo) (*C.Metadata, error) {
	if metadata == nil || hello == nil || hello.ServerName == "" {
		return nil, errors.New("MITM origin requires Metadata and SNI")
	}
	origin := metadata.Clone()
	if resolver.IsFakeIP(origin.DstIP) {
		// A missing Fake-IP mapping remains a failed pre-handle on the original
		// Metadata. A configured, validated SNI may recover only this independent
		// origin copy, followed by the normal pre-handle.
		origin.DstIP = netip.Addr{}
		origin.DNSMode = C.DNSNormal
		origin.Host = hello.ServerName
	} else if origin.Host == "" {
		origin.Host = hello.ServerName
	}
	if err := preHandleMetadata(origin); err != nil {
		return nil, err
	}
	if !origin.Valid() {
		return nil, errors.New("MITM origin Metadata is invalid after preprocessing")
	}
	return origin, nil
}

func resolveMetadata(metadata *C.Metadata) (proxy C.Proxy, rule C.Rule, err error) {
	return resolveMetadataContext(context.Background(), metadata)
}

func resolveMetadataContext(ctx context.Context, metadata *C.Metadata) (proxy C.Proxy, rule C.Rule, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if metadata.SpecialProxy != "" {
		var exist bool
		proxy, exist = proxies[metadata.SpecialProxy]
		if !exist {
			err = fmt.Errorf("proxy %s not found", metadata.SpecialProxy)
		}
		return
	}
	var (
		resolved             bool
		attemptProcessLookup = metadata.Type != C.INNER
	)

	if node, ok := resolver.DefaultHosts.Search(metadata.Host, false); ok {
		metadata.DstIP, _ = node.RandIP()
		resolved = true
	}

	helper := C.RuleMatchHelper{
		ResolveIP: func() {
			if !resolved && metadata.Host != "" && !metadata.Resolved() {
				lookupCtx, cancel := context.WithTimeout(ctx, resolver.DefaultDNSTimeout)
				defer cancel()
				ip, err := resolver.ResolveIP(lookupCtx, metadata.Host)
				if err != nil {
					log.Debugln("[DNS] resolve %s error: %s", metadata.Host, err.Error())
				} else {
					log.Debugln("[DNS] %s --> %s", metadata.Host, ip.String())
					metadata.DstIP = ip
				}
				resolved = true
			}
		},
		FindProcess: func() {
			if attemptProcessLookup {
				attemptProcessLookup = false
				if !features.CMFA {
					// normal check for process
					uid, path, err := process.FindProcessName(metadata.NetWork.String(), metadata.SrcIP, int(metadata.SrcPort))
					if err != nil {
						log.Debugln("[Process] find process error for %s: %v", metadata.String(), err)
					} else {
						metadata.Process = filepath.Base(path)
						metadata.ProcessPath = path
						metadata.Uid = uid

						if pkg, err := process.FindPackageName(metadata); err == nil { // for android (not CMFA) package names
							metadata.Process = pkg
						}
					}
				} else {
					// check package names
					pkg, err := process.FindPackageName(metadata)
					if err != nil {
						log.Debugln("[Process] find process error for %s: %v", metadata.String(), err)
					} else {
						metadata.Process = pkg
					}
				}
			}
		},
		CheckPassRule: func(adapterName string) bool {
			adapter, ok := proxies[adapterName]
			if !ok {
				return false
			}
			for a := adapter; a != nil; a = a.Unwrap(metadata, false) {
				if a.Type() == C.PassRule {
					return true
				}
			}
			return false
		},
	}

	switch FindProcessMode() {
	case process.FindProcessAlways:
		helper.FindProcess()
		helper.FindProcess = nil
	case process.FindProcessOff:
		helper.FindProcess = nil
	}

	switch mode {
	case Direct:
		proxy = proxies["DIRECT"]
	case Global:
		proxy = proxies["GLOBAL"]
	// Rule
	default:
		proxy, rule, err = matchContext(ctx, metadata, helper)
	}
	return
}

// processUDP starts a loop to handle udp packet
func processUDP(queue chan C.PacketAdapter) {
	for conn := range queue {
		handleUDPConn(conn)
	}
}

func handleUDPConn(packet C.PacketAdapter) {
	if !isHandle(packet.Metadata().Type) {
		packet.Drop()
		return
	}

	metadata := packet.Metadata()
	if !metadata.Valid() {
		packet.Drop()
		log.Warnln("[Metadata] not valid: %#v", metadata)
		return
	}
	fixMetadata(metadata) // fix some metadata not set via metadata.SetRemoteAddr or metadata.SetRemoteAddress

	if err := preHandleMetadata(metadata.Clone()); err != nil { // precheck without modify metadata
		packet.Drop()
		log.Debugln("[Metadata PreHandle] error: %s", err)
		return
	}

	key := packet.Key()
	sender, loaded := natTable.GetOrCreate(key, func() C.PacketSender {
		sender := newPacketSender()
		if sniffingEnable && snifferDispatcher.Enable() {
			return snifferDispatcher.UDPSniff(packet, sender)
		}
		return sender
	})
	if !loaded {
		dial := func() (C.PacketConn, C.WriteBackProxy, error) {
			originMetadata := metadata  // save origin metadata
			metadata = metadata.Clone() // don't modify PacketAdapter's metadata

			if err := sender.DoSniff(metadata); err != nil {
				log.Warnln("[UDP] DoSniff error: %s", err.Error())
				return nil, nil, err
			}

			_ = preHandleMetadata(metadata) // error was pre-checked

			proxy, rule, err := resolveMetadata(metadata)
			if err != nil {
				log.Warnln("[UDP] Parse metadata failed: %s", err.Error())
				return nil, nil, err
			}

			dialMetadata := metadata.Pure()
			ctx, cancel := context.WithTimeout(context.Background(), C.DefaultUDPTimeout)
			defer cancel()
			rawPc, err := retry(ctx, func(ctx context.Context) (C.PacketConn, error) {
				return proxy.ListenPacketContext(ctx, dialMetadata)
			}, func(err error) {
				logMetadataErr(metadata, rule, proxy, err)
			})
			if err != nil {
				return nil, nil, err
			}
			logMetadata(metadata, rule, rawPc)

			pc := statistic.NewUDPTracker(rawPc, statistic.DefaultManager, metadata, rule, 0, 0, true)

			sender.AddMapping(originMetadata, dialMetadata)
			oAddrPort := dialMetadata.AddrPort()
			writeBackProxy := nat.NewWriteBackProxy(packet)

			go handleUDPToLocal(writeBackProxy, pc, sender, key, oAddrPort)
			return pc, writeBackProxy, nil
		}

		go func() {
			pc, proxy, err := dial()
			if err != nil {
				sender.Close()
				natTable.Delete(key)
				return
			}
			sender.Process(pc, proxy)
		}()
	}
	sender.Send(packet) // nonblocking
}

func snapshotMITMMetadata(manager *mitm.Manager, metadata *C.Metadata) (*C.Metadata, bool) {
	if manager == nil || metadata == nil || !manager.ShouldInspect(metadata.DstPort) {
		return nil, false
	}
	return metadata.Clone(), true
}

func handleTCPConn(connCtx C.ConnContext) {
	if !isHandle(connCtx.Metadata().Type) {
		_ = connCtx.Conn().Close()
		return
	}

	defer func(conn net.Conn) {
		_ = conn.Close()
	}(connCtx.Conn())

	metadata := connCtx.Metadata()
	if !metadata.Valid() {
		log.Warnln("[Metadata] not valid: %#v", metadata)
		return
	}
	fixMetadata(metadata) // fix some metadata not set via metadata.SetRemoteAddr or metadata.SetRemoteAddress
	mitmPublishMu.Lock()
	manager := mitmDispatcher.Load()
	var binding *mitm.Connection
	if manager != nil {
		binding = manager.Bind(metadata.DstPort)
	}
	mitmPublishMu.Unlock()
	defer binding.Close()
	mitmShouldInspect := binding != nil
	var mitmCheckMetadata *C.Metadata
	if mitmShouldInspect {
		mitmCheckMetadata = metadata.Clone()
	}

	preHandleFailed := false
	if err := preHandleMetadata(metadata); err != nil {
		log.Debugln("[Metadata PreHandle] error: %s", err)
		preHandleFailed = true
	}

	conn := connCtx.Conn()
	conn.ResetPeeked() // reset before sniffer
	if sniffingEnable && snifferDispatcher.Enable() {
		// Try to sniff a domain when `preHandleMetadata` failed, this is usually
		// caused by a "Fake DNS record missing" error when enhanced-mode is fake-ip.
		if snifferDispatcher.TCPSniff(conn, metadata) {
			// we now have a domain name
			preHandleFailed = false
			// Preserve the existing Sniffer override decision when it ran.
			if mitmShouldInspect {
				mitmCheckMetadata = metadata.Clone()
			}
		}
	}

	if mitmShouldInspect {
		outcome, mitmErr := binding.Dispatch(context.Background(), conn, mitmCheckMetadata, func(hello *sniffer.TLSClientHelloInfo) (*C.Metadata, error) {
			return prepareMITMOrigin(metadata, hello)
		}, Tunnel.DialTCPWithTLSHandshake)
		if mitmErr != nil {
			log.Debugln("[MITM] connection handling error: %s", mitmErr)
		}
		if outcome != mitm.DispatchUnmatched || mitmErr != nil {
			return
		}
	}

	// If both trials have failed, we can do nothing but give up
	if preHandleFailed {
		log.Debugln("[Metadata PreHandle] failed to sniff a domain for connection %s --> %s, give up",
			metadata.SourceDetail(), metadata.RemoteAddress())
		return
	}

	peekMutex := sync.Mutex{}
	if !conn.Peeked() {
		peekMutex.Lock()
		go func() {
			defer peekMutex.Unlock()
			_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			_, _ = conn.Peek(1)
			_ = conn.SetReadDeadline(time.Time{})
		}()
	}

	proxy, rule, err := resolveMetadata(metadata)
	if err != nil {
		log.Warnln("[Metadata] parse failed: %s", err.Error())
		return
	}

	dialMetadata := nativeDialMetadata(metadata)

	var peekBytes []byte
	var peekLen int

	ctx, cancel := context.WithTimeout(context.Background(), C.DefaultTCPTimeout)
	defer cancel()
	remoteConn, err := retry(ctx, func(ctx context.Context) (remoteConn C.Conn, err error) {
		remoteConn, err = proxy.DialContext(ctx, dialMetadata)
		if err != nil {
			return
		}

		if N.NeedHandshake(remoteConn) {
			defer func() {
				if err != nil {
					_ = remoteConn.Close()
					for _, chain := range remoteConn.Chains() {
						if chain == "REJECT" {
							err = nil
							return
						}
					}
					remoteConn = nil
				}
			}()
			peekMutex.Lock()
			defer peekMutex.Unlock()
			peekBytes, _ = conn.Peek(conn.Buffered())
			_, err = remoteConn.Write(peekBytes)
			if err != nil {
				return
			}
			if peekLen = len(peekBytes); peekLen > 0 {
				_, _ = conn.Discard(peekLen)
			}
		}
		return
	}, func(err error) {
		logMetadataErr(metadata, rule, proxy, err)
	})
	if err != nil {
		return
	}
	logMetadata(metadata, rule, remoteConn)

	remoteConn = statistic.NewTCPTracker(remoteConn, statistic.DefaultManager, metadata, rule, int64(peekLen), 0, true)
	defer func(remoteConn C.Conn) {
		_ = remoteConn.Close()
	}(remoteConn)

	_ = conn.SetReadDeadline(time.Now()) // stop unfinished peek
	peekMutex.Lock()
	defer peekMutex.Unlock()
	_ = conn.SetReadDeadline(time.Time{}) // reset
	handleSocket(conn, remoteConn)
}

func logMetadataErr(metadata *C.Metadata, rule C.Rule, proxy C.ProxyAdapter, err error) {
	if rule == nil {
		log.Warnln("[%s] dial %s %s --> %s error: %s", strings.ToUpper(metadata.NetWork.String()), proxy.Name(), metadata.SourceDetail(), metadata.RemoteAddress(), err.Error())
	} else {
		log.Warnln("[%s] dial %s (match %s/%s) %s --> %s error: %s", strings.ToUpper(metadata.NetWork.String()), proxy.Name(), rule.RuleType().String(), rule.Payload(), metadata.SourceDetail(), metadata.RemoteAddress(), err.Error())
	}
}

func logMetadata(metadata *C.Metadata, rule C.Rule, remoteConn C.Connection) {
	switch {
	case metadata.SpecialProxy != "":
		log.Infoln("[%s] %s --> %s using %s", strings.ToUpper(metadata.NetWork.String()), metadata.SourceDetail(), metadata.RemoteAddress(), remoteConn.Chains().String())
	case rule != nil:
		if rule.Payload() != "" {
			log.Infoln("[%s] %s --> %s match %s using %s", strings.ToUpper(metadata.NetWork.String()), metadata.SourceDetail(), metadata.RemoteAddress(), fmt.Sprintf("%s(%s)", rule.RuleType().String(), rule.Payload()), remoteConn.Chains().String())
		} else {
			log.Infoln("[%s] %s --> %s match %s using %s", strings.ToUpper(metadata.NetWork.String()), metadata.SourceDetail(), metadata.RemoteAddress(), rule.RuleType().String(), remoteConn.Chains().String())
		}
	case mode == Global:
		log.Infoln("[%s] %s --> %s using GLOBAL", strings.ToUpper(metadata.NetWork.String()), metadata.SourceDetail(), metadata.RemoteAddress())
	case mode == Direct:
		log.Infoln("[%s] %s --> %s using DIRECT", strings.ToUpper(metadata.NetWork.String()), metadata.SourceDetail(), metadata.RemoteAddress())
	default:
		log.Infoln("[%s] %s --> %s doesn't match any rule using %s", strings.ToUpper(metadata.NetWork.String()), metadata.SourceDetail(), metadata.RemoteAddress(), remoteConn.Chains().String())
	}
}

func match(metadata *C.Metadata, helper C.RuleMatchHelper) (C.Proxy, C.Rule, error) {
	return matchContext(context.Background(), metadata, helper)
}

func matchContext(ctx context.Context, metadata *C.Metadata, helper C.RuleMatchHelper) (C.Proxy, C.Rule, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	configMux.RLock()
	defer configMux.RUnlock()

	var rematchChain []string
	for {
		var rematchProxy C.Proxy
		var rematchRule C.Rule
	GetRules:
		for _, rule := range getRules(metadata) {
			if matched, ada := rule.Match(metadata, helper); matched {
				adapter, ok := proxies[ada]
				if !ok {
					continue
				}

				// parse multi-layer nesting
				for adapter := adapter; adapter != nil; adapter = adapter.Unwrap(metadata, false) {
					if adapter.Type() == C.Pass {
						log.Debugln("%s match Pass rule", adapter.Name())
						continue GetRules
					}
					if adapter.Type() == C.Rematch {
						log.Debugln("%s match Rematch rule", adapter.Name())
						rematchProxy = adapter
						rematchRule = rule
						break GetRules
					}
				}

				if metadata.NetWork == C.UDP && !adapter.SupportUDP() {
					log.Debugln("%s UDP is not supported", adapter.Name())
					continue
				}

				return adapter, rule, nil
			}
		}
		if rematchProxy != nil {
			if slices.Contains(rematchChain, rematchProxy.Name()) {
				log.Warnln("[Rule] rematch cycle detected on %s", rematchProxy.Name())
				return rematchProxy, rematchRule, nil
			}
			rematchChain = append(rematchChain, rematchProxy.Name())
			conn, err := rematchProxy.DialContext(ctx, metadata) // not a real connection, just for metadata update
			if conn != nil {
				_ = conn.Close()
			}
			if err != nil {
				log.Warnln("[Rule] rematch proxy %s failed to update metadata: %s", rematchProxy.Name(), err)
				return rematchProxy, rematchRule, nil
			}
			log.Debugln("[Rule] rematch proxy %s update metadata to rematch-name=%q sub-rule=%q", rematchProxy.Name(), metadata.InName, metadata.SpecialRules)
			continue
		}
		return proxies["DIRECT"], nil, nil
	}
}

func getRules(metadata *C.Metadata) []C.Rule {
	if sr, ok := subRules[metadata.SpecialRules]; ok {
		log.Debugln("[Rule] use %s rules", metadata.SpecialRules)
		return sr
	} else {
		log.Debugln("[Rule] use default rules")
		return rules
	}
}

func shouldStopRetry(err error) bool {
	if errors.Is(err, resolver.ErrIPNotFound) {
		return true
	}
	if errors.Is(err, resolver.ErrIPVersion) {
		return true
	}
	if errors.Is(err, resolver.ErrIPv6Disabled) {
		return true
	}
	if errors.Is(err, loopback.ErrReject) {
		return true
	}
	return false
}

func retry[T any](ctx context.Context, ft func(context.Context) (T, error), fe func(err error)) (t T, err error) {
	s := slowdown.New()
	for i := 0; i < 10; i++ {
		t, err = ft(ctx)
		if err != nil {
			if fe != nil {
				fe(err)
			}
			if shouldStopRetry(err) {
				return
			}
			if s.Wait(ctx) == nil {
				continue
			} else {
				return
			}
		} else {
			break
		}
	}
	return
}
