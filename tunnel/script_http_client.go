package tunnel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/metacubex/mihomo/component/mitm/scriptapi"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
)

// ScriptHTTPClientFactory creates a short-lived HTTP client whose every
// connection follows Mihomo's normal rule and proxy selection path. The dial
// path is native and never returns through the inbound MITM dispatcher.
func ScriptHTTPClientFactory(allowPrivate bool) (*http.Client, func(), error) {
	return newScriptHTTPClientFactory(allowPrivate, nil)
}

func newScriptHTTPClientFactory(allowPrivate bool, roots *x509.CertPool) (*http.Client, func(), error) {
	transport := &http.Transport{
		MaxIdleConns:           8,
		MaxIdleConnsPerHost:    2,
		MaxConnsPerHost:        2,
		IdleConnTimeout:        30 * time.Second,
		ResponseHeaderTimeout:  15 * time.Second,
		MaxResponseHeaderBytes: 32 << 10,
		ForceAttemptHTTP2:      true,
	}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" && network != "tcp4" && network != "tcp6" {
			return nil, fmt.Errorf("script HTTP client only supports TCP, got %q", network)
		}
		host, port, err := splitScriptAddress(address)
		if err != nil {
			return nil, err
		}
		ip, err := resolveScriptHTTPHost(ctx, host, allowPrivate)
		if err != nil {
			return nil, err
		}
		metadata := scriptHTTPMetadata(host, port, ip)
		return Tunnel.dialMITMNativeTCPWithPinnedIP(ctx, metadata, nil, ip)
	}
	transport.DialTLSContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" && network != "tcp4" && network != "tcp6" {
			return nil, fmt.Errorf("script HTTPS client only supports TCP, got %q", network)
		}
		host, port, err := splitScriptAddress(address)
		if err != nil {
			return nil, err
		}
		ip, err := resolveScriptHTTPHost(ctx, host, allowPrivate)
		if err != nil {
			return nil, err
		}
		metadata := scriptHTTPMetadata(host, port, ip)
		handshake := func(handshakeCtx context.Context, raw net.Conn) (net.Conn, error) {
			secure := tls.Client(raw, &tls.Config{
				ServerName: host,
				RootCAs:    roots,
				MinVersion: tls.VersionTLS12,
				NextProtos: []string{"h2", "http/1.1"},
			})
			if err := secure.HandshakeContext(handshakeCtx); err != nil {
				_ = secure.Close()
				return nil, err
			}
			return secure, nil
		}
		return Tunnel.dialMITMNativeTCPWithPinnedIP(ctx, metadata, handshake, ip)
	}
	client := &http.Client{Transport: transport}
	return client, transport.CloseIdleConnections, nil
}

func splitScriptAddress(address string) (string, uint16, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return "", 0, fmt.Errorf("parse script HTTP target: %w", err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return "", 0, errors.New("script HTTP target has an invalid port")
	}
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "" {
		return "", 0, errors.New("script HTTP target has an empty host")
	}
	return host, uint16(port), nil
}

func resolveScriptHTTPHost(ctx context.Context, host string, allowPrivate bool) (netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap()
		if !allowPrivate && !scriptapi.IsPublicAddress(ip) {
			return netip.Addr{}, errors.New("script HTTP target resolves to a non-public address")
		}
		if ip.IsUnspecified() || ip.IsMulticast() {
			return netip.Addr{}, errors.New("script HTTP target is not a unicast address")
		}
		return ip, nil
	}
	ips, err := resolver.LookupIP(ctx, host)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("resolve script HTTP target %q: %w", host, err)
	}
	if len(ips) == 0 {
		return netip.Addr{}, fmt.Errorf("script HTTP target %q has no address", host)
	}
	for _, ip := range ips {
		if !allowPrivate && !scriptapi.IsPublicAddress(ip) {
			return netip.Addr{}, fmt.Errorf("script HTTP target %q resolves to a non-public address", host)
		}
		if !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() {
			return netip.Addr{}, fmt.Errorf("script HTTP target %q resolves to a non-unicast address", host)
		}
	}
	return ips[0].Unmap(), nil
}

func scriptHTTPMetadata(host string, port uint16, ip netip.Addr) *C.Metadata {
	metadata := &C.Metadata{NetWork: C.TCP, Type: C.TUNNEL, DstPort: port, DstIP: ip.Unmap()}
	if _, err := netip.ParseAddr(host); err != nil {
		metadata.Host = host
	}
	return metadata
}
