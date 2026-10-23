package config

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/metacubex/mihomo/component/mitm"
	"github.com/metacubex/mihomo/component/mitm/httphook"
	domainname "github.com/metacubex/sing/common/metadata"
)

// RawMITM configures the optional HTTP/1.1 HTTPS interception engine.
type RawMITM struct {
	Enable             bool          `yaml:"enable" json:"enable"`
	Domains            []string      `yaml:"domains" json:"domains"`
	Ports              []string      `yaml:"ports" json:"ports"`
	CACertificate      string        `yaml:"ca-cert" json:"ca-cert"`
	CAPrivateKey       string        `yaml:"ca-key" json:"ca-key"`
	ClientHelloTimeout int           `yaml:"client-hello-timeout" json:"client-hello-timeout"`
	HandshakeTimeout   int           `yaml:"handshake-timeout" json:"handshake-timeout"`
	ReadHeaderTimeout  int           `yaml:"read-header-timeout" json:"read-header-timeout"`
	RequestTimeout     int           `yaml:"request-timeout" json:"request-timeout"`
	IdleTimeout        int           `yaml:"idle-timeout" json:"idle-timeout"`
	Rewrite            RawRewrite    `yaml:"rewrite" json:"rewrite"`
	HTTPScript         RawHTTPScript `yaml:"http-script" json:"http-script"`
	GojaProcessor      RawGoja       `yaml:"goja-processor" json:"goja-processor"`
}

func parseMITM(raw RawMITM) (*mitm.Config, error) {
	if !raw.Enable {
		// Keep the default-off path cheap: do not touch configured CA files or
		// create a certificate manager unless interception was explicitly enabled.
		return &mitm.Config{}, nil
	}
	if len(raw.Domains) == 0 {
		return nil, fmt.Errorf("mitm.domains must include at least one exact name or *.suffix pattern")
	}
	domains := make([]string, 0, len(raw.Domains))
	seenDomains := make(map[string]struct{}, len(raw.Domains))
	for _, configured := range raw.Domains {
		domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(configured), "."))
		if strings.HasPrefix(domain, "*.") {
			suffix := strings.TrimPrefix(domain, "*.")
			if _, err := netip.ParseAddr(suffix); err == nil || !domainname.IsDomainName(suffix) {
				return nil, fmt.Errorf("invalid MITM domain pattern %q", configured)
			}
		} else if _, err := netip.ParseAddr(domain); err == nil || !domainname.IsDomainName(domain) {
			return nil, fmt.Errorf("invalid MITM domain %q", configured)
		}
		if _, exists := seenDomains[domain]; exists {
			continue
		}
		seenDomains[domain] = struct{}{}
		domains = append(domains, domain)
	}

	portSpecs := raw.Ports
	if len(portSpecs) == 0 {
		portSpecs = []string{"443"}
	}
	ports := make([]mitm.PortRange, 0, len(portSpecs))
	for _, spec := range portSpecs {
		parts := strings.Split(strings.TrimSpace(spec), "-")
		if len(parts) < 1 || len(parts) > 2 || parts[0] == "" || (len(parts) == 2 && parts[1] == "") {
			return nil, fmt.Errorf("invalid MITM port range %q", spec)
		}
		start, err := parseMITMPort(parts[0])
		if err != nil {
			return nil, fmt.Errorf("invalid MITM port range %q: %w", spec, err)
		}
		end := start
		if len(parts) == 2 {
			end, err = parseMITMPort(parts[1])
			if err != nil {
				return nil, fmt.Errorf("invalid MITM port range %q: %w", spec, err)
			}
		}
		if start > end {
			return nil, fmt.Errorf("invalid MITM port range %q: start exceeds end", spec)
		}
		ports = append(ports, mitm.PortRange{Start: start, End: end})
	}

	clientHelloTimeout, err := parseMITMTimeout("client-hello-timeout", raw.ClientHelloTimeout, 2, 1, 30)
	if err != nil {
		return nil, err
	}
	handshakeTimeout, err := parseMITMTimeout("handshake-timeout", raw.HandshakeTimeout, 10, 1, 120)
	if err != nil {
		return nil, err
	}
	readHeaderTimeout, err := parseMITMTimeout("read-header-timeout", raw.ReadHeaderTimeout, 10, 1, 120)
	if err != nil {
		return nil, err
	}
	requestTimeout, err := parseMITMTimeout("request-timeout", raw.RequestTimeout, 120, 1, 3600)
	if err != nil {
		return nil, err
	}
	idleTimeout, err := parseMITMTimeout("idle-timeout", raw.IdleTimeout, 60, 1, 3600)
	if err != nil {
		return nil, err
	}
	rewriteSnapshot, err := parseMITMRewrite(raw.Rewrite)
	if err != nil {
		return nil, fmt.Errorf("mitm.rewrite: %w", err)
	}
	httpScriptSnapshot, err := httphook.Compile(httphook.Config(raw.HTTPScript))
	if err != nil {
		return nil, fmt.Errorf("mitm.http-script: %w", err)
	}
	gojaFactory, err := parseMITMGoja(raw.GojaProcessor)
	if err != nil {
		return nil, fmt.Errorf("mitm.goja-processor: %w", err)
	}
	certificate, err := mitm.LoadCertificateAuthority(raw.CACertificate, raw.CAPrivateKey)
	if err != nil {
		return nil, err
	}
	return &mitm.Config{
		Enabled:            true,
		Rewrite:            rewriteSnapshot,
		ScriptHooks:        httpScriptSnapshot,
		ProcessorFactory:   gojaFactory,
		PortRanges:         ports,
		Domains:            domains,
		CA:                 certificate,
		ClientHelloTimeout: clientHelloTimeout,
		HandshakeTimeout:   handshakeTimeout,
		ReadHeaderTimeout:  readHeaderTimeout,
		RequestTimeout:     requestTimeout,
		IdleTimeout:        idleTimeout,
	}, nil
}

func parseMITMPort(raw string) (uint16, error) {
	value, err := strconv.ParseUint(strings.TrimSpace(raw), 10, 16)
	if err != nil || value == 0 {
		return 0, fmt.Errorf("port must be between 1 and 65535")
	}
	return uint16(value), nil
}

func parseMITMTimeout(name string, seconds, fallback, minimum, maximum int) (time.Duration, error) {
	if seconds == 0 {
		seconds = fallback
	}
	if seconds < minimum || seconds > maximum {
		return 0, fmt.Errorf("mitm.%s must be between %d and %d seconds", name, minimum, maximum)
	}
	return time.Duration(seconds) * time.Second, nil
}
