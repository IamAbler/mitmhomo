# mitmhomo

[English](README.md) | [简体中文](README_CN.md)

<p align="center">
  <a href="https://github.com/IamAbler/mitmhomo"><img src="https://img.shields.io/github/stars/IamAbler/mitmhomo?style=flat-square" alt="GitHub stars"></a>
  <a href="https://github.com/IamAbler/mitmhomo/tree/Alpha"><img src="https://img.shields.io/badge/branch-Alpha-blue?style=flat-square" alt="Alpha branch"></a>
  <a href="https://github.com/IamAbler/mitmhomo"><img src="https://img.shields.io/badge/status-independent%20fork-2ea44f?style=flat-square" alt="Independently maintained fork"></a>
</p>

## Project Overview

`mitmhomo` is an independently maintained downstream fork based on Mihomo Alpha. It adds native HTTPS MITM and is intended to grow HTTP rewrite and extensible script processing capabilities. The project is maintained separately and does not represent the official MetaCubeX project.

## Features

### Inherited from Mihomo

- HTTP, HTTPS, and SOCKS proxy listeners, with outbound support for protocols including VMess, VLESS, Shadowsocks, Trojan, Snell, TUIC, and Hysteria.
- Built-in DNS with DoH/DoT upstreams and fake IP, plus routing rules based on domains, GEOIP, IP-CIDR, or process.
- Proxy groups with fallback, load balancing, and latency-based selection; remote providers; Linux netfilter TCP redirection; and Mihomo's HTTP REST API controller.

See the [Mihomo feature overview](https://github.com/MetaCubeX/mihomo/blob/Alpha/README.md#features), [Mihomo documentation](https://wiki.metacubex.one/), the [Mihomo reference configuration](https://github.com/MetaCubeX/mihomo/blob/Alpha/docs/config.yaml), and the compatible [MetaCubeXD dashboard](https://github.com/MetaCubeX/metacubexd).

### Added by mitmhomo

- **M1 native HTTPS MITM for HTTP/1.1.** Interception is opt-in and limited by configured target domains and TCP ports. Matching uses the TLS server name (SNI); the request is forwarded using Mihomo's native rules and selected outbound.
- Loads a user-provided CA certificate and private key, then creates per-site certificates when needed.
- Applies updated MITM configuration to new connections on configuration reload and manages intercepted connection timeouts and closure.

HTTP rewrite, redirects, local responses, and JavaScript hooks are planned; they are not implemented in M1.

## Quick Start

Clone the downstream repository and build from its root directory:

```sh
git clone https://github.com/IamAbler/mitmhomo.git
cd mitmhomo
go mod download
go build -o mitmhomo .
mkdir -p config
```

Save the configuration shown below as `config/config.yaml`, provide the CA files in that same directory, then start the local proxy:

```sh
./mitmhomo -d ./config
```

The listener in the example accepts local HTTP and SOCKS proxy connections on `127.0.0.1:7890`. Replace the example SOCKS5 outbound with an endpoint you operate.

## MITM Configuration

| Field | Format and default | Behavior |
| --- | --- | --- |
| `enable` | Boolean; `false` by default | MITM stays off unless explicitly set to `true`. |
| `domains` | List of domain strings; required when enabled | Accepts exact names such as `example.com` and wildcard suffixes such as `*.example.com`. The wildcard matches subdomains, not the apex name. IP addresses are not accepted. |
| `ports` | List of quoted port or range strings; defaults to `443` | Ports are TCP destination ports from `1` to `65535`; ranges use `start-end` and include both endpoints. |
| `ca-cert` | File path; required when enabled | Path to a valid CA certificate. |
| `ca-key` | File path; required when enabled | Path to the matching private key. On Unix, its permissions must not grant access to group or other users; `0600` is suitable. |
| `client-hello-timeout` | Integer seconds; default `2`, range `1`–`30` | Maximum wait for the TLS ClientHello. |
| `handshake-timeout` | Integer seconds; default `10`, range `1`–`120` | TLS handshake timeout. |
| `read-header-timeout` | Integer seconds; default `10`, range `1`–`120` | HTTP request header timeout. |
| `request-timeout` | Integer seconds; default `120`, range `1`–`3600` | Request and response timeout. |
| `idle-timeout` | Integer seconds; default `60`, range `1`–`3600` | Keep-alive idle timeout. |

Relative CA paths resolve under Mihomo's configuration directory, set by `-d` (or the default Mihomo configuration directory). Absolute paths must pass Mihomo's safe-path checks, which allow the configuration directory and configured safe paths.

This example uses a local mixed HTTP/SOCKS listener and Mihomo's normal rule routing. Replace the SOCKS5 server with your own reachable outbound. The CA files are expected at `config/mitm-ca.pem` and `config/mitm-ca-key.pem` when started with `-d ./config`.

```yaml
bind-address: 127.0.0.1
allow-lan: false
mixed-port: 7890
mode: rule

proxies:
  - name: upstream-socks5
    type: socks5
    server: 127.0.0.1
    port: 1080

rules:
  - DOMAIN-SUFFIX,example.com,upstream-socks5
  - MATCH,DIRECT

mitm:
  enable: true
  domains:
    - example.com
    - "*.example.com"
  ports:
    - "443"
  ca-cert: mitm-ca.pem
  ca-key: mitm-ca-key.pem
```

The CA certificate and private key must be a valid matching pair, and the CA must be trusted by each client that should accept the generated site certificates. mitmhomo loads the CA; it does not create the CA for you. Never commit the CA private key. Do not disable TLS certificate verification. Enable interception only for traffic you own or are authorized to manage.

## Development Roadmap

The sequence below is a planning order and may change.

- [x] M1 — Native HTTPS MITM / HTTP/1.1
- [ ] M2 — HTTP Request / Response Rewrite, Redirect, Local Response
- [ ] M3 — HTTP/2 MITM
- [ ] M4 — JavaScript Runtime & HTTP Hooks
- [ ] M5 — HTTP/3 / QUIC MITM

## Known Limitations

- M1 supports HTTP/1.1 only. HTTP/2 and HTTP/3 MITM are not supported.
- HTTP rewrite, redirect, local response, and JavaScript processing are not implemented.
- `go.mod` declares Go 1.20, but compatibility with the Go 1.20 toolchain has not been verified. The M1 test record does not document a specific passing Go version, so this README does not claim one.
- External V2Ray interoperability tests have not been run.
- Real VLESS/VMess Early-data interoperability has not been verified.
- ClientHello traffic without a usable SNI or using ECH is not intercepted. HTTP CONNECT requests and protocol upgrades within an intercepted connection are unsupported.

## Building from Source

The source repository is `https://github.com/IamAbler/mitmhomo.git`. After cloning, the Go module is at the repository root; there is no local `core/` subdirectory.

```sh
git clone https://github.com/IamAbler/mitmhomo.git
cd mitmhomo
go mod download

# Standard build
go build -o mitmhomo .

# Build with the gVisor stack
go build -tags with_gvisor -o mitmhomo-gvisor .
```

`go.mod` declares Go 1.20. This declaration is not a verified minimum for this fork; in particular, Go 1.20 toolchain compatibility remains unverified. The repository does not record an exact Go version that passed the M1 test run.

## Upstream & Credits

mitmhomo is an independent downstream fork of [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo/tree/Alpha), maintained at [IamAbler/mitmhomo](https://github.com/IamAbler/mitmhomo). It is not an official MetaCubeX project.

Credits inherited from upstream:

- [Dreamacro/clash (archived source mirror)](https://github.com/ShangjinTang/clash-core)
- [SagerNet/sing-box](https://github.com/SagerNet/sing-box)
- [riobard/go-shadowsocks2](https://github.com/riobard/go-shadowsocks2)
- [v2ray/v2ray-core](https://github.com/v2ray/v2ray-core)
- [WireGuard/wireguard-go](https://github.com/WireGuard/wireguard-go)
- [yaling888/clash-plus-pro](https://github.com/yaling888/clash)

## License

This software is released under the [GPL-3.0 license](LICENSE), as in the upstream project.

**In addition, any downstream projects not affiliated with `MetaCubeX` shall not contain the word `mihomo` in their names.**
