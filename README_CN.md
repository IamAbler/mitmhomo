# mitmhomo

[English](README.md) | [简体中文](README_CN.md)

<p align="center">
  <a href="https://github.com/IamAbler/mitmhomo"><img src="https://img.shields.io/github/stars/IamAbler/mitmhomo?style=flat-square" alt="GitHub Stars"></a>
  <a href="https://github.com/IamAbler/mitmhomo/tree/Alpha"><img src="https://img.shields.io/badge/branch-Alpha-blue?style=flat-square" alt="Alpha 分支"></a>
  <a href="https://github.com/IamAbler/mitmhomo"><img src="https://img.shields.io/badge/status-independent%20fork-2ea44f?style=flat-square" alt="独立维护的下游 Fork"></a>
</p>

## 项目概述

mitmhomo 是 Mihomo 的一个分支项目，专注于原生 HTTPS MITM 和可编程 HTTP 请求/响应处理。

MITM 与脚本功能仍处于实验性开发阶段。

## 功能特性

### 继承自 Mihomo 的能力

mitmhomo 保留 Mihomo 的代理和路由能力。更多信息见 [Mihomo 功能介绍](https://github.com/MetaCubeX/mihomo/blob/Alpha/README.md#features)、[Mihomo 文档](https://wiki.metacubex.one/)、[Mihomo 参考配置](https://github.com/MetaCubeX/mihomo/blob/Alpha/docs/config.yaml)和兼容的 [MetaCubeXD Dashboard](https://github.com/MetaCubeX/metacubexd)。

### mitmhomo 新增能力

- 原生 HTTPS MITM，支持 HTTP/1.1 和 HTTP/2；按配置的域名和端口接管流量，并通过 Mihomo 路由。
- HTTP 请求/响应改写和合成响应。
- 用于处理 HTTP 请求/响应的实验性 JavaScript 脚本功能。

## 快速开始

克隆下游仓库，并在仓库根目录构建：

```sh
git clone https://github.com/IamAbler/mitmhomo.git
cd mitmhomo
go mod download
go build -o mitmhomo .
mkdir -p config
```

将下方配置保存为 `config/config.yaml`，把 CA 文件放在同一目录，然后启动本地代理：

```sh
./mitmhomo -d ./config
```

示例监听器在 `127.0.0.1:7890` 接受本地 HTTP 和 SOCKS 代理连接。请将示例 SOCKS5 出站替换为你实际管理且可连接的服务端。

## MITM 配置

| 字段 | 格式和默认值 | 行为 |
| --- | --- | --- |
| `enable` | 布尔值；默认 `false` | 只有显式设为 `true` 才启用 MITM。 |
| `domains` | 域名字符串列表；启用时必填 | 支持 `example.com` 这样的精确名称，以及 `*.example.com` 这样的通配后缀。通配符匹配子域名，不匹配根域名；不接受 IP 地址。 |
| `ports` | 带引号的端口或范围字符串列表；默认 `443` | TCP 目标端口范围为 `1` 至 `65535`；范围使用 `起始端口-结束端口`，包含两端。 |
| `ca-cert` | 文件路径；启用时必填 | 指向有效 CA 证书的路径。 |
| `ca-key` | 文件路径；启用时必填 | 指向对应私钥的路径。在 Unix 系统上，权限不能允许组用户或其他用户访问；可使用 `0600`。 |
| `client-hello-timeout` | 秒数整数；默认 `2`，范围 `1`–`30` | 等待 TLS ClientHello 的最长时间。 |
| `handshake-timeout` | 秒数整数；默认 `10`，范围 `1`–`120` | TLS 握手超时。 |
| `read-header-timeout` | 秒数整数；默认 `10`，范围 `1`–`120` | HTTP 请求头读取超时。 |
| `request-timeout` | 秒数整数；默认 `120`，范围 `1`–`3600` | 请求和响应超时。 |
| `idle-timeout` | 秒数整数；默认 `60`，范围 `1`–`3600` | Keep-alive 空闲超时。 |

CA 路径若为相对路径，将相对于 Mihomo 配置目录解析；该目录由 `-d` 指定，未指定时使用 Mihomo 默认配置目录。绝对路径必须通过 Mihomo 安全路径校验，默认允许配置目录和显式配置的安全路径。

下面的示例包含本地 mixed HTTP/SOCKS 入站和 Mihomo 常规规则路由。请将 SOCKS5 服务端替换为你自己的可连接出站。以 `-d ./config` 启动时，程序会从 `config/mitm-ca.pem` 和 `config/mitm-ca-key.pem` 加载 CA 文件。

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

CA 证书和私钥必须是有效的匹配密钥对；客户端也必须主动信任该 CA，才能接受动态生成的站点证书。mitmhomo 负责加载 CA，不会替用户创建 CA。不得将 CA 私钥提交到 Git 仓库，不得关闭 TLS 证书验证。仅对你有权管理或已获授权的流量启用拦截。

## 已知限制

- MITM 仅处理配置的域名和端口，且 TLS ClientHello 需要包含可用的服务器名称。
- 已接管连接中的 HTTP CONNECT 请求和协议升级暂不支持。

## 从源码构建

克隆源码仓库，并在仓库根目录构建：

```sh
git clone https://github.com/IamAbler/mitmhomo.git
cd mitmhomo
go mod download

# 普通构建
go build -o mitmhomo .

# 使用 gVisor 协议栈构建
go build -tags with_gvisor -o mitmhomo-gvisor .
```

`go.mod` 声明 Go 1.20；Go 1.20 工具链兼容性尚未验证。

## 上游与致谢

mitmhomo 是 [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo/tree/Alpha) 的独立下游 Fork，由 [IamAbler/mitmhomo](https://github.com/IamAbler/mitmhomo) 维护，不属于 MetaCubeX 官方项目。

继承上游的致谢名单：

- [Dreamacro/clash（归档源码镜像）](https://github.com/ShangjinTang/clash-core)
- [SagerNet/sing-box](https://github.com/SagerNet/sing-box)
- [riobard/go-shadowsocks2](https://github.com/riobard/go-shadowsocks2)
- [v2ray/v2ray-core](https://github.com/v2ray/v2ray-core)
- [WireGuard/wireguard-go](https://github.com/WireGuard/wireguard-go)
- [yaling888/clash-plus-pro](https://github.com/yaling888/clash)

## 许可证

本软件与上游项目相同，采用 [GPL-3.0 许可证](LICENSE)。

**In addition, any downstream projects not affiliated with `MetaCubeX` shall not contain the word `mihomo` in their names.**
