# Nimbus —— 独立安全代理系统（原型）

> 一个本地 HTTP/SOCKS5 代理 + VPS 服务端组成的加密隧道原型。使用 Go 实现，外层为 TLS 1.3，目标地址只在加密帧内传输。

## 状态

这是**实验原型**，不是生产级安全产品。仅证明在测试时的网络路径下功能可用，不构成长期抗封锁保证。

## 架构

```
本地应用
  → 本地 HTTP CONNECT / SOCKS5 代理 (127.0.0.1:34133)
  → TLS 1.3 外层链路（正常 SNI / ALPN h2，Web 外壳）
  → VPS 服务端
  → 目标网站（地址只在加密隧道内出现）
```

- 传输：TCP + TLS 1.3（ALPN `h2`，带 Web 外壳）或 QUIC/UDP（ALPN `h3`，纯隧道）；客户端 `transport` 支持 `tcp` / `quic` / `auto`，默认 `auto`（TCP 优先，失败回退 QUIC）
- 地址族偏好：`prefer_family` 支持 `ipv4` / `ipv6` / `auto`，默认 `ipv4`；域名解析后按偏好排序拨号，字面量地址直接使用
- 会话密钥：TCP 路径由 TLS exporter 派生，QUIC 路径由 PSK + 双 nonce 经 HKDF 派生；均为标准库 AES-GCM 帧加密
- 认证：HMAC 挑战-响应 + 随机 nonce + 重放表；失败返回普通 404
- 本地代理：HTTP CONNECT、SOCKS5 CONNECT、Socks5 远端 DNS
- 服务端：普通用户进程，不安装 systemd 服务；直接访问 `/` 返回正常网页，未知路径返回 404

## 目录

```
client/  本地代理与隧道客户端
server/  VPS 服务端
shared/  帧格式、加密、认证
configs/ 配置模板（真实配置不得提交）
scripts/ 部署与清理脚本（示例）
reports/ 报告（公开版见 public/）
tools/   诊断工具
```

## 客户端 Release（Windows）

可直接下载 [dist/nimbus-client-windows.zip](dist/nimbus-client-windows.zip)。压缩包内含编译好的 `nimbus-client.exe`、`run.bat`、脱敏 `config.json` 与快速说明。解压后按下方客户端教程填写配置，双击 `run.bat` 即可启动。

## 详细教程

- [服务端部署教程（VPS）](docs/SERVER_SETUP_zh.md)
- [客户端使用教程（Windows，含 release 压缩包说明）](docs/CLIENT_SETUP_zh.md)

## 构建

```bash
go test ./...
# 服务端（Linux）
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o build/nimbus-server ./server
# 客户端（Windows）
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o build/nimbus-client.exe ./client
```

## 配置

- 复制 `configs/config.example.json` 为本地私有配置，填写真实 `server_addr`、`sni`、`psk`、`ca_pem_file`
- `server_addr` 建议填域名（如 `vpn.example.net:44444`）而非写死 IP，这样 `prefer_family` 才能按 A/AAAA 记录排序拨号
- `transport` / `prefer_family` 可省略，默认分别为 `auto` / `ipv4`
- 复制 `configs/server.example.env` 中字段为 `server.json`，填写服务端监听地址、证书路径与同一 PSK；服务端可选 `quic_listen_addr` 开启 UDP 监听
- PSK 必须是 **32 字节的 base64**，两端必须一致
- `ca_pem_file` 指向服务端证书的信任锚（证书 pinning）；生产配置不得设置 `InsecureSkipVerify`
- **真实配置、PSK、证书、日志不得提交公开仓库**

## 运行与验证

```bash
# 服务端（VPS）
./nimbus-server -config server.json

# 客户端（本机）
./nimbus-client.exe -config client.json

# 验证（不要使用其他本地代理作为证据链）
curl -x http://127.0.0.1:34133 https://example.com
curl --socks5-hostname 127.0.0.1:34133 https://example.com
```

服务端日志只记录连接号、流号、错误类别，不记录目标域名或 IP。

## 回滚与清理

1. 按 `server.pid` 精确停止 VPS 进程，确认监听端口释放；
2. 停止本地客户端进程，确认 `127.0.0.1:34133` 释放；
3. 恢复系统代理设置为测试前状态；
4. 删除临时脚本与本地日志；
5. 不改动 VPS 上任何其他服务、端口或防火墙规则。

可使用 `scripts/cleanup.sh` 作为示例。

## 已知限制

- 未做长期稳定性、并发压力和视频码率测试；不声称 1080p/2K/4K 播放验收；
- Web 外壳不是加密替代品，也不构成抗主动探测的充分条件；
- 协议安全性未经过外部审计。
