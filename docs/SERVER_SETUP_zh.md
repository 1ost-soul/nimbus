# 服务端部署教程（VPS）

> 本文所有域名、端口、路径都是**脱敏示例**（`vpn.example.net`、`44444`、`/home/agent/nimbus`）。
> 请替换为你自己的值。**不要把真实域名、IP、PSK、证书或日志提交到公开仓库。**

服务端是一个**普通用户进程**，不需要 systemd，也不改动 VPS 上任何现有服务。

---

## 前置条件

- 一台有公网 IP 的 VPS，安全组/防火墙放通 **TCP 44444**、**UDP 44444**（裸 QUIC）和 **UDP 44445**（WebTransport，示例端口）
- 一个指向该 VPS 的域名（示例 `vpn.example.net`），用于 TLS 证书和客户端 SNI
- TLS 证书与私钥（Let's Encrypt 或自签均可），路径对运行用户可读
- 一个普通用户（示例 `agent`）；不要用 root 运行
- 确认 44444 / 44445 未被其他程序占用：
  ```bash
  ss -tulpn | grep -E '44444|44445'
  ```

---

## 1. 准备二进制

在**你自己的电脑**上交叉编译（不要在 VPS 上安装 Go）：

```bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o nimbus-server ./server
```

上传到 VPS：

```bash
scp nimbus-server agent@你的VPS:/home/agent/nimbus/
ssh agent@你的VPS
chmod +x /home/agent/nimbus/nimbus-server
```

---

## 2. 生成 PSK

PSK 是**32 字节的 base64 字符串**，两端必须完全一致：

```bash
openssl rand -base64 32
```

把输出记到私有位置（**不要提交**）。客户端的 `psk` 字段填同一个值。

---

## 3. 写 server.json

在 `/home/agent/nimbus/server.json` 创建：

```json
{
  "listen_addr": "[::]:44444",
  "quic_listen_addr": ":44444",
  "webtransport_listen_addr": ":44445",
  "cert_file": "/path/to/fullchain.pem",
  "key_file": "/path/to/privkey.pem",
  "psk": "REPLACE_WITH_BASE64_32_BYTE_KEY",
  "web_root_html": "<!doctype html><h1>It works.</h1>"
}
```

字段说明：

| 字段 | 说明 |
|---|---|
| `listen_addr` | TCP 监听地址。`[::]:44444` 为双栈；若只要 IPv4 用 `0.0.0.0:44444` |
| `quic_listen_addr` | UDP/QUIC 监听地址。留空或删除则不启用 QUIC |
| `webtransport_listen_addr` | HTTP/3 WebTransport 独立 UDP 监听地址。留空或删除则不启用 WebTransport；需与裸 QUIC 使用不同端口 |
| `cert_file` / `key_file` | TLS 证书与私钥路径 |
| `psk` | 上一步生成的 32 字节 base64 |
| `web_root_html` | 访问 `/` 时返回的普通网页内容（Web 外壳），可选 |

> TCP 和 UDP 共用 44444 是合法的（不同传输层协议互不冲突）。WebTransport 需要额外的 UDP 端口（示例 44445），因为同一 UDP 套接字不能同时承载裸 QUIC 隧道和 HTTP/3 服务。

---

## 4. 启动与验证

```bash
cd /home/agent/nimbus
nohup ./nimbus-server -config server.json >> server.log 2>&1 &
echo $! > server.pid
```

确认监听：

```bash
ss -tulpn | grep -E '44444|44445'
```

预期看到 `tcp LISTEN`（44444）、`udp UNCONN`（44444 裸 QUIC）和 `udp UNCONN`（44445 WebTransport）。

验证 Web 外壳：

```bash
curl -k https://vpn.example.net:44444/
# 应返回 It works.
curl -k https://vpn.example.net:44444/notfound
# 应返回 404
```

---

## 5. 停止与回滚

```bash
kill "$(cat /home/agent/nimbus/server.pid)"
# 确认端口释放
ss -tulpn | grep -E '44444|44445'
```

如需回滚到旧版本，直接替换回旧二进制再按第 4 步启动即可。服务端不注册开机自启，重启 VPS 后需手动启动。

---

## 安全注意

- 服务端日志只记录连接号、流号、错误类别，**不记录目标域名或 IP**
- 不要改动 SSH、Nginx、Docker 或 VPS 上任何其他服务
- 不要复用现有服务端口
- 证书私钥、`server.json`、`server.log` 均不得公开
