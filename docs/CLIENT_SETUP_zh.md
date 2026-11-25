# 客户端使用教程（Windows）

客户端在本机监听 `127.0.0.1:34133`，同时提供 **HTTP CONNECT** 和 **SOCKS5** 两种代理接口。
应用连到这个本地端口，流量经加密隧道转发到你的 VPS。

> 所有示例值（域名 `vpn.example.net`、端口 `44444`、占位 PSK）都是**脱敏示例**，必须替换。

---

## 方式 A：使用 release 压缩包（推荐）

Release 压缩包内含：

```
nimbus-client.exe    编译好的 Windows 客户端
run.bat             双击启动器（保持窗口，便于查看错误）
config.json         脱敏配置模板
README.txt          快速说明
```

步骤：

1. 解压到任意目录（路径不要有中文也可以，但建议纯英文路径）
2. 编辑 `config.json`，填入你自己的服务端信息（见下方字段说明）
3. 把你的 CA 证书文件放到同目录，并在 `ca_pem_file` 中填写其文件名
4. **双击 `run.bat`**，看到 `local proxy listening on 127.0.0.1:34133` 即启动成功
5. 按下方命令验证

> 命令行程序直接双击 `.exe` 会闪退，所以请用 `run.bat` 启动。

---

## 方式 B：从源码构建

```bash
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o nimbus-client.exe ./client
```

把 `configs/config.example.json` 复制为 `config.json` 并填写，然后：

```bat
nimbus-client.exe -config config.json
```

---

## 配置项说明

```json
{
  "local_addr":  "127.0.0.1:34133",
  "server_addr":  "vpn.example.net:44444",
  "sni":  "vpn.example.net",
  "psk":  "REPLACE_WITH_BASE64_32_BYTE_KEY",
  "ca_pem_file":  "pinned-ca.pem",
  "transport":  "auto",
  "prefer_family":  "ipv4"
}
```

| 字段 | 说明 |
|---|---|
| `local_addr` | 本地监听地址，默认 `127.0.0.1:34133` |
| `server_addr` | 服务端域名 + 端口。**建议填域名而不是写死 IP**，这样地址族偏好才能生效 |
| `sni` | TLS SNI，通常与服务端域名一致 |
| `psk` | 32 字节 base64，必须与服务端完全一致 |
| `ca_pem_file` | 信任锚证书（证书 pinning）；留空则使用系统根证书，生产环境不建议 |
| `transport` | `tcp` / `quic` / `auto`，默认 `auto`（TCP 优先，失败回退 QUIC） |
| `prefer_family` | `ipv4` / `ipv6` / `auto`，默认 `ipv4`；域名解析后按偏好排序拨号 |

### 地址族偏好如何工作

- 填域名时，客户端解析出 A / AAAA 记录，按 `prefer_family` 排序后依次尝试
- `ipv4`：IPv4 优先，IPv6 兜底；`ipv6` 反之
- `auto`：当前实现也是 IPv4 优先、IPv6 兜底
- 若 `server_addr` 写死 IP 字面量（如 `[2001:db8::1]:44444`），则直接使用该地址，偏好设置不生效

### 传输模式如何选择

- `tcp`：仅 TCP + TLS 1.3，带 Web 外壳
- `quic`：仅 UDP/QUIC（ALPN `h3`），纯隧道
- `auto`：先试 TCP，失败自动回退 QUIC（推荐）

---

## 验证

**不要用其他本地代理作为证据链**，确保测试前清空代理环境变量：

```bat
curl -x http://127.0.0.1:34133 https://example.com -o NUL -w "HTTP CODE=%{http_code}\n"
curl --socks5-hostname 127.0.0.1:34133 https://example.com -o NUL -w "SOCKS CODE=%{http_code}\n"
```

两条都应返回 `CODE=200`。`--socks5-hostname` 表示域名由服务端解析，目标地址不暴露在本地 DNS。

---

## 关闭

关闭 `run.bat` 窗口即可（或结束 `nimbus-client.exe` 进程）。客户端关闭不影响 VPS 服务端。

---

## 常见问题

- **双击 exe 闪退**：用 `run.bat` 启动，窗口会保留错误信息
- **认证失败**：检查两端 PSK 是否一致、系统时间是否偏差过大
- **证书校验失败**：检查 `ca_pem_file` 指向的证书是否与服务端证书链匹配
- **TCP 不通但 QUIC 通**：把 `transport` 改成 `quic`，并确认 VPS 放通了 UDP 端口
