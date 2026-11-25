# Nimbus — independent secure proxy prototype

Experimental prototype only. It is **not** a production security product and does not guarantee long-term resistance to blocking.

## Overview

Local HTTP/SOCKS5 proxy plus a VPS server connected by an encrypted tunnel:

- Transport: TCP + TLS 1.3 (ALPN `h2`, web shell), QUIC/UDP (ALPN `h3`), or HTTP/3 WebTransport via extended CONNECT. Client `transport`: `tcp` / `quic` / `webtransport` / `auto` (default `auto`: TCP -> QUIC -> WebTransport)
- Session keys: TLS exporter on TCP; PSK + dual nonces via HKDF on QUIC/WebTransport; standard-library AES-GCM frames
- Authentication: HMAC challenge-response with random nonces and a replay table; failures return a plain 404
- Local proxy: HTTP CONNECT, SOCKS5 CONNECT, remote DNS
- Server: ordinary user process on the VPS, no systemd unit

Destination host and port are only carried inside encrypted frames. Logs contain connection/stream IDs and error categories, never destination names or addresses.

## Layout

- `client/` — local proxy and tunnel client
- `server/` — VPS server
- `shared/` — framing, crypto, authentication
- `configs/` — sanitized config templates (never commit real configs)
- `scripts/` — example deployment and cleanup scripts
- `reports/` — private reports; sanitized copies live in `public/`

## Windows client release

Download [dist/nimbus-client-windows.zip](dist/nimbus-client-windows.zip). It contains the compiled `nimbus-client.exe`, `run.bat`, a sanitized `config.json`, and a short readme. See the Chinese client guide below for setup.

## Documentation (Chinese)

- [Server setup on VPS](docs/SERVER_SETUP_zh.md)
- [Client setup on Windows (incl. release archive)](docs/CLIENT_SETUP_zh.md)

## Build

```bash
go test ./...
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o build/nimbus-server ./server
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o build/nimbus-client.exe ./client
```

## Verify

```bash
curl -x http://127.0.0.1:34133 https://example.com
curl --socks5-hostname 127.0.0.1:34133 https://example.com
```

Do not use another local proxy as evidence for connectivity tests.

## Limitations

No long-run stability, concurrency stress, or video bitrate testing was performed. The web shell is not a substitute for encryption and is not sufficient by itself for active-probe resistance. The protocol has not been externally audited.
