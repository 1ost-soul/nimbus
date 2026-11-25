package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"golang.org/x/net/websocket"
	"nimbus/shared"
)

// dialCDNAddr 通过 WebSocket（wss）连接到 CDN 入口，并在其上运行隧道认证。
// TLS 的 SNI 与证书校验始终使用配置中的 sni，实际 TCP 目标由 addr 覆盖。
func (t *Tunnel) dialCDNAddr(addr string) (*Conn, error) {
	sni := t.tlsCfg.ServerName
	if sni == "" {
		return nil, fmt.Errorf("cdn mode requires sni")
	}
	cfg, err := websocket.NewConfig("wss://"+addr+"/tunnel", "https://"+sni)
	if err != nil {
		return nil, err
	}
	cdnCfg := t.cdnTLSCfg.Clone()
	cdnCfg.ServerName = sni
	cfg.TlsConfig = cdnCfg
	cfg.Dialer = &net.Dialer{Timeout: 10 * time.Second}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ws, err := cfg.DialContext(ctx)
	if err != nil {
		return nil, err
	}

	// CDN 模式下 TLS 终止在边缘节点，TLS exporter 不可端到端使用。
	// 这里改用与 QUIC 路径相同的 PSK + nonce 派生，协议帧层保持不变。
	sess, err := t.authenticate(ws, func(clientNonce, serverNonce []byte) (*shared.Session, error) {
		key, e := shared.DeriveQUICKey(t.psk, clientNonce, serverNonce)
		if e != nil {
			return nil, e
		}
		return shared.NewSessionFromKey(key)
	})
	if err != nil {
		_ = ws.Close()
		return nil, err
	}
	return newConn(t, ws, nil, sess), nil
}

// dialCDN 按启动优选结果逐个尝试入口；没有优选结果时回退系统 DNS。
func (t *Tunnel) dialCDN() (*Conn, error) {
	var addrs []string
	if len(t.cdnAddrs) > 0 {
		addrs = t.cdnAddrs
	} else {
		var err error
		addrs, err = resolveAddrs(t.serverAddr, t.preferFamily)
		if err != nil {
			return nil, err
		}
	}
	var lastErr error
	for _, addr := range addrs {
		c, err := t.dialCDNAddr(addr)
		if err == nil {
			return c, nil
		}
		lastErr = err
		log.Printf("cdn dial candidate failed: %s", errorKind(err))
	}
	return nil, lastErr
}
