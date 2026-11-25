package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
	"nimbus/shared"
)

// dialWebTransport 在 HTTP/3 连接上执行 extended CONNECT 握手，
// 然后在同一 QUIC 连接上开一条带 magic 前缀的双向 stream 承载隧道帧。
func (t *Tunnel) dialWebTransport() (*Conn, error) {
	target := t.webTransportAddr
	if target == "" {
		target = t.serverAddr
	}
	addrs, err := resolveAddrs(target, t.preferFamily)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, addr := range addrs {
		c, e := t.dialWebTransportAddr(addr)
		if e == nil {
			return c, nil
		}
		lastErr = e
		log.Printf("webtransport dial candidate failed: %s", errorKind(e))
	}
	return nil, lastErr
}

func (t *Tunnel) dialWebTransportAddr(addr string) (*Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// 复用现有证书 pinning，仅把 ALPN 调整为 HTTP/3 所需
	tlsConf := http3.ConfigureTLSConfig(t.quicTLSCfg.Clone())
	qconn, err := quic.DialAddr(ctx, addr, tlsConf, &quic.Config{
		HandshakeIdleTimeout: 10 * time.Second,
	})
	if err != nil {
		return nil, err
	}
	fail := func(e error) (*Conn, error) {
		qconn.CloseWithError(0, "")
		return nil, e
	}

	tr := &http3.Transport{}
	raw := tr.NewRawClientConn(qconn)

	// HTTP/3 控制流：处理对端发起的单向流（SETTINGS 等）
	go func() {
		for {
			st, e := qconn.AcceptUniStream(context.Background())
			if e != nil {
				return
			}
			go raw.HandleUnidirectionalStream(st)
		}
	}()

	// 等待 SETTINGS，确认服务端支持 extended CONNECT
	select {
	case <-raw.ReceivedSettings():
		if !raw.Settings().EnableExtendedConnect {
			return fail(fmt.Errorf("server did not enable extended connect"))
		}
	case <-ctx.Done():
		return fail(ctx.Err())
	}

	// 发起 WebTransport extended CONNECT 握手
	req, err := http.NewRequest(http.MethodConnect, "https://"+net.JoinHostPort(host, port)+"/tunnel", nil)
	if err != nil {
		return fail(err)
	}
	req.Proto = "webtransport"
	reqStr, err := raw.OpenRequestStream(ctx)
	if err != nil {
		return fail(err)
	}
	if err := reqStr.SendRequestHeader(req); err != nil {
		return fail(err)
	}
	resp, err := reqStr.ReadResponse()
	if err != nil {
		return fail(err)
	}
	if resp.StatusCode != http.StatusOK {
		return fail(fmt.Errorf("webtransport handshake status %d", resp.StatusCode))
	}
	reqStr.Close()

	// 打开隧道 data stream：先写 magic varint，服务端据此与普通 HTTP 请求流区分
	stream, err := qconn.OpenStreamSync(ctx)
	if err != nil {
		return fail(err)
	}
	if _, err := stream.Write(quicvarint.Append(nil, shared.WebTransportMagic)); err != nil {
		return fail(err)
	}

	sess, err := t.authenticate(stream, func(clientNonce, serverNonce []byte) (*shared.Session, error) {
		key, e := shared.DeriveQUICKey(t.psk, clientNonce, serverNonce)
		if e != nil {
			return nil, e
		}
		return shared.NewSessionFromKey(key)
	})
	if err != nil {
		return fail(err)
	}
	return newConn(t, stream, qconn, sess), nil
}
