package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"nimbus/shared"
)

// 错误只记录类别，避免日志泄露地址或目标信息。
func errorKind(err error) string {
	if err == nil {
		return "none"
	}
	if errors.Is(err, io.EOF) {
		return "eof"
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return opErr.Op + "-" + opErr.Net
	}
	return "other"
}

// Tunnel 管理与服务端的一条加密连接
type Tunnel struct {
	tlsCfg           *tls.Config
	quicTLSCfg       *tls.Config
	serverAddr       string
	webTransportAddr string // 可选：WebTransport 独立 UDP 地址，留空则复用 serverAddr
	psk              []byte
	transport        string // "tcp" / "quic" / "webtransport" / "auto"
	preferFamily     string // "ipv4" / "ipv6" / "auto"
}

// resolveAddrs 把 server_addr 解析为按地址族排序的候选列表。
// 字面量地址直接返回；域名则拆成 IPv4/IPv6 两组按偏好排序。
func resolveAddrs(addr, prefer string) ([]string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if net.ParseIP(host) != nil {
		return []string{addr}, nil
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}
	var v4, v6 []string
	for _, ip := range ips {
		candidate := net.JoinHostPort(ip.String(), port)
		if ip.To4() != nil {
			v4 = append(v4, candidate)
		} else {
			v6 = append(v6, candidate)
		}
	}
	if prefer == "ipv4" {
		return append(v4, v6...), nil
	}
	if prefer == "ipv6" {
		return append(v6, v4...), nil
	}
	return append(v4, v6...), nil // auto: IPv4 优先，IPv6 兜底
}

// dialTCPAddr 在单个地址上建立 TLS 连接并完成认证。
func (t *Tunnel) dialTCPAddr(addr string) (*Conn, error) {
	raw, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return nil, err
	}
	tc := tls.Client(raw, t.tlsCfg)
	tc.SetDeadline(time.Now().Add(15 * time.Second))
	if err := tc.Handshake(); err != nil {
		raw.Close()
		return nil, err
	}
	tc.SetDeadline(time.Time{})

	rw := io.ReadWriteCloser(tc)
	sess, err := t.authenticate(rw, func(clientNonce, serverNonce []byte) (*shared.Session, error) {
		return shared.NewSession(tc)
	})
	if err != nil {
		tc.Close()
		return nil, err
	}
	return newConn(t, rw, nil, sess), nil
}

// dialQUICAddr 在单个地址上建立 QUIC 连接并完成认证。
func (t *Tunnel) dialQUICAddr(addr string) (*Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	qconn, err := quic.DialAddr(ctx, addr, t.quicTLSCfg, &quic.Config{
		HandshakeIdleTimeout: 10 * time.Second,
	})
	if err != nil {
		return nil, err
	}
	stream, err := qconn.OpenStreamSync(ctx)
	if err != nil {
		qconn.CloseWithError(0, "")
		return nil, err
	}
	sess, err := t.authenticate(stream, func(clientNonce, serverNonce []byte) (*shared.Session, error) {
		key, e := shared.DeriveQUICKey(t.psk, clientNonce, serverNonce)
		if e != nil {
			return nil, e
		}
		return shared.NewSessionFromKey(key)
	})
	if err != nil {
		qconn.CloseWithError(0, "")
		return nil, err
	}
	return newConn(t, stream, qconn, sess), nil
}

// Conn 一条逻辑子连接（每个 tunnel 连接承载一个 stream，id=1）
type Conn struct {
	t      *Tunnel
	rw     io.ReadWriteCloser // TLS conn (TCP) 或 QUIC stream
	qconn  *quic.Conn         // 仅 QUIC 路径非空，用于彻底关闭
	sess   *shared.Session
	id     uint32
	inbox  chan []byte
	closed chan struct{}
	once   sync.Once

	writeMu sync.Mutex
	readBuf []byte
	readMu  sync.Mutex
}

// Dial 按 transport 策略建立连接并完成认证。
// auto: TCP 优先，失败回退 QUIC。
func (t *Tunnel) Dial() (*Conn, error) {
	switch t.transport {
	case "quic":
		return t.dialQUIC()
	case "webtransport":
		return t.dialWebTransport()
	case "", "tcp":
		c, err := t.dialTCP()
		if err == nil {
			return c, nil
		}
		if t.transport == "tcp" {
			return nil, err
		}
		// auto 未显式设置时：TCP -> QUIC -> WebTransport
		log.Printf("tcp dial failed: %s; falling back to quic", errorKind(err))
		if c, e := t.dialQUIC(); e == nil {
			return c, nil
		}
		log.Printf("quic dial failed; falling back to webtransport")
		return t.dialWebTransport()
	case "auto":
		c, err := t.dialTCP()
		if err == nil {
			return c, nil
		}
		log.Printf("tcp dial failed: %s; falling back to quic", errorKind(err))
		if c, e := t.dialQUIC(); e == nil {
			return c, nil
		}
		log.Printf("quic dial failed; falling back to webtransport")
		return t.dialWebTransport()
	default:
		return nil, fmt.Errorf("unknown transport")
	}
}

func (t *Tunnel) dialTCP() (*Conn, error) {
	addrs, err := resolveAddrs(t.serverAddr, t.preferFamily)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, addr := range addrs {
		c, e := t.dialTCPAddr(addr)
		if e == nil {
			return c, nil
		}
		lastErr = e
		log.Printf("tcp dial candidate failed: %s", errorKind(e))
	}
	return nil, lastErr
}

func (t *Tunnel) dialQUIC() (*Conn, error) {
	addrs, err := resolveAddrs(t.serverAddr, t.preferFamily)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, addr := range addrs {
		c, e := t.dialQUICAddr(addr)
		if e == nil {
			return c, nil
		}
		lastErr = e
		log.Printf("quic dial candidate failed: %s", errorKind(e))
	}
	return nil, lastErr
}

// authenticate 在任意 io.ReadWriteCloser 上执行共享的握手流程。
// makeSession 在客户端拿到 serverNonce 后调用，TCP 用 TLS exporter，QUIC 用 HKDF。
func (t *Tunnel) authenticate(rw io.ReadWriteCloser, makeSession func(clientNonce, serverNonce []byte) (*shared.Session, error)) (*shared.Session, error) {
	if deadline, ok := rw.(interface{ SetDeadline(time.Time) error }); ok {
		deadline.SetDeadline(time.Now().Add(15 * time.Second))
		defer deadline.SetDeadline(time.Time{})
	}

	clientNonce, err := shared.RandomNonce()
	if err != nil {
		return nil, err
	}
	if _, err := rw.Write([]byte(shared.Magic + string(clientNonce))); err != nil {
		return nil, err
	}
	serverNonce := make([]byte, shared.NonceLen)
	if _, err := io.ReadFull(rw, serverNonce); err != nil {
		return nil, err
	}

	ts := time.Now().Unix()
	mac := shared.ClientAuth(t.psk, clientNonce, serverNonce, ts)
	var auth [40]byte
	for i := 0; i < 8; i++ {
		auth[i] = byte(uint64(ts) >> (56 - 8*i))
	}
	copy(auth[8:], mac)
	if _, err := rw.Write(auth[:]); err != nil {
		return nil, err
	}

	sess, err := makeSession(clientNonce, serverNonce)
	if err != nil {
		return nil, err
	}
	typ, _, err := sess.ReadFrame(rw)
	if err != nil || typ != shared.FramePing {
		return nil, fmt.Errorf("auth failed")
	}
	return sess, nil
}

func newConn(t *Tunnel, rw io.ReadWriteCloser, qconn *quic.Conn, sess *shared.Session) *Conn {
	c := &Conn{
		t:      t,
		rw:     rw,
		qconn:  qconn,
		sess:   sess,
		id:     1,
		inbox:  make(chan []byte, 256),
		closed: make(chan struct{}),
	}
	go c.readLoop()
	return c
}

func (c *Conn) readLoop() {
	defer c.Close()
	for {
		typ, payload, err := c.sess.ReadFrame(c.rw)
		if err != nil {
			log.Printf("tunnel read loop end: %s", errorKind(err))
			return
		}
		switch typ {
		case shared.FrameData:
			_, data, err := shared.DecodeData(payload)
			if err != nil {
				continue
			}
			select {
			case c.inbox <- data:
			case <-c.closed:
				return
			}
		case shared.FrameClose:
			return
		case shared.FramePing:
		}
	}
}

func (c *Conn) Open(host string, port uint16) error {
	payload, err := shared.EncodeOpen(c.id, host, port)
	if err != nil {
		return err
	}
	return c.sess.WriteFrame(c.rw, shared.FrameOpen, payload)
}

func (c *Conn) Write(data []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := c.sess.WriteFrame(c.rw, shared.FrameData, shared.EncodeData(c.id, data)); err != nil {
		log.Printf("tunnel write failed: bytes=%d err=%s", len(data), errorKind(err))
		return 0, err
	}
	return len(data), nil
}

// CloseWrite 只关闭本方向的写入（半关闭），通知对端本流已无更多数据。
func (c *Conn) CloseWrite() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.sess.WriteFrame(c.rw, shared.FrameClose, shared.EncodeClose(c.id))
}

func (c *Conn) Read(b []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if len(c.readBuf) > 0 {
		n := copy(b, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}
	select {
	case data, ok := <-c.inbox:
		if !ok {
			return 0, io.EOF
		}
		n := copy(b, data)
		if n < len(data) {
			c.readBuf = append(c.readBuf, data[n:]...)
		}
		return n, nil
	case <-c.closed:
		return 0, io.EOF
	}
}

func (c *Conn) Close() error {
	c.once.Do(func() {
		close(c.closed)
		_ = c.sess.WriteFrame(c.rw, shared.FrameClose, shared.EncodeClose(c.id))
		c.rw.Close()
		if c.qconn != nil {
			c.qconn.CloseWithError(0, "")
		}
	})
	return nil
}
