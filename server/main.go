package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"nimbus/shared"
)

var (
	seenNonces = make(map[string]bool)
	seenMu     sync.Mutex
)

type outFrame struct {
	typ     byte
	payload []byte
}

type stream struct {
	id     uint32
	conn   net.Conn
	outbox chan outFrame
}

// 错误只记录类别，避免把目标域名/IP 写进日志。
func dialErrorKind(err error) string {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return "dns"
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return "timeout"
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return opErr.Op + "-" + opErr.Net
	}
	return "other"
}

func connErrorKind(err error) string {
	if err == nil {
		return "none"
	}
	if errors.Is(err, io.EOF) {
		return "eof"
	}
	if errors.Is(err, net.ErrClosed) {
		return "closed"
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return "timeout"
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return opErr.Op
	}
	return "other"
}

func main() {
	configPath := flag.String("config", "server.json", "server config path")
	flag.Parse()

	cfgBytes, err := os.ReadFile(*configPath)
	if err != nil {
		log.Fatalf("read config: %v", err)
	}
	var cfg shared.ServerConfig
	if err := json.Unmarshal(cfgBytes, &cfg); err != nil {
		log.Fatalf("parse config: %v", err)
	}
	if len(cfg.PSK) != 32 {
		log.Fatalf("psk must be 32 bytes")
	}

	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		log.Fatalf("load cert: %v", err)
	}

	// TCP + TLS 路径（保留原有 Web 外壳行为）
	ln, err := tls.Listen("tcp", cfg.ListenAddr, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"http/1.1"},
	})
	if err != nil {
		log.Fatalf("listen tcp: %v", err)
	}
	defer ln.Close()
	log.Printf("server listening tcp on %s", cfg.ListenAddr)

	// QUIC + UDP 路径（可选）
	if cfg.QUICListenAddr != "" {
		udpConn, err := shared.ListenUDP(cfg.QUICListenAddr)
		if err != nil {
			log.Fatalf("listen quic udp: %v", err)
		}
		qln, err := quic.Listen(udpConn, &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
			NextProtos:   []string{"h3"},
		}, shared.QUICConfig())
		if err != nil {
			log.Fatalf("listen quic: %v", err)
		}
		defer qln.Close()
		log.Printf("server listening quic on %s", cfg.QUICListenAddr)
		go acceptQUIC(qln, &cfg)
	}

	// WebTransport + HTTP/3 路径（可选，独立 UDP 监听，不占用 TCP/QUIC 端口）
	if cfg.WebTransportListenAddr != "" {
		go startWebTransport(&cfg, cert)
	}

	var nextID uint32
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept tcp: %v", err)
			continue
		}
		id := atomic.AddUint32(&nextID, 1)
		go handleConn(conn, &cfg, id)
	}
}

func acceptQUIC(ln *quic.Listener, cfg *shared.ServerConfig) {
	var nextID uint32
	for {
		qconn, err := ln.Accept(context.Background())
		if err != nil {
			log.Printf("accept quic: %s", connErrorKind(err))
			return
		}
		id := 1_000_000 + atomic.AddUint32(&nextID, 1)
		go handleQUICConn(qconn, cfg, id)
	}
}

func handleQUICConn(qconn *quic.Conn, cfg *shared.ServerConfig, connID uint32) {
	defer qconn.CloseWithError(0, "")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	stream, err := qconn.AcceptStream(ctx)
	if err != nil {
		log.Printf("conn=%d quic accept stream: %s", connID, connErrorKind(err))
		return
	}
	serveQUICStream(stream, cfg, connID)
}

// serveQUICStream 在一条 QUIC stream 上完成认证并进入隧道主循环。
// 裸 QUIC 与 WebTransport 路径共用。
func serveQUICStream(stream *quic.Stream, cfg *shared.ServerConfig, connID uint32) {
	if d, ok := interface{}(stream).(interface{ SetDeadline(time.Time) error }); ok {
		d.SetDeadline(time.Now().Add(15 * time.Second))
		defer d.SetDeadline(time.Time{})
	}

	// 认证首包：Magic(8) + clientNonce(16)
	hello := make([]byte, 8+shared.NonceLen)
	if _, err := io.ReadFull(stream, hello); err != nil || string(hello[:8]) != shared.Magic {
		log.Printf("conn=%d quic hello failed: %s", connID, connErrorKind(err))
		return
	}
	clientNonce := hello[8:]
	serverNonce, err := shared.RandomNonce()
	if err != nil {
		return
	}
	if _, err := stream.Write(serverNonce); err != nil {
		return
	}
	authResp := make([]byte, 8+32)
	if _, err := io.ReadFull(stream, authResp); err != nil {
		return
	}
	ts := int64(binaryU64(authResp[:8]))
	mac := authResp[8:]
	seenMu.Lock()
	okAuth := shared.VerifyAuth(cfg.PSK, clientNonce, serverNonce, mac, ts, seenNonces)
	seenMu.Unlock()
	if !okAuth {
		return
	}
	key, err := shared.DeriveQUICKey(cfg.PSK, clientNonce, serverNonce)
	if err != nil {
		return
	}
	sess, err := shared.NewSessionFromKey(key)
	if err != nil {
		return
	}
	if err := sess.WriteFrame(stream, shared.FramePing, []byte{1}); err != nil {
		return
	}
	// 认证阶段结束后立刻清除 deadline，否则 15 秒后整条隧道会被超时打断。
	if d, ok := interface{}(stream).(interface{ SetDeadline(time.Time) error }); ok {
		d.SetDeadline(time.Time{})
	}
	log.Printf("conn=%d quic authenticated", connID)
	serveTunnel(stream, sess, cfg, connID)
}

func handleConn(raw net.Conn, cfg *shared.ServerConfig, connID uint32) {
	defer raw.Close()
	tc, ok := raw.(*tls.Conn)
	if !ok {
		return
	}
	tc.SetDeadline(time.Now().Add(15 * time.Second))
	if err := tc.Handshake(); err != nil {
		log.Printf("conn=%d handshake failed: %v", connID, err)
		return
	}
	tc.SetDeadline(time.Time{})

	buf := make([]byte, 4096)
	n, err := tc.Read(buf)
	if err != nil || n == 0 {
		log.Printf("conn=%d first read failed: n=%d err=%v", connID, n, err)
		return
	}
	req := string(buf[:n])

	// CDN / WebSocket 隧道：必须在普通 Web 外壳之前判断。
	br := bufio.NewReader(io.MultiReader(bytes.NewReader(buf[:n]), tc))
	bw := bufio.NewWriter(tc)
	rw := bufio.NewReadWriter(br, bw)
	if httpReq, e := http.ReadRequest(br); e == nil &&
		strings.HasPrefix(httpReq.URL.Path, shared.WSPathPrefix) &&
		strings.EqualFold(httpReq.Header.Get("Upgrade"), "websocket") {
		serveWebSocket(tc, rw, httpReq, cfg, connID)
		return
	}

	// 普通 HTTP → Web 外壳
	if strings.HasPrefix(req, "GET ") || strings.HasPrefix(req, "POST ") ||
		strings.HasPrefix(req, "HEAD ") || strings.HasPrefix(req, "OPTIONS ") {
		serveWeb(tc, req, cfg)
		return
	}

	// 隧道认证首包：Magic(8) + clientNonce(16)
	if len(req) < 8+shared.NonceLen || !strings.HasPrefix(req, shared.Magic) {
		writeNotFound(tc)
		return
	}
	clientNonce := []byte(req[8 : 8+shared.NonceLen])
	serverNonce, err := shared.RandomNonce()
	if err != nil {
		return
	}
	if _, err := tc.Write(serverNonce); err != nil {
		return
	}
	authResp := make([]byte, 8+32)
	if _, err := io.ReadFull(tc, authResp); err != nil {
		return
	}
	ts := int64(binaryU64(authResp[:8]))
	mac := authResp[8:]
	seenMu.Lock()
	okAuth := shared.VerifyAuth(cfg.PSK, clientNonce, serverNonce, mac, ts, seenNonces)
	seenMu.Unlock()
	if !okAuth {
		writeNotFound(tc)
		return
	}
	sess, err := shared.NewSession(tc)
	if err != nil {
		return
	}
	serveTunnel(tc, sess, cfg, connID)
}

// serveTunnel 是 TCP/QUIC 共享的隧道主循环。rw 只负责 Frame 读写。
func serveTunnel(rw io.ReadWriteCloser, sess *shared.Session, cfg *shared.ServerConfig, connID uint32) {
	if err := sess.WriteFrame(rw, shared.FramePing, []byte{1}); err != nil {
		return
	}
	log.Printf("conn=%d authenticated", connID)

	streams := make(map[uint32]*stream)
	var streamsMu sync.Mutex

	writeCh := make(chan outFrame, 256)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case f := <-writeCh:
				if err := sess.WriteFrame(rw, f.typ, f.payload); err != nil {
					log.Printf("conn=%d write frame failed: %s", connID, connErrorKind(err))
					return
				}
			case <-done:
				return
			}
		}
	}()

	for {
		typ, payload, err := sess.ReadFrame(rw)
		if err != nil {
			log.Printf("conn=%d read loop end: %s", connID, connErrorKind(err))
			break
		}
		switch typ {
		case shared.FrameOpen:
			sid, host, port, err := shared.DecodeOpen(payload)
			if err != nil {
				continue
			}
			addr := fmt.Sprintf("%s:%d", host, port)
			dialStart := time.Now()
			target, err := net.DialTimeout("tcp", addr, 10*time.Second)
			if err != nil {
				log.Printf("conn=%d stream=%d dial failed: %s", connID, sid, dialErrorKind(err))
				select {
				case writeCh <- outFrame{typ: shared.FrameClose, payload: shared.EncodeClose(sid)}:
				case <-done:
				}
				continue
			}
			log.Printf("conn=%d stream=%d dial ok elapsed=%v", connID, sid, time.Since(dialStart).Round(time.Millisecond))
			st := &stream{id: sid, conn: target, outbox: writeCh}
			streamsMu.Lock()
			streams[sid] = st
			streamsMu.Unlock()
			go func(s *stream) {
				defer s.conn.Close()
				buf := make([]byte, 32*1024)
				for {
					n, err := s.conn.Read(buf)
					if n > 0 {
						select {
						case s.outbox <- outFrame{typ: shared.FrameData, payload: shared.EncodeData(s.id, buf[:n])}:
						case <-done:
							return
						}
					}
					if err != nil {
						log.Printf("conn=%d stream=%d target read end: bytes=%d err=%s", connID, s.id, n, connErrorKind(err))
						select {
						case writeCh <- outFrame{typ: shared.FrameClose, payload: shared.EncodeClose(s.id)}:
						case <-done:
						}
						return
					}
				}
			}(st)

		case shared.FrameData:
			sid, data, err := shared.DecodeData(payload)
			if err != nil {
				continue
			}
			streamsMu.Lock()
			st := streams[sid]
			streamsMu.Unlock()
			if st != nil && len(data) > 0 {
				if _, err := st.conn.Write(data); err != nil {
					log.Printf("conn=%d stream=%d target write failed: bytes=%d err=%s", connID, sid, len(data), connErrorKind(err))
					select {
					case writeCh <- outFrame{typ: shared.FrameClose, payload: shared.EncodeClose(sid)}:
					case <-done:
					}
				}
			}

		case shared.FrameClose:
			sid, err := shared.DecodeClose(payload)
			if err != nil {
				continue
			}
			streamsMu.Lock()
			if st := streams[sid]; st != nil {
				st.conn.Close()
				delete(streams, sid)
			}
			streamsMu.Unlock()
		}
	}

	close(done)
	streamsMu.Lock()
	for _, st := range streams {
		st.conn.Close()
	}
	streamsMu.Unlock()
}

func binaryU64(b []byte) uint64 {
	var v uint64
	for _, x := range b[:8] {
		v = v<<8 | uint64(x)
	}
	return v
}

const webHTML = `<!doctype html><html><head><meta charset="utf-8"><title>Welcome</title></head><body><h1>It works.</h1><p>This is a normal website.</p></body></html>`

func serveWeb(w io.Writer, req string, cfg *shared.ServerConfig) {
	firstLine := strings.SplitN(req, "\r\n", 2)[0]
	parts := strings.Fields(firstLine)
	path := "/"
	if len(parts) >= 2 {
		path = parts[1]
	}
	if path == "/" || path == "/index.html" {
		body := webHTML
		if cfg.WebRootHTML != "" {
			body = cfg.WebRootHTML
		}
		fmt.Fprintf(w, "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
		return
	}
	writeNotFound(w)
}

func writeNotFound(w io.Writer) {
	body := "<!doctype html><html><head><title>404</title></head><body><h1>404 Not Found</h1></body></html>"
	fmt.Fprintf(w, "HTTP/1.1 404 Not Found\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
}
