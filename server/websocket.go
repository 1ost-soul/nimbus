package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"

	"golang.org/x/net/websocket"
	"nimbus/shared"
)

// rawResponseWriter 让 x/net/websocket 的 Server 能在已有 TLS 连接上完成 upgrade。
type rawResponseWriter struct {
	conn   net.Conn
	rw     *bufio.ReadWriter
	header http.Header
}

func (w *rawResponseWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (w *rawResponseWriter) Write(b []byte) (int, error) { return w.rw.Write(b) }

func (w *rawResponseWriter) WriteHeader(code int) {
	fmt.Fprintf(w.rw, "HTTP/1.1 %d %s\r\n", code, http.StatusText(code))
}

func (w *rawResponseWriter) Flush() { _ = w.rw.Flush() }

func (w *rawResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.conn, w.rw, nil
}

func serveWebSocket(conn net.Conn, rw *bufio.ReadWriter, req *http.Request, cfg *shared.ServerConfig, connID uint32) {
	wsServer := websocket.Server{
		Handshake: func(_ *websocket.Config, r *http.Request) error {
			if r.URL.Path != "/tunnel" {
				return fmt.Errorf("forbidden path")
			}
			return nil
		},
		Handler: func(ws *websocket.Conn) {
			defer ws.Close()
			serveWSStream(ws, cfg, connID)
		},
	}
	wsServer.ServeHTTP(&rawResponseWriter{conn: conn, rw: rw}, req)
}

// serveWSStream 在 WebSocket 消息流上运行与 TCP/QUIC 相同的认证和帧循环。
// CDN 模式下 TLS 终止在边缘，因此会话密钥必须由 PSK + nonce 派生。
func serveWSStream(ws *websocket.Conn, cfg *shared.ServerConfig, connID uint32) {
	_ = ws.SetDeadline(time.Now().Add(15 * time.Second))
	defer ws.SetDeadline(time.Time{})

	hello := make([]byte, 8+shared.NonceLen)
	if _, err := io.ReadFull(ws, hello); err != nil || string(hello[:8]) != shared.Magic {
		return
	}
	clientNonce := hello[8:]
	serverNonce, err := shared.RandomNonce()
	if err != nil {
		return
	}
	if _, err := ws.Write(serverNonce); err != nil {
		return
	}
	authResp := make([]byte, 8+32)
	if _, err := io.ReadFull(ws, authResp); err != nil {
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
	if err := sess.WriteFrame(ws, shared.FramePing, []byte{1}); err != nil {
		return
	}
	_ = ws.SetDeadline(time.Time{})
	log.Printf("conn=%d websocket authenticated", connID)
	serveTunnel(ws, sess, cfg, connID)
}
