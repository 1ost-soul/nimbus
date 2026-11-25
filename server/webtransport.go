package main

import (
	"context"
	"crypto/tls"
	"log"
	"net/http"
	"sync/atomic"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
	"nimbus/shared"
)

// startWebTransport 在独立 UDP 端口上运行 HTTP/3 服务。
// 普通请求走 Web 外壳，/tunnel 接受 WebTransport extended CONNECT；
// 带 magic 前缀的双向 stream 则由隧道认证逻辑接管。
func startWebTransport(cfg *shared.ServerConfig, cert tls.Certificate) {
	tlsConf := http3.ConfigureTLSConfig(&tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	})
	udpConn, err := shared.ListenUDP(cfg.WebTransportListenAddr)
	if err != nil {
		log.Printf("listen webtransport udp: %v", err)
		return
	}
	ln, err := quic.Listen(udpConn, tlsConf, shared.QUICConfig())
	if err != nil {
		log.Printf("listen webtransport: %v", err)
		return
	}
	defer ln.Close()
	log.Printf("server listening webtransport on %s", cfg.WebTransportListenAddr)

	mux := http.NewServeMux()
	mux.HandleFunc("/tunnel", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect && r.Proto == "webtransport" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		body := webHTML
		if cfg.WebRootHTML != "" {
			body = cfg.WebRootHTML
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(body))
	})

	h3server := &http3.Server{Handler: mux}
	var nextID uint32
	for {
		qconn, err := ln.Accept(context.Background())
		if err != nil {
			log.Printf("accept webtransport: %s", connErrorKind(err))
			return
		}
		id := 2_000_000 + atomic.AddUint32(&nextID, 1)
		go handleWTConn(qconn, h3server, cfg, id)
	}
}

func handleWTConn(qconn *quic.Conn, server *http3.Server, cfg *shared.ServerConfig, connID uint32) {
	defer qconn.CloseWithError(0, "")

	raw, err := server.NewRawServerConn(qconn)
	if err != nil {
		log.Printf("conn=%d webtransport raw conn: %s", connID, connErrorKind(err))
		return
	}

	// HTTP/3 控制流：SETTINGS 等单向流交给 http3 处理
	go func() {
		for {
			st, e := qconn.AcceptUniStream(context.Background())
			if e != nil {
				return
			}
			go raw.HandleUnidirectionalStream(st)
		}
	}()

	for {
		st, err := qconn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		// Peek 会等待 stream 首字节；放到 goroutine 里，避免某条 stream
		// 数据晚到时阻塞 AcceptStream 循环、挡住后续 stream。
		go func(s *quic.Stream) {
			v, _ := quicvarint.Peek(s)
			if v == shared.WebTransportMagic {
				quicvarint.Read(quicvarint.NewReader(s)) // 消费 magic 前缀
				serveQUICStream(s, cfg, connID)
			} else {
				raw.HandleRequestStream(s)
			}
		}(st)
	}
}
