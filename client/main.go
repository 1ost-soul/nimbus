package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"log"
	"net"
	"os"

	"nimbus/shared"
)

type clientConfig struct {
	LocalAddr        string `json:"local_addr"`
	ServerAddr       string `json:"server_addr"`
	WebTransportAddr string `json:"webtransport_addr,omitempty"` // 可选：WebTransport 独立 UDP 地址，留空则复用 server_addr
	SNI              string `json:"sni"`
	PSK              []byte `json:"psk"`
	CAPEMFile        string `json:"ca_pem_file"`   // 可选：自定义 CA，用于 pinning
	Transport         string   `json:"transport"`          // tcp / quic / webtransport / auto（默认 auto）
	PreferFamily      string   `json:"prefer_family"`      // ipv4 / ipv6 / auto（默认 ipv4）
	ConnectionMode    string   `json:"connection_mode,omitempty"` // auto / direct_tcp / direct_quic / direct_webtransport / cdn
	CDNAutoSelect     *bool    `json:"cdn_auto_select,omitempty"` // CDN 启动时自动优选，默认 true
	CDNCandidateIPs   []string `json:"cdn_candidate_ips,omitempty"`
	CDNCAPEMFile      string   `json:"cdn_ca_pem_file,omitempty"` // 可选：CDN 入口证书 CA；留空使用系统根证书
}

var cfg clientConfig

func main() {
	configPath := flag.String("config", "client.json", "client config path")
	flag.Parse()

	b, err := os.ReadFile(*configPath)
	if err != nil {
		log.Fatalf("read config: %v", err)
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		log.Fatalf("parse config: %v", err)
	}
	if len(cfg.PSK) != 32 {
		log.Fatalf("psk must be 32 bytes")
	}
	if cfg.LocalAddr == "" {
		cfg.LocalAddr = "127.0.0.1:34133"
	}

	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		ServerName:         cfg.SNI,
		NextProtos:         []string{"h2"},
		InsecureSkipVerify: false,
	}
	if cfg.CAPEMFile != "" {
		pem, err := os.ReadFile(cfg.CAPEMFile)
		if err != nil {
			log.Fatalf("read ca: %v", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			log.Fatalf("invalid ca pem")
		}
		tlsCfg.RootCAs = pool
	}

	// QUIC 使用独立 ALPN（HTTP/3 的 h3），复用同一套证书 pinning。
	quicTLSCfg := tlsCfg.Clone()
	quicTLSCfg.NextProtos = []string{"h3"}

	// CDN 模式下 TLS 终止在 CDN 边缘节点，使用 http/1.1 ALPN 以支持 WebSocket upgrade。
	// 不复用上面针对源站的 CA pinning；默认使用系统根证书验证 CDN 证书。
	cdnTLSCfg := tlsCfg.Clone()
	cdnTLSCfg.NextProtos = []string{"http/1.1"}
	cdnTLSCfg.RootCAs = nil
	if cfg.CDNCAPEMFile != "" {
		pem, err := os.ReadFile(cfg.CDNCAPEMFile)
		if err != nil {
			log.Fatalf("read cdn ca: %v", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			log.Fatalf("invalid cdn ca pem")
		}
		cdnTLSCfg.RootCAs = pool
	}

	transport := cfg.Transport
	if transport == "" {
		transport = "auto"
	}
	preferFamily := cfg.PreferFamily
	if preferFamily == "" {
		preferFamily = "ipv4"
	}
	connectionMode := cfg.ConnectionMode
	if connectionMode == "" {
		switch transport {
		case "quic":
			connectionMode = "direct_quic"
		case "webtransport":
			connectionMode = "direct_webtransport"
		case "tcp":
			connectionMode = "direct_tcp"
		default:
			connectionMode = "auto"
		}
	}
	cdnAutoSelect := true
	if cfg.CDNAutoSelect != nil {
		cdnAutoSelect = *cfg.CDNAutoSelect
	}
	log.Printf("dial preference: family=%s transport=%s mode=%s", preferFamily, transport, connectionMode)

	tunnel := &Tunnel{
		tlsCfg:           tlsCfg,
		quicTLSCfg:       quicTLSCfg,
		cdnTLSCfg:        cdnTLSCfg,
		serverAddr:       cfg.ServerAddr,
		webTransportAddr: cfg.WebTransportAddr,
		psk:              cfg.PSK,
		transport:        transport,
		preferFamily:     preferFamily,
		connectionMode:   connectionMode,
	}
	if connectionMode == "cdn" && cdnAutoSelect {
		_, port, err := net.SplitHostPort(cfg.ServerAddr)
		if err != nil {
			port = "443"
		}
		tunnel.cdnAddrs = selectCDNCandidates(cfg.SNI, port, cfg.CDNCandidateIPs, cdnTLSCfg)
	}
	proxy := &LocalProxy{tunnel: tunnel, addr: cfg.LocalAddr}
	log.Printf("local proxy listening on %s", cfg.LocalAddr)
	if err := proxy.ListenAndServe(); err != nil {
		log.Fatalf("proxy: %v", err)
	}
}

var _ = shared.Magic
