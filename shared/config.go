package shared

// ServerConfig 服务端配置（不含真实凭据）
type ServerConfig struct {
	ListenAddr             string `json:"listen_addr"`
	QUICListenAddr         string `json:"quic_listen_addr"`         // 可选：QUIC 监听地址（UDP），为空则不启用
	WebTransportListenAddr string `json:"webtransport_listen_addr"` // 可选：WebTransport 监听地址（UDP），为空则不启用
	CertFile               string `json:"cert_file"`
	KeyFile                string `json:"key_file"`
	PSK                    []byte `json:"psk"` // base64 在配置层处理
	WebRootHTML            string `json:"web_root_html"`
}

// ClientConfig 客户端配置
type ClientConfig struct {
	LocalAddr  string `json:"local_addr"`
	ServerAddr string `json:"server_addr"` // host:port
	SNI        string `json:"sni"`
	PSK        []byte `json:"psk"`
}
