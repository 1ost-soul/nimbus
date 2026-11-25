package shared

import (
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

// QUICConfig returns the tuned QUIC configuration shared by the client and server.
// quic-go defaults (512 KiB stream / 512 KiB connection windows) are far too
// small for a high-BDP tunnel carrying 32 KiB frames.
func QUICConfig() *quic.Config {
	return &quic.Config{
		HandshakeIdleTimeout:           15 * time.Second,
		MaxIdleTimeout:                 60 * time.Second,
		InitialStreamReceiveWindow:     4 << 20, // 4 MiB
		MaxStreamReceiveWindow:         32 << 20,
		InitialConnectionReceiveWindow: 8 << 20, // 8 MiB
		MaxConnectionReceiveWindow:     64 << 20,
		KeepAlivePeriod:                20 * time.Second,
	}
}

// udpBufferSize is applied to both SO_RCVBUF and SO_SNDBUF on QUIC sockets.
const udpBufferSize = 8 << 20

// ListenUDP creates a UDP socket with enlarged buffers, ready for quic.Listen.
func ListenUDP(addr string) (*net.UDPConn, error) {
	a, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", a)
	if err != nil {
		return nil, err
	}
	tuneUDPConn(conn)
	return conn, nil
}

// DialUDP creates an unconnected UDP socket with enlarged buffers, ready for quic.Dial.
// quic-go calls WriteTo on the PacketConn, which fails on a pre-connected socket.
func DialUDP(raddr string) (*net.UDPConn, net.Addr, error) {
	a, err := net.ResolveUDPAddr("udp", raddr)
	if err != nil {
		return nil, nil, err
	}
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, nil, err
	}
	tuneUDPConn(conn)
	return conn, a, nil
}
