//go:build windows

package shared

import (
	"net"
	"syscall"
)

func tuneUDPConn(conn *net.UDPConn) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return
	}
	_ = raw.Control(func(fd uintptr) {
		h := syscall.Handle(fd)
		_ = syscall.SetsockoptInt(h, syscall.SOL_SOCKET, syscall.SO_RCVBUF, udpBufferSize)
		_ = syscall.SetsockoptInt(h, syscall.SOL_SOCKET, syscall.SO_SNDBUF, udpBufferSize)
	})
}
