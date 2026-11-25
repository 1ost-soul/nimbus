//go:build !windows && !linux

package shared

import "net"

// tuneUDPConn is a no-op on platforms where socket buffer tuning is not implemented.
func tuneUDPConn(conn *net.UDPConn) {}
