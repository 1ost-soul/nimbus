package main

import (
	"fmt"
	"net"
	"os"
	"time"
)

func try(network, addr string) {
	start := time.Now()
	c, err := net.DialTimeout(network, addr, 12*time.Second)
	if err != nil {
		fmt.Printf("%-6s %-28s FAIL err=%v elapsed=%v\n", network, addr, err, time.Since(start).Round(time.Millisecond))
		return
	}
	remote := c.RemoteAddr().String()
	c.Close()
	fmt.Printf("%-6s %-28s OK   remote=%s elapsed=%v\n", network, addr, remote, time.Since(start).Round(time.Millisecond))
}

func main() {
	addr := "www.youtube.com:443"
	if len(os.Args) > 1 {
		addr = os.Args[1]
	}
	try("tcp", addr)
	try("tcp4", addr)
	try("tcp6", addr)
}
