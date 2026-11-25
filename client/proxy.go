package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
)

// LocalProxy 本地 HTTP/SOCKS5 代理
type LocalProxy struct {
	tunnel *Tunnel
	addr   string
}

func (p *LocalProxy) ListenAndServe() error {
	ln, err := net.Listen("tcp", p.addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go p.handle(c)
	}
}

func (p *LocalProxy) handle(local net.Conn) {
	defer local.Close()
	br := bufio.NewReader(local)

	first, err := br.Peek(1)
	if err != nil {
		return
	}
	if first[0] == 0x05 {
		p.handleSOCKS5(local, br)
		return
	}

	line, err := br.ReadString('\n')
	if err != nil {
		return
	}
	line = strings.TrimRight(line, "\r\n")

	switch {
	case strings.HasPrefix(line, "CONNECT "):
		parts := strings.Fields(line)
		if len(parts) < 2 {
			return
		}
		host, port, err := parseHostPort(parts[1])
		if err != nil {
			local.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
			return
		}
		if err := skipHeaders(br); err != nil {
			return
		}
		c, err := p.openTunnel(host, port)
		if err != nil {
			local.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
			return
		}
		defer c.Close()
		if _, err := local.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
			return
		}
		pump(local, c)

	default:
		// 普通 HTTP 代理（绝对 URL）
		parts := strings.Fields(line)
		if len(parts) < 2 || !strings.Contains(parts[1], "://") {
			local.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
			return
		}
		host, port, path, err := parseAbsoluteURL(parts[1])
		if err != nil {
			local.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
			return
		}
		headers, err := readHeaders(br)
		if err != nil {
			return
		}
		c, err := p.openTunnel(host, port)
		if err != nil {
			local.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
			return
		}
		defer c.Close()
		req := fmt.Sprintf("%s %s HTTP/1.1\r\n%s", parts[0], path, headers)
		if _, err := c.Write([]byte(req)); err != nil {
			return
		}
		pump(local, c)
	}
}

func (p *LocalProxy) openTunnel(host string, port uint16) (*Conn, error) {
	c, err := p.tunnel.Dial()
	if err != nil {
		log.Printf("tunnel dial failed: %s", errorKind(err))
		return nil, err
	}
	if err := c.Open(host, port); err != nil {
		log.Printf("tunnel open failed: %s", errorKind(err))
		c.Close()
		return nil, err
	}
	return c, nil
}

func (p *LocalProxy) handleSOCKS5(local net.Conn, br *bufio.Reader) {
	// GREETING: VER NMETHODS METHODS...
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(br, greeting); err != nil {
		return
	}
	if greeting[0] != 5 {
		return
	}
	nmethods := int(greeting[1])
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}
	// 选择 NO AUTH
	if _, err := local.Write([]byte{5, 0}); err != nil {
		return
	}

	hdr := make([]byte, 4)
	if _, err := io.ReadFull(br, hdr); err != nil {
		return
	}
	if hdr[0] != 5 || hdr[1] != 1 { // 只支持 CONNECT
		local.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}

	var host string
	switch hdr[3] {
	case 1: // IPv4
		ip := make([]byte, 4)
		if _, err := io.ReadFull(br, ip); err != nil {
			return
		}
		host = net.IP(ip).String()
	case 3: // 域名，远端 DNS
		lb := make([]byte, 1)
		if _, err := io.ReadFull(br, lb); err != nil {
			return
		}
		hb := make([]byte, int(lb[0]))
		if _, err := io.ReadFull(br, hb); err != nil {
			return
		}
		host = string(hb)
	default:
		local.Write([]byte{5, 8, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(br, pb); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(pb)

	c, err := p.openTunnel(host, port)
	if err != nil {
		local.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer c.Close()
	if _, err := local.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	pump(local, c)
}

func pump(a, b io.ReadWriter) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(b, a)
		// 一侧读完后半关闭对端写入，避免另一侧永久阻塞
		closeWrite(b)
	}()
	go func() {
		defer wg.Done()
		io.Copy(a, b)
		closeWrite(a)
	}()
	wg.Wait()
}

func closeWrite(w io.Writer) {
	if cw, ok := w.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

func skipHeaders(br *bufio.Reader) error {
	for {
		l, err := br.ReadString('\n')
		if err != nil {
			return err
		}
		if l == "\r\n" || l == "\n" {
			return nil
		}
	}
}

func readHeaders(br *bufio.Reader) (string, error) {
	var sb strings.Builder
	for {
		l, err := br.ReadString('\n')
		if err != nil {
			return "", err
		}
		sb.WriteString(l)
		if l == "\r\n" || l == "\n" {
			return sb.String(), nil
		}
	}
}

func parseHostPort(s string) (string, uint16, error) {
	host, p, err := net.SplitHostPort(s)
	if err != nil {
		return "", 0, err
	}
	pn, err := strconv.Atoi(p)
	if err != nil || pn < 1 || pn > 65535 {
		return "", 0, fmt.Errorf("invalid port")
	}
	return host, uint16(pn), nil
}

func parseAbsoluteURL(s string) (string, uint16, string, error) {
	rest := s
	if idx := strings.Index(rest, "://"); idx >= 0 {
		rest = rest[idx+3:]
	}
	end := len(rest)
	for i, ch := range rest {
		if ch == '/' || ch == '?' {
			end = i
			break
		}
	}
	authority := rest[:end]
	path := rest[end:]
	if path == "" {
		path = "/"
	}
	if at := strings.LastIndex(authority, "@"); at >= 0 {
		authority = authority[at+1:]
	}
	port := uint16(80)
	if h, p, err := net.SplitHostPort(authority); err == nil {
		pn, err := strconv.Atoi(p)
		if err != nil {
			return "", 0, "", err
		}
		port = uint16(pn)
		authority = h
	}
	return authority, port, path, nil
}
