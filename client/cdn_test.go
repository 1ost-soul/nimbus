package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/net/websocket"
	"nimbus/shared"
)

func testCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test.example"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"test.example"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemEncodeCert(der)) {
		t.Fatal("append cert failed")
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

func pemEncodeCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestCDNWebSocketHandshake(t *testing.T) {
	cert, pool := testCert(t)
	psk := make([]byte, 32)
	if _, err := rand.Read(psk); err != nil {
		t.Fatal(err)
	}

	seen := make(map[string]bool)
	wsServer := websocket.Server{Handler: func(ws *websocket.Conn) {
		defer ws.Close()
		_ = ws.SetDeadline(time.Now().Add(5 * time.Second))
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
		authResp := make([]byte, 40)
		if _, err := io.ReadFull(ws, authResp); err != nil {
			return
		}
		ts := int64(binary.BigEndian.Uint64(authResp[:8]))
		if !shared.VerifyAuth(psk, clientNonce, serverNonce, authResp[8:], ts, seen) {
			return
		}
		key, err := shared.DeriveQUICKey(psk, clientNonce, serverNonce)
		if err != nil {
			return
		}
		sess, err := shared.NewSessionFromKey(key)
		if err != nil {
			return
		}
		_ = sess.WriteFrame(ws, shared.FramePing, []byte{1})
	}}
	wsPath := shared.DeriveWSPath(psk)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != wsPath {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		wsServer.ServeHTTP(w, r)
	})
	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}
	srv.StartTLS()
	defer srv.Close()

	tlsCfg := &tls.Config{ServerName: "test.example", RootCAs: pool, MinVersion: tls.VersionTLS12}
	cdnCfg := tlsCfg.Clone()
	cdnCfg.NextProtos = []string{"http/1.1"}
	tun := &Tunnel{
		tlsCfg:         tlsCfg,
		cdnTLSCfg:      cdnCfg,
		serverAddr:     srv.Listener.Addr().String(),
		psk:            psk,
		connectionMode: "cdn",
	}
	conn, err := tun.Dial()
	if err != nil {
		t.Fatalf("cdn dial: %v", err)
	}
	conn.Close()
}
