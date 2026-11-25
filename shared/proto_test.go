package shared

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"testing"
	"time"
)

func TestFrameEncryption(t *testing.T) {
	block, _ := aes.NewCipher(make([]byte, 32))
	aead, _ := cipher.NewGCM(block)
	s := &Session{aead: aead}

	host := "example.invalid"
	payload, _ := EncodeOpen(1, host, 443)
	frame, err := s.encryptFrame(FrameOpen, payload)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(frame, []byte(host)) || bytes.Contains(frame, []byte("example.invalid")) {
		t.Fatal("plaintext target domain leaked in frame")
	}

	s2 := &Session{aead: aead}
	typ, dec, err := s2.decryptFrame(frame)
	if err != nil {
		t.Fatal(err)
	}
	if typ != FrameOpen {
		t.Fatalf("wrong type %d", typ)
	}
	_, h, p, err := DecodeOpen(dec)
	if err != nil || h != host || p != 443 {
		t.Fatalf("decode failed: %s %d %v", h, p, err)
	}
}

func TestAuth(t *testing.T) {
	psk := make([]byte, 32)
	cn := make([]byte, 16)
	sn := make([]byte, 16)
	ts := time.Now().Unix()
	mac := ClientAuth(psk, cn, sn, ts)
	seen := make(map[string]bool)
	if !VerifyAuth(psk, cn, sn, mac, ts, seen) {
		t.Fatal("valid auth rejected")
	}
	if VerifyAuth(psk, cn, sn, mac, ts, seen) {
		t.Fatal("replay accepted")
	}
	badpsk := make([]byte, 32)
	badpsk[0] = 1
	if VerifyAuth(badpsk, cn, sn, mac, ts, make(map[string]bool)) {
		t.Fatal("bad psk accepted")
	}
}

// 两端时钟可不同步；新鲜度由 serverNonce 与 seen 表保证。
func TestAuthClockSkew(t *testing.T) {
	psk := make([]byte, 32)
	cn := make([]byte, 16)
	sn := make([]byte, 16)
	ts := time.Now().Add(-3 * time.Hour).Unix()
	mac := ClientAuth(psk, cn, sn, ts)
	if !VerifyAuth(psk, cn, sn, mac, ts, make(map[string]bool)) {
		t.Fatal("valid auth rejected due to clock skew")
	}
}

// 多帧连续传输时帧类型必须原样保留，CLOSE 不能被当作 DATA。
func TestFrameTypesAcrossStream(t *testing.T) {
	block, _ := aes.NewCipher(make([]byte, 32))
	aead, _ := cipher.NewGCM(block)
	w := &Session{aead: aead}
	r := &Session{aead: aead}
	types := []byte{FramePing, FrameOpen, FrameData, FrameClose}
	for i, want := range types {
		payload := []byte{byte(i), byte(i + 1)}
		frame, err := w.encryptFrame(want, payload)
		if err != nil {
			t.Fatal(err)
		}
		typ, got, err := r.decryptFrame(frame)
		if err != nil {
			t.Fatal(err)
		}
		if typ != want {
			t.Fatalf("frame %d: got type %d want %d", i, typ, want)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("frame %d: payload mismatch", i)
		}
	}
}
