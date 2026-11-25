// Package shared 定义 NB 的帧格式、加密与认证逻辑。
// 对外不出现协议名字面量。
package shared

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"

	"golang.org/x/crypto/hkdf"
)

const (
	version = byte(1)

	FrameOpen  = byte(1)
	FrameData  = byte(2)
	FrameClose = byte(3)
	FramePing  = byte(4)

	NonceLen = 16
	maxFrame = 1 << 20 // 1 MiB

	Magic = "NBFRAME1" // 内部同步标记，非协议名

	// WebTransportMagic 是在 HTTP/3 连接上区分隧道 stream 与普通请求 stream 的 varint 前缀。
	WebTransportMagic uint64 = 0x9e37
)

var (
	ErrAuth   = errors.New("authentication failed")
	ErrClosed = errors.New("connection closed")
)

// Config 服务端配置
type Config struct {
	PSK []byte
}

// GenPSK 生成随机 PSK
func GenPSK() ([]byte, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// deriveKey 用 TLS exporter 派生会话密钥
func deriveKey(conn *tls.Conn, label string) ([]byte, error) {
	state := conn.ConnectionState()
	return state.ExportKeyingMaterial(label, nil, 32)
}

// Session 封装加密会话，读写均加锁保证并发安全。
type Session struct {
	aead    cipher.AEAD
	seq     uint64
	readSeq uint64
	wmu     sync.Mutex
	rmu     sync.Mutex
}

// NewSession 从 TLS 连接派生会话（TCP 传输路径）
func NewSession(conn *tls.Conn) (*Session, error) {
	key, err := deriveKey(conn, "nimbus.session.v1")
	if err != nil {
		return nil, err
	}
	return NewSessionFromKey(key)
}

// NewSessionFromKey 从原始 32 字节密钥创建会话（QUIC 等非 TLS-Conn 路径使用）
func NewSessionFromKey(key []byte) (*Session, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("session key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Session{aead: aead}, nil
}

// DeriveQUICKey 用 PSK 与双 nonce 经 HKDF-SHA256 派生 QUIC 会话密钥。
// QUIC 的加密由 quic-go 在传输层完成，这里派生的是 NB 帧层的独立密钥。
func DeriveQUICKey(psk, clientNonce, serverNonce []byte) ([]byte, error) {
	salt := append(append([]byte{}, clientNonce...), serverNonce...)
	r := hkdf.New(sha256.New, psk, salt, []byte("nimbus.session.v1"))
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}
	return key, nil
}

func aad(seq uint64) []byte {
	b := make([]byte, 9)
	binary.BigEndian.PutUint64(b, seq)
	b[8] = version
	return b
}

// encryptFrame 构造一帧密文（内部使用，调用方需持有 wmu）
func (s *Session) encryptFrame(typ byte, payload []byte) ([]byte, error) {
	inner := make([]byte, 1+len(payload))
	inner[0] = typ
	copy(inner[1:], payload)

	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ct := s.aead.Seal(nil, nonce, inner, aad(s.seq))
	s.seq++

	out := make([]byte, 0, len(nonce)+4+len(ct))
	out = append(out, nonce...)
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(ct)))
	out = append(out, l[:]...)
	out = append(out, ct...)
	return out, nil
}

// WriteFrame 加密并写入一帧（带锁）
func (s *Session) WriteFrame(w io.Writer, typ byte, payload []byte) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	out, err := s.encryptFrame(typ, payload)
	if err != nil {
		return err
	}
	_, err = w.Write(out)
	return err
}

// ReadFrame 从 io.Reader 读取并解密一帧（带锁，单读循环使用）
func (s *Session) ReadFrame(r io.Reader) (byte, []byte, error) {
	s.rmu.Lock()
	defer s.rmu.Unlock()

	ns := s.aead.NonceSize()
	header := make([]byte, ns+4)
	if _, err := io.ReadFull(r, header); err != nil {
		return 0, nil, err
	}
	clen := int(binary.BigEndian.Uint32(header[ns : ns+4]))
	if clen <= 0 || clen > maxFrame {
		return 0, nil, fmt.Errorf("invalid frame length %d", clen)
	}
	all := make([]byte, ns+4+clen)
	copy(all, header)
	if _, err := io.ReadFull(r, all[ns+4:]); err != nil {
		return 0, nil, err
	}
	return s.decryptFrame(all)
}

// decryptFrame 解密一帧（内部使用，调用方需持有 rmu）
func (s *Session) decryptFrame(all []byte) (byte, []byte, error) {
	ns := s.aead.NonceSize()
	nonce := all[:ns]
	ct := all[ns+4:]
	inner, err := s.aead.Open(nil, nonce, ct, aad(s.readSeq))
	if err != nil {
		return 0, nil, err
	}
	s.readSeq++
	if len(inner) < 1 {
		return 0, nil, fmt.Errorf("empty frame")
	}
	return inner[0], inner[1:], nil
}

// ClientAuth 计算 HMAC
func ClientAuth(psk, clientNonce, serverNonce []byte, ts int64) []byte {
	m := hmac.New(sha256.New, psk)
	m.Write(clientNonce)
	m.Write(serverNonce)
	var tb [8]byte
	binary.BigEndian.PutUint64(tb[:], uint64(ts))
	m.Write(tb[:])
	return m.Sum(nil)
}

// VerifyAuth 验证认证，使用 nonce 防重放。
// 不校验 ts 与本地时钟的偏差：两端时钟可能不同步；
// 新鲜度由服务端每次随机生成的 serverNonce 保证。
func VerifyAuth(psk, clientNonce, serverNonce, mac []byte, ts int64, seen map[string]bool) bool {
	if !hmac.Equal(ClientAuth(psk, clientNonce, serverNonce, ts), mac) {
		return false
	}
	key := fmt.Sprintf("%x%x", clientNonce, serverNonce)
	if seen[key] {
		return false
	}
	// 限制长期运行的内存占用；serverNonce 每次随机，清空不会造成可利用重放。
	if len(seen) > 10000 {
		for k := range seen {
			delete(seen, k)
		}
	}
	seen[key] = true
	return true
}

// RandomNonce 生成随机 nonce
func RandomNonce() ([]byte, error) {
	b := make([]byte, NonceLen)
	_, err := rand.Read(b)
	return b, err
}

// EncodeOpen 编码 OPEN 载荷：streamID(4) + hostlen(1) + host + port(2)
func EncodeOpen(streamID uint32, host string, port uint16) ([]byte, error) {
	if len(host) == 0 || len(host) > 255 {
		return nil, fmt.Errorf("invalid host length")
	}
	b := make([]byte, 4+1+len(host)+2)
	binary.BigEndian.PutUint32(b[0:4], streamID)
	b[4] = byte(len(host))
	copy(b[5:], host)
	binary.BigEndian.PutUint16(b[5+len(host):], port)
	return b, nil
}

// DecodeOpen 解码 OPEN 载荷
func DecodeOpen(b []byte) (uint32, string, uint16, error) {
	if len(b) < 7 {
		return 0, "", 0, fmt.Errorf("short open")
	}
	id := binary.BigEndian.Uint32(b[0:4])
	hl := int(b[4])
	if len(b) < 5+hl+2 {
		return 0, "", 0, fmt.Errorf("short open")
	}
	host := string(b[5 : 5+hl])
	port := binary.BigEndian.Uint16(b[5+hl : 7+hl])
	return id, host, port, nil
}

// EncodeData 编码 DATA 载荷：streamID(4) + data
func EncodeData(streamID uint32, data []byte) []byte {
	b := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(b[0:4], streamID)
	copy(b[4:], data)
	return b
}

// DecodeData 解码 DATA 载荷
func DecodeData(b []byte) (uint32, []byte, error) {
	if len(b) < 4 {
		return 0, nil, fmt.Errorf("short data")
	}
	return binary.BigEndian.Uint32(b[0:4]), b[4:], nil
}

// EncodeClose 编码 CLOSE 载荷：streamID(4)
func EncodeClose(streamID uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, streamID)
	return b
}

// DecodeClose 解码 CLOSE 载荷
func DecodeClose(b []byte) (uint32, error) {
	if len(b) < 4 {
		return 0, fmt.Errorf("short close")
	}
	return binary.BigEndian.Uint32(b[0:4]), nil
}
