package shared

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// WSPathPrefix 是 CDN WebSocket 端点的公开前缀。
// Cloudflare Origin Rule 只需匹配此前缀，不会触碰该域名其他路径。
const WSPathPrefix = "/api/events/"

// DeriveWSPath 从 PSK 派生本次部署的 WebSocket 完整路径。
// 只有持有相同 PSK 的客户端才能构造出正确路径；探测者猜错会落回普通 404 Web 外壳。
func DeriveWSPath(psk []byte) string {
	mac := hmac.New(sha256.New, psk)
	mac.Write([]byte("nimbus.cdn.ws.path.v1"))
	return WSPathPrefix + hex.EncodeToString(mac.Sum(nil)[:12])
}
