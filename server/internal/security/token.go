package security

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

type Claims struct {
	Subject  string `json:"sub"`
	Expires  int64  `json:"exp"`
	Issuer   string `json:"iss"`
	Audience string `json:"aud"`
	Version  uint64 `json:"ver"`
}

const header = `{"alg":"HS256","typ":"JWT"}`

func Sign(key []byte, user string, version uint64, now time.Time) string {
	h := base64.RawURLEncoding.EncodeToString([]byte(header))
	b, _ := json.Marshal(Claims{user, now.Add(10 * time.Minute).Unix(), "muiltdesk", "muiltdesk-api", version})
	payload := h + "." + base64.RawURLEncoding.EncodeToString(b)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(payload))
	return payload + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
func Verify(key []byte, token string, now time.Time) (Claims, error) {
	var c Claims
	parts := strings.Split(token, ".")
	if len(parts) != 3 || len(token) > 4096 {
		return c, errors.New("invalid access token")
	}
	h, e := base64.RawURLEncoding.DecodeString(parts[0])
	if e != nil || string(h) != header {
		return c, errors.New("invalid token header")
	}
	signature, e := base64.RawURLEncoding.DecodeString(parts[2])
	if e != nil {
		return c, e
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(parts[0] + "." + parts[1]))
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return c, errors.New("invalid signature")
	}
	raw, e := base64.RawURLEncoding.DecodeString(parts[1])
	if e != nil {
		return c, e
	}
	if json.Unmarshal(raw, &c) != nil || c.Subject == "" || c.Issuer != "muiltdesk" || c.Audience != "muiltdesk-api" || c.Expires <= now.Unix() || c.Expires > now.Add(11*time.Minute).Unix() {
		return c, errors.New("expired or invalid token")
	}
	return c, nil
}
func DeviceMessage(method, path, nonce string) []byte {
	return []byte("MuiltDesk/v1\n" + method + "\n" + path + "\n" + nonce)
}
func VerifyDevice(publicKey, signature, method, path, nonce string) bool {
	key, e := base64.StdEncoding.DecodeString(publicKey)
	if e != nil || len(key) != ed25519.PublicKeySize {
		return false
	}
	sig, e := base64.StdEncoding.DecodeString(signature)
	return e == nil && ed25519.Verify(key, DeviceMessage(method, path, nonce), sig)
}
