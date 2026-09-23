package security

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"strconv"
	"time"
)

// TURN's REST credential mechanism specifically requires HMAC-SHA1; this is not password hashing.
func TURNCredential(secret, subject string, expires time.Time) (string, string) {
	username := strconv.FormatInt(expires.Unix(), 10) + ":" + subject
	mac := hmac.New(sha1.New, []byte(secret))
	mac.Write([]byte(username))
	return username, base64.StdEncoding.EncodeToString(mac.Sum(nil))
}
