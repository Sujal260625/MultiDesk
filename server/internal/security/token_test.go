package security

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestAccessTokenBoundaries(t *testing.T) {
	key := bytes.Repeat([]byte{42}, 32)
	now := time.Unix(1700000000, 0)
	token := Sign(key, "operator", 3, now)
	c, e := Verify(key, token, now)
	if e != nil || c.Subject != "operator" || c.Version != 3 {
		t.Fatal("valid token rejected")
	}
	cases := []string{"", token + "x", strings.Replace(token, ".", "", 1), base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`)) + "." + strings.Split(token, ".")[1] + "."}
	for _, v := range cases {
		if _, e := Verify(key, v, now); e == nil {
			t.Fatalf("invalid token accepted: %q", v)
		}
	}
	if _, e := Verify(bytes.Repeat([]byte{41}, 32), token, now); e == nil {
		t.Fatal("wrong signing key accepted")
	}
	if _, e := Verify(key, token, now.Add(10*time.Minute)); e == nil {
		t.Fatal("expiration boundary accepted")
	}
}
func TestDeviceProofBoundToMethodPathAndNonce(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	p := base64.StdEncoding.EncodeToString(pub)
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(key, DeviceMessage("POST", "/v1/devices", "nonce")))
	if !VerifyDevice(p, sig, "POST", "/v1/devices", "nonce") {
		t.Fatal("valid proof failed")
	}
	for _, v := range [][3]string{{"GET", "/v1/devices", "nonce"}, {"POST", "/v1/sessions", "nonce"}, {"POST", "/v1/devices", "other"}} {
		if VerifyDevice(p, sig, v[0], v[1], v[2]) {
			t.Fatal("proof was transferable")
		}
	}
	if VerifyDevice("bad", sig, "POST", "/v1/devices", "nonce") {
		t.Fatal("malformed key accepted")
	}
}
