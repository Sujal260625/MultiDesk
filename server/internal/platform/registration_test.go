package platform

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestRegistrationReusesIdentityButCannotRestoreRevokedDevice(t *testing.T) {
	f := setup(t)
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	body := `{"name":"Registered PC","os":"Windows 11","public_key":"` + base64.StdEncoding.EncodeToString(pub) + `"}`
	first := f.call(t, "POST", "/v1/devices", "operator", body, key)
	if first.Code != 201 {
		t.Fatal(first.Body.String())
	}
	var d Device
	_ = json.Unmarshal(first.Body.Bytes(), &d)
	again := f.call(t, "POST", "/v1/devices", "operator", body, key)
	if again.Code != 200 {
		t.Fatal(again.Body.String())
	}
	var same Device
	_ = json.Unmarshal(again.Body.Bytes(), &same)
	if same.ID != d.ID {
		t.Fatal("registration changed the public device ID")
	}
	if other := f.call(t, "POST", "/v1/devices", "stranger", body, key); other.Code != 409 {
		t.Fatal("device ownership changed")
	}
	f.s.devices[d.ID].Revoked = true
	if revoked := f.call(t, "POST", "/v1/devices", "operator", body, key); revoked.Code != 403 {
		t.Fatal("revoked device silently restored")
	}
}
