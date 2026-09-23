package platform

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestICERequiresActiveAuthorizedSession(t *testing.T) {
	f := setup(t)
	secret := strings.Repeat("x", 40)
	if err := f.s.ConfigureICE([]string{"stun:relay.example.invalid:3478", "turns:relay.example.invalid:5349?transport=tcp"}, secret); err != nil {
		t.Fatal(err)
	}
	v := f.request(t)
	path := "/v1/sessions/" + v.ID + "/ice"
	if w := f.call(t, "GET", path, "operator", "", nil); w.Code != 403 {
		t.Fatal("relay credentials issued before consent")
	}
	f.s.sessions[v.ID].State = "active"
	f.s.sessions[v.ID].Granted = []Permission{View}
	f.s.sessions[v.ID].Expires = f.s.now().Add(time.Hour)
	if w := f.call(t, "GET", path, "stranger", "", nil); w.Code != 404 {
		t.Fatal("unrelated account obtained relay credentials")
	}
	w := f.call(t, "GET", path, "operator", "", nil)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	var out struct {
		Servers []map[string]any `json:"ice_servers"`
		Expires time.Time        `json:"expires_at"`
	}
	if json.Unmarshal(w.Body.Bytes(), &out) != nil || len(out.Servers) != 2 {
		t.Fatal("invalid ICE response")
	}
	if out.Servers[0]["credential"] != nil || out.Servers[1]["credential"] == nil {
		t.Fatal("invalid relay credential scope")
	}
	if strings.Contains(w.Body.String(), secret) {
		t.Fatal("TURN secret disclosed")
	}
	if out.Expires.After(f.s.now().Add(10 * time.Minute)) {
		t.Fatal("relay token lifetime exceeds policy")
	}
	f.s.sessions[v.ID].State = "revoked"
	if w := f.call(t, "GET", path, "owner", "", nil); w.Code != 403 {
		t.Fatal("revoked session obtained credentials")
	}
}
func TestICEConfigurationRejectsUnsafeDefaults(t *testing.T) {
	f := setup(t)
	if f.s.ConfigureICE([]string{"turn:relay.invalid"}, "short") == nil {
		t.Fatal("weak relay secret accepted")
	}
	if f.s.ConfigureICE([]string{"https://relay.invalid"}, strings.Repeat("x", 40)) == nil {
		t.Fatal("non-ICE scheme accepted")
	}
}
