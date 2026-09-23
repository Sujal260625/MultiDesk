package platform

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type fixture struct {
	s                    *Service
	h                    http.Handler
	sourceKey, targetKey ed25519.PrivateKey
}

func setup(t *testing.T) *fixture {
	t.Helper()
	s := New(bytes.Repeat([]byte{7}, 32))
	s.accounts["operator"] = &account{ID: "operator", Name: "Operator"}
	s.accounts["owner"] = &account{ID: "owner", Name: "Owner"}
	s.accounts["stranger"] = &account{ID: "stranger", Name: "Stranger"}
	sp, sk, _ := ed25519.GenerateKey(rand.Reader)
	tp, tk, _ := ed25519.GenerateKey(rand.Reader)
	s.devices["source"] = &Device{ID: "source", OwnerID: "operator", PublicKey: base64.StdEncoding.EncodeToString(sp), LastSeen: s.now()}
	s.devices["target"] = &Device{ID: "target", OwnerID: "owner", PublicKey: base64.StdEncoding.EncodeToString(tp), LastSeen: s.now()}
	for _, id := range []string{"source", "target"} {
		s.peers[id] = &peer{send: make(chan []byte, 256)}
	}
	return &fixture{s, s.Handler(), sk, tk}
}
func (f *fixture) call(t *testing.T, method, path, user, body string, key ed25519.PrivateKey) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.RemoteAddr = "127.0.0.1:3456"
	if user != "" {
		r.Header.Set("Authorization", "Bearer "+f.s.signAccess(user))
	}
	if key != nil {
		nonce := randomID(24)
		f.s.challenges[nonce] = challenge{user, f.s.now().Add(time.Minute)}
		r.Header.Set("X-Device-Nonce", nonce)
		r.Header.Set("X-Device-Signature", base64.StdEncoding.EncodeToString(ed25519.Sign(key, []byte("MuiltDesk/v1\n"+method+"\n"+path+"\n"+nonce))))
	}
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, r)
	return w
}
func (f *fixture) request(t *testing.T) *Session {
	t.Helper()
	w := f.call(t, "POST", "/v1/sessions", "operator", `{"source_id":"source","target_id":"target","permissions":["view","mouse","keyboard"]}`, f.sourceKey)
	if w.Code != 201 {
		t.Fatalf("request: %d %s", w.Code, w.Body)
	}
	var v Session
	_ = json.Unmarshal(w.Body.Bytes(), &v)
	return &v
}
func TestConsentAndPermissionBoundaries(t *testing.T) {
	f := setup(t)
	v := f.request(t)
	if v.State != "pending" || len(v.Granted) != 0 {
		t.Fatal("request granted without consent")
	}
	if e := f.s.route("source", Signal{Type: "offer", SessionID: v.ID, Sequence: 1, Payload: json.RawMessage(`{}`)}); e == nil {
		t.Fatal("pending session signalled")
	}
	path := "/v1/sessions/" + v.ID + "/decision"
	if w := f.call(t, "POST", path, "stranger", `{"approve":true,"permissions":["view"]}`, f.targetKey); w.Code != 404 {
		t.Fatalf("stranger approved: %d", w.Code)
	}
	if w := f.call(t, "POST", path, "owner", `{"approve":true,"permissions":["view","files"]}`, f.targetKey); w.Code != 400 {
		t.Fatalf("unrequested permission: %d", w.Code)
	}
	if w := f.call(t, "POST", path, "owner", `{"approve":true,"permissions":["view","mouse"]}`, f.targetKey); w.Code != 200 {
		t.Fatalf("approve: %d %s", w.Code, w.Body)
	}
	if !contains(f.s.sessions[v.ID].Granted, Mouse) || contains(f.s.sessions[v.ID].Granted, Keyboard) {
		t.Fatal("incorrect grant")
	}
	m := Signal{Type: "offer", SessionID: v.ID, Sequence: 1, Payload: json.RawMessage(`{"sdp":"test"}`)}
	if e := f.s.route("source", m); e != nil {
		t.Fatal(e)
	}
	if e := f.s.route("source", m); e == nil {
		t.Fatal("signal replay accepted")
	}
	m.Sequence = 2
	m.Type = "input"
	if e := f.s.route("source", m); e == nil {
		t.Fatal("API accepted input")
	}
	w := f.call(t, "PATCH", "/v1/sessions/"+v.ID+"/permissions", "owner", `{"permissions":[]}`, f.targetKey)
	if w.Code != 200 || f.s.sessions[v.ID].State != "revoked" {
		t.Fatal("revocation failed")
	}
	m.Type = "ice"
	if e := f.s.route("source", m); e == nil {
		t.Fatal("revoked session signalled")
	}
}
func TestMaximumTenSessions(t *testing.T) {
	f := setup(t)
	for i := 0; i < 10; i++ {
		id := randomID(8)
		f.s.sessions[id] = &Session{ID: id, OperatorID: "operator", TargetID: id, State: "pending", Expires: f.s.now().Add(time.Minute)}
	}
	w := f.call(t, "POST", "/v1/sessions", "operator", `{"source_id":"source","target_id":"target","permissions":["view"]}`, f.sourceKey)
	if w.Code != 409 {
		t.Fatalf("expected limit, got %d", w.Code)
	}
}
func TestExpiredRequestCannotBeApproved(t *testing.T) {
	f := setup(t)
	v := f.request(t)
	f.s.sessions[v.ID].Expires = f.s.now().Add(-time.Second)
	w := f.call(t, "POST", "/v1/sessions/"+v.ID+"/decision", "owner", `{"approve":true,"permissions":["view"]}`, f.targetKey)
	if w.Code != 409 || f.s.sessions[v.ID].State != "expired" {
		t.Fatalf("expired session approved: %d", w.Code)
	}
}
func TestDeviceProofAndRevocation(t *testing.T) {
	f := setup(t)
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	body := `{"name":"My PC","os":"Windows 11","public_key":"` + base64.StdEncoding.EncodeToString(pub) + `"}`
	w := f.call(t, "POST", "/v1/devices", "operator", body, f.targetKey)
	if w.Code != 403 {
		t.Fatal("wrong key accepted")
	}
	w = f.call(t, "POST", "/v1/devices", "operator", body, key)
	if w.Code != 201 {
		t.Fatalf("register: %d %s", w.Code, w.Body)
	}
	v := f.request(t)
	w = f.call(t, "DELETE", "/v1/devices/target", "owner", "", nil)
	if w.Code != 200 || f.s.sessions[v.ID].State != "revoked" {
		t.Fatal("device revocation did not end pending session")
	}
}
func TestExclusiveControlHandover(t *testing.T) {
	f := setup(t)
	v := f.request(t)
	path := "/v1/sessions/" + v.ID
	w := f.call(t, "POST", path+"/decision", "owner", `{"approve":true,"permissions":["view","mouse","keyboard"]}`, f.targetKey)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	other := &Session{ID: "other", TargetID: "target", SourceID: "another", OperatorID: "stranger", State: "active", Requested: []Permission{View, Mouse}, Granted: []Permission{View}, Expires: f.s.now().Add(time.Hour)}
	f.s.sessions[other.ID] = other
	w = f.call(t, "PATCH", "/v1/sessions/other/permissions", "owner", `{"permissions":["view","mouse"]}`, f.targetKey)
	if w.Code != 409 {
		t.Fatal("concurrent control allowed")
	}
	w = f.call(t, "POST", "/v1/sessions/other/handover", "owner", "", f.targetKey)
	if w.Code != 200 || controls(f.s.sessions[v.ID].Granted) || !controls(other.Granted) {
		t.Fatal("handover failed")
	}
}
func TestRefreshReuseRevokesFamily(t *testing.T) {
	f := setup(t)
	initial := f.s.issue("operator", "")
	w := f.call(t, "POST", "/v1/auth/refresh", "", `{"refresh_token":"`+initial.RefreshToken+`"}`, nil)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	var next tokens
	_ = json.Unmarshal(w.Body.Bytes(), &next)
	w = f.call(t, "POST", "/v1/auth/refresh", "", `{"refresh_token":"`+initial.RefreshToken+`"}`, nil)
	if w.Code != 401 {
		t.Fatal("reuse accepted")
	}
	w = f.call(t, "POST", "/v1/auth/refresh", "", `{"refresh_token":"`+next.RefreshToken+`"}`, nil)
	if w.Code != 401 {
		t.Fatal("compromised token family survived")
	}
}
func TestTokenValidation(t *testing.T) {
	f := setup(t)
	token := f.s.signAccess("operator")
	if id, e := f.s.verifyAccess(token); e != nil || id != "operator" {
		t.Fatal("valid token failed")
	}
	if _, e := f.s.verifyAccess(token + "x"); e == nil {
		t.Fatal("tampered token passed")
	}
	now := f.s.now()
	f.s.now = func() time.Time { return now.Add(11 * time.Minute) }
	if _, e := f.s.verifyAccess(token); e == nil {
		t.Fatal("expired token passed")
	}
}
func TestRejectUnknownFieldsAndUnauthenticated(t *testing.T) {
	f := setup(t)
	w := f.call(t, "GET", "/v1/devices", "", "", nil)
	if w.Code != 401 {
		t.Fatal("unauthenticated read")
	}
	w = f.call(t, "POST", "/v1/sessions", "operator", `{"source_id":"source","hidden_access":true}`, f.sourceKey)
	if w.Code != 400 {
		t.Fatal("unknown field accepted")
	}
}
func TestArgonPasswordVerification(t *testing.T) {
	p := hashPassword("a long sample password")
	if !p.matches("a long sample password") || p.matches("wrong password") {
		t.Fatal("password validation failed")
	}
}
