package platform

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/mail"
	"sort"
	"strings"
	"sync"
	"time"

	"muiltdesk/server/internal/security"
	"muiltdesk/server/internal/store"

	"github.com/coder/websocket"
)

type Permission string

const (
	View     Permission = "view"
	Mouse    Permission = "mouse"
	Keyboard Permission = "keyboard"
)

var permissions = map[Permission]bool{"view": true, "mouse": true, "keyboard": true, "files": true, "clipboard": true, "audio": true, "microphone": true, "system_info": true, "restart_app": true, "restart_computer": true, "record": true, "ai_analysis": true, "workflows": true}

type Device struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	OwnerID    string    `json:"owner_id"`
	PublicKey  string    `json:"public_key"`
	OS         string    `json:"os"`
	LastSeen   time.Time `json:"last_seen"`
	Revoked    bool      `json:"revoked"`
	Online     bool      `json:"online"`
	Unattended bool      `json:"unattended"`
}
type Session struct {
	ID              string       `json:"id"`
	OperatorID      string       `json:"operator_id"`
	SourceID        string       `json:"source_id"`
	TargetID        string       `json:"target_id"`
	State           string       `json:"state"`
	Requested       []Permission `json:"requested"`
	Granted         []Permission `json:"granted"`
	Created         time.Time    `json:"created"`
	Expires         time.Time    `json:"expires"`
	Epoch           uint64       `json:"epoch"`
	SourcePublicKey string       `json:"source_public_key"`
	TargetPublicKey string       `json:"target_public_key"`
}
type Audit struct {
	ID       string    `json:"id"`
	Actor    string    `json:"actor"`
	Action   string    `json:"action"`
	Resource string    `json:"resource"`
	At       time.Time `json:"at"`
}
type challenge struct {
	User    string
	Expires time.Time
}
type rate struct {
	Count int
	Until time.Time
}
type peer struct {
	socket *websocket.Conn
	send   chan []byte
}
type Signal struct {
	Type      string          `json:"type"`
	SessionID string          `json:"session_id,omitempty"`
	Sequence  uint64          `json:"sequence,omitempty"`
	Payload   json.RawMessage `json:"payload,omitempty"`
}
type Service struct {
	mu         sync.Mutex
	key        []byte
	now        func() time.Time
	store      store.Store
	mailer     Mailer
	accounts   map[string]*account
	emails     map[string]string
	refresh    map[string]*refreshToken
	devices    map[string]*Device
	sessions   map[string]*Session
	challenges map[string]challenge
	peers      map[string]*peer
	sequences  map[string]uint64
	rates      map[string]rate
	audit      []Audit
	authSlots  chan struct{}
	iceURLs    []string
	turnSecret string
}

func New(key []byte) *Service {
	return NewWithStore(key, store.NewMemoryStore())
}

func NewWithStore(key []byte, st store.Store) *Service {
	if len(key) < 32 {
		panic("JWT key must be at least 32 bytes")
	}
	return &Service{
		key:        append([]byte(nil), key...),
		now:        time.Now,
		store:      st,
		mailer:     &SMTPMailer{},
		accounts:   map[string]*account{},
		emails:     map[string]string{},
		refresh:    map[string]*refreshToken{},
		devices:    map[string]*Device{},
		sessions:   map[string]*Session{},
		challenges: map[string]challenge{},
		peers:      map[string]*peer{},
		sequences:  map[string]uint64{},
		rates:      map[string]rate{},
		authSlots:  make(chan struct{}, 2),
	}
}

func (s *Service) recordEvent(ctx context.Context, actor, action, resource string) {
	s.record(actor, action, resource)
	if s.store != nil {
		_ = s.store.CreateAudit(ctx, &store.AuditEvent{
			ID:         randomID(12),
			ActorID:    actor,
			Action:     action,
			ResourceID: resource,
			OccurredAt: s.now().UTC(),
		})
	}
}
func sendJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, status int, message string) {
	sendJSON(w, status, map[string]string{"error": message})
}
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if d.Decode(v) != nil {
		fail(w, 400, "invalid request body")
		return false
	}
	if d.Decode(new(any)) != io.EOF {
		fail(w, 400, "expected one JSON object")
		return false
	}
	return true
}
func contains(p []Permission, v Permission) bool {
	for _, x := range p {
		if x == v {
			return true
		}
	}
	return false
}
func controls(p []Permission) bool { return contains(p, Mouse) || contains(p, Keyboard) }
func validPermissions(p []Permission) bool {
	if len(p) == 0 || len(p) > len(permissions) || !contains(p, View) {
		return false
	}
	seen := map[Permission]bool{}
	for _, x := range p {
		if !permissions[x] || seen[x] {
			return false
		}
		seen[x] = true
	}
	return true
}
func subset(a, b []Permission) bool {
	for _, x := range a {
		if !contains(b, x) {
			return false
		}
	}
	return true
}
func (s *Service) record(user, action, resource string) {
	event := Audit{randomID(12), user, action, resource, s.now().UTC()}
	s.audit = append(s.audit, event)
	if len(s.audit) > 10000 {
		s.audit = s.audit[len(s.audit)-10000:]
	}
	slog.Info("audit", "actor", user, "action", action, "resource", resource)
}
func (s *Service) notify(device, kind string, v any) {
	p := s.peers[device]
	if p == nil {
		return
	}
	body, _ := json.Marshal(v)
	raw, _ := json.Marshal(Signal{Type: kind, Payload: body})
	select {
	case p.send <- raw:
	default:
		go p.socket.Close(websocket.StatusPolicyViolation, "slow consumer")
	}
}
func (s *Service) live(d *Device) bool {
	return d != nil && !d.Revoked && s.peers[d.ID] != nil && s.now().Sub(d.LastSeen) < 45*time.Second
}
func (s *Service) expire() {
	now := s.now()
	for _, session := range s.sessions {
		if (session.State == "pending" || session.State == "active") && !now.Before(session.Expires) {
			s.end(session, "expired", "system")
		}
	}
	for k, c := range s.challenges {
		if !now.Before(c.Expires) {
			delete(s.challenges, k)
		}
	}
	for k, r := range s.rates {
		if !now.Before(r.Until) {
			delete(s.rates, k)
		}
	}
	for k, r := range s.refresh {
		if !now.Before(r.Expires) {
			delete(s.refresh, k)
		}
	}
}
func (s *Service) end(session *Session, state, actor string) {
	session.State = state
	session.Granted = nil
	session.Epoch++
	s.notify(session.SourceID, "session.updated", session)
	s.notify(session.TargetID, "session.updated", session)
	s.record(actor, "session."+state, session.ID)
}
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		sendJSON(w, 200, map[string]any{"status": "ok", "storage": "volatile", "production_ready": false})
	})
	mux.HandleFunc("POST /v1/auth/register", s.register)
	mux.HandleFunc("POST /v1/auth/login", s.login)
	mux.HandleFunc("POST /v1/auth/refresh", s.rotate)
	mux.HandleFunc("POST /v1/auth/logout", s.auth(s.logout))
	mux.HandleFunc("GET /v1/me", s.auth(s.me))
	mux.HandleFunc("POST /v1/devices/challenge", s.auth(s.newChallenge))
	mux.HandleFunc("POST /v1/devices", s.auth(s.registerDevice))
	mux.HandleFunc("GET /v1/devices", s.auth(s.listDevices))
	mux.HandleFunc("DELETE /v1/devices/{id}", s.auth(s.revokeDevice))
	mux.HandleFunc("POST /v1/sessions", s.auth(s.requestSession))
	mux.HandleFunc("GET /v1/sessions", s.auth(s.listSessions))
	mux.HandleFunc("GET /v1/sessions/{id}/ice", s.auth(s.iceConfiguration))
	mux.HandleFunc("POST /v1/sessions/{id}/decision", s.auth(s.decideSession))
	mux.HandleFunc("PATCH /v1/sessions/{id}/permissions", s.auth(s.changePermissions))
	mux.HandleFunc("POST /v1/sessions/{id}/handover", s.auth(s.handover))
	mux.HandleFunc("DELETE /v1/sessions/{id}", s.auth(s.stopSession))
	mux.HandleFunc("GET /v1/audit", s.auth(s.listAudit))
	mux.HandleFunc("GET /v1/signalling", s.signalling)

	// Email Verification & Password Reset
	mux.HandleFunc("POST /v1/auth/verify-email", s.auth(s.sendVerifyEmail))
	mux.HandleFunc("POST /v1/auth/verify-email/confirm", s.auth(s.confirmVerifyEmail))
	mux.HandleFunc("POST /v1/auth/password-reset", s.requestPasswordReset)
	mux.HandleFunc("POST /v1/auth/password-reset/confirm", s.confirmPasswordReset)

	// Two-Factor Authentication (TOTP)
	mux.HandleFunc("POST /v1/auth/2fa/setup", s.auth(s.setup2FA))
	mux.HandleFunc("POST /v1/auth/2fa/confirm", s.auth(s.confirm2FA))
	mux.HandleFunc("POST /v1/auth/2fa/verify", s.verify2FALogin)
	mux.HandleFunc("POST /v1/auth/2fa/disable", s.auth(s.disable2FA))

	// Organizations & Teams
	mux.HandleFunc("POST /v1/organizations", s.auth(s.createOrganization))
	mux.HandleFunc("GET /v1/organizations", s.auth(s.listOrganizations))
	mux.HandleFunc("GET /v1/organizations/{id}/members", s.auth(s.listMembers))
	mux.HandleFunc("POST /v1/organizations/{id}/members", s.auth(s.inviteMember))
	mux.HandleFunc("PATCH /v1/organizations/{id}/members/{userId}", s.auth(s.updateMemberRole))
	mux.HandleFunc("DELETE /v1/organizations/{id}/members/{userId}", s.auth(s.removeMember))

	// Workflows & Automation
	mux.HandleFunc("POST /v1/organizations/{id}/workflows", s.auth(s.createWorkflow))
	mux.HandleFunc("GET /v1/organizations/{id}/workflows", s.auth(s.listWorkflows))
	mux.HandleFunc("POST /v1/sessions/{sid}/workflows/{wid}/run", s.auth(s.runWorkflow))
	mux.HandleFunc("GET /v1/workflow-runs/{id}", s.auth(s.getWorkflowRun))

	// AI Diagnostic Assistant
	mux.HandleFunc("POST /v1/sessions/{id}/ai/analyze", s.auth(s.analyzeSessionWithAI))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		host, _, e := net.SplitHostPort(r.RemoteAddr)
		if e != nil {
			host = r.RemoteAddr
		}
		s.mu.Lock()
		s.expire()
		key := host
		limit := 300
		if strings.HasPrefix(r.URL.Path, "/v1/auth/") {
			key += "/auth"
			limit = 15
		}
		v := s.rates[key]
		if !s.now().Before(v.Until) {
			v = rate{Until: s.now().Add(time.Minute)}
		}
		v.Count++
		s.rates[key] = v
		s.mu.Unlock()
		if v.Count > limit {
			w.Header().Set("Retry-After", "60")
			fail(w, 429, "too many requests")
			return
		}
		mux.ServeHTTP(w, r)
	})
}

type authenticated func(http.ResponseWriter, *http.Request, string)

func (s *Service) auth(next authenticated) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw := r.Header.Get("Authorization")
		if !strings.HasPrefix(raw, "Bearer ") {
			fail(w, 401, "authentication required")
			return
		}
		user, e := s.verifyAccess(strings.TrimPrefix(raw, "Bearer "))
		if e != nil {
			fail(w, 401, "invalid or expired access token")
			return
		}
		s.mu.Lock()
		exists := s.accounts[user] != nil
		s.mu.Unlock()
		if !exists {
			fail(w, 401, "account unavailable")
			return
		}
		next(w, r, user)
	}
}
func (s *Service) authSlot(w http.ResponseWriter) bool {
	select {
	case s.authSlots <- struct{}{}:
		return true
	default:
		fail(w, 429, "authentication busy; retry shortly")
		return false
	}
}
func (s *Service) register(w http.ResponseWriter, r *http.Request) {
	var q struct {
		Email    string `json:"email"`
		Name     string `json:"name"`
		Password string `json:"password"`
	}
	if !decode(w, r, &q) {
		return
	}
	q.Email = strings.ToLower(strings.TrimSpace(q.Email))
	a, e := mail.ParseAddress(q.Email)
	if e != nil || a.Address != q.Email || len(q.Email) > 254 || len(q.Name) < 1 || len(q.Name) > 80 || len(q.Password) < 12 || len(q.Password) > 256 {
		fail(w, 400, "valid email, name and password of 12–256 bytes required")
		return
	}
	if !s.authSlot(w) {
		return
	}
	defer func() { <-s.authSlots }()
	p := hashPassword(q.Password)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.emails[q.Email] != "" {
		fail(w, 409, "account cannot be registered")
		return
	}
	id := randomID(18)
	s.accounts[id] = &account{ID: id, Email: q.Email, Name: q.Name, Password: p}
	s.emails[q.Email] = id
	s.record(id, "account.registered", id)
	sendJSON(w, 201, s.issue(id, ""))
}
func (s *Service) login(w http.ResponseWriter, r *http.Request) {
	var q struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if !decode(w, r, &q) {
		return
	}
	if len(q.Password) > 256 {
		fail(w, 400, "invalid credentials")
		return
	}
	if !s.authSlot(w) {
		return
	}
	defer func() { <-s.authSlots }()
	s.mu.Lock()
	a := s.accounts[s.emails[strings.ToLower(strings.TrimSpace(q.Email))]]
	s.mu.Unlock()
	p := password{make([]byte, 16), make([]byte, 32)}
	if a != nil {
		p = a.Password
	}
	ok := p.matches(q.Password)
	if a == nil || !ok {
		fail(w, 401, "invalid credentials")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.record(a.ID, "account.login", a.ID)
	sendJSON(w, 200, s.issue(a.ID, ""))
}
func (s *Service) rotate(w http.ResponseWriter, r *http.Request) {
	var q struct {
		Token string `json:"refresh_token"`
	}
	if !decode(w, r, &q) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	t := s.refresh[digest(q.Token)]
	if t == nil || !s.now().Before(t.Expires) {
		fail(w, 401, "invalid refresh token")
		return
	}
	if t.Used {
		for _, x := range s.refresh {
			if x.Family == t.Family {
				x.Used = true
			}
		}
		s.invalidate(t.UserID)
		s.record(t.UserID, "auth.refresh_reuse", t.Family)
		fail(w, 401, "refresh token reuse; sign in again")
		return
	}
	t.Used = true
	sendJSON(w, 200, s.issue(t.UserID, t.Family))
}
func (s *Service) logout(w http.ResponseWriter, r *http.Request, user string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.invalidate(user)
	s.record(user, "account.logout", user)
	sendJSON(w, 200, map[string]bool{"ok": true})
}

// Caller holds mu. Invalidates access tokens, refresh tokens and all owned connections.
func (s *Service) invalidate(user string) {
	s.accounts[user].Version++
	for _, v := range s.refresh {
		if v.UserID == user {
			v.Used = true
		}
	}
	for _, v := range s.sessions {
		if s.visible(v, user) && (v.State == "active" || v.State == "pending") {
			s.end(v, "closed", user)
		}
	}
	for id, p := range s.peers {
		if s.devices[id].OwnerID == user && p.socket != nil {
			go p.socket.Close(websocket.StatusPolicyViolation, "account access revoked")
		}
	}
}
func (s *Service) me(w http.ResponseWriter, r *http.Request, user string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.accounts[user]
	sendJSON(w, 200, map[string]string{"id": a.ID, "name": a.Name, "email": a.Email})
}
func (s *Service) newChallenge(w http.ResponseWriter, r *http.Request, user string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	nonce := randomID(32)
	s.challenges[nonce] = challenge{user, s.now().Add(time.Minute)}
	sendJSON(w, 201, map[string]string{"nonce": nonce, "expires_in": "60", "message_format": "MuiltDesk/v1\\nMETHOD\\nPATH\\nNONCE"})
}

// Challenges are one-time, short-lived and bound to user, endpoint and HTTP method.
func (s *Service) proof(r *http.Request, user, key string) error {
	nonce := r.Header.Get("X-Device-Nonce")
	c, ok := s.challenges[nonce]
	delete(s.challenges, nonce)
	if !ok || c.User != user || !s.now().Before(c.Expires) {
		return errors.New("invalid challenge")
	}
	if !security.VerifyDevice(key, r.Header.Get("X-Device-Signature"), r.Method, r.URL.Path, nonce) {
		return errors.New("invalid signature")
	}
	return nil
}
func (s *Service) registerDevice(w http.ResponseWriter, r *http.Request, user string) {
	var q struct {
		Name      string `json:"name"`
		PublicKey string `json:"public_key"`
		OS        string `json:"os"`
	}
	if !decode(w, r, &q) {
		return
	}
	if len(q.Name) < 1 || len(q.Name) > 80 || (q.OS != "Windows 10" && q.OS != "Windows 11") {
		fail(w, 400, "device name and supported Windows OS required")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.proof(r, user, q.PublicKey) != nil {
		fail(w, 403, "device identity proof required")
		return
	}
	count := 0
	for _, d := range s.devices {
		if d.PublicKey == q.PublicKey {
			if d.OwnerID != user {
				fail(w, 409, "device identity already registered")
				return
			}
			if d.Revoked {
				fail(w, 403, "device identity has been revoked")
				return
			}
			d.Name, d.OS = q.Name, q.OS
			s.record(user, "device.registration_confirmed", d.ID)
			sendJSON(w, 200, d)
			return
		}
		if d.OwnerID == user && !d.Revoked {
			count++
		}
	}
	if count >= 100 {
		fail(w, 409, "device registration limit reached")
		return
	}
	d := &Device{ID: randomID(12), Name: q.Name, OwnerID: user, PublicKey: q.PublicKey, OS: q.OS}
	s.devices[d.ID] = d
	s.record(user, "device.registered", d.ID)
	sendJSON(w, 201, d)
}
func (s *Service) listDevices(w http.ResponseWriter, r *http.Request, user string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []Device{}
	for _, d := range s.devices {
		if d.OwnerID == user {
			v := *d
			v.Online = s.live(d)
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	sendJSON(w, 200, out)
}
func (s *Service) revokeDevice(w http.ResponseWriter, r *http.Request, user string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.devices[r.PathValue("id")]
	if d == nil || d.OwnerID != user {
		fail(w, 404, "device not found")
		return
	}
	d.Revoked = true
	for _, v := range s.sessions {
		if (v.SourceID == d.ID || v.TargetID == d.ID) && (v.State == "pending" || v.State == "active") {
			s.end(v, "revoked", user)
		}
	}
	if p := s.peers[d.ID]; p != nil && p.socket != nil {
		go p.socket.Close(websocket.StatusPolicyViolation, "device revoked")
	}
	s.record(user, "device.revoked", d.ID)
	sendJSON(w, 200, map[string]bool{"ok": true})
}
func (s *Service) visible(v *Session, user string) bool {
	return v.OperatorID == user || (s.devices[v.TargetID] != nil && s.devices[v.TargetID].OwnerID == user)
}
func (s *Service) listSessions(w http.ResponseWriter, r *http.Request, user string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []Session{}
	for _, v := range s.sessions {
		if s.visible(v, user) {
			out = append(out, *v)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.After(out[j].Created) })
	sendJSON(w, 200, out)
}
func (s *Service) requestSession(w http.ResponseWriter, r *http.Request, user string) {
	var q struct {
		SourceID    string       `json:"source_id"`
		TargetID    string       `json:"target_id"`
		Permissions []Permission `json:"permissions"`
	}
	if !decode(w, r, &q) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	source, target := s.devices[q.SourceID], s.devices[q.TargetID]
	if source == nil || source.OwnerID != user || !s.live(source) || !s.live(target) || q.SourceID == q.TargetID {
		fail(w, 404, "available source and target devices required")
		return
	}
	if s.proof(r, user, source.PublicKey) != nil {
		fail(w, 403, "source device proof required")
		return
	}
	if !validPermissions(q.Permissions) {
		fail(w, 400, "valid permissions including view required")
		return
	}
	count := 0
	for _, v := range s.sessions {
		if v.OperatorID == user && (v.State == "pending" || v.State == "active") {
			count++
			if v.TargetID == target.ID {
				fail(w, 409, "a session for this target already exists")
				return
			}
		}
	}
	if count >= 10 {
		fail(w, 409, "maximum 10 pending or active sessions")
		return
	}
	v := &Session{ID: randomID(18), OperatorID: user, SourceID: source.ID, TargetID: target.ID, State: "pending", Requested: q.Permissions, Granted: []Permission{}, Created: s.now().UTC(), Expires: s.now().Add(2 * time.Minute), Epoch: 1}
	v.SourcePublicKey, v.TargetPublicKey = source.PublicKey, target.PublicKey
	s.sessions[v.ID] = v
	s.notify(v.TargetID, "session.requested", map[string]any{"session": v, "operator_name": s.accounts[user].Name})
	s.record(user, "session.requested", v.ID)
	sendJSON(w, 201, v)
}
func (s *Service) targetSession(w http.ResponseWriter, r *http.Request, user string) *Session {
	v := s.sessions[r.PathValue("id")]
	if v == nil || s.devices[v.TargetID].OwnerID != user {
		fail(w, 404, "session not found")
		return nil
	}
	d := s.devices[v.TargetID]
	if !s.live(d) || s.proof(r, user, d.PublicKey) != nil {
		fail(w, 403, "online target device proof required")
		return nil
	}
	return v
}
func (s *Service) controllerBusy(v *Session) bool {
	for _, other := range s.sessions {
		if other.ID != v.ID && other.TargetID == v.TargetID && other.State == "active" && controls(other.Granted) {
			return true
		}
	}
	return false
}
func (s *Service) decideSession(w http.ResponseWriter, r *http.Request, user string) {
	var q struct {
		Approve     bool         `json:"approve"`
		Permissions []Permission `json:"permissions"`
	}
	if !decode(w, r, &q) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.targetSession(w, r, user)
	if v == nil {
		return
	}
	if v.State != "pending" {
		fail(w, 409, "session is not pending")
		return
	}
	if !q.Approve {
		s.end(v, "rejected", user)
		sendJSON(w, 200, v)
		return
	}
	if !validPermissions(q.Permissions) || !subset(q.Permissions, v.Requested) {
		fail(w, 400, "grants must be a subset of requested permissions")
		return
	}
	if controls(q.Permissions) && s.controllerBusy(v) {
		fail(w, 409, "another operator controls this device; approve view-only then hand over")
		return
	}
	v.Granted = q.Permissions
	v.State = "active"
	v.Expires = s.now().Add(8 * time.Hour)
	v.Epoch++
	s.notify(v.SourceID, "session.updated", v)
	s.notify(v.TargetID, "session.updated", v)
	s.record(user, "session.approved", v.ID)
	sendJSON(w, 200, v)
}
func (s *Service) changePermissions(w http.ResponseWriter, r *http.Request, user string) {
	var q struct {
		Permissions []Permission `json:"permissions"`
	}
	if !decode(w, r, &q) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.targetSession(w, r, user)
	if v == nil {
		return
	}
	if v.State != "active" {
		fail(w, 409, "session is not active")
		return
	}
	if len(q.Permissions) == 0 {
		s.end(v, "revoked", user)
		sendJSON(w, 200, v)
		return
	}
	if !validPermissions(q.Permissions) || !subset(q.Permissions, v.Requested) {
		fail(w, 400, "invalid grants")
		return
	}
	if controls(q.Permissions) && s.controllerBusy(v) {
		fail(w, 409, "control handover required")
		return
	}
	v.Granted = q.Permissions
	v.Epoch++
	s.notify(v.SourceID, "session.updated", v)
	s.notify(v.TargetID, "session.updated", v)
	s.record(user, "session.permissions_changed", v.ID)
	sendJSON(w, 200, v)
}
func (s *Service) handover(w http.ResponseWriter, r *http.Request, user string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.targetSession(w, r, user)
	if v == nil {
		return
	}
	if v.State != "active" || !controls(v.Requested) {
		fail(w, 409, "active session with requested control required")
		return
	}
	for _, old := range s.sessions {
		if old.TargetID == v.TargetID && old.State == "active" && old.ID != v.ID {
			next := []Permission{}
			for _, p := range old.Granted {
				if p != Mouse && p != Keyboard {
					next = append(next, p)
				}
			}
			old.Granted = next
			old.Epoch++
			s.notify(old.SourceID, "session.updated", old)
			s.notify(old.TargetID, "session.updated", old)
		}
	}
	for _, p := range []Permission{Mouse, Keyboard} {
		if contains(v.Requested, p) && !contains(v.Granted, p) {
			v.Granted = append(v.Granted, p)
		}
	}
	v.Epoch++
	s.notify(v.SourceID, "session.updated", v)
	s.notify(v.TargetID, "session.updated", v)
	s.record(user, "session.control_handover", v.ID)
	sendJSON(w, 200, v)
}
func (s *Service) stopSession(w http.ResponseWriter, r *http.Request, user string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.sessions[r.PathValue("id")]
	if v == nil || !s.visible(v, user) {
		fail(w, 404, "session not found")
		return
	}
	if v.State == "active" || v.State == "pending" {
		s.end(v, "closed", user)
	}
	sendJSON(w, 200, v)
}
func (s *Service) listAudit(w http.ResponseWriter, r *http.Request, user string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []Audit{}
	for i := len(s.audit) - 1; i >= 0 && len(out) < 200; i-- {
		e := s.audit[i]
		d := s.devices[e.Resource]
		v := s.sessions[e.Resource]
		if e.Actor == user || (d != nil && d.OwnerID == user) || (v != nil && s.visible(v, user)) {
			out = append(out, e)
		}
	}
	sendJSON(w, 200, out)
}

func (s *Service) signalling(w http.ResponseWriter, r *http.Request) {
	id := r.Header.Get("X-Device-ID")
	if id == "" {
		id = r.URL.Query().Get("device_id")
	}
	if id == "" {
		fail(w, 400, "X-Device-ID required")
		return
	}
	normID := strings.ReplaceAll(strings.TrimSpace(id), " ", "")

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		CompressionMode: websocket.CompressionDisabled,
		OriginPatterns:  []string{"*"},
	})
	if err != nil {
		return
	}
	conn.SetReadLimit(32 * 1024 * 1024)

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	p := &peer{conn, make(chan []byte, 512)}
	s.mu.Lock()
	if old := s.peers[normID]; old != nil {
		_ = old.socket.Close(websocket.StatusNormalClosure, "replaced by new session")
	}
	s.peers[normID] = p
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		if s.peers[normID] == p {
			delete(s.peers, normID)
		}
		s.mu.Unlock()
		_ = conn.CloseNow()
	}()

	go func() {
		ticker := time.NewTicker(20 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case data := <-p.send:
				writeCtx, done := context.WithTimeout(ctx, 5*time.Second)
				e := conn.Write(writeCtx, websocket.MessageText, data)
				done()
				if e != nil {
					cancel()
					return
				}
			case <-ticker.C:
				pingCtx, done := context.WithTimeout(ctx, 10*time.Second)
				e := conn.Ping(pingCtx)
				done()
				if e != nil {
					cancel()
					return
				}
			}
		}
	}()

	for {
		kind, raw, e := conn.Read(ctx)
		if e != nil {
			return
		}
		if kind != websocket.MessageText {
			continue
		}

		var msg struct {
			Type      string          `json:"type"`
			TargetID  string          `json:"target_id,omitempty"`
			Payload   json.RawMessage `json:"payload,omitempty"`
			SessionID string          `json:"session_id,omitempty"`
		}
		if json.Unmarshal(raw, &msg) != nil {
			continue
		}

		if msg.Type == "heartbeat" {
			_ = conn.Write(ctx, websocket.MessageText, []byte(`{"type":"heartbeat"}`))
			continue
		}

		target := msg.TargetID
		if target == "" {
			var subPayload struct {
				TargetID string `json:"target_id,omitempty"`
				Session  struct {
					TargetID string `json:"target_id,omitempty"`
					SourceID string `json:"source_id,omitempty"`
				} `json:"session,omitempty"`
			}
			if json.Unmarshal(msg.Payload, &subPayload) == nil {
				if subPayload.TargetID != "" {
					target = subPayload.TargetID
				} else if subPayload.Session.TargetID != "" {
					target = subPayload.Session.TargetID
					if strings.ReplaceAll(target, " ", "") == normID {
						target = subPayload.Session.SourceID
					}
				}
			}
		}

		normTarget := strings.ReplaceAll(strings.TrimSpace(target), " ", "")
		if normTarget == "" {
			continue
		}

		s.mu.Lock()
		targetPeer := s.peers[normTarget]
		s.mu.Unlock()

		if targetPeer != nil {
			select {
			case targetPeer.send <- raw:
			default:
			}
		} else if msg.Type == "session.requested" {
			offlineMsg, _ := json.Marshal(map[string]any{
				"type":      "session.updated",
				"state":     "offline",
				"reason":    "Remote desk is not online.",
				"target_id": target,
			})
			select {
			case p.send <- offlineMsg:
			default:
			}
		}
	}
}
