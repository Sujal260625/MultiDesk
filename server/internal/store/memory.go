package store

import (
	"context"
	"sync"
	"time"
)

// MemoryStore is a thread-safe, in-process implementation of Store.
// It is intended for development, testing, and single-node deployments where
// volatile storage is acceptable.  All data is lost on process restart.
type MemoryStore struct {
	mu sync.Mutex

	accounts     map[string]*Account     // id → account
	emails       map[string]string       // email → id
	refresh      map[string]*RefreshToken // hash → token
	devices      map[string]*Device      // id → device
	sessions     map[string]*Session     // id → session
	audit        []*AuditEvent
	secondFactor map[string]*SecondFactor // userID → factor
	emailTokens  map[string]*EmailToken   // tokenHash → token
	orgs         map[string]*Organization // id → org
	memberships  map[string]*Membership   // orgID+":"+userID → membership
	invites      map[string]*OrgInvite    // tokenHash → invite
	workflows    map[string]*Workflow     // id → workflow
	wfRuns       map[string]*WorkflowRun  // id → run
	transfers    map[string]*TransferRecord // id → record
	online       map[string]time.Time     // deviceID → expiry
}

// NewMemoryStore creates a ready-to-use in-memory Store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		accounts:     make(map[string]*Account),
		emails:       make(map[string]string),
		refresh:      make(map[string]*RefreshToken),
		devices:      make(map[string]*Device),
		sessions:     make(map[string]*Session),
		secondFactor: make(map[string]*SecondFactor),
		emailTokens:  make(map[string]*EmailToken),
		orgs:         make(map[string]*Organization),
		memberships:  make(map[string]*Membership),
		invites:      make(map[string]*OrgInvite),
		workflows:    make(map[string]*Workflow),
		wfRuns:       make(map[string]*WorkflowRun),
		transfers:    make(map[string]*TransferRecord),
		online:       make(map[string]time.Time),
	}
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func memberKey(orgID, userID string) string { return orgID + ":" + userID }

func cloneAccount(a *Account) *Account { c := *a; return &c }
func cloneDevice(d *Device) *Device    { c := *d; return &c }
func cloneSession(s *Session) *Session { c := *s; return &c }

// ─── Accounts ────────────────────────────────────────────────────────────────

func (m *MemoryStore) CreateAccount(_ context.Context, id, email, name string, passwordHash []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.emails[email]; exists {
		return ErrConflict
	}
	h := make([]byte, len(passwordHash))
	copy(h, passwordHash)
	m.accounts[id] = &Account{
		ID:           id,
		Email:        email,
		Name:         name,
		PasswordHash: h,
		CreatedAt:    time.Now().UTC(),
	}
	m.emails[email] = id
	return nil
}

func (m *MemoryStore) GetAccountByID(_ context.Context, id string) (*Account, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.accounts[id]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneAccount(a), nil
}

func (m *MemoryStore) GetAccountByEmail(_ context.Context, email string) (*Account, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.emails[email]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneAccount(m.accounts[id]), nil
}

func (m *MemoryStore) UpdateAccountVersion(_ context.Context, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.accounts[userID]
	if !ok {
		return ErrNotFound
	}
	a.TokenVersion++
	return nil
}

func (m *MemoryStore) SetEmailVerified(_ context.Context, userID string, t time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.accounts[userID]
	if !ok {
		return ErrNotFound
	}
	tc := t.UTC()
	a.EmailVerifiedAt = &tc
	return nil
}

func (m *MemoryStore) UpdatePassword(_ context.Context, userID string, passwordHash []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.accounts[userID]
	if !ok {
		return ErrNotFound
	}
	h := make([]byte, len(passwordHash))
	copy(h, passwordHash)
	a.PasswordHash = h
	a.TokenVersion++ // invalidate existing JWTs on password change
	return nil
}

// ─── Refresh tokens ───────────────────────────────────────────────────────────

func (m *MemoryStore) CreateRefreshToken(_ context.Context, hash, userID, familyID string, expires time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.refresh[hash] = &RefreshToken{
		Hash:      hash,
		UserID:    userID,
		FamilyID:  familyID,
		ExpiresAt: expires.UTC(),
	}
	return nil
}

func (m *MemoryStore) GetRefreshToken(_ context.Context, hash string) (*RefreshToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.refresh[hash]
	if !ok {
		return nil, ErrNotFound
	}
	c := *t
	return &c, nil
}

func (m *MemoryStore) MarkRefreshTokenUsed(_ context.Context, hash string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.refresh[hash]
	if !ok {
		return ErrNotFound
	}
	tc := at.UTC()
	t.UsedAt = &tc
	return nil
}

func (m *MemoryStore) RevokeFamily(_ context.Context, familyID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now().UTC()
	for _, t := range m.refresh {
		if t.FamilyID == familyID {
			tc := now
			t.UsedAt = &tc
			t.RevokedAt = &tc
		}
	}
	return nil
}

// ─── Devices ─────────────────────────────────────────────────────────────────

func (m *MemoryStore) CreateDevice(_ context.Context, d *Device) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.devices[d.ID]; exists {
		return ErrConflict
	}
	c := *d
	m.devices[d.ID] = &c
	return nil
}

func (m *MemoryStore) GetDevice(_ context.Context, id string) (*Device, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.devices[id]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneDevice(d), nil
}

func (m *MemoryStore) GetDeviceByPublicKey(_ context.Context, publicKey string) (*Device, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, d := range m.devices {
		if d.PublicKey == publicKey {
			return cloneDevice(d), nil
		}
	}
	return nil, ErrNotFound
}

func (m *MemoryStore) ListDevicesByOwner(_ context.Context, ownerID string) ([]*Device, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*Device
	for _, d := range m.devices {
		if d.OwnerID == ownerID {
			c := *d
			out = append(out, &c)
		}
	}
	return out, nil
}

func (m *MemoryStore) UpdateDevice(_ context.Context, d *Device) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.devices[d.ID]; !ok {
		return ErrNotFound
	}
	c := *d
	m.devices[d.ID] = &c
	return nil
}

func (m *MemoryStore) RevokeDevice(_ context.Context, id string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.devices[id]
	if !ok {
		return ErrNotFound
	}
	tc := at.UTC()
	d.RevokedAt = &tc
	d.Revoked = true
	return nil
}

// ─── Sessions ─────────────────────────────────────────────────────────────────

func (m *MemoryStore) CreateSession(_ context.Context, s *Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.sessions[s.ID]; exists {
		return ErrConflict
	}
	c := *s
	m.sessions[s.ID] = &c
	return nil
}

func (m *MemoryStore) GetSession(_ context.Context, id string) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneSession(s), nil
}

func (m *MemoryStore) UpdateSession(_ context.Context, s *Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.sessions[s.ID]; !ok {
		return ErrNotFound
	}
	c := *s
	m.sessions[s.ID] = &c
	return nil
}

func (m *MemoryStore) ListActiveSessionsByDevice(_ context.Context, deviceID string) ([]*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*Session
	for _, s := range m.sessions {
		if (s.SourceDeviceID == deviceID || s.TargetDeviceID == deviceID) &&
			(s.State == "pending" || s.State == "active") {
			c := *s
			out = append(out, &c)
		}
	}
	return out, nil
}

func (m *MemoryStore) ListSessionsByOperator(_ context.Context, operatorID string) ([]*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*Session
	for _, s := range m.sessions {
		if s.OperatorID == operatorID {
			c := *s
			out = append(out, &c)
		}
	}
	return out, nil
}

// ─── Audit ───────────────────────────────────────────────────────────────────

func (m *MemoryStore) CreateAudit(_ context.Context, e *AuditEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := *e
	m.audit = append(m.audit, &c)
	if len(m.audit) > 10000 {
		m.audit = m.audit[len(m.audit)-10000:]
	}
	return nil
}

func (m *MemoryStore) ListAudit(_ context.Context, actorID string, limit int) ([]*AuditEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*AuditEvent
	for i := len(m.audit) - 1; i >= 0 && len(out) < limit; i-- {
		e := m.audit[i]
		if e.ActorID == actorID {
			c := *e
			out = append(out, &c)
		}
	}
	return out, nil
}

// ─── Presence ─────────────────────────────────────────────────────────────────

func (m *MemoryStore) SetOnline(_ context.Context, deviceID string, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.online[deviceID] = time.Now().Add(ttl)
	return nil
}

func (m *MemoryStore) IsOnline(_ context.Context, deviceID string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	exp, ok := m.online[deviceID]
	if !ok {
		return false, nil
	}
	return time.Now().Before(exp), nil
}

// ─── 2FA ─────────────────────────────────────────────────────────────────────

func (m *MemoryStore) CreateSecondFactor(_ context.Context, id, userID, kind string, secret []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	sec := make([]byte, len(secret))
	copy(sec, secret)
	m.secondFactor[userID] = &SecondFactor{
		ID:              id,
		UserID:          userID,
		Kind:            kind,
		EncryptedSecret: sec,
	}
	return nil
}

func (m *MemoryStore) GetSecondFactor(_ context.Context, userID string) (*SecondFactor, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	sf, ok := m.secondFactor[userID]
	if !ok {
		return nil, ErrNotFound
	}
	c := *sf
	return &c, nil
}

func (m *MemoryStore) VerifySecondFactor(_ context.Context, id string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, sf := range m.secondFactor {
		if sf.ID == id {
			tc := at.UTC()
			sf.VerifiedAt = &tc
			return nil
		}
	}
	return ErrNotFound
}

func (m *MemoryStore) DeleteSecondFactor(_ context.Context, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.secondFactor[userID]; !ok {
		return ErrNotFound
	}
	delete(m.secondFactor, userID)
	return nil
}

// ─── Email tokens ─────────────────────────────────────────────────────────────

func (m *MemoryStore) CreateEmailToken(_ context.Context, tokenHash, userID, kind string, expires time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.emailTokens[tokenHash] = &EmailToken{
		TokenHash: tokenHash,
		UserID:    userID,
		Kind:      kind,
		ExpiresAt: expires.UTC(),
	}
	return nil
}

func (m *MemoryStore) GetEmailToken(_ context.Context, tokenHash string) (*EmailToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	et, ok := m.emailTokens[tokenHash]
	if !ok {
		return nil, ErrNotFound
	}
	c := *et
	return &c, nil
}

func (m *MemoryStore) DeleteEmailToken(_ context.Context, tokenHash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.emailTokens, tokenHash)
	return nil
}

// ─── Organizations ────────────────────────────────────────────────────────────

func (m *MemoryStore) CreateOrganization(_ context.Context, o *Organization) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.orgs[o.ID]; exists {
		return ErrConflict
	}
	c := *o
	m.orgs[o.ID] = &c
	return nil
}

func (m *MemoryStore) GetOrganization(_ context.Context, id string) (*Organization, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	o, ok := m.orgs[id]
	if !ok {
		return nil, ErrNotFound
	}
	c := *o
	return &c, nil
}

func (m *MemoryStore) ListUserOrganizations(_ context.Context, userID string) ([]*Organization, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*Organization
	for _, mem := range m.memberships {
		if mem.UserID == userID {
			if o, ok := m.orgs[mem.OrganizationID]; ok {
				c := *o
				out = append(out, &c)
			}
		}
	}
	return out, nil
}

// ─── Memberships ─────────────────────────────────────────────────────────────

func (m *MemoryStore) CreateMembership(_ context.Context, orgID, userID, role string, expires *time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := memberKey(orgID, userID)
	mem := &Membership{OrganizationID: orgID, UserID: userID, Role: role}
	if expires != nil {
		tc := expires.UTC()
		mem.ExpiresAt = &tc
	}
	m.memberships[key] = mem
	return nil
}

func (m *MemoryStore) GetMembership(_ context.Context, orgID, userID string) (*Membership, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	mem, ok := m.memberships[memberKey(orgID, userID)]
	if !ok {
		return nil, ErrNotFound
	}
	c := *mem
	return &c, nil
}

func (m *MemoryStore) ListMembers(_ context.Context, orgID string) ([]*Membership, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*Membership
	for _, mem := range m.memberships {
		if mem.OrganizationID == orgID {
			c := *mem
			out = append(out, &c)
		}
	}
	return out, nil
}

func (m *MemoryStore) UpdateMemberRole(_ context.Context, orgID, userID, role string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	mem, ok := m.memberships[memberKey(orgID, userID)]
	if !ok {
		return ErrNotFound
	}
	mem.Role = role
	return nil
}

func (m *MemoryStore) RemoveMembership(_ context.Context, orgID, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := memberKey(orgID, userID)
	if _, ok := m.memberships[key]; !ok {
		return ErrNotFound
	}
	delete(m.memberships, key)
	return nil
}

// ─── Invites ──────────────────────────────────────────────────────────────────

func (m *MemoryStore) CreateInvite(_ context.Context, inv *OrgInvite) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := *inv
	m.invites[inv.TokenHash] = &c
	return nil
}

func (m *MemoryStore) GetInviteByToken(_ context.Context, tokenHash string) (*OrgInvite, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	inv, ok := m.invites[tokenHash]
	if !ok {
		return nil, ErrNotFound
	}
	c := *inv
	return &c, nil
}

func (m *MemoryStore) AcceptInvite(_ context.Context, tokenHash string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	inv, ok := m.invites[tokenHash]
	if !ok {
		return ErrNotFound
	}
	tc := at.UTC()
	inv.AcceptedAt = &tc
	return nil
}

// ─── Workflows ────────────────────────────────────────────────────────────────

func (m *MemoryStore) CreateWorkflow(_ context.Context, w *Workflow) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.workflows[w.ID]; exists {
		return ErrConflict
	}
	c := *w
	m.workflows[w.ID] = &c
	return nil
}

func (m *MemoryStore) GetWorkflow(_ context.Context, id string) (*Workflow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	w, ok := m.workflows[id]
	if !ok {
		return nil, ErrNotFound
	}
	c := *w
	return &c, nil
}

func (m *MemoryStore) ListWorkflows(_ context.Context, orgID string) ([]*Workflow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*Workflow
	for _, w := range m.workflows {
		if w.OrganizationID == orgID {
			c := *w
			out = append(out, &c)
		}
	}
	return out, nil
}

func (m *MemoryStore) UpdateWorkflow(_ context.Context, w *Workflow) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.workflows[w.ID]; !ok {
		return ErrNotFound
	}
	c := *w
	m.workflows[w.ID] = &c
	return nil
}

func (m *MemoryStore) CreateWorkflowRun(_ context.Context, run *WorkflowRun) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.wfRuns[run.ID]; exists {
		return ErrConflict
	}
	c := *run
	m.wfRuns[run.ID] = &c
	return nil
}

func (m *MemoryStore) GetWorkflowRun(_ context.Context, id string) (*WorkflowRun, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.wfRuns[id]
	if !ok {
		return nil, ErrNotFound
	}
	c := *r
	return &c, nil
}

func (m *MemoryStore) UpdateWorkflowRun(_ context.Context, run *WorkflowRun) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.wfRuns[run.ID]; !ok {
		return ErrNotFound
	}
	c := *run
	m.wfRuns[run.ID] = &c
	return nil
}

// ─── Transfers ────────────────────────────────────────────────────────────────

func (m *MemoryStore) CreateTransferRecord(_ context.Context, tr *TransferRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := *tr
	m.transfers[tr.ID] = &c
	return nil
}

func (m *MemoryStore) UpdateTransferRecord(_ context.Context, tr *TransferRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.transfers[tr.ID]; !ok {
		return ErrNotFound
	}
	c := *tr
	m.transfers[tr.ID] = &c
	return nil
}

// ─── Lifecycle ────────────────────────────────────────────────────────────────

func (m *MemoryStore) Close() error { return nil }
