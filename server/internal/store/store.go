// Package store defines the persistence interface for MuiltDesk and all
// associated domain types. Implementations include in-memory (testing /
// single-node), PostgreSQL (production) and a Redis decorator that layers
// presence and pub/sub on top of any base Store.
package store

import (
	"context"
	"errors"
	"time"
)

// ─── sentinel errors ─────────────────────────────────────────────────────────

var (
	ErrNotFound   = errors.New("store: record not found")
	ErrConflict   = errors.New("store: unique constraint violation")
	ErrExpired    = errors.New("store: record is expired")
)

// ─── domain types ────────────────────────────────────────────────────────────

// Account represents a registered user.
type Account struct {
	ID              string    `json:"id"`
	Email           string    `json:"email"`
	Name            string    `json:"name"`
	PasswordHash    []byte    `json:"omit"`  // argon2id salt‖hash blob
	TokenVersion    uint64    `json:"token_version"`
	EmailVerifiedAt *time.Time `json:"email_verified_at,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
}

// RefreshToken is the server-side record for a refresh token family.
// Only the SHA-256 hash of the raw token is stored.
type RefreshToken struct {
	Hash      string    `json:"hash"`
	UserID    string    `json:"user_id"`
	FamilyID  string    `json:"family_id"`
	ExpiresAt time.Time `json:"expires_at"`
	UsedAt    *time.Time `json:"used_at,omitempty"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

// Device represents a registered Windows endpoint.
type Device struct {
	ID             string     `json:"id"`
	Name           string     `json:"name"`
	OwnerID        string     `json:"owner_id"`
	OrganizationID *string    `json:"organization_id,omitempty"`
	PublicKey      string     `json:"public_key"` // base64-std Ed25519 public key
	OS             string     `json:"os"`
	LastSeen       time.Time  `json:"last_seen"`
	RevokedAt      *time.Time `json:"revoked_at,omitempty"`
	Revoked        bool       `json:"revoked"`
	Online         bool       `json:"online"`
	Unattended     bool       `json:"unattended"`
	CreatedAt      time.Time  `json:"created_at"`
}

// Session represents a remote-control session between a source and target device.
type Session struct {
	ID               string    `json:"id"`
	OperatorID       string    `json:"operator_id"`
	SourceDeviceID   string    `json:"source_id"`
	TargetDeviceID   string    `json:"target_id"`
	State            string    `json:"state"` // pending|active|rejected|closed|expired|revoked|disconnected
	RequestedPerms   []string  `json:"requested"`
	GrantedPerms     []string  `json:"granted"`
	Epoch            uint64    `json:"epoch"`
	SourcePublicKey  string    `json:"source_public_key"`
	TargetPublicKey  string    `json:"target_public_key"`
	RecordingConsent bool      `json:"recording_consent"`
	ChatEnabled      bool      `json:"chat_enabled"`
	NotesCount       int       `json:"notes_count"`
	CreatedAt        time.Time `json:"created"`
	ExpiresAt        time.Time `json:"expires"`
	EndedAt          *time.Time `json:"ended_at,omitempty"`
}

// AuditEvent records a security-relevant action.
type AuditEvent struct {
	ID             string    `json:"id"`
	ActorID        string    `json:"actor"`
	OrganizationID *string   `json:"organization_id,omitempty"`
	Action         string    `json:"action"`
	ResourceID     string    `json:"resource"`
	Metadata       map[string]any `json:"metadata,omitempty"`
	OccurredAt     time.Time `json:"at"`
}

// SecondFactor stores TOTP or backup-code 2FA for an account.
type SecondFactor struct {
	ID              string     `json:"id"`
	UserID          string     `json:"user_id"`
	Kind            string     `json:"kind"` // totp | backup
	EncryptedSecret []byte     `json:"-"`
	VerifiedAt      *time.Time `json:"verified_at,omitempty"`
}

// EmailToken is a short-lived token for email verification or password reset.
type EmailToken struct {
	TokenHash string    `json:"token_hash"` // SHA-256 hex of raw token
	UserID    string    `json:"user_id"`
	Kind      string    `json:"kind"` // verify | reset
	ExpiresAt time.Time `json:"expires_at"`
}

// Organization represents a team or company.
type Organization struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	OwnerID   string    `json:"owner_id"`
	CreatedAt time.Time `json:"created_at"`
}

// Membership links a user to an organization with a role.
type Membership struct {
	OrganizationID string     `json:"organization_id"`
	UserID         string     `json:"user_id"`
	Role           string     `json:"role"` // owner|administrator|operator|viewer|guest
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
}

// OrgInvite holds a pending invitation to an organization.
type OrgInvite struct {
	ID        string     `json:"id"`
	OrgID     string     `json:"org_id"`
	Email     string     `json:"email"`
	Role      string     `json:"role"`
	TokenHash string     `json:"-"`
	ExpiresAt time.Time  `json:"expires_at"`
	AcceptedAt *time.Time `json:"accepted_at,omitempty"`
}

// Workflow defines an automation that runs inside a session.
type Workflow struct {
	ID                 string    `json:"id"`
	OrganizationID     string    `json:"organization_id"`
	Name               string    `json:"name"`
	Definition         []byte    `json:"definition"` // raw JSON
	RequiredPermissions []string `json:"required_permissions"`
	Enabled            bool      `json:"enabled"`
	CreatedBy          string    `json:"created_by"`
}

// WorkflowRun is a single execution of a Workflow.
type WorkflowRun struct {
	ID         string     `json:"id"`
	WorkflowID string     `json:"workflow_id"`
	SessionID  string     `json:"session_id"`
	ApprovedBy *string    `json:"approved_by,omitempty"`
	State      string     `json:"state"` // pending|running|succeeded|failed|cancelled
	StartedAt  *time.Time `json:"started_at,omitempty"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
}

// TransferRecord tracks a file transfer associated with a session.
type TransferRecord struct {
	ID         string    `json:"id"`
	SessionID  string    `json:"session_id"`
	Basename   string    `json:"basename"`
	SizeBytes  int64     `json:"size_bytes"`
	SHA256     []byte    `json:"sha256"`
	State      string    `json:"state"` // pending|complete|failed
	CreatedAt  time.Time `json:"created_at"`
}

// ─── Store interface ──────────────────────────────────────────────────────────

// Store is the single persistence abstraction used throughout the service layer.
// All methods accept a context so callers can cancel or time-out operations.
// Implementations must be safe for concurrent use.
type Store interface {
	// ── Accounts ──────────────────────────────────────────────────────────
	CreateAccount(ctx context.Context, id, email, name string, passwordHash []byte) error
	GetAccountByID(ctx context.Context, id string) (*Account, error)
	GetAccountByEmail(ctx context.Context, email string) (*Account, error)
	// UpdateAccountVersion increments the token_version, invalidating all JWTs.
	UpdateAccountVersion(ctx context.Context, userID string) error
	SetEmailVerified(ctx context.Context, userID string, t time.Time) error
	// UpdatePassword replaces the stored password hash.
	UpdatePassword(ctx context.Context, userID string, passwordHash []byte) error

	// ── Refresh tokens ────────────────────────────────────────────────────
	CreateRefreshToken(ctx context.Context, hash, userID, familyID string, expires time.Time) error
	GetRefreshToken(ctx context.Context, hash string) (*RefreshToken, error)
	MarkRefreshTokenUsed(ctx context.Context, hash string, at time.Time) error
	// RevokeFamily marks every token in a family as used (token theft detected).
	RevokeFamily(ctx context.Context, familyID string) error

	// ── Devices ───────────────────────────────────────────────────────────
	CreateDevice(ctx context.Context, d *Device) error
	GetDevice(ctx context.Context, id string) (*Device, error)
	GetDeviceByPublicKey(ctx context.Context, publicKey string) (*Device, error)
	ListDevicesByOwner(ctx context.Context, ownerID string) ([]*Device, error)
	UpdateDevice(ctx context.Context, d *Device) error
	RevokeDevice(ctx context.Context, id string, at time.Time) error

	// ── Sessions ──────────────────────────────────────────────────────────
	CreateSession(ctx context.Context, s *Session) error
	GetSession(ctx context.Context, id string) (*Session, error)
	UpdateSession(ctx context.Context, s *Session) error
	ListActiveSessionsByDevice(ctx context.Context, deviceID string) ([]*Session, error)
	ListSessionsByOperator(ctx context.Context, operatorID string) ([]*Session, error)

	// ── Audit ─────────────────────────────────────────────────────────────
	CreateAudit(ctx context.Context, e *AuditEvent) error
	ListAudit(ctx context.Context, actorID string, limit int) ([]*AuditEvent, error)

	// ── Presence ──────────────────────────────────────────────────────────
	// SetOnline marks a device as online with the given TTL.
	// The in-memory implementation uses an in-process map; Redis uses SET EX.
	SetOnline(ctx context.Context, deviceID string, ttl time.Duration) error
	IsOnline(ctx context.Context, deviceID string) (bool, error)

	// ── 2FA ───────────────────────────────────────────────────────────────
	CreateSecondFactor(ctx context.Context, id, userID, kind string, secret []byte) error
	GetSecondFactor(ctx context.Context, userID string) (*SecondFactor, error)
	VerifySecondFactor(ctx context.Context, id string, at time.Time) error
	DeleteSecondFactor(ctx context.Context, userID string) error

	// ── Email tokens ──────────────────────────────────────────────────────
	CreateEmailToken(ctx context.Context, tokenHash, userID, kind string, expires time.Time) error
	GetEmailToken(ctx context.Context, tokenHash string) (*EmailToken, error)
	DeleteEmailToken(ctx context.Context, tokenHash string) error

	// ── Organizations ─────────────────────────────────────────────────────
	CreateOrganization(ctx context.Context, o *Organization) error
	GetOrganization(ctx context.Context, id string) (*Organization, error)
	ListUserOrganizations(ctx context.Context, userID string) ([]*Organization, error)

	// ── Memberships ───────────────────────────────────────────────────────
	CreateMembership(ctx context.Context, orgID, userID, role string, expires *time.Time) error
	GetMembership(ctx context.Context, orgID, userID string) (*Membership, error)
	ListMembers(ctx context.Context, orgID string) ([]*Membership, error)
	UpdateMemberRole(ctx context.Context, orgID, userID, role string) error
	RemoveMembership(ctx context.Context, orgID, userID string) error

	// ── Invites ───────────────────────────────────────────────────────────
	CreateInvite(ctx context.Context, inv *OrgInvite) error
	GetInviteByToken(ctx context.Context, tokenHash string) (*OrgInvite, error)
	AcceptInvite(ctx context.Context, tokenHash string, at time.Time) error

	// ── Workflows ─────────────────────────────────────────────────────────
	CreateWorkflow(ctx context.Context, w *Workflow) error
	GetWorkflow(ctx context.Context, id string) (*Workflow, error)
	ListWorkflows(ctx context.Context, orgID string) ([]*Workflow, error)
	UpdateWorkflow(ctx context.Context, w *Workflow) error
	CreateWorkflowRun(ctx context.Context, run *WorkflowRun) error
	GetWorkflowRun(ctx context.Context, id string) (*WorkflowRun, error)
	UpdateWorkflowRun(ctx context.Context, run *WorkflowRun) error

	// ── Transfers ─────────────────────────────────────────────────────────
	CreateTransferRecord(ctx context.Context, tr *TransferRecord) error
	UpdateTransferRecord(ctx context.Context, tr *TransferRecord) error

	// Close releases all resources held by the store.
	Close() error
}
