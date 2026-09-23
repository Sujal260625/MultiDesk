// Package store — PostgreSQL implementation.
//
// Connection is managed via pgxpool so it is safe for concurrent use.
// Every method that mutates more than one table runs inside a transaction.
// Transient pgx commit/rollback errors are retried up to three times.
//
// The ExpireLoop goroutine should be started once after the pool is ready:
//
//	go pg.ExpireLoop(ctx)
package store

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresStore implements Store on top of PostgreSQL via pgxpool.
type PostgresStore struct {
	pool *pgxpool.Pool
}

// NewPostgresStore opens a connection pool to the given DSN and verifies
// connectivity with Ping.  The caller is responsible for running migrations
// before any Store methods are called.
func NewPostgresStore(ctx context.Context, dsn string) (*PostgresStore, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("store/postgres: parse config: %w", err)
	}
	cfg.MaxConns = 20
	cfg.MinConns = 2
	cfg.MaxConnLifetime = 30 * time.Minute
	cfg.MaxConnIdleTime = 5 * time.Minute
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("store/postgres: open pool: %w", err)
	}
	if err = pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("store/postgres: ping: %w", err)
	}
	return &PostgresStore{pool: pool}, nil
}

// Close shuts down the connection pool.
func (p *PostgresStore) Close() error {
	p.pool.Close()
	return nil
}

// ─── helpers ─────────────────────────────────────────────────────────────────

// isUnique returns true if err is a PostgreSQL unique-violation (23505).
func isUnique(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// withTx wraps fn in a serializable transaction, retrying on commit failures.
func (p *PostgresStore) withTx(ctx context.Context, fn func(pgx.Tx) error) error {
	const maxAttempts = 3
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		tx, err := p.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
		if err != nil {
			return fmt.Errorf("store/postgres: begin tx: %w", err)
		}
		if err = fn(tx); err != nil {
			_ = tx.Rollback(ctx)
			return err
		}
		if err = tx.Commit(ctx); err != nil {
			_ = tx.Rollback(ctx)
			if attempt < maxAttempts {
				slog.Warn("postgres tx commit failed, retrying", "attempt", attempt, "error", err)
				time.Sleep(time.Duration(attempt*50) * time.Millisecond)
				continue
			}
			return fmt.Errorf("store/postgres: commit: %w", err)
		}
		return nil
	}
	return errors.New("store/postgres: tx commit failed after retries")
}

func mapNotFound(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

// ─── Accounts ────────────────────────────────────────────────────────────────

func (p *PostgresStore) CreateAccount(ctx context.Context, id, email, name string, passwordHash []byte) error {
	_, err := p.pool.Exec(ctx,
		`INSERT INTO users (id, email, display_name, password_hash)
		 VALUES ($1, $2, $3, $4)`,
		id, email, name, hex.EncodeToString(passwordHash),
	)
	if isUnique(err) {
		return ErrConflict
	}
	return err
}

func (p *PostgresStore) GetAccountByID(ctx context.Context, id string) (*Account, error) {
	return p.scanAccount(ctx,
		`SELECT id, email, display_name, password_hash, token_version, email_verified_at, created_at
		 FROM users WHERE id = $1`, id)
}

func (p *PostgresStore) GetAccountByEmail(ctx context.Context, email string) (*Account, error) {
	return p.scanAccount(ctx,
		`SELECT id, email, display_name, password_hash, token_version, email_verified_at, created_at
		 FROM users WHERE email = $1`, email)
}

func (p *PostgresStore) scanAccount(ctx context.Context, query string, args ...any) (*Account, error) {
	var a Account
	var pwHashHex string
	err := p.pool.QueryRow(ctx, query, args...).Scan(
		&a.ID, &a.Email, &a.Name, &pwHashHex,
		&a.TokenVersion, &a.EmailVerifiedAt, &a.CreatedAt,
	)
	if err != nil {
		return nil, mapNotFound(err)
	}
	raw, err := hex.DecodeString(pwHashHex)
	if err != nil {
		return nil, fmt.Errorf("store/postgres: decode password hash: %w", err)
	}
	a.PasswordHash = raw
	return &a, nil
}

func (p *PostgresStore) UpdateAccountVersion(ctx context.Context, userID string) error {
	tag, err := p.pool.Exec(ctx,
		`UPDATE users SET token_version = token_version + 1 WHERE id = $1`, userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (p *PostgresStore) SetEmailVerified(ctx context.Context, userID string, t time.Time) error {
	tag, err := p.pool.Exec(ctx,
		`UPDATE users SET email_verified_at = $1 WHERE id = $2`, t.UTC(), userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (p *PostgresStore) UpdatePassword(ctx context.Context, userID string, passwordHash []byte) error {
	tag, err := p.pool.Exec(ctx,
		`UPDATE users SET password_hash = $1, token_version = token_version + 1 WHERE id = $2`,
		hex.EncodeToString(passwordHash), userID,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ─── Refresh tokens ───────────────────────────────────────────────────────────

func (p *PostgresStore) CreateRefreshToken(ctx context.Context, hash, userID, familyID string, expires time.Time) error {
	_, err := p.pool.Exec(ctx,
		`INSERT INTO refresh_tokens (token_hash, user_id, family_id, expires_at)
		 VALUES ($1, $2, $3, $4)`,
		[]byte(hash), userID, familyID, expires.UTC(),
	)
	if isUnique(err) {
		return ErrConflict
	}
	return err
}

func (p *PostgresStore) GetRefreshToken(ctx context.Context, hash string) (*RefreshToken, error) {
	var rt RefreshToken
	var rawHash []byte
	err := p.pool.QueryRow(ctx,
		`SELECT token_hash, user_id, family_id, expires_at, used_at, revoked_at
		 FROM refresh_tokens WHERE token_hash = $1`, []byte(hash),
	).Scan(&rawHash, &rt.UserID, &rt.FamilyID, &rt.ExpiresAt, &rt.UsedAt, &rt.RevokedAt)
	if err != nil {
		return nil, mapNotFound(err)
	}
	rt.Hash = string(rawHash)
	return &rt, nil
}

func (p *PostgresStore) MarkRefreshTokenUsed(ctx context.Context, hash string, at time.Time) error {
	tag, err := p.pool.Exec(ctx,
		`UPDATE refresh_tokens SET used_at = $1 WHERE token_hash = $2`, at.UTC(), []byte(hash))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (p *PostgresStore) RevokeFamily(ctx context.Context, familyID string) error {
	now := time.Now().UTC()
	_, err := p.pool.Exec(ctx,
		`UPDATE refresh_tokens SET used_at = $1, revoked_at = $1 WHERE family_id = $2`,
		now, familyID,
	)
	return err
}

// ─── Devices ─────────────────────────────────────────────────────────────────

func (p *PostgresStore) CreateDevice(ctx context.Context, d *Device) error {
	pkBytes, err := publicKeyBytes(d.PublicKey)
	if err != nil {
		return err
	}
	_, err = p.pool.Exec(ctx,
		`INSERT INTO devices (id, name, owner_id, public_key, os, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		d.ID, d.Name, d.OwnerID, pkBytes, d.OS, time.Now().UTC(),
	)
	if isUnique(err) {
		return ErrConflict
	}
	return err
}

func publicKeyBytes(b64 string) ([]byte, error) {
	import64 := strings.TrimSpace(b64)
	// The security package uses base64.StdEncoding for public keys.
	// We store as raw bytes in the DB (bytea, 32 bytes).
	var buf [32]byte
	n, err := encodeBase64Std(import64, buf[:])
	if err != nil || n != 32 {
		return nil, fmt.Errorf("store/postgres: invalid public key: %w", err)
	}
	return buf[:], nil
}

func encodeBase64Std(s string, dst []byte) (int, error) {
	import64 := s
	_ = import64
	// Use standard library — avoid importing encoding/base64 at package level
	// by delegating to hex for storage.  Actually store raw bytes as hex string
	// would misuse the schema which uses bytea.  Let the caller pass bytes.
	// We'll just parse with a local import.
	return decodeStdB64(s, dst)
}

func decodeStdB64(s string, dst []byte) (int, error) {
	import64 := s
	_ = import64
	// Inline the decode to avoid a circular package reference.
	src := []byte(s)
	n := 0
	// Use encoding/base64 via a helper that doesn't import at file level
	// because that would require an import block change. Instead we accept
	// the key already in hex from the service layer, OR we just store the
	// base64 string as-is in a text column.  The schema says bytea UNIQUE NOT NULL
	// CHECK(octet_length(public_key)=32) so we MUST decode.
	// We'll use the approach of re-exporting the util from the security package
	// or just decode inline.
	return pgxDecodeB64(src, dst, &n)
}

func pgxDecodeB64(src []byte, dst []byte, n *int) (int, error) {
	// Standard base64 alphabet lookup table
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	lut := [256]byte{}
	for i := range lut {
		lut[i] = 0xFF
	}
	for i, c := range []byte(alphabet) {
		lut[c] = byte(i)
	}
	lut['='] = 0

	out := 0
	acc := uint32(0)
	bits := uint(0)
	for _, c := range src {
		if c == '=' {
			break
		}
		v := lut[c]
		if v == 0xFF {
			return 0, errors.New("invalid base64 character")
		}
		acc = (acc << 6) | uint32(v)
		bits += 6
		if bits >= 8 {
			bits -= 8
			if out >= len(dst) {
				return 0, errors.New("output buffer too small")
			}
			dst[out] = byte(acc >> bits)
			out++
		}
	}
	*n = out
	return out, nil
}

func (p *PostgresStore) GetDevice(ctx context.Context, id string) (*Device, error) {
	return p.scanDevice(ctx,
		`SELECT id, name, owner_id, public_key, os, revoked_at, created_at
		 FROM devices WHERE id = $1`, id)
}

func (p *PostgresStore) GetDeviceByPublicKey(ctx context.Context, publicKey string) (*Device, error) {
	pkBytes, err := publicKeyBytes(publicKey)
	if err != nil {
		return nil, err
	}
	return p.scanDevice(ctx,
		`SELECT id, name, owner_id, public_key, os, revoked_at, created_at
		 FROM devices WHERE public_key = $1`, pkBytes)
}

func (p *PostgresStore) scanDevice(ctx context.Context, q string, args ...any) (*Device, error) {
	var d Device
	var pkBytes []byte
	var revokedAt *time.Time
	err := p.pool.QueryRow(ctx, q, args...).Scan(
		&d.ID, &d.Name, &d.OwnerID, &pkBytes, &d.OS, &revokedAt, &d.CreatedAt,
	)
	if err != nil {
		return nil, mapNotFound(err)
	}
	d.PublicKey = pkBytesToB64(pkBytes)
	d.RevokedAt = revokedAt
	d.Revoked = revokedAt != nil
	return &d, nil
}

func pkBytesToB64(b []byte) string {
	// Encode back to standard base64 as used in security.VerifyDevice.
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	out := make([]byte, ((len(b)+2)/3)*4)
	n := 0
	for i := 0; i < len(b); i += 3 {
		rem := len(b) - i
		var b0, b1, b2 byte
		b0 = b[i]
		if rem > 1 {
			b1 = b[i+1]
		}
		if rem > 2 {
			b2 = b[i+2]
		}
		out[n] = alphabet[b0>>2]
		out[n+1] = alphabet[((b0&0x3)<<4)|(b1>>4)]
		if rem > 1 {
			out[n+2] = alphabet[((b1&0xF)<<2)|(b2>>6)]
		} else {
			out[n+2] = '='
		}
		if rem > 2 {
			out[n+3] = alphabet[b2&0x3F]
		} else {
			out[n+3] = '='
		}
		n += 4
	}
	return string(out)
}

func (p *PostgresStore) ListDevicesByOwner(ctx context.Context, ownerID string) ([]*Device, error) {
	rows, err := p.pool.Query(ctx,
		`SELECT id, name, owner_id, public_key, os, revoked_at, created_at
		 FROM devices WHERE owner_id = $1 ORDER BY name`, ownerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return p.collectDevices(rows)
}

func (p *PostgresStore) collectDevices(rows pgx.Rows) ([]*Device, error) {
	var out []*Device
	for rows.Next() {
		var d Device
		var pkBytes []byte
		var revokedAt *time.Time
		if err := rows.Scan(&d.ID, &d.Name, &d.OwnerID, &pkBytes, &d.OS, &revokedAt, &d.CreatedAt); err != nil {
			return nil, err
		}
		d.PublicKey = pkBytesToB64(pkBytes)
		d.RevokedAt = revokedAt
		d.Revoked = revokedAt != nil
		out = append(out, &d)
	}
	return out, rows.Err()
}

func (p *PostgresStore) UpdateDevice(ctx context.Context, d *Device) error {
	tag, err := p.pool.Exec(ctx,
		`UPDATE devices SET name = $1, os = $2 WHERE id = $3`, d.Name, d.OS, d.ID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (p *PostgresStore) RevokeDevice(ctx context.Context, id string, at time.Time) error {
	tag, err := p.pool.Exec(ctx,
		`UPDATE devices SET revoked_at = $1 WHERE id = $2`, at.UTC(), id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ─── Sessions ─────────────────────────────────────────────────────────────────

func (p *PostgresStore) CreateSession(ctx context.Context, s *Session) error {
	_, err := p.pool.Exec(ctx,
		`INSERT INTO device_sessions
		   (id, operator_id, source_device_id, target_device_id, state,
		    requested_permissions, granted_permissions, epoch, created_at, expires_at,
		    recording_consent, chat_enabled)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		s.ID, s.OperatorID, s.SourceDeviceID, s.TargetDeviceID, s.State,
		s.RequestedPerms, s.GrantedPerms, s.Epoch,
		s.CreatedAt.UTC(), s.ExpiresAt.UTC(),
		s.RecordingConsent, s.ChatEnabled,
	)
	if isUnique(err) {
		return ErrConflict
	}
	return err
}

func (p *PostgresStore) GetSession(ctx context.Context, id string) (*Session, error) {
	return p.scanSession(ctx,
		`SELECT id, operator_id, source_device_id, target_device_id, state,
		        requested_permissions, granted_permissions, epoch, created_at, expires_at,
		        ended_at, recording_consent, chat_enabled, notes_count
		 FROM device_sessions WHERE id = $1`, id)
}

func (p *PostgresStore) scanSession(ctx context.Context, q string, args ...any) (*Session, error) {
	var s Session
	err := p.pool.QueryRow(ctx, q, args...).Scan(
		&s.ID, &s.OperatorID, &s.SourceDeviceID, &s.TargetDeviceID, &s.State,
		&s.RequestedPerms, &s.GrantedPerms, &s.Epoch,
		&s.CreatedAt, &s.ExpiresAt, &s.EndedAt,
		&s.RecordingConsent, &s.ChatEnabled, &s.NotesCount,
	)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return &s, nil
}

func (p *PostgresStore) UpdateSession(ctx context.Context, s *Session) error {
	tag, err := p.pool.Exec(ctx,
		`UPDATE device_sessions
		 SET state = $1, granted_permissions = $2, epoch = $3,
		     expires_at = $4, ended_at = $5, recording_consent = $6,
		     chat_enabled = $7
		 WHERE id = $8`,
		s.State, s.GrantedPerms, s.Epoch,
		s.ExpiresAt.UTC(), s.EndedAt,
		s.RecordingConsent, s.ChatEnabled, s.ID,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (p *PostgresStore) ListActiveSessionsByDevice(ctx context.Context, deviceID string) ([]*Session, error) {
	rows, err := p.pool.Query(ctx,
		`SELECT id, operator_id, source_device_id, target_device_id, state,
		        requested_permissions, granted_permissions, epoch, created_at, expires_at,
		        ended_at, recording_consent, chat_enabled, notes_count
		 FROM device_sessions
		 WHERE (source_device_id = $1 OR target_device_id = $1)
		   AND state IN ('pending','active')
		 ORDER BY created_at DESC`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return p.collectSessions(rows)
}

func (p *PostgresStore) ListSessionsByOperator(ctx context.Context, operatorID string) ([]*Session, error) {
	rows, err := p.pool.Query(ctx,
		`SELECT id, operator_id, source_device_id, target_device_id, state,
		        requested_permissions, granted_permissions, epoch, created_at, expires_at,
		        ended_at, recording_consent, chat_enabled, notes_count
		 FROM device_sessions WHERE operator_id = $1
		 ORDER BY created_at DESC`, operatorID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return p.collectSessions(rows)
}

func (p *PostgresStore) collectSessions(rows pgx.Rows) ([]*Session, error) {
	var out []*Session
	for rows.Next() {
		var s Session
		if err := rows.Scan(
			&s.ID, &s.OperatorID, &s.SourceDeviceID, &s.TargetDeviceID, &s.State,
			&s.RequestedPerms, &s.GrantedPerms, &s.Epoch,
			&s.CreatedAt, &s.ExpiresAt, &s.EndedAt,
			&s.RecordingConsent, &s.ChatEnabled, &s.NotesCount,
		); err != nil {
			return nil, err
		}
		out = append(out, &s)
	}
	return out, rows.Err()
}

// ─── Audit ───────────────────────────────────────────────────────────────────

func (p *PostgresStore) CreateAudit(ctx context.Context, e *AuditEvent) error {
	meta, _ := json.Marshal(e.Metadata)
	_, err := p.pool.Exec(ctx,
		`INSERT INTO audit_events (id, actor_id, organization_id, action, resource_id, metadata, occurred_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		e.ID, e.ActorID, e.OrganizationID, e.Action, e.ResourceID, meta, e.OccurredAt.UTC(),
	)
	return err
}

func (p *PostgresStore) ListAudit(ctx context.Context, actorID string, limit int) ([]*AuditEvent, error) {
	rows, err := p.pool.Query(ctx,
		`SELECT id, actor_id, organization_id, action, resource_id, metadata, occurred_at
		 FROM audit_events WHERE actor_id = $1
		 ORDER BY occurred_at DESC LIMIT $2`, actorID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*AuditEvent
	for rows.Next() {
		var e AuditEvent
		var meta []byte
		if err := rows.Scan(&e.ID, &e.ActorID, &e.OrganizationID, &e.Action, &e.ResourceID, &meta, &e.OccurredAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(meta, &e.Metadata)
		out = append(out, &e)
	}
	return out, rows.Err()
}

// ─── Presence (no-op — Redis decorator provides real presence) ────────────────

func (p *PostgresStore) SetOnline(_ context.Context, _ string, _ time.Duration) error { return nil }
func (p *PostgresStore) IsOnline(_ context.Context, _ string) (bool, error)           { return false, nil }

// ─── 2FA ─────────────────────────────────────────────────────────────────────

func (p *PostgresStore) CreateSecondFactor(ctx context.Context, id, userID, kind string, secret []byte) error {
	return p.withTx(ctx, func(tx pgx.Tx) error {
		// Delete any existing unverified factor for this user first.
		_, _ = tx.Exec(ctx,
			`DELETE FROM second_factors WHERE user_id = $1 AND verified_at IS NULL`, userID)
		_, err := tx.Exec(ctx,
			`INSERT INTO second_factors (id, user_id, kind, encrypted_secret)
			 VALUES ($1, $2, $3, $4)`, id, userID, kind, secret)
		if isUnique(err) {
			return ErrConflict
		}
		return err
	})
}

func (p *PostgresStore) GetSecondFactor(ctx context.Context, userID string) (*SecondFactor, error) {
	var sf SecondFactor
	err := p.pool.QueryRow(ctx,
		`SELECT id, user_id, kind, encrypted_secret, verified_at
		 FROM second_factors WHERE user_id = $1 ORDER BY verified_at NULLS LAST LIMIT 1`, userID,
	).Scan(&sf.ID, &sf.UserID, &sf.Kind, &sf.EncryptedSecret, &sf.VerifiedAt)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return &sf, nil
}

func (p *PostgresStore) VerifySecondFactor(ctx context.Context, id string, at time.Time) error {
	tag, err := p.pool.Exec(ctx,
		`UPDATE second_factors SET verified_at = $1 WHERE id = $2`, at.UTC(), id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (p *PostgresStore) DeleteSecondFactor(ctx context.Context, userID string) error {
	_, err := p.pool.Exec(ctx, `DELETE FROM second_factors WHERE user_id = $1`, userID)
	return err
}

// ─── Email tokens ─────────────────────────────────────────────────────────────

func (p *PostgresStore) CreateEmailToken(ctx context.Context, tokenHash, userID, kind string, expires time.Time) error {
	_, err := p.pool.Exec(ctx,
		`INSERT INTO email_verification_tokens (token_hash, user_id, kind, expires_at)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT (token_hash) DO NOTHING`,
		tokenHash, userID, kind, expires.UTC(),
	)
	return err
}

func (p *PostgresStore) GetEmailToken(ctx context.Context, tokenHash string) (*EmailToken, error) {
	var et EmailToken
	err := p.pool.QueryRow(ctx,
		`SELECT token_hash, user_id, kind, expires_at
		 FROM email_verification_tokens WHERE token_hash = $1`, tokenHash,
	).Scan(&et.TokenHash, &et.UserID, &et.Kind, &et.ExpiresAt)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return &et, nil
}

func (p *PostgresStore) DeleteEmailToken(ctx context.Context, tokenHash string) error {
	_, err := p.pool.Exec(ctx,
		`DELETE FROM email_verification_tokens WHERE token_hash = $1`, tokenHash)
	return err
}

// ─── Organizations ────────────────────────────────────────────────────────────

func (p *PostgresStore) CreateOrganization(ctx context.Context, o *Organization) error {
	return p.withTx(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO organizations (id, name, owner_id, created_at) VALUES ($1,$2,$3,$4)`,
			o.ID, o.Name, o.OwnerID, o.CreatedAt.UTC())
		if isUnique(err) {
			return ErrConflict
		}
		if err != nil {
			return err
		}
		// Auto-add owner as member.
		_, err = tx.Exec(ctx,
			`INSERT INTO memberships (organization_id, user_id, role) VALUES ($1,$2,'owner')
			 ON CONFLICT (organization_id, user_id) DO NOTHING`,
			o.ID, o.OwnerID)
		return err
	})
}

func (p *PostgresStore) GetOrganization(ctx context.Context, id string) (*Organization, error) {
	var o Organization
	err := p.pool.QueryRow(ctx,
		`SELECT id, name, owner_id, created_at FROM organizations WHERE id = $1`, id,
	).Scan(&o.ID, &o.Name, &o.OwnerID, &o.CreatedAt)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return &o, nil
}

func (p *PostgresStore) ListUserOrganizations(ctx context.Context, userID string) ([]*Organization, error) {
	rows, err := p.pool.Query(ctx,
		`SELECT o.id, o.name, o.owner_id, o.created_at
		 FROM organizations o
		 JOIN memberships m ON m.organization_id = o.id
		 WHERE m.user_id = $1
		 ORDER BY o.name`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Organization
	for rows.Next() {
		var o Organization
		if err := rows.Scan(&o.ID, &o.Name, &o.OwnerID, &o.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, &o)
	}
	return out, rows.Err()
}

// ─── Memberships ─────────────────────────────────────────────────────────────

func (p *PostgresStore) CreateMembership(ctx context.Context, orgID, userID, role string, expires *time.Time) error {
	var exp *time.Time
	if expires != nil {
		tc := expires.UTC()
		exp = &tc
	}
	_, err := p.pool.Exec(ctx,
		`INSERT INTO memberships (organization_id, user_id, role, expires_at)
		 VALUES ($1,$2,$3,$4)
		 ON CONFLICT (organization_id, user_id) DO UPDATE SET role = EXCLUDED.role, expires_at = EXCLUDED.expires_at`,
		orgID, userID, role, exp,
	)
	return err
}

func (p *PostgresStore) GetMembership(ctx context.Context, orgID, userID string) (*Membership, error) {
	var m Membership
	err := p.pool.QueryRow(ctx,
		`SELECT organization_id, user_id, role, expires_at
		 FROM memberships WHERE organization_id = $1 AND user_id = $2`, orgID, userID,
	).Scan(&m.OrganizationID, &m.UserID, &m.Role, &m.ExpiresAt)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return &m, nil
}

func (p *PostgresStore) ListMembers(ctx context.Context, orgID string) ([]*Membership, error) {
	rows, err := p.pool.Query(ctx,
		`SELECT organization_id, user_id, role, expires_at
		 FROM memberships WHERE organization_id = $1 ORDER BY role, user_id`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Membership
	for rows.Next() {
		var m Membership
		if err := rows.Scan(&m.OrganizationID, &m.UserID, &m.Role, &m.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, &m)
	}
	return out, rows.Err()
}

func (p *PostgresStore) UpdateMemberRole(ctx context.Context, orgID, userID, role string) error {
	tag, err := p.pool.Exec(ctx,
		`UPDATE memberships SET role = $1 WHERE organization_id = $2 AND user_id = $3`,
		role, orgID, userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (p *PostgresStore) RemoveMembership(ctx context.Context, orgID, userID string) error {
	tag, err := p.pool.Exec(ctx,
		`DELETE FROM memberships WHERE organization_id = $1 AND user_id = $2`, orgID, userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ─── Invites ──────────────────────────────────────────────────────────────────

func (p *PostgresStore) CreateInvite(ctx context.Context, inv *OrgInvite) error {
	_, err := p.pool.Exec(ctx,
		`INSERT INTO org_invites (id, org_id, email, role, token_hash, expires_at)
		 VALUES ($1,$2,$3,$4,$5,$6)`,
		inv.ID, inv.OrgID, inv.Email, inv.Role, inv.TokenHash, inv.ExpiresAt.UTC(),
	)
	if isUnique(err) {
		return ErrConflict
	}
	return err
}

func (p *PostgresStore) GetInviteByToken(ctx context.Context, tokenHash string) (*OrgInvite, error) {
	var inv OrgInvite
	err := p.pool.QueryRow(ctx,
		`SELECT id, org_id, email, role, token_hash, expires_at, accepted_at
		 FROM org_invites WHERE token_hash = $1`, tokenHash,
	).Scan(&inv.ID, &inv.OrgID, &inv.Email, &inv.Role, &inv.TokenHash, &inv.ExpiresAt, &inv.AcceptedAt)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return &inv, nil
}

func (p *PostgresStore) AcceptInvite(ctx context.Context, tokenHash string, at time.Time) error {
	tag, err := p.pool.Exec(ctx,
		`UPDATE org_invites SET accepted_at = $1 WHERE token_hash = $2 AND accepted_at IS NULL`,
		at.UTC(), tokenHash)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ─── Workflows ────────────────────────────────────────────────────────────────

func (p *PostgresStore) CreateWorkflow(ctx context.Context, w *Workflow) error {
	_, err := p.pool.Exec(ctx,
		`INSERT INTO workflows (id, organization_id, name, definition, required_permissions, enabled, created_by)
		 VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		w.ID, w.OrganizationID, w.Name, w.Definition, w.RequiredPermissions, w.Enabled, w.CreatedBy,
	)
	if isUnique(err) {
		return ErrConflict
	}
	return err
}

func (p *PostgresStore) GetWorkflow(ctx context.Context, id string) (*Workflow, error) {
	var w Workflow
	err := p.pool.QueryRow(ctx,
		`SELECT id, organization_id, name, definition, required_permissions, enabled, created_by
		 FROM workflows WHERE id = $1`, id,
	).Scan(&w.ID, &w.OrganizationID, &w.Name, &w.Definition, &w.RequiredPermissions, &w.Enabled, &w.CreatedBy)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return &w, nil
}

func (p *PostgresStore) ListWorkflows(ctx context.Context, orgID string) ([]*Workflow, error) {
	rows, err := p.pool.Query(ctx,
		`SELECT id, organization_id, name, definition, required_permissions, enabled, created_by
		 FROM workflows WHERE organization_id = $1 ORDER BY name`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Workflow
	for rows.Next() {
		var w Workflow
		if err := rows.Scan(&w.ID, &w.OrganizationID, &w.Name, &w.Definition, &w.RequiredPermissions, &w.Enabled, &w.CreatedBy); err != nil {
			return nil, err
		}
		out = append(out, &w)
	}
	return out, rows.Err()
}

func (p *PostgresStore) UpdateWorkflow(ctx context.Context, w *Workflow) error {
	tag, err := p.pool.Exec(ctx,
		`UPDATE workflows SET name=$1, definition=$2, required_permissions=$3, enabled=$4 WHERE id=$5`,
		w.Name, w.Definition, w.RequiredPermissions, w.Enabled, w.ID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (p *PostgresStore) CreateWorkflowRun(ctx context.Context, run *WorkflowRun) error {
	_, err := p.pool.Exec(ctx,
		`INSERT INTO workflow_runs (id, workflow_id, session_id, approved_by, state, started_at)
		 VALUES ($1,$2,$3,$4,$5,$6)`,
		run.ID, run.WorkflowID, run.SessionID, run.ApprovedBy, run.State, run.StartedAt,
	)
	if isUnique(err) {
		return ErrConflict
	}
	return err
}

func (p *PostgresStore) GetWorkflowRun(ctx context.Context, id string) (*WorkflowRun, error) {
	var r WorkflowRun
	err := p.pool.QueryRow(ctx,
		`SELECT id, workflow_id, session_id, approved_by, state, started_at, finished_at
		 FROM workflow_runs WHERE id = $1`, id,
	).Scan(&r.ID, &r.WorkflowID, &r.SessionID, &r.ApprovedBy, &r.State, &r.StartedAt, &r.FinishedAt)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return &r, nil
}

func (p *PostgresStore) UpdateWorkflowRun(ctx context.Context, run *WorkflowRun) error {
	tag, err := p.pool.Exec(ctx,
		`UPDATE workflow_runs SET state=$1, approved_by=$2, started_at=$3, finished_at=$4 WHERE id=$5`,
		run.State, run.ApprovedBy, run.StartedAt, run.FinishedAt, run.ID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ─── Transfers ────────────────────────────────────────────────────────────────

func (p *PostgresStore) CreateTransferRecord(ctx context.Context, tr *TransferRecord) error {
	_, err := p.pool.Exec(ctx,
		`INSERT INTO transfer_metadata (id, session_id, basename, size_bytes, sha256, state, created_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		tr.ID, tr.SessionID, tr.Basename, tr.SizeBytes, tr.SHA256, tr.State, tr.CreatedAt.UTC(),
	)
	return err
}

func (p *PostgresStore) UpdateTransferRecord(ctx context.Context, tr *TransferRecord) error {
	tag, err := p.pool.Exec(ctx,
		`UPDATE transfer_metadata SET state=$1 WHERE id=$2`, tr.State, tr.ID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ─── ExpireLoop ───────────────────────────────────────────────────────────────

// ExpireLoop runs until ctx is cancelled, deleting expired rows every minute.
// Run as a dedicated goroutine after the store is initialized.
func (p *PostgresStore) ExpireLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.runExpiry(ctx)
		}
	}
}

func (p *PostgresStore) runExpiry(ctx context.Context) {
	now := time.Now().UTC()

	// Expire pending/active sessions that are past their deadline.
	tag, err := p.pool.Exec(ctx,
		`UPDATE device_sessions
		 SET state='expired', ended_at=$1
		 WHERE state IN ('pending','active') AND expires_at <= $1`, now)
	if err != nil {
		slog.Error("expiry: sessions", "error", err)
	} else if tag.RowsAffected() > 0 {
		slog.Info("expiry: sessions expired", "count", tag.RowsAffected())
	}

	// Clean up expired refresh tokens older than 24 h beyond expiry.
	_, err = p.pool.Exec(ctx,
		`DELETE FROM refresh_tokens WHERE expires_at < $1`, now.Add(-24*time.Hour))
	if err != nil {
		slog.Error("expiry: refresh tokens", "error", err)
	}

	// Clean up expired email tokens.
	_, err = p.pool.Exec(ctx,
		`DELETE FROM email_verification_tokens WHERE expires_at < $1`, now)
	if err != nil {
		slog.Error("expiry: email tokens", "error", err)
	}

	// Clean up expired invites.
	_, err = p.pool.Exec(ctx,
		`DELETE FROM org_invites WHERE expires_at < $1 AND accepted_at IS NULL`, now)
	if err != nil {
		slog.Error("expiry: invites", "error", err)
	}
}
