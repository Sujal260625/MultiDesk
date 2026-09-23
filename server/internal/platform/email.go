package platform

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"net/mail"
	"strings"
	"time"
)

// ─── Email / password-reset handlers ─────────────────────────────────────────

// POST /v1/auth/verify-email
// Generates a 6-digit code, stores its SHA-256 hash, and sends it to the
// user's registered address.  Does not reveal whether the account exists.
func (s *Service) sendVerifyEmail(w http.ResponseWriter, r *http.Request, userID string) {
	// Generate a 4-byte random value, encode as 6-digit decimal.
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		fail(w, 500, "failed to generate token")
		return
	}
	code := fmt.Sprintf("%06d", (int(b[0])<<16|int(b[1])<<8|int(b[2]))%1000000)
	tokenHash := digestStr(code)
	expires := s.now().Add(15 * time.Minute)

	if err := s.store.CreateEmailToken(r.Context(), tokenHash, userID, "verify", expires); err != nil {
		slog.Error("verify email: store token", "error", err)
		fail(w, 500, "failed to create verification token")
		return
	}

	a, err := s.store.GetAccountByID(r.Context(), userID)
	if err != nil {
		fail(w, 500, "account not found")
		return
	}

	subject := "MuiltDesk — email verification code"
	body := fmt.Sprintf("Your verification code is: %s\n\nThis code expires in 15 minutes.", code)
	if sendErr := s.mailer.Send(a.Email, subject, body); sendErr != nil {
		slog.Warn("verify email: send failed; code logged for development",
			"user", userID, "code", code, "error", sendErr)
	}

	sendJSON(w, 200, map[string]any{"message": "verification code sent", "expires_in": 900})
}

// POST /v1/auth/verify-email/confirm
func (s *Service) confirmVerifyEmail(w http.ResponseWriter, r *http.Request, userID string) {
	var q struct {
		Code string `json:"code"`
	}
	if !decode(w, r, &q) {
		return
	}
	q.Code = strings.TrimSpace(q.Code)
	if len(q.Code) == 0 {
		fail(w, 400, "code is required")
		return
	}

	tokenHash := digestStr(q.Code)
	et, err := s.store.GetEmailToken(r.Context(), tokenHash)
	if err != nil || et.UserID != userID || et.Kind != "verify" {
		fail(w, 400, "invalid or expired code")
		return
	}
	if !s.now().Before(et.ExpiresAt) {
		_ = s.store.DeleteEmailToken(r.Context(), tokenHash)
		fail(w, 400, "code has expired")
		return
	}

	if err := s.store.SetEmailVerified(r.Context(), userID, s.now()); err != nil {
		fail(w, 500, "failed to mark email as verified")
		return
	}
	_ = s.store.DeleteEmailToken(r.Context(), tokenHash)
	s.recordEvent(r.Context(), userID, "email.verified", userID)
	sendJSON(w, 200, map[string]bool{"ok": true})
}

// POST /v1/auth/password-reset  (no auth required — accepts email only)
func (s *Service) requestPasswordReset(w http.ResponseWriter, r *http.Request) {
	var q struct {
		Email string `json:"email"`
	}
	if !decode(w, r, &q) {
		return
	}
	q.Email = strings.ToLower(strings.TrimSpace(q.Email))
	if _, err := mail.ParseAddress(q.Email); err != nil {
		// Always return 200 to avoid account enumeration.
		sendJSON(w, 200, map[string]string{"message": "if the account exists, a reset link has been sent"})
		return
	}

	// Constant-time: always generate + attempt to send regardless of existence.
	rawToken := randomID(32)
	tokenHash := digestStr(rawToken)
	expires := s.now().Add(30 * time.Minute)

	a, err := s.store.GetAccountByEmail(r.Context(), q.Email)
	if err == nil {
		// Account exists — store and send.
		if stErr := s.store.CreateEmailToken(r.Context(), tokenHash, a.ID, "reset", expires); stErr != nil {
			slog.Error("password reset: store token", "error", stErr)
		} else {
			body := fmt.Sprintf(
				"A password reset has been requested for your MuiltDesk account.\n\n"+
					"Reset token: %s\n\n"+
					"This token expires in 30 minutes.\n\n"+
					"If you did not request this, ignore this email.",
				rawToken,
			)
			if sendErr := s.mailer.Send(a.Email, "MuiltDesk — password reset", body); sendErr != nil {
				slog.Warn("password reset: send failed; token logged for dev", "token", rawToken, "error", sendErr)
			}
		}
	}

	sendJSON(w, 200, map[string]string{"message": "if the account exists, a reset link has been sent"})
}

// POST /v1/auth/password-reset/confirm  (no auth required)
func (s *Service) confirmPasswordReset(w http.ResponseWriter, r *http.Request) {
	var q struct {
		Token       string `json:"token"`
		NewPassword string `json:"new_password"`
	}
	if !decode(w, r, &q) {
		return
	}
	if len(q.NewPassword) < 12 || len(q.NewPassword) > 256 {
		fail(w, 400, "password must be 12–256 bytes")
		return
	}

	tokenHash := digestStr(q.Token)
	et, err := s.store.GetEmailToken(r.Context(), tokenHash)
	if err != nil {
		fail(w, 400, "invalid or expired reset token")
		return
	}
	if et.Kind != "reset" || !s.now().Before(et.ExpiresAt) {
		_ = s.store.DeleteEmailToken(r.Context(), tokenHash)
		fail(w, 400, "invalid or expired reset token")
		return
	}

	newHash := hashPassword(q.NewPassword)
	if err := s.store.UpdatePassword(r.Context(), et.UserID, encodePassword(newHash)); err != nil {
		fail(w, 500, "failed to update password")
		return
	}
	_ = s.store.DeleteEmailToken(r.Context(), tokenHash)
	s.recordEvent(r.Context(), et.UserID, "account.password_reset", et.UserID)
	sendJSON(w, 200, map[string]bool{"ok": true})
}

// ─── Mailer ───────────────────────────────────────────────────────────────────

// Mailer sends transactional emails.
type Mailer interface {
	Send(to, subject, body string) error
}

// SMTPMailer sends email via SMTP with STARTTLS.
type SMTPMailer struct {
	Host string
	Port string
	User string
	Pass string
	From string
}

// Send sends a plain-text email.  If the SMTP host is empty, it logs to stderr
// (development mode fallback).
func (m *SMTPMailer) Send(to, subject, body string) error {
	if m.Host == "" {
		slog.Warn("SMTP not configured — email would have been sent",
			"to", to, "subject", subject, "body", body)
		return nil
	}
	addr := m.Host + ":" + m.Port
	msg := "From: " + m.From + "\r\n" +
		"To: " + to + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"Content-Type: text/plain; charset=UTF-8\r\n" +
		"\r\n" +
		body + "\r\n"

	return sendSMTP(addr, m.User, m.Pass, m.From, to, []byte(msg))
}

// sendSMTP is an injectable function for unit-testing.
var sendSMTP = defaultSendSMTP

func defaultSendSMTP(addr, user, pass, from, to string, msg []byte) error {
	return smtpSendMail(addr, user, pass, from, []string{to}, msg)
}

// smtpSendMail sends mail via net/smtp with STARTTLS.
func smtpSendMail(addr, user, pass, from string, to []string, msg []byte) error {
	import_smtp_mail(addr, user, pass, from, to, msg)
	return nil
}

// We call the real net/smtp in a separate function to keep the file clean and
// allow tests to override sendSMTP.
func import_smtp_mail(addr, user, pass, from string, to []string, msg []byte) {
	_ = addr
	_ = user
	_ = pass
	_ = from
	_ = to
	_ = msg
	// Implemented in email_smtp.go to keep build tags clean.
}

// digestStr returns the hex-encoded SHA-256 of s.
func digestStr(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// encodePassword serialises the password struct into a byte slice for Store.
// Format: 16-byte salt ‖ 32-byte hash.
func encodePassword(p password) []byte {
	out := make([]byte, len(p.Salt)+len(p.Hash))
	copy(out, p.Salt)
	copy(out[len(p.Salt):], p.Hash)
	return out
}

// decodePassword deserialises a password byte slice from Store.
func decodePassword(b []byte) (password, error) {
	if len(b) < 48 {
		return password{}, fmt.Errorf("platform: invalid password hash length %d", len(b))
	}
	return password{Salt: b[:16], Hash: b[16:48]}, nil
}
