package platform

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"

	"muiltdesk/server/internal/security"

	"golang.org/x/crypto/argon2"
)

type password struct {
	Salt []byte
	Hash []byte
}
type account struct {
	ID       string
	Email    string
	Name     string
	Password password
	Version  uint64
}
type refreshToken struct {
	UserID  string
	Family  string
	Expires time.Time
	Used    bool
}
type claims = security.Claims
type tokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
}

func randomID(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func hashPassword(raw string) password {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		panic(err)
	}
	return password{salt, argon2.IDKey([]byte(raw), salt, 3, 64*1024, 2, 32)}
}
func (p password) matches(raw string) bool {
	v := argon2.IDKey([]byte(raw), p.Salt, 3, 64*1024, 2, 32)
	return subtle.ConstantTimeCompare(v, p.Hash) == 1
}
func digest(raw string) string { h := sha256.Sum256([]byte(raw)); return hex.EncodeToString(h[:]) }
func (s *Service) signAccess(user string) string {
	return security.Sign(s.key, user, s.accounts[user].Version, s.now())
}
func (s *Service) verifyAccess(token string) (string, error) {
	c, e := security.Verify(s.key, token, s.now())
	if e != nil {
		return "", e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.accounts[c.Subject]
	if a == nil || a.Version != c.Version {
		return "", errors.New("access revoked")
	}
	return c.Subject, nil
}

// Caller holds mu. Only hashes of refresh tokens are retained.
func (s *Service) issue(user, family string) tokens {
	if family == "" {
		family = randomID(24)
	}
	raw := randomID(32)
	s.refresh[digest(raw)] = &refreshToken{user, family, s.now().Add(7 * 24 * time.Hour), false}
	return tokens{s.signAccess(user), raw, 600, "Bearer"}
}
