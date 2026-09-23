package platform

import (
	"errors"
	"muiltdesk/server/internal/security"
	"net/http"
	"strings"
	"time"
)

// ConfigureICE is intended for startup only. No third-party relay is hardcoded.
func (s *Service) ConfigureICE(urls []string, secret string) error {
	for _, url := range urls {
		if (!strings.HasPrefix(url, "stun:") && !strings.HasPrefix(url, "stuns:") && !strings.HasPrefix(url, "turn:") && !strings.HasPrefix(url, "turns:")) || strings.ContainsAny(url, " \n\r@") {
			return errors.New("invalid STUN/TURN URL")
		}
		if (strings.HasPrefix(url, "turn:") || strings.HasPrefix(url, "turns:")) && (len(secret) < 32 || strings.Contains(secret, "REPLACE")) {
			return errors.New("TURN requires a random shared secret of at least 32 bytes")
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.iceURLs = append([]string(nil), urls...)
	s.turnSecret = secret
	return nil
}
func (s *Service) iceConfiguration(w http.ResponseWriter, r *http.Request, user string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	session := s.sessions[r.PathValue("id")]
	if session == nil || !s.visible(session, user) {
		fail(w, 404, "session not found")
		return
	}
	if session.State != "active" || !s.now().Before(session.Expires) {
		fail(w, 403, "an active approved session is required")
		return
	}
	if len(s.iceURLs) == 0 {
		fail(w, 503, "STUN/TURN endpoints are not configured")
		return
	}
	expires := s.now().Add(10 * time.Minute)
	if session.Expires.Before(expires) {
		expires = session.Expires
	}
	username, credential := security.TURNCredential(s.turnSecret, user, expires)
	entries := []map[string]any{}
	for _, url := range s.iceURLs {
		entry := map[string]any{"urls": []string{url}}
		if strings.HasPrefix(url, "turn:") || strings.HasPrefix(url, "turns:") {
			entry["username"] = username
			entry["credential"] = credential
		}
		entries = append(entries, entry)
	}
	sendJSON(w, 200, map[string]any{"ice_servers": entries, "expires_at": expires})
}
