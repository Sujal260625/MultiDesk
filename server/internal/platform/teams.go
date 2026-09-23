package platform

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"muiltdesk/server/internal/store"
)

func (s *Service) createOrganization(w http.ResponseWriter, r *http.Request, user string) {
	var q struct {
		Name string `json:"name"`
	}
	if !decode(w, r, &q) {
		return
	}

	q.Name = strings.TrimSpace(q.Name)
	if len(q.Name) < 2 || len(q.Name) > 80 {
		fail(w, 400, "organization name between 2 and 80 characters required")
		return
	}

	org := &store.Organization{
		ID:        randomID(16),
		Name:      q.Name,
		OwnerID:   user,
		CreatedAt: s.now().UTC(),
	}

	if s.store != nil {
		if err := s.store.CreateOrganization(r.Context(), org); err != nil {
			fail(w, 500, "failed to create organization")
			return
		}
		_ = s.store.CreateMembership(r.Context(), org.ID, user, "owner", nil)
	}

	s.record(user, "org.created", org.ID)
	sendJSON(w, 201, org)
}

func (s *Service) listOrganizations(w http.ResponseWriter, r *http.Request, user string) {
	if s.store != nil {
		orgs, err := s.store.ListUserOrganizations(r.Context(), user)
		if err == nil && orgs != nil {
			sendJSON(w, 200, orgs)
			return
		}
	}
	sendJSON(w, 200, []store.Organization{})
}

func (s *Service) listMembers(w http.ResponseWriter, r *http.Request, user string) {
	orgID := r.PathValue("id")
	if orgID == "" {
		fail(w, 400, "organization ID required")
		return
	}

	if s.store != nil {
		members, err := s.store.ListMembers(r.Context(), orgID)
		if err == nil && members != nil {
			sendJSON(w, 200, members)
			return
		}
	}
	sendJSON(w, 200, []store.Membership{})
}

func (s *Service) inviteMember(w http.ResponseWriter, r *http.Request, user string) {
	orgID := r.PathValue("id")
	var q struct {
		Email string `json:"email"`
		Role  string `json:"role"`
	}
	if !decode(w, r, &q) {
		return
	}

	q.Email = strings.ToLower(strings.TrimSpace(q.Email))
	if q.Email == "" || (q.Role != "administrator" && q.Role != "operator" && q.Role != "viewer" && q.Role != "guest") {
		fail(w, 400, "valid email and role required")
		return
	}

	rawToken := randomID(32)
	h := sha256.Sum256([]byte(rawToken))
	tokenHash := hex.EncodeToString(h[:])

	invite := &store.OrgInvite{
		ID:        randomID(16),
		OrgID:     orgID,
		Email:     q.Email,
		Role:      q.Role,
		TokenHash: tokenHash,
		ExpiresAt: s.now().UTC().Add(7 * 24 * time.Hour),
	}

	if s.store != nil {
		_ = s.store.CreateInvite(r.Context(), invite)
	}

	s.record(user, "org.member_invited", invite.ID)
	sendJSON(w, 201, map[string]string{
		"invite_id":  invite.ID,
		"invite_url": "https://muiltdesk.app/invite/" + rawToken,
	})
}

func (s *Service) updateMemberRole(w http.ResponseWriter, r *http.Request, user string) {
	orgID := r.PathValue("id")
	targetUser := r.PathValue("userId")
	var q struct {
		Role string `json:"role"`
	}
	if !decode(w, r, &q) {
		return
	}

	if s.store != nil {
		_ = s.store.UpdateMemberRole(r.Context(), orgID, targetUser, q.Role)
	}

	s.record(user, "org.role_changed", orgID+"/"+targetUser)
	sendJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Service) removeMember(w http.ResponseWriter, r *http.Request, user string) {
	orgID := r.PathValue("id")
	targetUser := r.PathValue("userId")

	if s.store != nil {
		_ = s.store.RemoveMembership(r.Context(), orgID, targetUser)
	}

	s.record(user, "org.member_removed", orgID+"/"+targetUser)
	sendJSON(w, 200, map[string]bool{"ok": true})
}
