package platform

import (
	"encoding/json"
	"net/http"
	"strings"

	"muiltdesk/server/internal/store"
)

func (s *Service) createWorkflow(w http.ResponseWriter, r *http.Request, user string) {
	orgID := r.PathValue("id")
	var q struct {
		Name                string          `json:"name"`
		Definition          json.RawMessage `json:"definition"`
		RequiredPermissions []string        `json:"required_permissions"`
		Enabled             bool            `json:"enabled"`
	}
	if !decode(w, r, &q) {
		return
	}

	q.Name = strings.TrimSpace(q.Name)
	if len(q.Name) < 2 || len(q.Name) > 100 {
		fail(w, 400, "workflow name between 2 and 100 characters required")
		return
	}

	wf := &store.Workflow{
		ID:                  randomID(16),
		OrganizationID:      orgID,
		Name:                q.Name,
		Definition:          []byte(q.Definition),
		RequiredPermissions: q.RequiredPermissions,
		Enabled:             q.Enabled,
		CreatedBy:           user,
	}

	if s.store != nil {
		if err := s.store.CreateWorkflow(r.Context(), wf); err != nil {
			fail(w, 500, "failed to create workflow")
			return
		}
	}

	s.record(user, "workflow.created", wf.ID)
	sendJSON(w, 201, wf)
}

func (s *Service) listWorkflows(w http.ResponseWriter, r *http.Request, user string) {
	orgID := r.PathValue("id")
	if s.store != nil {
		wfs, err := s.store.ListWorkflows(r.Context(), orgID)
		if err == nil && wfs != nil {
			sendJSON(w, 200, wfs)
			return
		}
	}
	sendJSON(w, 200, []store.Workflow{})
}

func (s *Service) runWorkflow(w http.ResponseWriter, r *http.Request, user string) {
	sessionID := r.PathValue("sid")
	workflowID := r.PathValue("wid")

	now := s.now().UTC()
	run := &store.WorkflowRun{
		ID:         randomID(16),
		WorkflowID: workflowID,
		SessionID:  sessionID,
		ApprovedBy: &user,
		State:      "running",
		StartedAt:  &now,
	}

	if s.store != nil {
		_ = s.store.CreateWorkflowRun(r.Context(), run)
	}

	s.record(user, "workflow.started", run.ID)
	sendJSON(w, 202, run)
}

func (s *Service) getWorkflowRun(w http.ResponseWriter, r *http.Request, user string) {
	runID := r.PathValue("id")
	if s.store != nil {
		run, err := s.store.GetWorkflowRun(r.Context(), runID)
		if err == nil && run != nil {
			sendJSON(w, 200, run)
			return
		}
	}
	fail(w, 404, "workflow run not found")
}
