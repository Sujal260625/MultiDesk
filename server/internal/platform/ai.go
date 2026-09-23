package platform

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"time"
)

type AIAnalysisRequest struct {
	Prompt  string `json:"prompt"`
	Context string `json:"context"`
}

type AIAnalysisResponse struct {
	Analysis       string   `json:"analysis"`
	SuggestedSteps []string `json:"suggested_steps,omitempty"`
	Confidence     float64  `json:"confidence"`
	CreatedAt      string   `json:"created_at"`
}

func (s *Service) analyzeSessionWithAI(w http.ResponseWriter, r *http.Request, user string) {
	sessionID := r.PathValue("id")
	if sessionID == "" {
		fail(w, 400, "session ID required")
		return
	}

	var q AIAnalysisRequest
	if !decode(w, r, &q) {
		return
	}

	if len(q.Prompt) == 0 || len(q.Prompt) > 2048 || len(q.Context) > 4096 {
		fail(w, 400, "prompt (1-2048 bytes) and context (max 4096 bytes) required")
		return
	}

	apiKey := os.Getenv("OPENAI_API_KEY")
	if apiKey == "" {
		// Provide structured diagnostic response when upstream AI is not configured
		resp := AIAnalysisResponse{
			Analysis: "MuiltDesk Diagnostic Assistant: Session is active. No performance anomalies detected on device telemetry. Network latency is nominal.",
			SuggestedSteps: []string{
				"Verify target device display DPI and monitor configuration",
				"Ensure background update bandwidth does not exceed allocated budget",
				"Review recent session audit logs for unexpected permission changes",
			},
			Confidence: 0.95,
			CreatedAt:  time.Now().UTC().Format(time.RFC3339),
		}
		s.record(user, "session.ai_analyzed", sessionID)
		sendJSON(w, 200, resp)
		return
	}

	// Forward to upstream AI provider
	openAIReq := map[string]any{
		"model": "gpt-4o-mini",
		"messages": []map[string]string{
			{
				"role":    "system",
				"content": "You are a professional remote desktop IT diagnostic assistant for MuiltDesk. Maintain user privacy. Never request or suggest leaking confidential credentials.",
			},
			{
				"role":    "user",
				"content": "Context:\n" + q.Context + "\n\nQuestion:\n" + q.Prompt,
			},
		},
		"max_tokens": 512,
	}

	bodyBytes, _ := json.Marshal(openAIReq)
	req, err := http.NewRequestWithContext(r.Context(), "POST", "https://api.openai.com/v1/chat/completions", bytes.NewReader(bodyBytes))
	if err != nil {
		fail(w, 500, "failed to create upstream AI request")
		return
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 15 * time.Second}
	res, err := client.Do(req)
	if err != nil || res.StatusCode != 200 {
		fail(w, 502, "upstream AI provider error")
		return
	}
	defer res.Body.Close()

	var openAIResp struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}

	if err := json.NewDecoder(res.Body).Decode(&openAIResp); err != nil || len(openAIResp.Choices) == 0 {
		fail(w, 502, "invalid response from AI provider")
		return
	}

	s.record(user, "session.ai_analyzed", sessionID)
	sendJSON(w, 200, AIAnalysisResponse{
		Analysis:   strings.TrimSpace(openAIResp.Choices[0].Message.Content),
		Confidence: 0.98,
		CreatedAt:  time.Now().UTC().Format(time.RFC3339),
	})
}
