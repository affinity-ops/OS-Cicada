// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package ciba implements OAuth 2.0 Client Initiated Backchannel Authentication
// for the Sentry Gateway's last-hop authorization system.
//
// When the Gateway's Tier 1 policy pre-check flags a high-risk action, instead
// of calling a developer webhook (the old Tier 2 path), it initiates a CIBA flow:
//
//   1. POST to Core API /v1/internal/ciba/request — creates a pending authorization
//   2. Poll Core API /v1/internal/ciba/poll/{traceId} until approved/denied/expired
//   3. Return the result to the caller in handleAgentRequest
//
// The Core API delivers the notification to the owner via the dashboard (dev phase)
// or the Flutter companion app (production). The Gateway does not care about the
// delivery mechanism — it only creates and polls.
//
// Fail-closed: if polling times out or the network fails, the action is denied.
package ciba

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// DefaultTimeout is how long the Gateway waits for the owner to respond
// before auto-denying the action. Configurable via CIBA_TIMEOUT_SECONDS.
const DefaultTimeout = 120 * time.Second

// DefaultPollInterval is how often the Gateway polls the Core API for a
// decision. Configurable via CIBA_POLL_INTERVAL_MS.
const DefaultPollInterval = 500 * time.Millisecond

// Request is the payload sent to the Core API to create a CIBA authorization.
type Request struct {
	TraceID        string  `json:"trace_id"`
	AgentID        string  `json:"agent_id"`
	TenantID       string  `json:"tenant_id"`
	ActionSummary  string  `json:"action_summary"`
	TargetURL      string  `json:"target_url,omitempty"`
	PayloadPreview string  `json:"payload_preview,omitempty"`
	RiskScore      float64 `json:"risk_score"`
	RiskReason     string  `json:"risk_reason,omitempty"`
	TimeoutSeconds int     `json:"timeout_seconds"`
}

// PollResponse is the JSON returned by the Core API poll endpoint.
type PollResponse struct {
	TraceID     string `json:"trace_id"`
	Status      string `json:"status"` // pending | approved | denied | expired
	Approved    bool   `json:"approved"`
	RespondedBy string `json:"responded_by,omitempty"`
}

// Result carries the outcome back to the Gateway's request handler.
type Result struct {
	Approved    bool
	Status      string // approved | denied | expired | error
	RespondedBy string
	Err         error
}

// Authorize initiates a CIBA flow and blocks until the owner responds or the
// timeout expires. This replaces the old humanWebhook() call in hitl.go.
//
// The caller (handleAgentRequest in main.go) should run this synchronously —
// the agent's action is held until this function returns.
func Authorize(ctx context.Context, req Request) Result {
	coreAPI := coreAPIURL()
	timeout := cibaTimeout()
	pollInterval := cibaPollInterval()

	if req.TimeoutSeconds <= 0 {
		req.TimeoutSeconds = int(timeout.Seconds())
	}

	// ── Step 1: Create the CIBA authorization request ─────────────────────
	body, err := json.Marshal(req)
	if err != nil {
		return Result{Approved: false, Status: "error", Err: fmt.Errorf("failed to marshal CIBA request: %w", err)}
	}

	createURL := fmt.Sprintf("%s/api/v1/internal/ciba/request", coreAPI)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, createURL, strings.NewReader(string(body)))
	if err != nil {
		return Result{Approved: false, Status: "error", Err: fmt.Errorf("failed to build CIBA create request: %w", err)}
	}
	httpReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		log.Printf("[CIBA] Failed to create authorization request: %v", err)
		return Result{Approved: false, Status: "error", Err: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		log.Printf("[CIBA] Core API returned %d creating CIBA request: %s", resp.StatusCode, string(respBody))
		return Result{Approved: false, Status: "error", Err: fmt.Errorf("core API returned %d", resp.StatusCode)}
	}

	log.Printf("[CIBA] Authorization request created for agent=%s trace=%s (timeout=%ds)", req.AgentID, req.TraceID, req.TimeoutSeconds)

	// ── Step 2: Poll until resolved or timed out ──────────────────────────
	pollURL := fmt.Sprintf("%s/api/v1/internal/ciba/poll/%s", coreAPI, req.TraceID)
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return Result{Approved: false, Status: "error", Err: ctx.Err()}
		case <-time.After(pollInterval):
		}

		pollReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, pollURL, nil)
		pollResp, err := client.Do(pollReq)
		if err != nil {
			log.Printf("[CIBA] Poll error for trace=%s: %v", req.TraceID, err)
			continue // Retry on transient network errors
		}

		var pr PollResponse
		if err := json.NewDecoder(pollResp.Body).Decode(&pr); err != nil {
			pollResp.Body.Close()
			log.Printf("[CIBA] Malformed poll response for trace=%s: %v", req.TraceID, err)
			continue
		}
		pollResp.Body.Close()

		switch pr.Status {
		case "approved":
			log.Printf("[CIBA] APPROVED by %s for agent=%s trace=%s", pr.RespondedBy, req.AgentID, req.TraceID)
			return Result{Approved: true, Status: "approved", RespondedBy: pr.RespondedBy}
		case "denied":
			log.Printf("[CIBA] DENIED by %s for agent=%s trace=%s", pr.RespondedBy, req.AgentID, req.TraceID)
			return Result{Approved: false, Status: "denied", RespondedBy: pr.RespondedBy}
		case "expired":
			log.Printf("[CIBA] EXPIRED for agent=%s trace=%s", req.AgentID, req.TraceID)
			return Result{Approved: false, Status: "expired"}
		case "pending":
			// Keep polling
		}
	}

	// Timeout reached — fail closed
	log.Printf("[CIBA] TIMEOUT for agent=%s trace=%s — fail closed", req.AgentID, req.TraceID)
	return Result{Approved: false, Status: "expired"}
}

// ────────────────────────────────────────────────────────────────────────────
// Configuration
// ────────────────────────────────────────────────────────────────────────────

func coreAPIURL() string {
	if v := os.Getenv("CICADA_CORE_API_URL"); v != "" {
		return v
	}
	return "http://localhost:8000"
}

func cibaTimeout() time.Duration {
	if v := os.Getenv("CIBA_TIMEOUT_SECONDS"); v != "" {
		if secs, err := strconv.Atoi(v); err == nil && secs > 0 {
			return time.Duration(secs) * time.Second
		}
	}
	return DefaultTimeout
}

func cibaPollInterval() time.Duration {
	if v := os.Getenv("CIBA_POLL_INTERVAL_MS"); v != "" {
		if ms, err := strconv.Atoi(v); err == nil && ms > 0 {
			return time.Duration(ms) * time.Millisecond
		}
	}
	return DefaultPollInterval
}
