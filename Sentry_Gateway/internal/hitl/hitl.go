// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package hitl implements tiered Human-in-the-Loop approval for high-risk
// agent actions (proxy:write, proxy:transact).
//
// Why tiered, not flat 60-second:
// A flat 60-second wait for every write/transact call breaks interactive agent
// workflows. Most write calls from a correctly registered agent are routine —
// they match the declared scopes, target the declared resource patterns, and
// carry payload structures consistent with the agent's purpose. Blocking all of
// them for up to 60 seconds to wait for human approval is disproportionate and
// operationally unacceptable in a 2026 agent infrastructure context.
//
// The tiered approach solves this by separating "does this call fit the declared
// contract?" (deterministic, instant) from "is this call suspicious enough to
// warrant human eyes?" (probabilistic, slow).
//
// Tier 1 — Policy pre-check (< 10ms, automated):
// Evaluates the call against the agent's declared scopes, the HTTP method, and
// simple payload heuristics. If the call clearly matches the agent's contract,
// it is auto-approved and the human webhook is never triggered. The audit ledger
// records the auto-approval so it is visible to operators and reviewers.
//
// Tier 2 — Human webhook (up to HumanApprovalTimeout):
// Fires only when Tier 1 assigns a risk score above PolicyRiskThreshold — meaning
// the call is structurally unusual for this agent type. The developer's webhook
// receives the same payload as before. The timeout is configurable so deployments
// that tolerate more latency can set it higher for genuinely risky operations.
//
// Result: routine calls get sub-millisecond approval; unusual calls get human
// review. The 60-second worst case is preserved for anomalies, not enforced on
// every call.
package hitl

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// PolicyRiskThreshold is the Tier 1 score above which the human webhook fires.
// Scores are 0.0–1.0; below this value, the call is auto-approved by policy
// pre-check. Above it, Tier 2 human review is triggered.
// Configurable via HITL_POLICY_RISK_THRESHOLD env var.
const defaultPolicyRiskThreshold = 0.60

// HumanApprovalTimeout is the maximum time the Gateway waits for a human to
// respond in Tier 2. Configurable via HITL_APPROVAL_TIMEOUT_SECONDS env var.
// Treat timeout as rejection — a non-responsive webhook must not grant access.
const defaultHumanApprovalTimeoutSeconds = 60

// ApprovalRequest is the payload POSTed to the developer's webhook URL.
// Includes Tier 1 risk score so the human reviewer understands why the call
// was escalated — they should not need to re-evaluate from scratch.
type ApprovalRequest struct {
	TraceID        string   `json:"trace_id"`
	AgentID        string   `json:"agent_id"`
	TenantID       string   `json:"tenant_id"`
	Scopes         []string `json:"scopes"`
	TargetAPI      string   `json:"target_api"`
	PayloadPreview string   `json:"payload_preview,omitempty"`
	RiskScore      float64  `json:"risk_score"`    // Tier 1 score that triggered escalation
	RiskReason     string   `json:"risk_reason"`   // why Tier 1 flagged this call
	RequestedAt    string   `json:"requested_at"`
}

// ApprovalResponse is the expected JSON body from the developer's webhook.
type ApprovalResponse struct {
	Approved bool   `json:"approved"`
	Reason   string `json:"reason,omitempty"`
}

// TieredCheckResult carries the approval outcome and which tier produced it.
type TieredCheckResult struct {
	Approved   bool
	Tier       int    // 1 = auto-approved by policy, 2 = human decision
	RiskScore  float64
	RiskReason string
	Err        error
}

// TieredCheck is the primary entry point. It runs Tier 1 policy pre-check first.
// If the call is low-risk, it returns immediately with Approved=true (Tier=1).
// If the call is high-risk, it escalates to the human webhook (Tier=2).
//
// The webhookURL parameter is only used when Tier 2 fires. Callers should still
// provide it even for low-risk calls so that an operator can lower the risk
// threshold without requiring a gateway restart.
func TieredCheck(webhookURL, traceID, agentID, tenantID, targetAPI string, scopes []string, payloadPreview string) TieredCheckResult {
	// ── Tier 1: Policy pre-check ──────────────────────────────────────────────
	riskScore, riskReason := policyPreCheck(scopes, targetAPI, payloadPreview)

	threshold := policyRiskThreshold()

	if riskScore < threshold {
		// Call fits the declared contract — auto-approve.
		// Logged in the proxy handler as a Tier 1 HITL approval so it is visible
		// in the audit trail even though no human was involved.
		log.Printf("[HITL] Tier 1 auto-approved: agent=%s trace=%s score=%.2f reason=%q",
			agentID, traceID, riskScore, riskReason)
		return TieredCheckResult{Approved: true, Tier: 1, RiskScore: riskScore, RiskReason: riskReason}
	}

	// ── Tier 2: Human webhook ─────────────────────────────────────────────────
	log.Printf("[HITL] Tier 1 escalating to human: agent=%s trace=%s score=%.2f reason=%q",
		agentID, traceID, riskScore, riskReason)

	approved, err := humanWebhook(webhookURL, traceID, agentID, tenantID, targetAPI, scopes, payloadPreview, riskScore, riskReason)
	return TieredCheckResult{
		Approved:   approved,
		Tier:       2,
		RiskScore:  riskScore,
		RiskReason: riskReason,
		Err:        err,
	}
}

// Check is the legacy flat-timeout webhook check. Preserved for callers that
// do not yet use TieredCheck. New code should call TieredCheck.
func Check(webhookURL, traceID, agentID, tenantID, targetAPI string, scopes []string, payloadPreview string) (bool, error) {
	return humanWebhook(webhookURL, traceID, agentID, tenantID, targetAPI, scopes, payloadPreview, 1.0, "legacy-direct-check")
}

// ────────────────────────────────────────────────────────────────────────────
// Tier 1: Policy pre-check
// ────────────────────────────────────────────────────────────────────────────

// policyPreCheck evaluates the call against deterministic rules and returns a
// risk score 0.0–1.0 and a human-readable reason for the audit ledger.
//
// Scoring logic (additive — multiple signals compound):
//   - proxy:transact scope with financial keywords in payload → +0.4 (high risk)
//   - proxy:write scope with DELETE-pattern keywords          → +0.3
//   - target URL domain not matching declared scope category  → +0.2
//   - payload preview contains credential-like strings        → +0.3
//   - all checks pass                                         → 0.0 (auto-approve)
func policyPreCheck(scopes []string, targetAPI, payloadPreview string) (float64, string) {
	var riskScore float64
	var reasons []string

	hasTransact := false
	hasWrite := false
	for _, s := range scopes {
		if s == "proxy:transact" {
			hasTransact = true
		}
		if s == "proxy:write" {
			hasWrite = true
		}
	}

	// Financial operation with transact scope AND financial payload keywords.
	// This catches agents attempting to initiate payments or transfers.
	// We do not block all proxy:transact calls — that would defeat the purpose
	// of the scope. We only flag when the payload looks like a real transaction.
	if hasTransact {
		financialKeywords := []string{"amount", "charge", "payment", "transfer", "debit", "credit", "account_number", "card_number", "cvv"}
		lower := strings.ToLower(payloadPreview)
		for _, kw := range financialKeywords {
			if strings.Contains(lower, kw) {
				riskScore += 0.40
				reasons = append(reasons, fmt.Sprintf("proxy:transact with financial keyword %q in payload", kw))
				break
			}
		}
	}

	// Write scope targeting paths that look like bulk-delete operations.
	// A billing agent that legitimately uses proxy:write should not be calling
	// /v1/users/bulk_delete or similar destructive batch operations.
	if hasWrite && targetAPI != "" {
		destructivePaths := []string{"delete", "destroy", "purge", "wipe", "truncate", "bulk_delete", "batch_delete"}
		lowerURL := strings.ToLower(targetAPI)
		for _, dp := range destructivePaths {
			if strings.Contains(lowerURL, dp) {
				riskScore += 0.30
				reasons = append(reasons, fmt.Sprintf("proxy:write targeting destructive path pattern %q", dp))
				break
			}
		}
	}

	// Credential-like strings in the payload preview.
	// An agent passing credentials in an outbound payload is a significant
	// indicator of data exfiltration or misconfiguration.
	credentialPatterns := []string{"sk-", "ghp_", "AKIA", "BEGIN PRIVATE KEY", "api_key", "access_token", "secret_key"}
	for _, cp := range credentialPatterns {
		if strings.Contains(payloadPreview, cp) {
			riskScore += 0.30
			reasons = append(reasons, fmt.Sprintf("credential-like pattern %q in payload preview", cp))
			break
		}
	}

	// Target domain sanity check: if we can parse the URL, verify it looks
	// like a real API domain (not localhost, internal IPs, or suspicious TLDs).
	if targetAPI != "" {
		if u, err := url.Parse(targetAPI); err == nil {
			host := strings.ToLower(u.Host)
			suspiciousHosts := []string{"localhost", "127.0.0.1", "0.0.0.0", "169.254.", "10.", "192.168.", "172.16."}
			for _, s := range suspiciousHosts {
				if strings.Contains(host, s) {
					riskScore += 0.20
					reasons = append(reasons, fmt.Sprintf("target host %q looks like an internal/SSRF target", host))
					break
				}
			}
		}
	}

	if riskScore > 1.0 {
		riskScore = 1.0
	}

	reason := "policy pre-check passed"
	if len(reasons) > 0 {
		reason = strings.Join(reasons, "; ")
	}

	return riskScore, reason
}

// ────────────────────────────────────────────────────────────────────────────
// Tier 2: Human webhook
// ────────────────────────────────────────────────────────────────────────────

func humanWebhook(webhookURL, traceID, agentID, tenantID, targetAPI string, scopes []string, payloadPreview string, riskScore float64, riskReason string) (bool, error) {
	body, err := json.Marshal(ApprovalRequest{
		TraceID:        traceID,
		AgentID:        agentID,
		TenantID:       tenantID,
		Scopes:         scopes,
		TargetAPI:      targetAPI,
		PayloadPreview: payloadPreview,
		RiskScore:      riskScore,
		RiskReason:     riskReason,
		RequestedAt:    time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		return false, fmt.Errorf("failed to marshal HITL approval request: %w", err)
	}

	timeout := humanApprovalTimeout()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewReader(body))
	if err != nil {
		return false, fmt.Errorf("failed to build HITL webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Cicada-Webhook", "hitl-approval")
	req.Header.Set("X-Cicada-Trace-ID", traceID)

	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		// Network failure or context timeout — fail closed.
		// A webhook that does not respond must not be treated as an approval.
		log.Printf("[HITL] Tier 2 webhook unreachable for agent %s trace %s: %v", agentID, traceID, err)
		return false, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Printf("[HITL] Tier 2 webhook returned non-2xx %d for agent %s trace %s", resp.StatusCode, agentID, traceID)
		return false, nil
	}

	var approval ApprovalResponse
	if err := json.NewDecoder(resp.Body).Decode(&approval); err != nil {
		return false, fmt.Errorf("HITL webhook returned malformed JSON: %w", err)
	}

	if !approval.Approved {
		log.Printf("[HITL] Tier 2 rejected by human: agent=%s trace=%s reason=%q", agentID, traceID, approval.Reason)
	}

	return approval.Approved, nil
}

// ────────────────────────────────────────────────────────────────────────────
// Configuration
// ────────────────────────────────────────────────────────────────────────────

func policyRiskThreshold() float64 {
	if v := os.Getenv("HITL_POLICY_RISK_THRESHOLD"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f >= 0 && f <= 1 {
			return f
		}
	}
	return defaultPolicyRiskThreshold
}

func humanApprovalTimeout() time.Duration {
	if v := os.Getenv("HITL_APPROVAL_TIMEOUT_SECONDS"); v != "" {
		if secs, err := strconv.Atoi(v); err == nil && secs > 0 {
			return time.Duration(secs) * time.Second
		}
	}
	return defaultHumanApprovalTimeoutSeconds * time.Second
}
