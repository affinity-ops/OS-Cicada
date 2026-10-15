// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package hitl

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ── Tier 1: Policy Pre-Check (pure logic, no infrastructure) ──────────────────

func TestPolicyPreCheck_CleanCall(t *testing.T) {
	score, reason := policyPreCheck([]string{"proxy:write"}, "https://api.stripe.com/v1/customers", `{"name": "John Doe"}`)
	if score != 0 {
		t.Errorf("clean write call should have zero risk, got %f (%s)", score, reason)
	}
	if reason != "policy pre-check passed" {
		t.Errorf("expected 'policy pre-check passed', got %q", reason)
	}
}

func TestPolicyPreCheck_TransactWithFinancialKeyword(t *testing.T) {

	score, reason := policyPreCheck([]string{"proxy:transact"}, "https://api.stripe.com/v1/charges", `{"amount": 5000, "currency": "usd"}`)
	if score < 0.40 {
		t.Errorf("proxy:transact with 'amount' should score ≥ 0.40, got %f", score)
	}
	if reason == "policy pre-check passed" {
		t.Error("expected risk reason, got 'policy pre-check passed'")
	}
}

func TestPolicyPreCheck_TransactNoFinancialKeyword(t *testing.T) {
	score, _ := policyPreCheck([]string{"proxy:transact"}, "https://api.example.com/v1/data", `{"name": "test"}`)
	if score >= 0.40 {
		t.Errorf("proxy:transact without financial keywords should not trigger financial check, got %f", score)
	}
}

func TestPolicyPreCheck_WriteWithDestructivePath(t *testing.T) {
	cases := []string{
		"https://api.example.com/v1/users/bulk_delete",
		"https://api.example.com/v1/data/purge",
		"https://api.example.com/v1/records/destroy",
		"https://api.example.com/v1/table/truncate",
	}
	for _, url := range cases {
		score, _ := policyPreCheck([]string{"proxy:write"}, url, `{}`)
		if score < 0.30 {
			t.Errorf("proxy:write targeting %q should score ≥ 0.30, got %f", url, score)
		}
	}
}

func TestPolicyPreCheck_CredentialInPayload(t *testing.T) {
	payloads := []struct {
		payload  string
		expected string
	}{
		{`{"key": "sk-abc123"}`, "sk-"},
		{`{"token": "ghp_xxxxxxxxxxx"}`, "ghp_"},
		{`{"secret": "AKIAIOSFODNN7EXAMPLE"}`, "AKIA"},
		{`-----BEGIN PRIVATE KEY-----`, "BEGIN PRIVATE KEY"},
	}
	for _, tc := range payloads {
		score, _ := policyPreCheck([]string{"proxy:write"}, "https://api.example.com/v1/data", tc.payload)
		if score < 0.30 {
			t.Errorf("credential pattern %q in payload should score ≥ 0.30, got %f", tc.expected, score)
		}
	}
}

func TestPolicyPreCheck_SSRFTarget(t *testing.T) {
	internalHosts := []string{
		"http://localhost:8080/admin",
		"http://127.0.0.1:9090/metrics",
		"http://192.168.1.1/api",
		"http://10.0.0.1:3000/internal",
		"http://169.254.169.254/latest/meta-data",
	}
	for _, url := range internalHosts {
		score, _ := policyPreCheck([]string{"proxy:write"}, url, `{}`)
		if score < 0.20 {
			t.Errorf("internal host %q should score ≥ 0.20, got %f", url, score)
		}
	}
}

func TestPolicyPreCheck_CompoundRisk(t *testing.T) {
	// proxy:transact + financial keyword + credential + internal host → all compound
	score, _ := policyPreCheck(
		[]string{"proxy:transact"},
		"http://192.168.1.1/v1/transfer",
		`{"amount": 10000, "api_key": "sk-secret123"}`,
	)
	if score < 0.80 {
		t.Errorf("compound risk should score ≥ 0.80, got %f", score)
	}
}

func TestPolicyPreCheck_ScoreCappedAt1(t *testing.T) {
	score, _ := policyPreCheck(
		[]string{"proxy:transact"},
		"http://127.0.0.1/bulk_delete",
		`{"amount": 99999, "api_key": "sk-steal"}`,
	)
	if score > 1.0 {
		t.Errorf("risk score should be capped at 1.0, got %f", score)
	}
}

func TestPolicyPreCheck_NoScopesNoRisk(t *testing.T) {
	score, reason := policyPreCheck(nil, "https://api.example.com/v1/data", `{"name": "test"}`)
	if score > 0 {
		t.Errorf("no scopes, clean URL, clean payload should have zero risk, got %f", score)
	}
	if reason != "policy pre-check passed" {
		t.Errorf("expected 'policy pre-check passed', got %q", reason)
	}
}

// ── TieredCheck (full flow, Tier 1 auto-approve) ──────────────────────────────

func TestTieredCheck_LowRiskAutoApproved(t *testing.T) {
	result := TieredCheck("https://hooks.example.com/hitl", "trace-1", "agent-1", "tenant-1",
		"https://api.stripe.com/v1/customers", []string{"proxy:write"}, `{"name": "John Doe"}`)
	if !result.Approved {
		t.Error("low-risk call should be auto-approved at Tier 1")
	}
	if result.Tier != 1 {
		t.Errorf("expected Tier 1 auto-approval, got Tier %d", result.Tier)
	}
}

func TestTieredCheck_HighRiskEscalatesToTier2(t *testing.T) {
	// Set up a mock webhook server that rejects the call
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(ApprovalResponse{Approved: false, Reason: "suspicious activity"})
	}))
	defer server.Close()

	result := TieredCheck(server.URL, "trace-2", "agent-2", "tenant-2",
		"http://192.168.1.1/bulk_delete", []string{"proxy:transact"}, `{"amount": 50000}`)
	if result.Tier != 2 {
		t.Errorf("high-risk call should escalate to Tier 2, got Tier %d", result.Tier)
	}
	if result.Approved {
		t.Error("webhook rejected → should not be approved")
	}
}

func TestTieredCheck_Tier2WebhookApproves(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the request payload is well-formed
		var req ApprovalRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("webhook received malformed JSON: %v", err)
		}
		if req.AgentID != "agent-3" {
			t.Errorf("webhook received wrong agent_id: %q", req.AgentID)
		}
		if req.RiskScore < 0.50 {
			t.Errorf("webhook should receive risk score, got %f", req.RiskScore)
		}
		json.NewEncoder(w).Encode(ApprovalResponse{Approved: true, Reason: "operator approved"})
	}))
	defer server.Close()

	result := TieredCheck(server.URL, "trace-3", "agent-3", "tenant-3",
		"http://localhost:8080/admin/reset", []string{"proxy:transact"}, `{"amount": 99999}`)
	if result.Tier != 2 {
		t.Errorf("expected Tier 2 escalation, got Tier %d", result.Tier)
	}
	if !result.Approved {
		t.Error("webhook approved → result should be approved")
	}
}

func TestTieredCheck_Tier2WebhookUnreachable_FailClosed(t *testing.T) {
	// Webhook at a dead URL → should fail closed (not approved)
	result := TieredCheck("http://127.0.0.1:1", "trace-4", "agent-4", "tenant-4",
		"http://10.0.0.1/admin/delete", []string{"proxy:transact"}, `{"amount": 50000}`)
	if result.Approved {
		t.Error("unreachable webhook must fail closed (not approved)")
	}
	if result.Tier != 2 {
		t.Errorf("should have escalated to Tier 2 first, got Tier %d", result.Tier)
	}
}

func TestTieredCheck_Tier2WebhookNon2xx_FailClosed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	result := TieredCheck(server.URL, "trace-5", "agent-5", "tenant-5",
		"http://10.0.0.1/destroy", []string{"proxy:transact"}, `{"amount": 50000}`)
	if result.Approved {
		t.Error("webhook returning 500 must fail closed")
	}
}

// ── Configuration ─────────────────────────────────────────────────────────────

func TestPolicyRiskThreshold_Default(t *testing.T) {
	threshold := policyRiskThreshold()
	if threshold != defaultPolicyRiskThreshold {
		t.Errorf("default policy risk threshold = %f, want %f", threshold, defaultPolicyRiskThreshold)
	}
}

func TestHumanApprovalTimeout_Default(t *testing.T) {
	timeout := humanApprovalTimeout()
	expected := defaultHumanApprovalTimeoutSeconds
	if int(timeout.Seconds()) != expected {
		t.Errorf("default timeout = %v, want %d seconds", timeout, expected)
	}
}
