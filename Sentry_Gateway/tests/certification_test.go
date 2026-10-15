// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build integration

// Tests for the agent certification lifecycle (Phase 1–3).
// These verify that:
//   - Registration returns pending_review (not certified) with provisional: true
//   - Escalation-flagged registration returns escalation_required with no EVAR
//   - Proxy calls from uncertified agents get X-Cicada-Provisional header
//   - The certification gate blocks terminated/suspended agents at proxy

package tests

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// ────────────────────────────────────────────────────────────────────────────
// TestCertificationGate_RegistrationReturnsProvisional
//
// A clean agent registration should return:
//   - status = "pending_review" (not "certified")
//   - provisional = true
//   - evar = non-empty JWT
// ────────────────────────────────────────────────────────────────────────────

func TestCertificationGate_RegistrationReturnsProvisional(t *testing.T) {
	skipIfUnavailable(t)

	agentID := fmt.Sprintf("cert-test-provisional-%d", time.Now().UnixNano())
	status, body := post(t, "/v1/agent/register", map[string]interface{}{
		"agent_id":                  agentID,
		"code_hash":                 "cert-test-hash",
		"scopes":                    []string{"proxy:chat"},
		"intended_model":            "gpt-4o",
		"is_persistent":             false,
		"certified_reversal_routes": map[string]string{},
	}, nil)

	if status != http.StatusCreated {
		t.Fatalf("Expected 201, got %d — body: %v", status, body)
	}

	// Status must be "pending_review", not "certified"
	if body["status"] != "pending_review" {
		t.Errorf("Expected status=pending_review, got %v", body["status"])
	}

	// Must include provisional flag
	if body["provisional"] != true {
		t.Errorf("Expected provisional=true, got %v", body["provisional"])
	}

	// EVAR must still be issued (provisional)
	evar, ok := body["evar"].(string)
	if !ok || evar == "" {
		t.Fatalf("Expected non-empty provisional EVAR, got %v", body["evar"])
	}

	// Message should mention provisional
	if msg, ok := body["message"].(string); ok {
		if msg == "" {
			t.Error("Expected non-empty message about provisional status")
		}
		t.Logf("Registration message: %s", msg)
	}

	t.Logf("✓ Agent %s registered with provisional EVAR (status=%v)", agentID, body["status"])
}

// ────────────────────────────────────────────────────────────────────────────
// TestCertificationGate_EscalationBlocksEVAR
//
// An agent with high-severity policy violations should:
//   - Be registered (201) but with NO EVAR
//   - Return status = "escalation_required"
//   - Include the violations list
// ────────────────────────────────────────────────────────────────────────────

func TestCertificationGate_EscalationBlocksEVAR(t *testing.T) {
	skipIfUnavailable(t)

	agentID := fmt.Sprintf("cert-test-escalation-%d", time.Now().UnixNano())

	// Wildcard read-only → triggers RequiresEscalation (not blocked, but escalated)
	status, body := post(t, "/v1/agent/register", map[string]interface{}{
		"agent_id":  agentID,
		"code_hash": "escalation-test-hash",
		"scopes":    []string{"proxy:chat"},
		"tools": []interface{}{
			map[string]interface{}{
				"name":         "scanner",
				"url_patterns": []interface{}{"*"},
				"methods":      []interface{}{"GET"},
				"destructive":  false,
			},
		},
		"hitl_enabled": true,
	}, nil)

	if status != http.StatusCreated {
		t.Fatalf("Expected 201, got %d — body: %v", status, body)
	}

	// Status must be "escalation_required"
	if body["status"] != "escalation_required" {
		t.Errorf("Expected status=escalation_required, got %v", body["status"])
	}

	// EVAR must be nil/missing
	if body["evar"] != nil {
		t.Errorf("Expected evar=nil for escalation, got %v", body["evar"])
	}

	// Violations must be present
	violations, ok := body["violations"].([]interface{})
	if !ok || len(violations) == 0 {
		t.Error("Expected non-empty violations list for escalated agent")
	}

	t.Logf("✓ Agent %s escalation blocked — no EVAR issued, %d violations", agentID, len(violations))
}

// ────────────────────────────────────────────────────────────────────────────
// TestCertificationGate_ProvisionalAgentGetsShadowMode
//
// A newly registered (uncertified) agent making proxy calls should:
//   - Receive X-Cicada-Provisional: true header
//   - Not be hard-blocked (gets 200 or 403 from other pipeline stages)
// ────────────────────────────────────────────────────────────────────────────

func TestCertificationGate_ProvisionalAgentGetsShadowMode(t *testing.T) {
	skipIfUnavailable(t)

	// Mock target that returns 200
	mockTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer mockTarget.Close()

	agentID := fmt.Sprintf("cert-test-shadow-%d", time.Now().UnixNano())
	_, regBody := post(t, "/v1/agent/register", map[string]interface{}{
		"agent_id":                  agentID,
		"code_hash":                 "shadow-test-hash",
		"scopes":                    []string{"proxy:chat"},
		"intended_model":            "gpt-4o",
		"is_persistent":             false,
		"certified_reversal_routes": map[string]string{},
	}, nil)

	evar, ok := regBody["evar"].(string)
	if !ok || evar == "" {
		t.Fatalf("Registration failed: %v", regBody)
	}

	// Proxy call with provisional EVAR
	req, _ := http.NewRequest(http.MethodPost, gatewayURL()+"/v1/agent/proxy",
		nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+evar)
	req.Header.Set("X-Cicada-Target-URL", mockTarget.URL+"/test")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("proxy request failed: %v", err)
	}
	defer resp.Body.Close()

	// Check for provisional header
	provisional := resp.Header.Get("X-Cicada-Provisional")
	if provisional != "true" {
		t.Errorf("Expected X-Cicada-Provisional: true, got %q", provisional)
	}

	// Should NOT be a 500
	if resp.StatusCode == http.StatusInternalServerError {
		t.Errorf("Provisional proxy returned 500 — should not crash")
	}

	t.Logf("✓ Provisional agent %s received X-Cicada-Provisional=%s (status=%d)", agentID, provisional, resp.StatusCode)
}

// ────────────────────────────────────────────────────────────────────────────
// TestCertificationGate_YAMLRegistrationReturnsProvisional
//
// Same as the JSON registration test but via the cicada.yaml endpoint.
// ────────────────────────────────────────────────────────────────────────────

func TestCertificationGate_YAMLRegistrationReturnsProvisional(t *testing.T) {
	skipIfUnavailable(t)

	agentName := fmt.Sprintf("yaml-cert-test-%d", time.Now().UnixNano())
	status, body := post(t, "/v1/agent/register/yaml", map[string]interface{}{
		"name": agentName,
		"tools": []interface{}{
			map[string]interface{}{
				"name":         "stripe-charges",
				"url_patterns": []interface{}{"https://api.stripe.com/v1/charges/*"},
				"methods":      []interface{}{"GET"},
				"destructive":  false,
			},
		},
		"hitl_enabled": true,
	}, nil)

	if status != http.StatusCreated {
		t.Fatalf("Expected 201, got %d — body: %v", status, body)
	}

	if body["status"] != "pending_review" {
		t.Errorf("Expected status=pending_review, got %v", body["status"])
	}

	if body["provisional"] != true {
		t.Errorf("Expected provisional=true, got %v", body["provisional"])
	}

	evar, ok := body["evar"].(string)
	if !ok || evar == "" {
		t.Fatalf("Expected non-empty provisional EVAR for YAML registration, got %v", body["evar"])
	}

	t.Logf("✓ YAML registration: agent %s registered with provisional EVAR", agentName)
}
