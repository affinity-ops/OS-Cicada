// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"testing"
)

// ── SanitizePolicy Tests ────────────────────────────────────────

func TestSanitize_CleanPolicy(t *testing.T) {
	reg := map[string]interface{}{
		"tools": []interface{}{
			map[string]interface{}{
				"name":         "stripe-charges",
				"url_patterns": []interface{}{"https://api.stripe.com/v1/charges/*"},
				"methods":      []interface{}{"GET", "POST"},
				"destructive":  false,
			},
		},
		"hitl_enabled":           true,
		"destructive_capability": false,
	}

	result := SanitizePolicy(reg)
	if !result.Allowed {
		t.Errorf("clean policy should be allowed, got violations: %+v", result.Violations)
	}
	if result.RequiresEscalation {
		t.Error("clean policy should not require escalation")
	}
}

func TestSanitize_WildcardDestructive_Rejected(t *testing.T) {
	reg := map[string]interface{}{
		"tools": []interface{}{
			map[string]interface{}{
				"name":         "super-tool",
				"url_patterns": []interface{}{"*"},
				"methods":      []interface{}{"DELETE"},
				"destructive":  true,
			},
		},
		"hitl_enabled": true,
	}

	result := SanitizePolicy(reg)
	if result.Allowed {
		t.Error("wildcard destructive tool should be rejected")
	}
	assertViolationCode(t, result, "WILDCARD_DESTRUCTIVE")
}

func TestSanitize_WildcardReadOnly_Escalated(t *testing.T) {
	reg := map[string]interface{}{
		"tools": []interface{}{
			map[string]interface{}{
				"name":         "scanner",
				"url_patterns": []interface{}{"*"},
				"methods":      []interface{}{"GET"},
				"destructive":  false,
			},
		},
		"hitl_enabled": true,
	}

	result := SanitizePolicy(reg)
	if !result.Allowed {
		t.Error("wildcard read-only should still be allowed (just escalated)")
	}
	if !result.RequiresEscalation {
		t.Error("wildcard read-only should require escalation")
	}
	assertViolationCode(t, result, "WILDCARD_BROAD")
}

func TestSanitize_HttpsWildcard_Rejected(t *testing.T) {
	reg := map[string]interface{}{
		"tools": []interface{}{
			map[string]interface{}{
				"name":         "nuke-tool",
				"url_patterns": []interface{}{"https://*"},
				"methods":      []interface{}{"POST", "DELETE"},
				"destructive":  true,
			},
		},
	}

	result := SanitizePolicy(reg)
	if result.Allowed {
		t.Error("https://* with destructive should be rejected")
	}
}

func TestSanitize_DestructiveNoHITL_Rejected(t *testing.T) {
	reg := map[string]interface{}{
		"tools": []interface{}{
			map[string]interface{}{
				"name":         "safe-tool",
				"url_patterns": []interface{}{"https://api.example.com/*"},
				"methods":      []interface{}{"GET"},
			},
		},
		"destructive_capability": true,
		"hitl_enabled":           false,
	}

	result := SanitizePolicy(reg)
	if result.Allowed {
		t.Error("destructive without HITL should be rejected")
	}
	assertViolationCode(t, result, "DESTRUCTIVE_NO_HITL")
}

func TestSanitize_DestructiveWithHITL_Allowed(t *testing.T) {
	reg := map[string]interface{}{
		"tools": []interface{}{
			map[string]interface{}{
				"name":         "db-tool",
				"url_patterns": []interface{}{"https://api.internal.com/v1/db/*"},
				"methods":      []interface{}{"POST", "DELETE"},
				"destructive":  true,
			},
		},
		"destructive_capability": true,
		"hitl_enabled":           true,
	}

	result := SanitizePolicy(reg)
	if !result.Allowed {
		t.Errorf("destructive with HITL should be allowed, violations: %+v", result.Violations)
	}
}

func TestSanitize_HighCriticalityNoHITL_Escalated(t *testing.T) {
	reg := map[string]interface{}{
		"identity": map[string]interface{}{
			"name":        "critical-agent",
			"criticality": "critical",
		},
		"tools":       []interface{}{},
		"hitl_enabled": false,
	}

	result := SanitizePolicy(reg)
	if !result.RequiresEscalation {
		t.Error("critical criticality without HITL should require escalation")
	}
	assertViolationCode(t, result, "HIGH_CRIT_NO_HITL")
}

func TestSanitize_HighEntropyScope_Critical(t *testing.T) {
	reg := map[string]interface{}{
		"tools": []interface{}{
			map[string]interface{}{
				"name":        "danger-tool",
				"url_patterns": []interface{}{"https://api.example.com/*"},
				"methods":     []interface{}{"DELETE"},
				"destructive": true,
				"scopes":      []interface{}{"unlimited"},
			},
		},
		"hitl_enabled": true,
	}

	result := SanitizePolicy(reg)
	if result.Allowed {
		t.Error("unlimited scope on destructive tool should be rejected")
	}
	assertViolationCode(t, result, "HIGH_ENTROPY_SCOPE")
}

func TestSanitize_HighEntropyScope_ReadOnly_Escalated(t *testing.T) {
	reg := map[string]interface{}{
		"tools": []interface{}{
			map[string]interface{}{
				"name":        "reader",
				"url_patterns": []interface{}{"https://api.example.com/*"},
				"methods":     []interface{}{"GET"},
				"destructive": false,
				"scopes":      []interface{}{"grant_all"},
			},
		},
		"hitl_enabled": true,
	}

	result := SanitizePolicy(reg)
	if !result.RequiresEscalation {
		t.Error("grant_all scope on read tool should require escalation")
	}
}

func TestSanitize_UnlimitedVelocity_Escalated(t *testing.T) {
	reg := map[string]interface{}{
		"tools":       []interface{}{},
		"hitl_enabled": true,
		"velocity_config": map[string]interface{}{
			"max_reads_per_minute":  float64(50000),
			"max_writes_per_minute": float64(10000),
		},
	}

	result := SanitizePolicy(reg)
	if !result.RequiresEscalation {
		t.Error("unlimited velocity should require escalation")
	}
	assertViolationCode(t, result, "UNLIMITED_VELOCITY")
}

func TestSanitize_MultipleViolations(t *testing.T) {
	reg := map[string]interface{}{
		"tools": []interface{}{
			map[string]interface{}{
				"name":         "nuke",
				"url_patterns": []interface{}{"*"},
				"methods":      []interface{}{"DELETE"},
				"destructive":  true,
				"scopes":       []interface{}{"unlimited"},
			},
		},
		"destructive_capability": true,
		"hitl_enabled":           false,
		"velocity_config": map[string]interface{}{
			"max_writes_per_minute": float64(99999),
		},
	}

	result := SanitizePolicy(reg)
	if result.Allowed {
		t.Error("multiple critical violations should block")
	}
	if len(result.Violations) < 3 {
		t.Errorf("expected 3+ violations, got %d: %+v", len(result.Violations), result.Violations)
	}
}

func TestSanitize_EmptyPolicy(t *testing.T) {
	result := SanitizePolicy(map[string]interface{}{})
	if !result.Allowed {
		t.Error("empty policy should be allowed (no tools = no risk)")
	}
}

func TestSanitize_HighEntropy_GodMode(t *testing.T) {
	reg := map[string]interface{}{
		"tools": []interface{}{
			map[string]interface{}{
				"name":        "god_mode_tool",
				"url_patterns": []interface{}{"https://api.example.com/*"},
				"methods":     []interface{}{"GET"},
				"destructive": true,
			},
		},
		"hitl_enabled": true,
	}

	result := SanitizePolicy(reg)
	assertViolationCode(t, result, "HIGH_ENTROPY_KEYWORD")
}

func TestSanitize_MethodDetection_PostIsDestructive(t *testing.T) {
	reg := map[string]interface{}{
		"tools": []interface{}{
			map[string]interface{}{
				"name":         "poster",
				"url_patterns": []interface{}{"https://*"},
				"methods":      []interface{}{"POST"},
			},
		},
	}

	result := SanitizePolicy(reg)
	// POST to https://* should be treated as destructive wildcard
	assertViolationCode(t, result, "WILDCARD_DESTRUCTIVE")
}

// ── Rule 5: Wildcard + Non-Destructive Contradiction ────────────

// TestSanitize_WildcardNonDestructive_Rejected verifies that an agent declaring
// destructive_capability=false with wildcard URL patterns is blocked. This is the
// exact staging-debug-agent scenario: the developer thinks the agent is safe
// because destructive_capability=false, but grants it the same wildcard IAM role
// the human DevOps team uses.
func TestSanitize_WildcardNonDestructive_Rejected(t *testing.T) {
	reg := map[string]interface{}{
		"tools": []interface{}{
			map[string]interface{}{
				"name":         "staging-debug-tool",
				"url_patterns": []interface{}{"https://*"},
				"methods":      []interface{}{"GET", "POST"},
				"destructive":  false,
			},
		},
		"destructive_capability": false,
		"hitl_enabled":           false,
	}

	result := SanitizePolicy(reg)
	if result.Allowed {
		t.Error("wildcard URL with destructive_capability=false should be rejected")
	}
	assertViolationCode(t, result, "WILDCARD_NON_DESTRUCTIVE_CONTRADICTION")
}

// TestSanitize_HighEntropyScopeNonDestructive_Rejected verifies that an agent
// declaring destructive_capability=false with high-entropy scopes is blocked.
func TestSanitize_HighEntropyScopeNonDestructive_Rejected(t *testing.T) {
	reg := map[string]interface{}{
		"tools": []interface{}{
			map[string]interface{}{
				"name":         "cloud-debug-tool",
				"url_patterns": []interface{}{"https://cloud.example.com/api/*"},
				"methods":      []interface{}{"GET"},
				"destructive":  false,
				"scopes":       []interface{}{"admin"},
			},
		},
		"destructive_capability": false,
		"hitl_enabled":           true,
	}

	result := SanitizePolicy(reg)
	if result.Allowed {
		t.Error("high-entropy scope with destructive_capability=false should be rejected")
	}
	assertViolationCode(t, result, "WILDCARD_NON_DESTRUCTIVE_CONTRADICTION")
}

// TestSanitize_NarrowNonDestructive_Allowed verifies that a properly scoped
// non-destructive agent passes sanitization without contradiction violations.
func TestSanitize_NarrowNonDestructive_Allowed(t *testing.T) {
	reg := map[string]interface{}{
		"tools": []interface{}{
			map[string]interface{}{
				"name":         "staging-reader",
				"url_patterns": []interface{}{"https://staging.internal.com/v1/connectivity/*"},
				"methods":      []interface{}{"GET"},
				"destructive":  false,
				"scopes":       []interface{}{"read:staging"},
			},
		},
		"destructive_capability": false,
		"hitl_enabled":           false,
	}

	result := SanitizePolicy(reg)
	if !result.Allowed {
		t.Errorf("narrowly-scoped non-destructive agent should be allowed, got violations: %+v", result.Violations)
	}
	// Ensure no contradiction violations exist
	for _, v := range result.Violations {
		if v.Code == "WILDCARD_NON_DESTRUCTIVE_CONTRADICTION" {
			t.Errorf("narrowly-scoped agent should not trigger contradiction: %s", v.Message)
		}
	}
}

// ── Helpers ──────────────────────────────────────────────────────

func assertViolationCode(t *testing.T, result SanitizeResult, code string) {
	t.Helper()
	for _, v := range result.Violations {
		if v.Code == code {
			return
		}
	}
	t.Errorf("expected violation code %s, violations: %+v", code, result.Violations)
}
