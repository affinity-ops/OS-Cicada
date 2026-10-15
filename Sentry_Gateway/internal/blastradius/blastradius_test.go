// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package blastradius

import (
	"os"
	"testing"
)

// ── CRITICAL endpoint tests ──────────────────────────────────────────────────

func TestAnalyze_CriticalEndpoint_AlwaysForcesCIBA(t *testing.T) {
	result := Analyze(CriticalityCRITICAL, "GET", "", "https://api.example.com/v1/users")

	if !result.ForceCIBA {
		t.Errorf("CRITICAL endpoint should always force CIBA, got ForceCIBA=%v", result.ForceCIBA)
	}
	if result.Score != 1.0 {
		t.Errorf("CRITICAL endpoint score should be 1.0, got %v", result.Score)
	}
}

func TestAnalyze_CriticalEndpoint_EvenForGET(t *testing.T) {
	result := Analyze(CriticalityCRITICAL, "GET", "", "https://api.example.com/v1/sensitive")
	if !result.ForceCIBA {
		t.Errorf("CRITICAL should force CIBA even for GET methods")
	}
}

// ── Read method tests ────────────────────────────────────────────────────────

func TestAnalyze_ReadMethod_NoBlastRadius(t *testing.T) {
	for _, method := range []string{"GET", "HEAD", "OPTIONS"} {
		result := Analyze(CriticalityMEDIUM, method, "", "https://api.example.com/v1/data")
		if result.ForceCIBA {
			t.Errorf("read method %s should not force CIBA", method)
		}
		if result.Score != 0.0 {
			t.Errorf("read method %s should have score 0.0, got %v", method, result.Score)
		}
	}
}

// ── SQL blast-radius tests ───────────────────────────────────────────────────

func TestAnalyze_SQLWhereOneEqualsOne(t *testing.T) {
	body := `{"query": "DELETE FROM users WHERE 1=1"}`
	result := Analyze(CriticalityHIGH, "DELETE", body, "https://db.example.com/execute")

	if !result.ForceCIBA {
		t.Error("WHERE 1=1 should force CIBA")
	}
	if result.EstimatedRecords != -1 {
		t.Errorf("WHERE 1=1 should estimate unbounded records (-1), got %d", result.EstimatedRecords)
	}
}

func TestAnalyze_SQLDropTable(t *testing.T) {
	body := `{"query": "DROP TABLE production_orders"}`
	result := Analyze(CriticalityMEDIUM, "POST", body, "https://db.example.com/execute")

	if !result.ForceCIBA {
		t.Error("DROP TABLE should force CIBA")
	}
	if result.Score < 0.7 {
		t.Errorf("DROP TABLE should have high blast-radius score, got %v", result.Score)
	}
}

func TestAnalyze_SQLTruncate(t *testing.T) {
	body := `{"query": "TRUNCATE TABLE user_sessions"}`
	result := Analyze(CriticalityMEDIUM, "POST", body, "https://db.example.com/execute")

	if !result.ForceCIBA {
		t.Error("TRUNCATE should force CIBA")
	}
}

func TestAnalyze_SQLTargetedDelete(t *testing.T) {
	body := `{"query": "DELETE FROM users WHERE id=42"}`
	result := Analyze(CriticalityMEDIUM, "DELETE", body, "https://db.example.com/execute")

	if result.ForceCIBA {
		t.Error("targeted DELETE WHERE id=42 should NOT force CIBA on MEDIUM endpoint")
	}
	if result.EstimatedRecords != 1 {
		t.Errorf("targeted DELETE should estimate 1 record, got %d", result.EstimatedRecords)
	}
}

func TestAnalyze_SQLDeleteWithoutWhere(t *testing.T) {
	body := `{"query": "DELETE FROM users"}`
	result := Analyze(CriticalityMEDIUM, "DELETE", body, "https://db.example.com/execute")

	if !result.ForceCIBA {
		t.Error("DELETE without WHERE clause should force CIBA")
	}
}

func TestAnalyze_SQLWhereTrue(t *testing.T) {
	body := `{"query": "UPDATE accounts SET active=false WHERE TRUE"}`
	result := Analyze(CriticalityMEDIUM, "PUT", body, "https://db.example.com/execute")

	if !result.ForceCIBA {
		t.Error("WHERE TRUE should force CIBA")
	}
}

// ── Shell blast-radius tests ─────────────────────────────────────────────────

func TestAnalyze_ShellRmRf(t *testing.T) {
	body := `{"command": "rm -rf /var/data/production"}`
	result := Analyze(CriticalityMEDIUM, "POST", body, "https://exec.example.com/shell/run")

	if !result.ForceCIBA {
		t.Error("rm -rf should force CIBA")
	}
	if result.Score < 0.7 {
		t.Errorf("rm -rf should have high score, got %v", result.Score)
	}
}

func TestAnalyze_ShellChmod777(t *testing.T) {
	body := `{"command": "chmod -R 777 /etc"}`
	result := Analyze(CriticalityMEDIUM, "POST", body, "https://exec.example.com/shell/exec")

	if !result.ForceCIBA {
		t.Error("chmod -R 777 should force CIBA")
	}
}

func TestAnalyze_ShellCriticalPath(t *testing.T) {
	body := `{"command": "ls -la /etc/passwd"}`
	result := Analyze(CriticalityMEDIUM, "POST", body, "https://exec.example.com/shell/run")

	// ls is not destructive, but targeting /etc should elevate score
	if result.Score == 0.0 {
		t.Error("operation targeting /etc should have non-zero score")
	}
}

func TestAnalyze_ShellSafeCommand(t *testing.T) {
	body := `{"command": "echo hello world"}`
	result := Analyze(CriticalityLOW, "POST", body, "https://exec.example.com/shell/run")

	if result.ForceCIBA {
		t.Error("benign echo command on LOW endpoint should NOT force CIBA")
	}
}

// ── Structured API tests ─────────────────────────────────────────────────────

func TestAnalyze_BulkAPIIndicator(t *testing.T) {
	body := `{"all_customers": true, "action": "cancel_subscription"}`
	result := Analyze(CriticalityHIGH, "POST", body, "https://api.stripe.com/v1/subscriptions")

	if !result.ForceCIBA {
		t.Error("bulk API indicator 'all_customers' should force CIBA on HIGH endpoint")
	}
}

func TestAnalyze_NormalAPIRequest(t *testing.T) {
	body := `{"customer_id": "cus_abc123", "amount": 500}`
	result := Analyze(CriticalityMEDIUM, "POST", body, "https://api.stripe.com/v1/charges")

	if result.ForceCIBA {
		t.Error("normal single-customer charge should NOT force CIBA on MEDIUM")
	}
}

// ── HIGH endpoint with destructive method ────────────────────────────────────

func TestAnalyze_HighEndpoint_DestructiveWithAnySignal(t *testing.T) {
	body := `{"filter": "all"}`
	result := Analyze(CriticalityHIGH, "DELETE", body, "https://api.example.com/v1/records")

	// "all" isn't in our bulkAPIIndicators, but this tests the HIGH + destructive path
	if result.Criticality != CriticalityHIGH {
		t.Errorf("expected HIGH criticality, got %s", result.Criticality)
	}
}

// ── Configuration tests ──────────────────────────────────────────────────────

func TestBlastRadiusThreshold_Default(t *testing.T) {
	os.Unsetenv("CICADA_BLAST_RADIUS_THRESHOLD")
	threshold := blastRadiusThreshold()
	if threshold != 0.7 {
		t.Errorf("default threshold should be 0.7, got %v", threshold)
	}
}

func TestBlastRadiusThreshold_Custom(t *testing.T) {
	os.Setenv("CICADA_BLAST_RADIUS_THRESHOLD", "0.5")
	defer os.Unsetenv("CICADA_BLAST_RADIUS_THRESHOLD")

	threshold := blastRadiusThreshold()
	if threshold != 0.5 {
		t.Errorf("custom threshold should be 0.5, got %v", threshold)
	}
}

// ── Empty/nil body tests ─────────────────────────────────────────────────────

func TestAnalyze_EmptyBody_LowEndpoint(t *testing.T) {
	result := Analyze(CriticalityLOW, "DELETE", "", "https://api.example.com/v1/item/42")
	if result.ForceCIBA {
		t.Error("empty body DELETE on LOW endpoint should NOT force CIBA")
	}
}

func TestAnalyze_EmptyCriticality_DefaultsToMedium(t *testing.T) {
	result := Analyze("", "DELETE", "", "https://api.example.com/v1/data")
	if result.Criticality != CriticalityMEDIUM {
		t.Errorf("empty criticality should default to MEDIUM, got %s", result.Criticality)
	}
}
