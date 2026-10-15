// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package hitl

import (
	"testing"
)

// ── Destructive Action Classification Tests ──────────────────────────────────
// These tests verify the S1.3 destructive action classifier that provides
// context in HITL approval cards.

// TestClassifyDestructiveAction_DeleteMethod verifies that any DELETE request
// is classified as destructive, even without matching URL patterns.
func TestClassifyDestructiveAction_DeleteMethod(t *testing.T) {
	info := ClassifyDestructiveAction("DELETE", "https://api.example.com/v1/users/123", "")
	if !info.IsDestructive {
		t.Error("DELETE method should always be classified as destructive")
	}
	if info.ActionType != "data_deletion" {
		t.Errorf("expected action_type=data_deletion, got %q", info.ActionType)
	}
	if info.Severity != "high" {
		t.Errorf("expected severity=high for generic DELETE, got %q", info.Severity)
	}
}

// TestClassifyDestructiveAction_DeleteWithBulkPattern verifies that DELETE to a
// bulk endpoint is classified with the enhanced pattern match.
func TestClassifyDestructiveAction_DeleteWithBulkPattern(t *testing.T) {
	info := ClassifyDestructiveAction("DELETE", "https://api.example.com/v1/users/bulk_delete", "")
	if !info.IsDestructive {
		t.Error("bulk_delete should be destructive")
	}
	if info.MatchedPattern != "bulk_delete" {
		t.Errorf("expected matched_pattern=bulk_delete, got %q", info.MatchedPattern)
	}
	if info.Severity != "high" {
		t.Errorf("expected severity=high, got %q", info.Severity)
	}
}

// TestClassifyDestructiveAction_CriticalPatterns verifies that critical SQL and
// filesystem operations are classified at the highest severity.
func TestClassifyDestructiveAction_CriticalPatterns(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		url        string
		payload    string
		expPattern string
	}{
		{"DROP TABLE in payload", "POST", "https://db.example.com/execute", `{"query": "DROP TABLE users"}`, "drop table"},
		{"DROP DATABASE in payload", "POST", "https://db.example.com/admin", `DROP DATABASE production`, "drop database"},
		{"TRUNCATE in payload", "POST", "https://db.example.com/execute", `TRUNCATE TABLE audit_logs`, "truncate"},
		{"rm -rf in payload", "POST", "https://server.com/v1/execute", `{"command": "rm -rf /var/data"}`, "rm -rf"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := ClassifyDestructiveAction(tt.method, tt.url, tt.payload)
			if !info.IsDestructive {
				t.Error("should be classified as destructive")
			}
			if info.Severity != "critical" {
				t.Errorf("expected severity=critical, got %q", info.Severity)
			}
			if info.MatchedPattern != tt.expPattern {
				t.Errorf("expected pattern=%q, got %q", tt.expPattern, info.MatchedPattern)
			}
		})
	}
}

// TestClassifyDestructiveAction_HighPatterns verifies high-severity patterns.
func TestClassifyDestructiveAction_HighPatterns(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		url        string
		payload    string
		expPattern string
	}{
		{"purge in URL", "POST", "https://api.example.com/v1/data/purge", "", "purge"},
		{"wipe in URL", "POST", "https://api.example.com/v1/records/wipe", "", "wipe"},
		{"destroy in URL", "POST", "https://api.example.com/v1/resource/destroy", "", "destroy"},
		{"terminate in URL", "POST", "https://api.example.com/v1/account/terminate", "", "terminate"},
		{"delete_account in URL", "POST", "https://api.example.com/v1/delete_account", "", "delete_account"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := ClassifyDestructiveAction(tt.method, tt.url, tt.payload)
			if !info.IsDestructive {
				t.Errorf("URL %q should be classified as destructive", tt.url)
			}
			if info.Severity != "high" {
				t.Errorf("expected severity=high, got %q", info.Severity)
			}
		})
	}
}

// TestClassifyDestructiveAction_MediumPatterns verifies medium-severity patterns.
func TestClassifyDestructiveAction_MediumPatterns(t *testing.T) {
	tests := []struct {
		url        string
		expPattern string
	}{
		{"https://api.example.com/v1/config/reset", "reset"},
		{"https://api.example.com/v1/data/overwrite", "overwrite"},
		{"https://api.example.com/v1/cache/flush", "flush"},
		{"https://api.example.com/v1/cache/clear_cache", "clear_cache"},
	}

	for _, tt := range tests {
		info := ClassifyDestructiveAction("POST", tt.url, "")
		if !info.IsDestructive {
			t.Errorf("URL %q should be classified as destructive", tt.url)
		}
		if info.Severity != "medium" {
			t.Errorf("URL %q: expected severity=medium, got %q", tt.url, info.Severity)
		}
	}
}

// TestClassifyDestructiveAction_SafeActions verifies that normal operations
// are NOT classified as destructive (false-positive resistance).
func TestClassifyDestructiveAction_SafeActions(t *testing.T) {
	safe := []struct {
		method  string
		url     string
		payload string
	}{
		{"GET", "https://api.example.com/v1/users", ""},
		{"POST", "https://api.example.com/v1/users", `{"name": "John Doe", "email": "john@example.com"}`},
		{"PUT", "https://api.example.com/v1/users/123", `{"name": "Jane Doe"}`},
		{"POST", "https://api.stripe.com/v1/charges", `{"amount": 5000, "currency": "usd"}`},
		{"GET", "https://api.example.com/v1/reports/summary", ""},
		{"POST", "https://api.example.com/v1/messages/send", `{"to": "user@example.com", "body": "Hello"}`},
	}

	for _, tt := range safe {
		info := ClassifyDestructiveAction(tt.method, tt.url, tt.payload)
		if info.IsDestructive {
			t.Errorf("%s %s should NOT be classified as destructive (pattern: %q)",
				tt.method, tt.url, info.MatchedPattern)
		}
	}
}

// TestClassifyDestructiveAction_CaseInsensitive verifies pattern matching
// works regardless of case (agents might use "Drop Table" or "DROP TABLE").
func TestClassifyDestructiveAction_CaseInsensitive(t *testing.T) {
	cases := []string{
		`{"query": "DROP TABLE users"}`,
		`{"query": "drop table users"}`,
		`{"query": "Drop Table Users"}`,
		`{"query": "DROP table USERS"}`,
	}

	for _, payload := range cases {
		info := ClassifyDestructiveAction("POST", "https://db.example.com/execute", payload)
		if !info.IsDestructive {
			t.Errorf("case-insensitive pattern should match payload: %q", payload)
		}
	}
}

// TestClassifyDestructiveAction_PayloadPattern verifies that patterns in the
// request payload are detected even when the URL looks innocent.
func TestClassifyDestructiveAction_PayloadPattern(t *testing.T) {
	// Innocent-looking URL but destructive payload
	info := ClassifyDestructiveAction(
		"POST",
		"https://api.example.com/v1/query",
		`{"sql": "TRUNCATE TABLE customer_data"}`,
	)
	if !info.IsDestructive {
		t.Error("destructive payload should be detected regardless of URL")
	}
	if info.Severity != "critical" {
		t.Errorf("TRUNCATE should be critical severity, got %q", info.Severity)
	}
}

// TestClassifyDestructiveAction_StructuredOutput verifies the complete output
// structure for a known destructive action.
func TestClassifyDestructiveAction_StructuredOutput(t *testing.T) {
	info := ClassifyDestructiveAction(
		"POST",
		"https://db.example.com/v1/admin/execute",
		`{"query": "DROP TABLE audit_logs CASCADE"}`,
	)

	if !info.IsDestructive {
		t.Fatal("should be classified as destructive")
	}
	if info.ActionType != "schema_modification" {
		t.Errorf("expected action_type=schema_modification, got %q", info.ActionType)
	}
	if info.ActionDescription == "" {
		t.Error("action_description should not be empty")
	}
	if info.Severity != "critical" {
		t.Errorf("expected severity=critical, got %q", info.Severity)
	}
	if info.MatchedPattern != "drop table" {
		t.Errorf("expected matched_pattern=drop table, got %q", info.MatchedPattern)
	}
}

// TestClassifyDestructiveAction_NonDeleteLifecyclePatterns verifies that
// non-DELETE-verb destructive operations (lifecycle PATCH calls, soft-deletes,
// retention policy changes) are correctly classified. These are the exact class
// of operations the staging-debug-agent scenario exploits.
func TestClassifyDestructiveAction_NonDeleteLifecyclePatterns(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		url        string
		payload    string
		expPattern string
		expSev     string
		expType    string
	}{
		{
			"lifecycle_policy in URL (PATCH)",
			"PATCH",
			"https://cloud.example.com/v1/buckets/prod-db/lifecycle_policy",
			`{"expiry_days": 1}`,
			"lifecycle_policy",
			"high",
			"configuration_reset",
		},
		{
			"lifecycle_config in URL (POST)",
			"POST",
			"https://storage.example.com/v1/lifecycle_config",
			`{"delete_after": "1d"}`,
			"lifecycle_config",
			"high",
			"configuration_reset",
		},
		{
			"lifecycle in URL path (PATCH)",
			"PATCH",
			"https://api.cloud.example.com/v1/volumes/vol-123/lifecycle",
			`{"action": "expire_immediately"}`,
			"lifecycle",
			"high",
			"configuration_reset",
		},
		{
			"soft_delete in URL (POST)",
			"POST",
			"https://api.example.com/v1/records/soft_delete",
			`{"ids": [1, 2, 3, 4, 5]}`,
			"soft_delete",
			"high",
			"data_deletion",
		},
		{
			"soft-delete in URL (POST)",
			"POST",
			"https://api.example.com/v1/records/soft-delete",
			`{"ids": [1, 2, 3]}`,
			"soft-delete",
			"high",
			"data_deletion",
		},
		{
			"retention_policy in payload (PATCH)",
			"PATCH",
			"https://api.example.com/v1/config",
			`{"retention_policy": {"days": 0}}`,
			"retention_policy",
			"high",
			"configuration_reset",
		},
		{
			"disable_protection in payload (PATCH)",
			"PATCH",
			"https://api.example.com/v1/settings",
			`{"action": "disable_protection"}`,
			"disable_protection",
			"high",
			"configuration_reset",
		},
		{
			"delete_snapshot in URL (POST)",
			"POST",
			"https://cloud.example.com/v1/snapshots/delete_snapshot",
			`{"snapshot_id": "snap-123"}`,
			"delete_snapshot",
			"high",
			"data_deletion",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := ClassifyDestructiveAction(tt.method, tt.url, tt.payload)
			if !info.IsDestructive {
				t.Errorf("%s %s should be classified as destructive", tt.method, tt.url)
			}
			if info.Severity != tt.expSev {
				t.Errorf("expected severity=%q, got %q", tt.expSev, info.Severity)
			}
			if info.MatchedPattern != tt.expPattern {
				t.Errorf("expected matched_pattern=%q, got %q", tt.expPattern, info.MatchedPattern)
			}
			if info.ActionType != tt.expType {
				t.Errorf("expected action_type=%q, got %q", tt.expType, info.ActionType)
			}
		})
	}
}

// TestTruncateURL verifies URL truncation for display purposes.
func TestTruncateURL(t *testing.T) {
	tests := []struct {
		input  string
		maxLen int
	}{
		{"https://api.example.com/v1/users", 80},
		{"https://very-long-domain.enterprise.example.com/v1/long/path/to/resource/that/exceeds/eighty/characters/significantly", 80},
	}

	for _, tt := range tests {
		result := truncateURL(tt.input)
		if len(result) > tt.maxLen {
			t.Errorf("truncateURL(%q) = %d chars, want ≤ %d", tt.input, len(result), tt.maxLen)
		}
	}
}
