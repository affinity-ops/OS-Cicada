// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"os"
	"testing"
)

// setTempLedgerPath uses a temp file for the test ledger so we don't
// pollute the real edge database.
func setTempLedgerPath(t *testing.T) {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "test_ledger_*.db")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	os.Setenv("CICADA_LEDGER_PATH", f.Name())
	t.Cleanup(func() { os.Unsetenv("CICADA_LEDGER_PATH") })
}

func TestNewEdgeLedger_Initialises(t *testing.T) {
	setTempLedgerPath(t)

	ledger, err := NewEdgeLedger(nil)
	if err != nil {
		t.Fatalf("NewEdgeLedger failed: %v", err)
	}
	defer ledger.Close()

	// Should start with the genesis hash
	if ledger.latestHash != "genesis_000000000000000000000000000000" {
		t.Errorf("expected genesis hash, got %s", ledger.latestHash)
	}
}

func TestEdgeLedger_AppendRecord(t *testing.T) {
	setTempLedgerPath(t)

	ledger, err := NewEdgeLedger(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()

	record := EventRecord{
		EventID:     "evt-001",
		TraceID:     "trace-001",
		TenantID:    "tenant-001",
		AgentID:     "agent-001",
		Decision:    "allow",
		ActionClass: "llm_proxy",
		ReasonCodes: []string{"within_policy"},
		RiskScore:   0.1,
	}

	err = ledger.AppendRecord(record)
	if err != nil {
		t.Fatalf("AppendRecord failed: %v", err)
	}

	// Hash should have changed from genesis
	if ledger.latestHash == "genesis_000000000000000000000000000000" {
		t.Fatal("hash should change after appending a record")
	}
}

func TestEdgeLedger_ChainIntegrity(t *testing.T) {
	setTempLedgerPath(t)

	ledger, err := NewEdgeLedger(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()

	// Append multiple records and verify chain continuity
	var hashes []string

	for i := 0; i < 5; i++ {
		record := EventRecord{
			EventID:     "evt-" + string(rune('A'+i)),
			TraceID:     "trace-" + string(rune('A'+i)),
			TenantID:    "tenant-001",
			AgentID:     "agent-001",
			Decision:    "allow",
			ActionClass: "llm_proxy",
			ReasonCodes: []string{"clean"},
			RiskScore:   0.0,
		}
		if err := ledger.AppendRecord(record); err != nil {
			t.Fatalf("AppendRecord %d failed: %v", i, err)
		}
		hashes = append(hashes, ledger.latestHash)
	}

	// All hashes should be unique
	seen := make(map[string]bool)
	for _, h := range hashes {
		if seen[h] {
			t.Fatal("duplicate hash detected — chain is broken")
		}
		seen[h] = true
	}
}

func TestEdgeLedger_UnsyncedRecords(t *testing.T) {
	setTempLedgerPath(t)

	ledger, err := NewEdgeLedger(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()

	// Append 3 records
	for i := 0; i < 3; i++ {
		record := EventRecord{
			EventID:     "evt-" + string(rune('0'+i)),
			TraceID:     "trace-" + string(rune('0'+i)),
			TenantID:    "tenant-001",
			AgentID:     "agent-001",
			Decision:    "allow",
			ActionClass: "test",
			ReasonCodes: []string{"ok"},
			RiskScore:   0.0,
		}
		if err := ledger.AppendRecord(record); err != nil {
			t.Fatal(err)
		}
	}

	// All 3 should be unsynced
	records, err := ledger.UnsyncedRecords(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 3 {
		t.Errorf("expected 3 unsynced records, got %d", len(records))
	}
}

func TestEdgeLedger_MarkSynced(t *testing.T) {
	setTempLedgerPath(t)

	ledger, err := NewEdgeLedger(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()

	// Append 2 records
	for i := 0; i < 2; i++ {
		record := EventRecord{
			EventID:     "evt-sync-" + string(rune('0'+i)),
			TraceID:     "trace-sync-" + string(rune('0'+i)),
			TenantID:    "tenant-001",
			AgentID:     "agent-001",
			Decision:    "deny",
			ActionClass: "test",
			ReasonCodes: []string{"policy_violation"},
			RiskScore:   0.9,
		}
		if err := ledger.AppendRecord(record); err != nil {
			t.Fatal(err)
		}
	}

	// Mark first as synced
	if err := ledger.MarkSynced([]string{"evt-sync-0"}); err != nil {
		t.Fatal(err)
	}

	// Only 1 should remain unsynced
	records, err := ledger.UnsyncedRecords(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Errorf("expected 1 unsynced record after MarkSynced, got %d", len(records))
	}
	if records[0].EventID != "evt-sync-1" {
		t.Errorf("expected evt-sync-1 to be unsynced, got %s", records[0].EventID)
	}
}

func TestDecisionToStatus(t *testing.T) {
	tests := []struct {
		decision string
		expected string
	}{
		{"deny", "blocked"},
		{"contamination_detected", "blocked"},
		{"allow", "approved"},
		{"ghost_proxied", "shadow_sandbox"},
		{"shadow_allowed", "shadow_allowed"},
		{"unknown_decision", "pending_swarm"},
		{"", "pending_swarm"},
	}
	for _, tt := range tests {
		got := decisionToStatus(tt.decision)
		if got != tt.expected {
			t.Errorf("decisionToStatus(%q) = %q, want %q", tt.decision, got, tt.expected)
		}
	}
}
