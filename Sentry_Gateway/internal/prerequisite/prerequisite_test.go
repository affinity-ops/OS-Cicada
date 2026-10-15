// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package prerequisite

import (
	"testing"
)

// ── Forward Saga: Prerequisite Enforcement ────────────────────────────────────
//
// These tests verify the Forward Saga pattern using CheckDeterministic (no DB required).
// The prerequisite map simulates the agent_tools table, and the ledger check function
// simulates querying the action_ledger.

// buildTestManifest creates a prerequisite map simulating a storage agent's tool chain:
//   storage:verify_backup → no prerequisite (can be called freely)
//   storage:delete_volume → requires storage:verify_backup
//   storage:read_volume   → no prerequisite
//   crm:update_record     → requires crm:read_record
func buildTestManifest() map[string]string {
	return map[string]string{
		"storage:verify_backup": "",                       // no prerequisite
		"storage:delete_volume": "storage:verify_backup",  // requires backup first
		"storage:read_volume":   "",                       // no prerequisite
		"crm:update_record":     "crm:read_record",        // requires read first
		"crm:read_record":       "",                       // no prerequisite
	}
}

// ── Happy Path: Prerequisite Satisfied ────────────────────────────────────────

// TestPrerequisiteSatisfied verifies that a tool with a completed prerequisite passes.
func TestPrerequisiteSatisfied(t *testing.T) {
	manifest := buildTestManifest()

	// Simulate: agent has called verify_backup → it's in the ledger
	ledgerCheck := func(toolID string) bool {
		return toolID == "storage:verify_backup"
	}

	result := CheckDeterministic("storage:delete_volume", manifest, ledgerCheck)

	if !result.Passed {
		t.Errorf("delete_volume should pass when verify_backup is in ledger, got: %s", result.Reason)
	}
	if result.RequiredToolID != "storage:verify_backup" {
		t.Errorf("required tool should be 'storage:verify_backup', got %q", result.RequiredToolID)
	}
}

// ── Blocked: Prerequisite Missing ─────────────────────────────────────────────

// TestPrerequisiteMissing verifies that a tool is BLOCKED when its prerequisite
// has NOT been completed — the core Forward Saga enforcement.
func TestPrerequisiteMissing(t *testing.T) {
	manifest := buildTestManifest()

	// Simulate: agent has NOT called verify_backup
	ledgerCheck := func(toolID string) bool {
		return false // nothing in ledger
	}

	result := CheckDeterministic("storage:delete_volume", manifest, ledgerCheck)

	if result.Passed {
		t.Error("delete_volume should be BLOCKED when verify_backup is missing from ledger")
	}
	if result.RequiredToolID != "storage:verify_backup" {
		t.Errorf("required tool should be 'storage:verify_backup', got %q", result.RequiredToolID)
	}
	if result.ToolID != "storage:delete_volume" {
		t.Errorf("tool_id should be 'storage:delete_volume', got %q", result.ToolID)
	}
}

// ── No Prerequisite Required ──────────────────────────────────────────────────

// TestNoPrerequisite verifies that tools without a prerequisite always pass.
func TestNoPrerequisite(t *testing.T) {
	manifest := buildTestManifest()

	result := CheckDeterministic("storage:read_volume", manifest, nil)

	if !result.Passed {
		t.Errorf("read_volume has no prerequisite — should always pass, got: %s", result.Reason)
	}
}

// TestVerifyBackupHasNoPrerequisite verifies that the first step in a chain
// (the prerequisite itself) has no prerequisite of its own.
func TestVerifyBackupHasNoPrerequisite(t *testing.T) {
	manifest := buildTestManifest()

	result := CheckDeterministic("storage:verify_backup", manifest, nil)

	if !result.Passed {
		t.Errorf("verify_backup is the chain root — should always pass, got: %s", result.Reason)
	}
}

// ── Unknown Tool ──────────────────────────────────────────────────────────────

// TestUnknownTool verifies that tools not in the manifest pass through.
// Unknown tools are handled by other layers (scope enforcement, semantic check).
func TestUnknownTool(t *testing.T) {
	manifest := buildTestManifest()

	result := CheckDeterministic("unknown:mystery_tool", manifest, nil)

	if !result.Passed {
		t.Errorf("unknown tools should pass through prerequisite layer, got: %s", result.Reason)
	}
}

// ── Empty Tool ID ─────────────────────────────────────────────────────────────

// TestEmptyToolID verifies that an empty tool_id skips the check entirely.
func TestEmptyToolID(t *testing.T) {
	manifest := buildTestManifest()

	result := CheckDeterministic("", manifest, nil)

	if !result.Passed {
		t.Error("empty tool_id should skip prerequisite check")
	}
}

// ── Multi-Chain: CRM Example ──────────────────────────────────────────────────

// TestCRMChain_ReadThenUpdate verifies a different prerequisite chain works.
func TestCRMChain_ReadThenUpdate(t *testing.T) {
	manifest := buildTestManifest()

	// Agent has completed crm:read_record
	ledgerCheck := func(toolID string) bool {
		return toolID == "crm:read_record"
	}

	result := CheckDeterministic("crm:update_record", manifest, ledgerCheck)

	if !result.Passed {
		t.Errorf("update_record should pass when read_record is in ledger, got: %s", result.Reason)
	}
}

// TestCRMChain_UpdateWithoutRead verifies that update is blocked without read.
func TestCRMChain_UpdateWithoutRead(t *testing.T) {
	manifest := buildTestManifest()

	// Agent has NOT called read_record (but has done a different tool)
	ledgerCheck := func(toolID string) bool {
		return toolID == "storage:verify_backup" // wrong tool — doesn't satisfy CRM chain
	}

	result := CheckDeterministic("crm:update_record", manifest, ledgerCheck)

	if result.Passed {
		t.Error("update_record should be BLOCKED when read_record is missing (wrong prerequisite completed)")
	}
}

// ── Cross-Chain Isolation ─────────────────────────────────────────────────────

// TestCrossChainIsolation verifies that satisfying a prerequisite in one chain
// does NOT satisfy a prerequisite in a different chain.
func TestCrossChainIsolation(t *testing.T) {
	manifest := buildTestManifest()

	// Agent completed crm:read_record (CRM chain) but NOT storage:verify_backup
	ledgerCheck := func(toolID string) bool {
		return toolID == "crm:read_record"
	}

	// Should be BLOCKED because verify_backup (storage chain) was not completed
	result := CheckDeterministic("storage:delete_volume", manifest, ledgerCheck)

	if result.Passed {
		t.Error("storage chain should not be satisfied by CRM chain prerequisite")
	}
}

// ── Configuration ─────────────────────────────────────────────────────────────

// TestIsEnabled_Default verifies prerequisite checking is enabled by default.
func TestIsEnabled_Default(t *testing.T) {
	if !isEnabled() {
		t.Error("prerequisite checking should be enabled by default")
	}
}

// TestWindowMinutes_Default verifies the default window is 10 minutes.
func TestWindowMinutes_Default(t *testing.T) {
	window := getWindowMinutes()
	if window != DefaultWindowMinutes {
		t.Errorf("default window = %d, want %d", window, DefaultWindowMinutes)
	}
}

// ── Result Fields ─────────────────────────────────────────────────────────────

// TestResultFields_Blocked verifies all fields are populated on a block.
func TestResultFields_Blocked(t *testing.T) {
	manifest := buildTestManifest()
	ledgerCheck := func(toolID string) bool { return false }

	result := CheckDeterministic("storage:delete_volume", manifest, ledgerCheck)

	if result.Passed {
		t.Fatal("expected block")
	}
	if result.ToolID != "storage:delete_volume" {
		t.Errorf("ToolID = %q, want 'storage:delete_volume'", result.ToolID)
	}
	if result.RequiredToolID != "storage:verify_backup" {
		t.Errorf("RequiredToolID = %q, want 'storage:verify_backup'", result.RequiredToolID)
	}
	if result.Reason == "" {
		t.Error("Reason should not be empty on block")
	}
}

// TestResultFields_Passed verifies all fields are populated on a pass.
func TestResultFields_Passed(t *testing.T) {
	manifest := buildTestManifest()
	ledgerCheck := func(toolID string) bool { return toolID == "storage:verify_backup" }

	result := CheckDeterministic("storage:delete_volume", manifest, ledgerCheck)

	if !result.Passed {
		t.Fatal("expected pass")
	}
	if result.RequiredToolID != "storage:verify_backup" {
		t.Errorf("RequiredToolID = %q, want 'storage:verify_backup'", result.RequiredToolID)
	}
	if result.Reason == "" {
		t.Error("Reason should not be empty on pass")
	}
}
