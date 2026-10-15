// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package roles

import (
	"testing"
)

// ptr is a test helper to get a pointer to a string literal.
func ptr(s string) *string { return &s }

// ── sub_agent ─────────────────────────────────────────────────────────────────

func TestEnforce_SubAgent_CorrectOrchestrator(t *testing.T) {
	record := &AgentRoleRecord{Role: "sub_agent", OrchestratorID: ptr("orch-1")}
	err := enforceRole(record, "sub-agent-1", "orch-1", -1)
	if err != nil {
		t.Errorf("Expected nil error for correct orchestrator, got: %v", err)
	}
}

func TestEnforce_SubAgent_WrongOrchestrator(t *testing.T) {
	record := &AgentRoleRecord{Role: "sub_agent", OrchestratorID: ptr("orch-1")}
	err := enforceRole(record, "sub-agent-1", "rogue-orch", -1)
	if err == nil {
		t.Error("Expected error for wrong orchestrator, got nil")
	}
}

func TestEnforce_SubAgent_NoOrchestratorID(t *testing.T) {
	// sub_agent registered without an orchestrator_id — must be denied
	record := &AgentRoleRecord{Role: "sub_agent", OrchestratorID: nil}
	err := enforceRole(record, "sub-agent-1", "any-caller", -1)
	if err == nil {
		t.Error("Expected error for sub_agent with nil orchestrator_id, got nil")
	}
}

func TestEnforce_SubAgent_EmptyOrchestratorID(t *testing.T) {
	record := &AgentRoleRecord{Role: "sub_agent", OrchestratorID: ptr("")}
	err := enforceRole(record, "sub-agent-1", "any-caller", -1)
	if err == nil {
		t.Error("Expected error for sub_agent with empty orchestrator_id, got nil")
	}
}

// ── autonomous ────────────────────────────────────────────────────────────────

func TestEnforce_Autonomous_AboveThreshold(t *testing.T) {
	record := &AgentRoleRecord{Role: "autonomous"}
	// Score above 0.80 — must pass
	err := enforceRole(record, "auto-1", "auto-1", 0.85)
	if err != nil {
		t.Errorf("Expected nil for score above threshold, got: %v", err)
	}
}

func TestEnforce_Autonomous_ExactlyAtThreshold(t *testing.T) {
	record := &AgentRoleRecord{Role: "autonomous"}
	err := enforceRole(record, "auto-1", "auto-1", AutonomousSwarmThreshold)
	if err != nil {
		t.Errorf("Expected nil for score exactly at threshold (%.2f), got: %v", AutonomousSwarmThreshold, err)
	}
}

func TestEnforce_Autonomous_BelowThreshold(t *testing.T) {
	record := &AgentRoleRecord{Role: "autonomous"}
	err := enforceRole(record, "auto-1", "auto-1", 0.50)
	if err == nil {
		t.Error("Expected error for autonomous agent below swarm threshold, got nil")
	}
}

func TestEnforce_Autonomous_SwarmNotRun(t *testing.T) {
	// swarmScore = -1 means swarm hasn't run yet — must not block
	record := &AgentRoleRecord{Role: "autonomous"}
	err := enforceRole(record, "auto-1", "auto-1", -1)
	if err != nil {
		t.Errorf("Expected nil when swarm score is -1 (not run), got: %v", err)
	}
}

func TestEnforce_Autonomous_ZeroScore(t *testing.T) {
	// Score 0.0 is a valid failing score — must block
	record := &AgentRoleRecord{Role: "autonomous"}
	err := enforceRole(record, "auto-1", "auto-1", 0.0)
	if err == nil {
		t.Error("Expected error for autonomous agent with score 0.0, got nil")
	}
}

// ── tool_executor ─────────────────────────────────────────────────────────────

func TestEnforce_ToolExecutor_CalledByOrchestrator(t *testing.T) {
	// tool_executor invoked by a different agent (orchestrator) — allowed
	record := &AgentRoleRecord{Role: "tool_executor"}
	err := enforceRole(record, "tool-1", "orch-1", -1)
	if err != nil {
		t.Errorf("Expected nil for tool_executor invoked by orchestrator, got: %v", err)
	}
}

func TestEnforce_ToolExecutor_DirectCall(t *testing.T) {
	// tool_executor trying to make a direct call (caller == self) — blocked
	record := &AgentRoleRecord{Role: "tool_executor"}
	err := enforceRole(record, "tool-1", "tool-1", -1)
	if err == nil {
		t.Error("Expected error for tool_executor making direct call, got nil")
	}
}

// ── orchestrator ─────────────────────────────────────────────────────────────

func TestEnforce_Orchestrator_NoConstraints(t *testing.T) {
	record := &AgentRoleRecord{Role: "orchestrator"}
	// orchestrator has no score or caller constraints beyond basic validation
	err := enforceRole(record, "orch-1", "orch-1", 0.3)
	if err != nil {
		t.Errorf("Expected nil for orchestrator (no extra constraints), got: %v", err)
	}
}

// ── peer ─────────────────────────────────────────────────────────────────────

func TestEnforce_Peer_NoConstraints(t *testing.T) {
	record := &AgentRoleRecord{Role: "peer"}
	err := enforceRole(record, "peer-1", "peer-1", 0.1)
	if err != nil {
		t.Errorf("Expected nil for peer (no extra constraints), got: %v", err)
	}
}

// ── unknown role falls back to autonomous rules ───────────────────────────────

func TestEnforce_UnknownRole_BelowAutonomousThreshold(t *testing.T) {
	record := &AgentRoleRecord{Role: "wizard"} // not a known role
	err := enforceRole(record, "mystery-1", "mystery-1", 0.5)
	if err == nil {
		t.Error("Expected error for unknown role with score below autonomous threshold")
	}
}

func TestEnforce_UnknownRole_AboveAutonomousThreshold(t *testing.T) {
	record := &AgentRoleRecord{Role: "wizard"}
	err := enforceRole(record, "mystery-1", "mystery-1", 0.9)
	if err != nil {
		t.Errorf("Expected nil for unknown role with score above threshold, got: %v", err)
	}
}

func TestEnforce_UnknownRole_SwarmNotRun(t *testing.T) {
	record := &AgentRoleRecord{Role: "wizard"}
	err := enforceRole(record, "mystery-1", "mystery-1", -1)
	if err != nil {
		t.Errorf("Expected nil for unknown role when swarm not run, got: %v", err)
	}
}

// ── AutonomousSwarmThreshold constant ────────────────────────────────────────

func TestAutonomousSwarmThreshold_Value(t *testing.T) {
	// This threshold is a security invariant. If someone changes it, this test
	// forces them to consciously update both the constant and the test — not just
	// edit the constant and hope nobody notices the trust relaxation.
	if AutonomousSwarmThreshold != 0.80 {
		t.Errorf("AutonomousSwarmThreshold = %.2f; changing this value affects the trust model — update this test intentionally", AutonomousSwarmThreshold)
	}
}
