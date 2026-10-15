// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package roles enforces the Cicada agent role registry at Gateway admission.
//
// Design rationale: In multi-agent orchestration workflows, an uncertified agent
// can exploit a certified orchestrator by routing through it — inheriting the
// orchestrator's trust tier without being vetted itself. The role registry closes
// this by requiring every agent to declare its role at registration and enforcing
// role-specific admission rules at the Gateway.
//
// Role definitions:
//
//   orchestrator  — Can spawn and direct sub-agents. Requires at minimum proxy:write
//                   scope. All spawned sub-agents are logged to action_ledger.
//
//   sub_agent     — Can only act when invoked by its declared orchestrator. The
//                   EVAR of the calling orchestrator must match orchestrator_id.
//                   Prevents an attacker from registering a fake orchestrator to
//                   unlock a sub_agent's permissions.
//
//   peer          — Can communicate laterally with other certified agents.
//                   Cannot spawn sub-agents.
//
//   autonomous    — Operates without an orchestrator. Highest swarm score
//                   threshold (0.8 vs standard 0.6) because no orchestrator is
//                   providing a second layer of intent verification.
//
//   tool_executor — Passive: only executes tools when explicitly called.
//                   Cannot initiate calls to other agents or external APIs.
package roles

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/asai/cicada/sentry/internal/store"
)

// failClosed returns true when FAIL_CLOSED_ON_DB_ERROR=true is set.
// When true, a DB error during role lookup results in a deny rather than
// defaulting to autonomous. Use this in production — fail-open exists only
// for backwards-compatible prototype deployments.
func failClosed() bool {
	return os.Getenv("FAIL_CLOSED_ON_DB_ERROR") == "true"
}

// AutonomousSwarmThreshold is the minimum swarm confidence score required to
// admit an autonomous agent. Higher than the standard 0.6 because autonomous
// agents have no orchestrator providing a second intent-verification layer.
const AutonomousSwarmThreshold = 0.80

// AgentRoleRecord contains the role fields fetched from the agents table.
type AgentRoleRecord struct {
	Role           string  // orchestrator | sub_agent | peer | autonomous | tool_executor
	OrchestratorID *string // non-nil only for sub_agent role
}

// Fetch loads the role record for an agent from PostgreSQL.
func Fetch(ctx context.Context, agentID string) (*AgentRoleRecord, error) {
	var r AgentRoleRecord
	err := store.DB.QueryRow(ctx,
		`SELECT COALESCE(role, 'autonomous'), orchestrator_id
		   FROM agents WHERE id = $1`,
		agentID,
	).Scan(&r.Role, &r.OrchestratorID)
	if err != nil {
		return nil, fmt.Errorf("role lookup failed for agent %s: %w", agentID, err)
	}
	return &r, nil
}

// Enforce applies role-specific admission rules. Returns an error if the call
// violates the agent's declared role contract.
//
// callerEVARAgentID is the agent_id of the entity presenting the session token
// (i.e. the entity making the call on behalf of this agent). For direct calls
// it equals agentID. For orchestrated calls it is the orchestrator's agent_id.
//
// swarmScore is the Verification Swarm confidence score (0.0–1.0) from the
// current admission. Pass -1 if the swarm has not run yet.
func Enforce(ctx context.Context, agentID, callerEVARAgentID string, swarmScore float64) error {
	record, err := Fetch(ctx, agentID)
	if err != nil {
		if failClosed() {
			// Fail closed: an agent whose role cannot be verified is denied.
			// Set FAIL_CLOSED_ON_DB_ERROR=true in production.
			log.Printf("[ROLES] DB unavailable for agent %s — denying (fail-closed mode): %v", agentID, err)
			return fmt.Errorf("role enforcement: database unavailable — access denied")
		}
		// Fail open: backwards-compatible default for prototype deployments.
		log.Printf("[ROLES] Could not fetch role for agent %s, defaulting to autonomous: %v", agentID, err)
		return nil
	}
	return enforceRole(record, agentID, callerEVARAgentID, swarmScore)
}

// enforceRole contains the pure decision logic for role enforcement. Separated
// from Enforce so it can be tested without a database dependency.
func enforceRole(record *AgentRoleRecord, agentID, callerEVARAgentID string, swarmScore float64) error {
	switch record.Role {

	case "sub_agent":
		// A sub_agent may only be invoked by its declared orchestrator.
		// This check prevents a rogue orchestrator from co-opting any sub_agent
		// it happens to know the agent_id of.
		if record.OrchestratorID == nil || *record.OrchestratorID == "" {
			return fmt.Errorf("sub_agent %s has no orchestrator_id declared — re-register with an orchestrator binding", agentID)
		}
		if callerEVARAgentID != *record.OrchestratorID {
			log.Printf("[ROLES] sub_agent %s called by %s — expected orchestrator %s", agentID, callerEVARAgentID, *record.OrchestratorID)
			return fmt.Errorf("sub_agent may only be invoked by its declared orchestrator")
		}

	case "autonomous":
		// Autonomous agents hold themselves to a higher standard because they
		// operate without a human-supervised orchestrator chain.
		if swarmScore >= 0 && swarmScore < AutonomousSwarmThreshold {
			return fmt.Errorf("autonomous agent %s swarm score %.2f below required threshold %.2f", agentID, swarmScore, AutonomousSwarmThreshold)
		}

	case "tool_executor":
		// Tool executors cannot initiate external API calls — they must be
		// invoked by another agent or system, not arrive as a direct proxy request.
		if callerEVARAgentID == agentID {
			return fmt.Errorf("tool_executor %s cannot initiate direct proxy calls — must be invoked by an orchestrator or peer", agentID)
		}

	// orchestrator and peer have no additional admission constraints beyond
	// standard EVAR validation and swarm scoring.
	case "orchestrator", "peer":
		// no additional constraints

	default:
		// Unknown role — treat as autonomous (safe default).
		log.Printf("[ROLES] Unknown role %q for agent %s — treating as autonomous", record.Role, agentID)
		if swarmScore >= 0 && swarmScore < AutonomousSwarmThreshold {
			return fmt.Errorf("agent %s (unknown role %q) swarm score %.2f below autonomous threshold", agentID, record.Role, swarmScore)
		}
	}

	return nil
}
