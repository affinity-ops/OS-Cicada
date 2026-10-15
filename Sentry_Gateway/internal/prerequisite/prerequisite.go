// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package prerequisite implements the Forward Saga pattern for Cicada's
// Sentry Gateway (Pillar 3 of Multi-Faceted Agent Governance).
//
// The problem this solves:
// A multi-step agent task like "archive customer data" should follow a strict
// sequence: Backup → Verify → Delete. Without prerequisite enforcement, an
// agent (or a compromised prompt) can skip straight to Delete, causing
// irreversible data loss. Static scope checks allow the call because the agent
// has "proxy:write" — they answer "is this agent allowed to delete?" but NOT
// "has this agent completed the required steps first?"
//
// How prerequisite checking works:
//
//  1. During agent provisioning, each tool in the agent_tools table can declare
//     a `requires_previous_tool` — another tool_id that must have been executed
//     successfully before this tool is allowed to run.
//
//  2. On each proxied request, the Gateway extracts the tool_id from the
//     request (via X-Cicada-Tool-ID header or from the agent's tool manifest).
//
//  3. The prerequisite checker looks up the tool's requires_previous_tool.
//     If it's NULL, the tool has no prerequisite and the check passes.
//
//  4. If a prerequisite exists, the checker queries the action_ledger:
//     "Has this agent_id successfully called {prerequisite_tool_id} within
//     the last {PrerequisiteWindowMinutes} minutes?"
//
//  5. If the prerequisite was completed → PASS (action chain intact).
//     If the prerequisite was NOT completed → BLOCK with a clear reason.
//
// Why the ledger, not a state machine:
// The action_ledger is already an immutable, append-only audit trail of every
// agent action. Rather than building a separate state machine (extra table,
// extra complexity, extra failure mode), we query the existing ledger as a
// "Requirement Sieve." If the backup is in the ledger, the delete is allowed.
// If it's not, the delete is rejected. The ledger IS the state machine.
//
// Configuration:
//   PREREQUISITE_WINDOW_MINUTES=10   (how recent the prerequisite must be)
//   PREREQUISITE_ENABLED=true        (master switch — default true)
package prerequisite

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/asai/cicada/sentry/internal/store"
)

// DefaultWindowMinutes is how recently the prerequisite tool must have been
// executed. 10 minutes is generous enough for a multi-step workflow but tight
// enough that a backup from yesterday doesn't satisfy a delete today.
const DefaultWindowMinutes = 10

// ── Result ────────────────────────────────────────────────────────────────────

// Result captures the prerequisite check outcome for a single request.
type Result struct {
	// Passed is true if either (a) the tool has no prerequisite, or
	// (b) the prerequisite was found in the ledger within the time window.
	Passed bool `json:"passed"`

	// ToolID is the tool being invoked in the current request.
	ToolID string `json:"tool_id"`

	// RequiredToolID is the prerequisite tool_id (empty if none).
	RequiredToolID string `json:"required_tool_id,omitempty"`

	// Reason is a human-readable explanation for the audit trail.
	Reason string `json:"reason"`

	// WindowMinutes is the time window used for the check.
	WindowMinutes int `json:"window_minutes"`
}

// ── Tool Prerequisite Lookup ──────────────────────────────────────────────────

// ToolPrerequisite holds the prerequisite configuration for a single tool.
type ToolPrerequisite struct {
	ToolID              string // the tool being checked
	ToolScope           string // read/write/delete/transact (or empty if unrestricted)
	RequiresPreviousTool string // the tool_id that must have been called first (or empty)
}

// LookupToolPrerequisite queries the agent_tools table for a specific tool's
// prerequisite configuration. Returns nil if the tool is not found (which means
// the tool is unknown — the caller decides whether to allow or deny).
//
// This function queries the Core API's PostgreSQL database (agent_tools table).
// In production, this data would be cached in the session token or Redis to
// avoid a DB round-trip per request. For now, we query directly.
func LookupToolPrerequisite(ctx context.Context, agentID, toolID string) (*ToolPrerequisite, error) {
	if store.DB == nil {
		return nil, fmt.Errorf("database unavailable")
	}

	var tp ToolPrerequisite
	var scope, reqTool *string

	err := store.DB.QueryRow(ctx,
		`SELECT tool_id, tool_scope, requires_previous_tool
		 FROM agent_tools
		 WHERE agent_id = $1::uuid AND tool_id = $2 AND is_active = true`,
		agentID, toolID,
	).Scan(&tp.ToolID, &scope, &reqTool)

	if err != nil {
		return nil, fmt.Errorf("lookup tool prerequisite: %w", err)
	}

	if scope != nil {
		tp.ToolScope = *scope
	}
	if reqTool != nil {
		tp.RequiresPreviousTool = *reqTool
	}

	return &tp, nil
}

// ── Ledger Query ──────────────────────────────────────────────────────────────

// HasCompletedPrerequisite queries the action_ledger to determine if the agent
// has successfully executed the prerequisite tool within the time window.
//
// The query looks for:
//   - agent_id matches
//   - action_type matches the prerequisite tool_id
//   - status is 'approved' (successful execution)
//   - created_at is within the configured window
//
// Returns true if at least one matching ledger entry exists.
func HasCompletedPrerequisite(ctx context.Context, agentID, prerequisiteToolID string) (bool, error) {
	if store.DB == nil {
		return false, fmt.Errorf("database unavailable")
	}

	windowMinutes := getWindowMinutes()
	cutoff := time.Now().Add(-time.Duration(windowMinutes) * time.Minute)

	var count int
	err := store.DB.QueryRow(ctx,
		`SELECT COUNT(*)
		 FROM action_ledger
		 WHERE agent_id = $1::uuid
		   AND action_type = $2
		   AND status = 'approved'
		   AND created_at >= $3`,
		agentID, prerequisiteToolID, cutoff,
	).Scan(&count)

	if err != nil {
		return false, fmt.Errorf("query prerequisite completion: %w", err)
	}

	return count > 0, nil
}

// ── Public API ────────────────────────────────────────────────────────────────

// Check evaluates whether an agent has satisfied the prerequisite for a tool.
//
// Parameters:
//   - agentID: the agent attempting the action
//   - toolID:  the tool being invoked (from X-Cicada-Tool-ID header)
//
// Returns a Result indicating whether the prerequisite is satisfied.
// If the database is unavailable, the check fails open (Passed=true) because
// prerequisite checking is one layer of defence-in-depth — other layers
// (velocity, drift, CIBA) provide additional protection.
func Check(ctx context.Context, agentID, toolID string) Result {
	// ── Master switch ─────────────────────────────────────────────────────
	if !isEnabled() {
		return Result{
			Passed: true,
			ToolID: toolID,
			Reason: "prerequisite checking disabled (PREREQUISITE_ENABLED=false)",
		}
	}

	// ── No tool specified ─────────────────────────────────────────────────
	if toolID == "" {
		return Result{
			Passed: true,
			ToolID: "",
			Reason: "no tool_id specified — prerequisite check skipped",
		}
	}

	// ── Lookup tool's prerequisite ────────────────────────────────────────
	tp, err := LookupToolPrerequisite(ctx, agentID, toolID)
	if err != nil {
		// Tool not found in manifest or DB unavailable — fail open.
		log.Printf("[PREREQUISITE] Lookup failed for agent=%s tool=%s: %v (failing open)", agentID, toolID, err)
		return Result{
			Passed:        true,
			ToolID:        toolID,
			Reason:        fmt.Sprintf("prerequisite lookup failed: %v — failing open", err),
			WindowMinutes: getWindowMinutes(),
		}
	}

	// ── No prerequisite required ──────────────────────────────────────────
	if tp.RequiresPreviousTool == "" {
		return Result{
			Passed:        true,
			ToolID:        toolID,
			Reason:        "tool has no prerequisite requirement",
			WindowMinutes: getWindowMinutes(),
		}
	}

	// ── Check if prerequisite was completed ───────────────────────────────
	completed, err := HasCompletedPrerequisite(ctx, agentID, tp.RequiresPreviousTool)
	if err != nil {
		// DB error — fail open (other layers provide protection)
		log.Printf("[PREREQUISITE] Ledger query failed for agent=%s prerequisite=%s: %v (failing open)",
			agentID, tp.RequiresPreviousTool, err)
		return Result{
			Passed:         true,
			ToolID:         toolID,
			RequiredToolID: tp.RequiresPreviousTool,
			Reason:         fmt.Sprintf("ledger query failed: %v — failing open", err),
			WindowMinutes:  getWindowMinutes(),
		}
	}

	windowMinutes := getWindowMinutes()

	if completed {
		reason := fmt.Sprintf(
			"prerequisite satisfied: agent completed '%s' within the last %d minutes before calling '%s'",
			tp.RequiresPreviousTool, windowMinutes, toolID,
		)
		return Result{
			Passed:         true,
			ToolID:         toolID,
			RequiredToolID: tp.RequiresPreviousTool,
			Reason:         reason,
			WindowMinutes:  windowMinutes,
		}
	}

	// ── PREREQUISITE NOT MET — BLOCK ──────────────────────────────────────
	reason := fmt.Sprintf(
		"ACTION CHAIN BROKEN: agent has not completed prerequisite '%s' within the last %d minutes. "+
			"Tool '%s' requires '%s' to be executed first. "+
			"This is a Forward Saga enforcement — destructive actions require verified preparation steps.",
		tp.RequiresPreviousTool, windowMinutes, toolID, tp.RequiresPreviousTool,
	)
	log.Printf("[PREREQUISITE] BLOCKED: agent=%s tool=%s missing_prerequisite=%s window=%dm",
		agentID, toolID, tp.RequiresPreviousTool, windowMinutes)

	return Result{
		Passed:         false,
		ToolID:         toolID,
		RequiredToolID: tp.RequiresPreviousTool,
		Reason:         reason,
		WindowMinutes:  windowMinutes,
	}
}

// ── Deterministic Check (no DB required) ──────────────────────────────────────

// CheckDeterministic evaluates prerequisites using a provided tool manifest
// and ledger check function. This is the testable, dependency-injected variant
// used by the pipeline and unit tests. It does not require a live database.
//
// Parameters:
//   - toolID:           the tool being invoked
//   - prerequisiteMap:  map[toolID] → required prerequisite tool_id (empty string = no prerequisite)
//   - ledgerCheckFn:    function that returns true if the prerequisite tool was completed
func CheckDeterministic(toolID string, prerequisiteMap map[string]string, ledgerCheckFn func(prerequisiteToolID string) bool) Result {
	if !isEnabled() {
		return Result{Passed: true, ToolID: toolID, Reason: "prerequisite checking disabled"}
	}

	if toolID == "" {
		return Result{Passed: true, ToolID: "", Reason: "no tool_id specified"}
	}

	requiredTool, exists := prerequisiteMap[toolID]
	if !exists {
		// Tool not in manifest — pass through (unknown tools are handled by other layers)
		return Result{Passed: true, ToolID: toolID, Reason: "tool not in prerequisite manifest"}
	}

	if requiredTool == "" {
		return Result{Passed: true, ToolID: toolID, Reason: "tool has no prerequisite requirement"}
	}

	windowMinutes := getWindowMinutes()

	if ledgerCheckFn != nil && ledgerCheckFn(requiredTool) {
		return Result{
			Passed:         true,
			ToolID:         toolID,
			RequiredToolID: requiredTool,
			Reason:         fmt.Sprintf("prerequisite '%s' verified in ledger", requiredTool),
			WindowMinutes:  windowMinutes,
		}
	}

	return Result{
		Passed:         false,
		ToolID:         toolID,
		RequiredToolID: requiredTool,
		Reason: fmt.Sprintf(
			"ACTION CHAIN BROKEN: prerequisite '%s' not found. Tool '%s' requires '%s' first.",
			requiredTool, toolID, requiredTool,
		),
		WindowMinutes: windowMinutes,
	}
}

// ── Configuration ─────────────────────────────────────────────────────────────

// isEnabled returns whether prerequisite checking is active.
// Default: true. Set PREREQUISITE_ENABLED=false to disable.
func isEnabled() bool {
	if v := os.Getenv("PREREQUISITE_ENABLED"); v != "" {
		return strings.ToLower(v) != "false" && v != "0"
	}
	return true
}

// getWindowMinutes returns how recently the prerequisite must have been executed.
// Configurable via PREREQUISITE_WINDOW_MINUTES.
func getWindowMinutes() int {
	if v := os.Getenv("PREREQUISITE_WINDOW_MINUTES"); v != "" {
		if i, err := strconv.Atoi(v); err == nil && i > 0 {
			return i
		}
	}
	return DefaultWindowMinutes
}
