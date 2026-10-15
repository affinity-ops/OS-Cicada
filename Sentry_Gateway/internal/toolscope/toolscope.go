// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package toolscope implements Atomic Tool Scoping for Cicada's Sentry Gateway
// (Pillar 2 of Multi-Faceted Agent Governance).
//
// The problem this solves:
// A multi-faceted agent might have access to several tools — some for reading
// data, some for writing, some for deleting. Without scope binding, an agent
// using a "read" tool (Facet A) can call any HTTP method, including DELETE.
// Broad scope entitlements (proxy:write) don't distinguish between individual
// tool capabilities.
//
// How tool scoping works:
//
//  1. Each tool in agent_tools declares a `tool_scope`:
//       - "read"     → only GET, HEAD, OPTIONS
//       - "write"    → only POST, PUT, PATCH
//       - "delete"   → only DELETE
//       - "transact" → only POST (restricted to financial/critical endpoints)
//       - NULL/""    → unrestricted (backwards compatible with existing tools)
//
//  2. On each proxied request, the Gateway extracts the tool_id from the
//     X-Cicada-Tool-ID header and looks up its declared scope.
//
//  3. The scope checker validates: "Is the HTTP method of this request
//     allowed by this tool's declared scope?"
//
//  4. If the method violates the scope → BLOCK with a clear reason.
//     If the method matches the scope → PASS.
//
// Why this is separate from semantic intent:
// Semantic intent checks "does this call make sense given what this agent IS?"
// Tool scoping checks "does this HTTP method match what this specific tool
// is ALLOWED TO DO?" An agent can pass semantic intent (it's a storage agent
// calling a storage API) but fail tool scope (it's using a read-only tool
// to issue a DELETE).
//
// Configuration:
//   TOOLSCOPE_ENABLED=true   (master switch — default true)
package toolscope

import (
	"fmt"
	"os"
	"strings"
)

// ── Scope-to-Method Mapping ───────────────────────────────────────────────────

// allowedMethods maps each tool_scope to its permitted HTTP methods.
// This is the core enforcement table — if a method is not in the set for a
// given scope, the request is blocked.
//
// Design rationale:
//   - "read":     GET/HEAD/OPTIONS — safe methods that cannot mutate state
//   - "write":    POST/PUT/PATCH — state-creating/modifying methods
//   - "delete":   DELETE only — destructive operations isolated from write
//   - "transact": POST only — financial operations via POST (no PUT/PATCH
//                 which implies updating an existing transaction)
var allowedMethods = map[string]map[string]bool{
	"read": {
		"GET":     true,
		"HEAD":    true,
		"OPTIONS": true,
	},
	"write": {
		"POST":  true,
		"PUT":   true,
		"PATCH": true,
	},
	"delete": {
		"DELETE": true,
	},
	"transact": {
		"POST": true,
	},
}

// validScopes is the set of recognised scope values. Used for validation
// when checking whether a tool_scope string is legitimate.
var validScopes = map[string]bool{
	"read":     true,
	"write":    true,
	"delete":   true,
	"transact": true,
}

// ── Result ────────────────────────────────────────────────────────────────────

// Result captures the tool scope check outcome.
type Result struct {
	// Passed is true if the HTTP method is allowed by the tool's scope,
	// or if the tool has no scope restriction (NULL/empty).
	Passed bool `json:"passed"`

	// ToolID is the tool being invoked.
	ToolID string `json:"tool_id"`

	// DeclaredScope is the tool's scope from agent_tools (empty if unrestricted).
	DeclaredScope string `json:"declared_scope,omitempty"`

	// HTTPMethod is the method being attempted.
	HTTPMethod string `json:"http_method"`

	// Reason is a human-readable explanation for the audit trail.
	Reason string `json:"reason"`
}

// ── Public API ────────────────────────────────────────────────────────────────

// Check validates whether the given HTTP method is permitted by the tool's
// declared scope. This is a pure, deterministic function — no DB or Redis
// needed. The caller provides the scope from the tool manifest.
//
// Parameters:
//   - toolID:     the tool being invoked (for audit logging)
//   - toolScope:  the tool's declared scope from agent_tools ("read", "write",
//                 "delete", "transact", or "" for unrestricted)
//   - httpMethod: the HTTP method of the current request (GET, POST, DELETE, etc.)
//
// Returns a Result indicating whether the method is allowed by the scope.
func Check(toolID, toolScope, httpMethod string) Result {
	// ── Master switch ─────────────────────────────────────────────────────
	if !isEnabled() {
		return Result{
			Passed: true,
			ToolID: toolID,
			Reason: "tool scope enforcement disabled (TOOLSCOPE_ENABLED=false)",
		}
	}

	// ── No tool specified ─────────────────────────────────────────────────
	if toolID == "" {
		return Result{
			Passed: true,
			ToolID: "",
			Reason: "no tool_id specified — scope check skipped",
		}
	}

	// ── No scope restriction ──────────────────────────────────────────────
	// NULL/empty scope = backwards compatible (unrestricted tool).
	if toolScope == "" {
		return Result{
			Passed:     true,
			ToolID:     toolID,
			HTTPMethod: httpMethod,
			Reason:     "tool has no scope restriction (unrestricted)",
		}
	}

	// ── Validate scope value ──────────────────────────────────────────────
	scopeLower := strings.ToLower(toolScope)
	if !validScopes[scopeLower] {
		// Unknown scope — treat as unrestricted but log a warning.
		return Result{
			Passed:        true,
			ToolID:        toolID,
			DeclaredScope: toolScope,
			HTTPMethod:    httpMethod,
			Reason:        fmt.Sprintf("unknown tool_scope '%s' — treating as unrestricted", toolScope),
		}
	}

	// ── Check method against scope ────────────────────────────────────────
	methodUpper := strings.ToUpper(httpMethod)
	allowed, exists := allowedMethods[scopeLower]
	if !exists {
		// Should not happen (we validated above), but defensive
		return Result{
			Passed:        true,
			ToolID:        toolID,
			DeclaredScope: scopeLower,
			HTTPMethod:    methodUpper,
			Reason:        "scope has no method mapping — treating as unrestricted",
		}
	}

	if allowed[methodUpper] {
		// ── PASS: method matches scope ────────────────────────────────────
		return Result{
			Passed:        true,
			ToolID:        toolID,
			DeclaredScope: scopeLower,
			HTTPMethod:    methodUpper,
			Reason: fmt.Sprintf(
				"method %s is permitted by tool scope '%s'",
				methodUpper, scopeLower,
			),
		}
	}

	// ── BLOCK: method violates scope ──────────────────────────────────────
	// Build the list of allowed methods for the error message.
	allowedList := make([]string, 0, len(allowed))
	for m := range allowed {
		allowedList = append(allowedList, m)
	}

	reason := fmt.Sprintf(
		"SCOPE VIOLATION: tool '%s' is scoped to '%s' (allowed: %s) "+
			"but the request uses method %s. "+
			"This agent facet cannot perform %s operations with this tool.",
		toolID, scopeLower, strings.Join(allowedList, ", "),
		methodUpper, methodUpper,
	)

	return Result{
		Passed:        false,
		ToolID:        toolID,
		DeclaredScope: scopeLower,
		HTTPMethod:    methodUpper,
		Reason:        reason,
	}
}

// ── Configuration ─────────────────────────────────────────────────────────────

// isEnabled returns whether tool scope enforcement is active.
// Default: true. Set TOOLSCOPE_ENABLED=false to disable.
func isEnabled() bool {
	if v := os.Getenv("TOOLSCOPE_ENABLED"); v != "" {
		return strings.ToLower(v) != "false" && v != "0"
	}
	return true
}
