// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package hitl — destructive action classification for HITL approval cards.
//
// S1.3: When an agent with destructive_capability=true triggers a HITL hold,
// the approval card sent to the human reviewer must show WHAT the destructive
// action is (e.g., "DROP TABLE", "rm -rf", "DELETE /v1/users/all"). Without
// this context, the reviewer has to interpret raw JSON payloads — which is
// both slow and error-prone for time-sensitive security decisions.
//
// This file provides:
//   1. ClassifyDestructiveAction — analyses the target URL and payload to
//      determine the specific type of destructive action being attempted
//   2. DestructiveActionInfo — structured metadata about the destructive action
//      that is injected into the HITL approval payload
//
// Integration:
//   - Called by the proxy handler in main.go before creating the HITL hold
//   - The returned DestructiveActionInfo is included in the ApprovalRequest
//   - The Dashboard HITL page renders a red warning banner with the action type
//   - The Aegis mobile companion shows the action type in the push notification
package hitl

import (
	"strings"
)

// DestructiveActionInfo describes the specific destructive action an agent is
// attempting. This is displayed to the human reviewer so they can make an
// informed approval/rejection decision.
type DestructiveActionInfo struct {
	// IsDestructive is true when the request matches known destructive patterns.
	IsDestructive bool `json:"is_destructive"`

	// ActionType is the classified category: "data_deletion", "schema_modification",
	// "filesystem_operation", "account_termination", "configuration_reset", or "unknown".
	ActionType string `json:"action_type"`

	// ActionDescription is a human-readable explanation of the destructive action.
	// Example: "Bulk delete of user records via DELETE /v1/users/bulk_delete"
	ActionDescription string `json:"action_description"`

	// Severity is "critical" for irreversible actions (DROP, truncate, rm -rf),
	// "high" for significant data changes (bulk delete, purge),
	// "medium" for potentially destructive operations (overwrite, force update).
	Severity string `json:"severity"`

	// MatchedPattern is the specific keyword or pattern that triggered the classification.
	// Useful for audit and debugging false positives.
	MatchedPattern string `json:"matched_pattern"`
}

// destructivePattern maps URL/payload keywords to their classification.
type destructivePattern struct {
	keyword     string
	actionType  string
	description string
	severity    string
}

// knownDestructivePatterns is the ordered list of patterns checked against
// the target URL and payload. Checked in order; first match wins.
// More specific patterns should come before generic ones.
var knownDestructivePatterns = []destructivePattern{
	// ── Critical: Irreversible data destruction ──────────────────────────
	{keyword: "drop table", actionType: "schema_modification", description: "SQL DROP TABLE — irreversible schema destruction", severity: "critical"},
	{keyword: "drop database", actionType: "schema_modification", description: "SQL DROP DATABASE — entire database destruction", severity: "critical"},
	{keyword: "truncate", actionType: "data_deletion", description: "SQL TRUNCATE — removes all rows without rollback", severity: "critical"},
	{keyword: "rm -rf", actionType: "filesystem_operation", description: "Recursive force-delete — irreversible filesystem destruction", severity: "critical"},
	{keyword: "rmdir", actionType: "filesystem_operation", description: "Directory removal operation", severity: "critical"},
	{keyword: "format", actionType: "filesystem_operation", description: "Filesystem format operation", severity: "critical"},
	{keyword: "fdisk", actionType: "filesystem_operation", description: "Disk partition modification", severity: "critical"},

	// ── High: Significant data changes ───────────────────────────────────
	{keyword: "bulk_delete", actionType: "data_deletion", description: "Bulk deletion of multiple records", severity: "high"},
	{keyword: "batch_delete", actionType: "data_deletion", description: "Batch deletion of multiple records", severity: "high"},
	{keyword: "mass_delete", actionType: "data_deletion", description: "Mass deletion operation", severity: "high"},
	{keyword: "purge", actionType: "data_deletion", description: "Data purge — removes records permanently", severity: "high"},
	{keyword: "wipe", actionType: "data_deletion", description: "Data wipe operation", severity: "high"},
	{keyword: "destroy", actionType: "data_deletion", description: "Resource destruction", severity: "high"},
	{keyword: "terminate", actionType: "account_termination", description: "Account or service termination", severity: "high"},
	{keyword: "deactivate_all", actionType: "account_termination", description: "Mass account deactivation", severity: "high"},
	{keyword: "revoke_all", actionType: "account_termination", description: "Mass credential revocation", severity: "high"},
	{keyword: "delete_account", actionType: "account_termination", description: "Account deletion", severity: "high"},
	{keyword: "unsubscribe_all", actionType: "account_termination", description: "Mass unsubscription", severity: "high"},

	// ── High: Non-DELETE-verb destructive operations ─────────────────────
	// These operations achieve destructive outcomes via PATCH/POST/PUT without
	// ever issuing an HTTP DELETE — the exact class that bypasses the DELETE-verb
	// gate. The staging-debug-agent scenario exploits this: a PATCH to a
	// lifecycle endpoint can delete volumes, expire backups, or disable
	// retention policies, none of which use the DELETE method.
	{keyword: "lifecycle_policy", actionType: "configuration_reset", description: "Lifecycle policy modification — may trigger automatic data deletion", severity: "high"},
	{keyword: "lifecycle_config", actionType: "configuration_reset", description: "Lifecycle configuration change — controls data retention and expiry", severity: "high"},
	{keyword: "lifecycle_rule", actionType: "configuration_reset", description: "Lifecycle rule modification — may schedule data for automatic deletion", severity: "high"},
	{keyword: "lifecycle", actionType: "configuration_reset", description: "Lifecycle endpoint access — may modify retention or expiry rules", severity: "high"},
	{keyword: "soft_delete", actionType: "data_deletion", description: "Soft-delete operation — marks records for deferred permanent deletion", severity: "high"},
	{keyword: "soft-delete", actionType: "data_deletion", description: "Soft-delete operation — marks records for deferred permanent deletion", severity: "high"},
	{keyword: "bulk_soft_delete", actionType: "data_deletion", description: "Bulk soft-delete — marks multiple records for deferred deletion", severity: "high"},
	{keyword: "expire", actionType: "configuration_reset", description: "Expiration trigger — may cause data or credential invalidation", severity: "high"},
	{keyword: "retention_policy", actionType: "configuration_reset", description: "Retention policy change — controls how long data is preserved", severity: "high"},
	{keyword: "disable_protection", actionType: "configuration_reset", description: "Protection disable — removes safeguards against deletion", severity: "high"},
	{keyword: "disable_versioning", actionType: "configuration_reset", description: "Versioning disable — removes rollback capability for data", severity: "high"},
	{keyword: "suspend_backup", actionType: "configuration_reset", description: "Backup suspension — stops automated backup schedules", severity: "high"},
	{keyword: "delete_snapshot", actionType: "data_deletion", description: "Snapshot deletion — removes point-in-time recovery data", severity: "high"},

	// ── Medium: Potentially destructive operations ───────────────────────
	{keyword: "reset", actionType: "configuration_reset", description: "Configuration or data reset", severity: "medium"},
	{keyword: "overwrite", actionType: "data_deletion", description: "Data overwrite — replaces existing data", severity: "medium"},
	{keyword: "force_update", actionType: "data_deletion", description: "Force update — bypasses normal validation", severity: "medium"},
	{keyword: "rollback", actionType: "configuration_reset", description: "Data rollback operation", severity: "medium"},
	{keyword: "clear_cache", actionType: "configuration_reset", description: "Cache clear operation", severity: "medium"},
	{keyword: "flush", actionType: "configuration_reset", description: "Data flush operation", severity: "medium"},
}

// ClassifyDestructiveAction analyses the target URL and payload to determine
// if the request represents a destructive operation and, if so, what type.
//
// Parameters:
//   - httpMethod: the HTTP method (DELETE, POST, PUT, etc.)
//   - targetURL: the full target URL
//   - payloadPreview: first N characters of the request body
//
// Returns DestructiveActionInfo with IsDestructive=false if no patterns match.
func ClassifyDestructiveAction(httpMethod, targetURL, payloadPreview string) DestructiveActionInfo {
	// DELETE method is inherently destructive — always flag it
	methodUpper := strings.ToUpper(httpMethod)
	if methodUpper == "DELETE" {
		// Even without keyword matches, a DELETE is destructive.
		// Check for additional patterns to refine the classification.
		info := checkPatterns(targetURL, payloadPreview)
		if info.IsDestructive {
			// Pattern match enhances the DELETE classification
			return info
		}
		// Generic DELETE — still destructive but lower severity
		return DestructiveActionInfo{
			IsDestructive:     true,
			ActionType:        "data_deletion",
			ActionDescription: "HTTP DELETE request to " + truncateURL(targetURL),
			Severity:          "high",
			MatchedPattern:    "HTTP DELETE method",
		}
	}

	// For non-DELETE methods, check URL and payload against known patterns
	return checkPatterns(targetURL, payloadPreview)
}

// checkPatterns scans the target URL and payload against knownDestructivePatterns.
// Returns the first match found (patterns are ordered by severity, most critical first).
func checkPatterns(targetURL, payloadPreview string) DestructiveActionInfo {
	searchText := strings.ToLower(targetURL + " " + payloadPreview)

	for _, p := range knownDestructivePatterns {
		if strings.Contains(searchText, p.keyword) {
			return DestructiveActionInfo{
				IsDestructive:     true,
				ActionType:        p.actionType,
				ActionDescription: p.description,
				Severity:          p.severity,
				MatchedPattern:    p.keyword,
			}
		}
	}

	return DestructiveActionInfo{IsDestructive: false}
}

// truncateURL shortens a URL for display purposes without exposing query params.
func truncateURL(url string) string {
	if len(url) <= 80 {
		return url
	}
	// Strip query params
	if idx := strings.Index(url, "?"); idx != -1 {
		url = url[:idx]
	}
	if len(url) > 80 {
		return url[:77] + "..."
	}
	return url
}
