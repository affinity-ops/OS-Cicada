// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"fmt"
	"log"
	"strings"
)

// SchemaRequirement defines a required table and its critical columns.
// The Gateway will refuse to start if any of these are missing.
type SchemaRequirement struct {
	Table   string
	Columns []string
}

// requiredSchema is the definitive list of tables and columns that the
// Gateway expects to exist. Schema is owned by Laravel migrations
// (Core_API/database/migrations/). If any table or column is missing,
// the Gateway will log a fatal error and refuse to start.
//
// This is a deliberate fail-fast design: a Gateway that boots against
// incomplete schema could silently fail to write audit records, enforce
// certification status, or validate EVAR credentials. A hard crash with
// a clear error message is always preferable to silent data loss.
var requiredSchema = []SchemaRequirement{
	// ── Core governance tables ──────────────────────────────────────
	{
		Table: "tenants",
		Columns: []string{
			"id", "name", "created_at",
		},
	},
	{
		Table: "agents",
		Columns: []string{
			"id", "tenant_id", "pub_key_hash", "scope_entitlements",
			"trust_tier", "revoked_at", "name", "agent_type", "version",
			"role", "ghost_mode_allowed", "approval_status",
			// EVAR lifecycle
			"evar_issued_at", "evar_expires_at", "evar_rotation_count",
			"evar_last_rotated_at", "evar_rotation_status",
			// Swarm verification
			"swarm_confidence_score", "swarm_verdict", "swarm_reasons", "verified_at",
		},
	},
	{
		Table: "action_ledger",
		Columns: []string{
			"tenant_id", "agent_id", "action_type", "payload_hash",
			"target_api", "status", "reasoning_trace", "semantic_alignment_score", "model",
		},
	},
	{
		Table: "tenant_keys",
		Columns: []string{
			"id", "tenant_id", "payload_encrypted",
		},
	},
	{
		Table: "certification_events",
		Columns: []string{
			"id", "agent_id", "tenant_id", "event_type",
			"performed_by", "reason", "metadata", "created_at",
		},
	},

	// ── Operator and audit tables ───────────────────────────────────
	{
		Table: "operator_audit_log",
		Columns: []string{
			"id", "operator_label", "action", "entity_type",
			"entity_id", "before_state", "after_state", "notes",
		},
	},
	{
		Table: "gateway_instances",
		Columns: []string{
			"id", "gateway_id", "last_seen_at",
		},
	},

	// ── Policy governance ───────────────────────────────────────────
	{
		Table: "policy_versions",
		Columns: []string{
			"id", "policy_name", "version", "rego_content",
			"created_by", "active",
		},
	},

	// ── CIBA / Aegis mobile tables ──────────────────────────────────
	{
		Table: "mobile_devices",
		Columns: []string{
			"id", "tenant_id", "ed25519_pub", "x25519_pub",
			"status", "last_heartbeat_at", "ml_dsa65_pub", "ml_kem768_pub",
		},
	},
	{
		Table: "decision_nonces",
		Columns: []string{
			"nonce", "hold_ref", "consumed_at", "expires_at",
		},
	},
	{
		Table: "hold_payloads",
		Columns: []string{
			"hold_ref", "ciphertext", "ephemeral_pub", "nonce",
			"target_device", "expires_at",
		},
	},
	{
		Table: "quorum_votes",
		Columns: []string{
			"id", "hold_ref", "device_fingerprint", "vote", "signature",
		},
	},
	{
		Table: "aegis_devices",
		Columns: []string{
			"id", "operator_evar_id", "tenant_id", "gateway_node_id",
			"device_id", "platform", "is_active",
		},
	},
	{
		Table: "attestation_config",
		Columns: []string{
			"tenant_id", "enforced",
		},
	},

	// ── Credential rotation audit trail ─────────────────────────────
	{
		Table: "credential_rotation_events",
		Columns: []string{
			"id", "agent_id", "tenant_id", "event_type",
			"old_evar_hash", "new_evar_hash", "created_at",
		},
	},
}

// ValidateSchema checks that every required table and column exists in the
// database. If any are missing, it returns a detailed error listing every
// missing element.
//
// This function does NOT create or alter schema. Schema ownership belongs
// to Laravel migrations (Core_API/database/migrations/). If validation
// fails, the operator must run `php artisan migrate` before starting the
// Gateway.
//
// This is a fail-fast safety mechanism. A Gateway that boots against
// incomplete schema could silently fail to write immutable audit records.
// A hard crash with a clear error message is always preferable.
func ValidateSchema(ctx context.Context) error {
	var missing []string

	for _, req := range requiredSchema {
		// Check table exists
		var tableExists bool
		err := DB.QueryRow(ctx,
			`SELECT EXISTS(
				SELECT 1 FROM information_schema.tables
				WHERE table_schema IN ('public', 'sentry') AND table_name = $1
			)`, req.Table,
		).Scan(&tableExists)

		if err != nil {
			return fmt.Errorf("schema validation query failed for table %q: %w", req.Table, err)
		}

		if !tableExists {
			missing = append(missing, fmt.Sprintf("TABLE %s (entire table missing)", req.Table))
			continue // No point checking columns if table doesn't exist
		}

		// Check each required column
		for _, col := range req.Columns {
			var colExists bool
			err := DB.QueryRow(ctx,
				`SELECT EXISTS(
					SELECT 1 FROM information_schema.columns
					WHERE table_schema IN ('public', 'sentry') AND table_name = $1 AND column_name = $2
				)`, req.Table, col,
			).Scan(&colExists)

			if err != nil {
				return fmt.Errorf("schema validation query failed for %s.%s: %w", req.Table, col, err)
			}

			if !colExists {
				missing = append(missing, fmt.Sprintf("COLUMN %s.%s", req.Table, col))
			}
		}
	}

	if len(missing) > 0 {
		log.Printf("[FATAL] ════════════════════════════════════════════════════════")
		log.Printf("[FATAL] SCHEMA VALIDATION FAILED — %d missing element(s):", len(missing))
		log.Printf("[FATAL] ════════════════════════════════════════════════════════")
		for _, m := range missing {
			log.Printf("[FATAL]   ✘ %s", m)
		}
		log.Printf("[FATAL] ════════════════════════════════════════════════════════")
		log.Printf("[FATAL] Schema is owned by Laravel. To fix, run:")
		log.Printf("[FATAL]   cd Core_API && php artisan migrate")
		log.Printf("[FATAL] Then restart the Gateway.")
		log.Printf("[FATAL] ════════════════════════════════════════════════════════")
		return fmt.Errorf("schema validation failed: %d missing elements: %s",
			len(missing), strings.Join(missing, "; "))
	}

	log.Printf("[STORE] ✔ Schema validation passed — %d tables, all columns verified", len(requiredSchema))
	return nil
}
