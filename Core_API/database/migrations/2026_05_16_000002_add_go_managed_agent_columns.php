<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

/**
 * Schema Consolidation — Go-Managed Agent Columns
 *
 * Adds 11 columns to the agents table that were previously created by
 * the Sentry Gateway's Go migration system (migrations 002, 015, 016).
 *
 * All statements use ADD COLUMN IF NOT EXISTS for production safety.
 *
 * Columns added:
 *   Swarm verification:   swarm_confidence_score, swarm_verdict, swarm_reasons, verified_at
 *   Ghost mode:           ghost_mode_allowed
 *   EVAR lifecycle:       evar_issued_at, evar_expires_at, evar_rotation_count,
 *                         evar_last_rotated_at, evar_rotation_status
 *   Certification:        approval_status
 *
 * @see Sentry_Gateway/migrations/002_ghost_mode_consent.sql
 * @see Sentry_Gateway/migrations/015_certification_lifecycle.sql
 * @see Sentry_Gateway/migrations/016_provisioning_governance_columns.sql
 */
return new class extends Migration
{
    public function up(): void
    {
        // ── Swarm verification fields (Go migration 016) ────────────────
        DB::statement("ALTER TABLE agents ADD COLUMN IF NOT EXISTS swarm_confidence_score NUMERIC(5,4)");
        DB::statement("ALTER TABLE agents ADD COLUMN IF NOT EXISTS swarm_verdict VARCHAR(50)");
        DB::statement("ALTER TABLE agents ADD COLUMN IF NOT EXISTS swarm_reasons JSONB");
        DB::statement("ALTER TABLE agents ADD COLUMN IF NOT EXISTS verified_at TIMESTAMPTZ");

        // ── Ghost mode consent (Go migration 002) ───────────────────────
        DB::statement("ALTER TABLE agents ADD COLUMN IF NOT EXISTS ghost_mode_allowed BOOLEAN NOT NULL DEFAULT FALSE");

        // ── EVAR lifecycle (Go migration 015) ───────────────────────────
        DB::statement("ALTER TABLE agents ADD COLUMN IF NOT EXISTS evar_issued_at TIMESTAMPTZ");
        DB::statement("ALTER TABLE agents ADD COLUMN IF NOT EXISTS evar_expires_at TIMESTAMPTZ");
        DB::statement("ALTER TABLE agents ADD COLUMN IF NOT EXISTS evar_rotation_count INTEGER NOT NULL DEFAULT 0");
        DB::statement("ALTER TABLE agents ADD COLUMN IF NOT EXISTS evar_last_rotated_at TIMESTAMPTZ");
        DB::statement("ALTER TABLE agents ADD COLUMN IF NOT EXISTS evar_rotation_status VARCHAR(50) DEFAULT 'active'");

        // ── Certification status (Go migration 015) ─────────────────────
        DB::statement("ALTER TABLE agents ADD COLUMN IF NOT EXISTS approval_status TEXT NOT NULL DEFAULT 'pending_review'");
    }

    public function down(): void
    {
        $columns = [
            'swarm_confidence_score', 'swarm_verdict', 'swarm_reasons', 'verified_at',
            'ghost_mode_allowed',
            'evar_issued_at', 'evar_expires_at', 'evar_rotation_count',
            'evar_last_rotated_at', 'evar_rotation_status',
            'approval_status',
        ];

        foreach ($columns as $col) {
            DB::statement("ALTER TABLE agents DROP COLUMN IF EXISTS {$col}");
        }
    }
};
