<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

/**
 * Schema Consolidation — Go-Managed Tables
 *
 * Transfers ownership of 8 tables that were previously created by the Sentry
 * Gateway's Go migration system into the Laravel migration pipeline.
 *
 * All statements use IF NOT EXISTS so this migration is safe to run against
 * production databases where these tables already exist.
 *
 * Tables created:
 *   - mobile_devices        (Aegis companion device registry)
 *   - decision_nonces       (CIBA one-time decision tokens)
 *   - hold_payloads         (Encrypted CIBA hold data)
 *   - quorum_votes          (Multi-device approval votes)
 *   - policy_versions       (OPA Rego policy version history)
 *   - aegis_devices         (Device telemetry registry)
 *   - attestation_config    (Per-tenant attestation settings)
 *   - credential_rotation_events (EVAR rotation immutable audit trail)
 *
 * @see Sentry_Gateway/migrations/ for the original Go SQL files (archived)
 */
return new class extends Migration
{
    public function up(): void
    {
        // STRICT API BOUNDARY: Schema ownership has been returned to the Go Gateway
        // which now manages its own schema in the 'sentry' PostgreSQL namespace.
        // We drop these from the public schema if they exist to prevent drift.
        DB::statement("DROP TRIGGER IF EXISTS trg_rotation_events_immutable ON credential_rotation_events");
        DB::statement("DROP FUNCTION IF EXISTS prevent_rotation_event_updates()");
        DB::statement("DROP TABLE IF EXISTS credential_rotation_events");
        DB::statement("DROP TABLE IF EXISTS attestation_config");
        DB::statement("DROP TABLE IF EXISTS aegis_devices");
        DB::statement("DROP TABLE IF EXISTS policy_versions");
        DB::statement("DROP TABLE IF EXISTS quorum_votes");
        DB::statement("DROP TABLE IF EXISTS hold_payloads");
        DB::statement("DROP TABLE IF EXISTS decision_nonces");
        DB::statement("DROP TABLE IF EXISTS mobile_devices");
    }

    public function down(): void
    {
        // No-op: Gateway creates its own tables on boot
    }
};
