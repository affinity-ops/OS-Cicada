<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

/**
 * Schema Consolidation — Certification Events Table
 *
 * Creates the certification_events table that was previously managed by
 * the Sentry Gateway's Go migration 015_certification_lifecycle.sql.
 *
 * This table stores the immutable audit trail for agent certification
 * lifecycle transitions (certified → suspended → terminated → recertified).
 *
 * Used by:
 *   - Core_API: CertificationLifecycleController (write)
 *   - Sentry_Gateway: proxy enforcement (read — checks approval_status)
 *   - Gateway_Portal: Agent Registry UI (read — displays certification history)
 *
 * @see Sentry_Gateway/migrations/015_certification_lifecycle.sql
 */
return new class extends Migration
{
    public function up(): void
    {
        DB::statement("
            CREATE TABLE IF NOT EXISTS certification_events (
                id UUID NOT NULL DEFAULT gen_random_uuid(),
                agent_id UUID NOT NULL,
                tenant_id UUID NOT NULL,
                event_type TEXT NOT NULL,
                performed_by TEXT NOT NULL,
                reason TEXT,
                metadata JSONB DEFAULT '{}'::jsonb,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                PRIMARY KEY (id)
            )
        ");

        DB::statement("CREATE INDEX IF NOT EXISTS idx_cert_events_agent ON certification_events(agent_id, created_at DESC)");
        DB::statement("CREATE INDEX IF NOT EXISTS idx_cert_events_tenant ON certification_events(tenant_id, created_at DESC)");
    }

    public function down(): void
    {
        DB::statement("DROP TABLE IF EXISTS certification_events");
    }
};
