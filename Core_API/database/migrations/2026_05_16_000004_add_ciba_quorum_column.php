<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

/**
 * Schema Consolidation — CIBA Quorum Enforcement
 *
 * Adds the required_votes column to ciba_authorization_requests.
 * This was added by Go migration 009_quorum_enforcement.sql to support
 * multi-device quorum voting for high-risk CIBA operations.
 *
 * @see Sentry_Gateway/migrations/009_quorum_enforcement.sql
 */
return new class extends Migration
{
    public function up(): void
    {
        DB::statement("ALTER TABLE ciba_authorization_requests ADD COLUMN IF NOT EXISTS required_votes INTEGER NOT NULL DEFAULT 1");
    }

    public function down(): void
    {
        DB::statement("ALTER TABLE ciba_authorization_requests DROP COLUMN IF EXISTS required_votes");
    }
};
