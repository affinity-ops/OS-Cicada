<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Closes schema drift between cicada_ledger (production) and cicada_test.
 *
 * Root cause: user_agent and session_id were added to cicada_ledger via ad-hoc
 * ALTER TABLE but never recorded in a Laravel migration. The test DB, which is
 * built from migrations only, was missing these columns, causing AuditService
 * inserts to crash with SQLSTATE[42703].
 *
 * Similarly, saga_revert_route was added to the agents table in production but
 * never migrated. The schema parity check (verify-schema-parity.sh --ci)
 * flagged both drifts.
 *
 * Uses hasColumn() guards so this migration is safe to run on databases where
 * the columns already exist (idempotent).
 */
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        // ── operator_audit_log: add SOC2 tracking columns ────────────────
        Schema::table('operator_audit_log', function (Blueprint $table) {
            if (!Schema::hasColumn('operator_audit_log', 'user_agent')) {
                $table->text('user_agent')->nullable()->after('ip_address');
            }
            if (!Schema::hasColumn('operator_audit_log', 'session_id')) {
                $table->string('session_id', 255)->nullable()->after('user_agent');
            }
        });

        // ── agents: add saga_revert_route ────────────────────────────────
        Schema::table('agents', function (Blueprint $table) {
            if (!Schema::hasColumn('agents', 'saga_revert_route')) {
                $table->text('saga_revert_route')->nullable()->after('hitl_timeout_hours');
            }
        });
    }

    public function down(): void
    {
        Schema::table('operator_audit_log', function (Blueprint $table) {
            $table->dropColumn(['user_agent', 'session_id']);
        });

        Schema::table('agents', function (Blueprint $table) {
            $table->dropColumn('saga_revert_route');
        });
    }
};
