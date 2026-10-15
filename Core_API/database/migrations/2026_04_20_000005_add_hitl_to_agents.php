<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

// Adds Human-in-the-Loop (HITL) fields to the agents table.
//
// hitl_enabled is opt-in (default false) because HITL adds human response time
// (up to 60 seconds) to every write/transact call. Developers consciously
// accept that tradeoff for agents where the audit requirement outweighs speed.
//
// hitl_webhook_url is the developer-provided endpoint the Gateway POSTs to when
// HITL is triggered. The response must be {"approved": bool} within 60 seconds;
// timeout is treated as rejection to prevent indefinitely stalled sessions.
return new class extends Migration
{
    public function up(): void
    {
        if (!$this->columnExists('agents', 'hitl_enabled')) {
            DB::statement('ALTER TABLE agents ADD COLUMN hitl_enabled BOOLEAN NOT NULL DEFAULT FALSE');
        }
        if (!$this->columnExists('agents', 'hitl_webhook_url')) {
            DB::statement('ALTER TABLE agents ADD COLUMN hitl_webhook_url TEXT NULL');
        }
    }

    public function down(): void
    {
        DB::statement('ALTER TABLE agents DROP COLUMN IF EXISTS hitl_enabled');
        DB::statement('ALTER TABLE agents DROP COLUMN IF EXISTS hitl_webhook_url');
    }

    private function columnExists(string $table, string $column): bool
    {
        return DB::select(
            "SELECT 1 FROM information_schema.columns
              WHERE table_name = ? AND column_name = ?",
            [$table, $column]
        ) !== [];
    }
};
