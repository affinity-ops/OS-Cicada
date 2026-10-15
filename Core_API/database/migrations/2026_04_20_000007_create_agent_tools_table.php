<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

// Tool registry — declares exactly which callable tools each agent is approved
// to use, independent of its broad scope entitlements.
//
// tool_id follows a namespaced convention: {provider}:{function}, e.g.
// "stripe:create_charge" or "sendgrid:send_email". Namespacing prevents
// collision between providers and makes action_ledger entries human-readable
// without cross-referencing other tables.
//
// The Sentry Gateway embeds the tool list in the JIT session token at issuance
// so individual proxy calls do not need a DB lookup per tool check.
return new class extends Migration
{
    public function up(): void
    {
        DB::statement("
            CREATE TABLE IF NOT EXISTS agent_tools (
                id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                agent_id         UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
                tool_id          VARCHAR(255) NOT NULL,
                tool_name        VARCHAR(255) NOT NULL,
                tool_description TEXT NULL,
                is_active        BOOLEAN NOT NULL DEFAULT TRUE,
                created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                UNIQUE (agent_id, tool_id)
            )
        ");
        DB::statement('CREATE INDEX IF NOT EXISTS idx_agent_tools_agent_id ON agent_tools (agent_id)');
    }

    public function down(): void
    {
        DB::statement('DROP TABLE IF EXISTS agent_tools');
    }
};
