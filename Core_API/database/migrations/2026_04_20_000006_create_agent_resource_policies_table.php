<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

// Fine-Grained Authorization (FGA) resource policies per agent.
//
// Scope entitlements (proxy:write etc.) are coarse: they grant a category of
// action. Resource policies are precise: they grant a specific HTTP method on a
// specific URL pattern. An agent with proxy:write may update a user profile but
// must not delete all records — resource_pattern + allowed_methods expresses
// that boundary.
//
// resource_pattern uses a single trailing-wildcard glob (e.g.
// "https://api.stripe.com/v1/charges*"). Full regex is intentionally not
// supported: it avoids catastrophic backtracking and is easier for developers
// to reason about.
//
// Backwards compatible: if an agent has no rows here, the Gateway falls back
// to scope-only enforcement so existing agents are unaffected.
return new class extends Migration
{
    public function up(): void
    {
        DB::statement("
            CREATE TABLE IF NOT EXISTS agent_resource_policies (
                id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                agent_id          UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
                resource_pattern  VARCHAR(500) NOT NULL,
                allowed_methods   JSONB NOT NULL DEFAULT '[\"GET\"]',
                active            BOOLEAN NOT NULL DEFAULT TRUE,
                created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        ");
        DB::statement('CREATE INDEX IF NOT EXISTS idx_arp_agent_id ON agent_resource_policies (agent_id)');
    }

    public function down(): void
    {
        DB::statement('DROP TABLE IF EXISTS agent_resource_policies');
    }
};
