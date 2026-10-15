<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Aegis Rules — structured operator-defined rules that govern Aegis behaviour.
 * Two-layer enforcement: rules are prepended to the LLM system prompt (soft)
 * AND checked mechanically before any MCP tool executes (hard).
 */
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Facades\DB;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('aegis_rules', function (Blueprint $table) {
            $table->uuid('id')->primary()->default(DB::raw('gen_random_uuid()'));
            $table->string('slug')->unique();
            $table->string('name');
            $table->string('category');       // permission | threshold | scope | escalation | rate_limit | custom
            $table->string('rule_type');       // boolean | numeric | select | text
            $table->jsonb('rule_config');      // { "value": ..., "operator": ... }
            $table->text('description')->nullable();
            $table->boolean('is_active')->default(true);
            $table->boolean('is_system')->default(false); // true = seeded, cannot delete
            $table->integer('priority')->default(0);
            $table->timestamps();
        });

        // Seed the default rule catalogue
        DB::table('aegis_rules')->insert([
            [
                'slug'        => 'require_hitl_ghost_mode',
                'name'        => 'Require HITL for Ghost Mode',
                'category'    => 'escalation',
                'rule_type'   => 'boolean',
                'rule_config' => json_encode(['enabled' => true]),
                'description' => 'Ghost mode diverts live traffic to a sandbox. Require operator approval before engaging.',
                'is_active'   => true,
                'is_system'   => true,
                'priority'    => 100,
                'created_at'  => now(),
                'updated_at'  => now(),
            ],
            [
                'slug'        => 'require_hitl_rollback',
                'name'        => 'Require HITL for Rollbacks',
                'category'    => 'escalation',
                'rule_type'   => 'boolean',
                'rule_config' => json_encode(['enabled' => true]),
                'description' => 'Saga rollbacks reverse completed actions. Require operator approval before triggering.',
                'is_active'   => true,
                'is_system'   => true,
                'priority'    => 100,
                'created_at'  => now(),
                'updated_at'  => now(),
            ],
            [
                'slug'        => 'max_quarantines_per_hour',
                'name'        => 'Max Quarantines Per Hour',
                'category'    => 'rate_limit',
                'rule_type'   => 'numeric',
                'rule_config' => json_encode(['value' => 5]),
                'description' => 'Limit how many agents Aegis can quarantine per hour to prevent mass lockouts.',
                'is_active'   => true,
                'is_system'   => true,
                'priority'    => 90,
                'created_at'  => now(),
                'updated_at'  => now(),
            ],
            [
                'slug'        => 'min_confidence_to_act',
                'name'        => 'Minimum Confidence to Act',
                'category'    => 'threshold',
                'rule_type'   => 'numeric',
                'rule_config' => json_encode(['value' => 85, 'unit' => 'percent']),
                'description' => 'Aegis must report a confidence level above this threshold before taking any control action.',
                'is_active'   => true,
                'is_system'   => true,
                'priority'    => 95,
                'created_at'  => now(),
                'updated_at'  => now(),
            ],
            [
                'slug'        => 'scope_trust_tiers',
                'name'        => 'Allowed Trust Tiers for Auto-Action',
                'category'    => 'scope',
                'rule_type'   => 'select',
                'rule_config' => json_encode(['allowed' => ['monitoring', 'untrusted', 'probation']]),
                'description' => 'Aegis may only auto-act on agents in these trust tiers. Higher-tier agents require HITL.',
                'is_active'   => true,
                'is_system'   => true,
                'priority'    => 85,
                'created_at'  => now(),
                'updated_at'  => now(),
            ],
            [
                'slug'        => 'block_certified_without_hitl',
                'name'        => 'Protect Certified Agents',
                'category'    => 'escalation',
                'rule_type'   => 'boolean',
                'rule_config' => json_encode(['enabled' => true, 'protected_tiers' => ['certified', 'partner']]),
                'description' => 'Never quarantine or ghost-mode a certified/partner agent without operator approval.',
                'is_active'   => true,
                'is_system'   => true,
                'priority'    => 100,
                'created_at'  => now(),
                'updated_at'  => now(),
            ],
        ]);
    }

    public function down(): void
    {
        Schema::dropIfExists('aegis_rules');
    }
};
