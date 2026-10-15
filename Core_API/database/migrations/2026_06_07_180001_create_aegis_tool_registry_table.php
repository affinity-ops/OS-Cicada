<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Aegis Tool Registry — operator-configurable MCP tool settings.
 * Mirrors the 12 tools defined in mcpserver.go with per-tool controls.
 */
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Facades\DB;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('aegis_tool_registry', function (Blueprint $table) {
            $table->uuid('id')->primary()->default(DB::raw('gen_random_uuid()'));
            $table->string('tool_name')->unique();
            $table->string('display_name');
            $table->text('description')->nullable();
            $table->string('category');           // telemetry | registry | control | policy
            $table->boolean('is_enabled')->default(true);
            $table->boolean('requires_hitl')->default(false);
            $table->integer('max_per_hour')->nullable();
            $table->jsonb('conditions')->default('{}');
            $table->timestamps();
        });

        // Seed from the 12 MCP tools in mcpserver.go
        $tools = [
            // Telemetry — read-only, always enabled, no HITL
            ['tool_name' => 'get_threat_signals',    'display_name' => 'Get Threat Signals',     'description' => 'Returns aggregated anomaly counts across V01–V10 threat vectors.',                                       'category' => 'telemetry', 'is_enabled' => true,  'requires_hitl' => false, 'max_per_hour' => null],
            ['tool_name' => 'get_agent_velocity',    'display_name' => 'Get Agent Velocity',     'description' => 'Returns current write/delete call rate for a specific agent.',                                            'category' => 'telemetry', 'is_enabled' => true,  'requires_hitl' => false, 'max_per_hour' => null],
            ['tool_name' => 'list_quarantined',      'display_name' => 'List Quarantined',       'description' => 'Lists all agent IDs currently quarantined across gateway nodes.',                                         'category' => 'telemetry', 'is_enabled' => true,  'requires_hitl' => false, 'max_per_hour' => null],

            // Registry — read-only, always enabled, no HITL
            ['tool_name' => 'get_agent',             'display_name' => 'Get Agent',              'description' => 'Retrieves full agent record including trust tier, role, and revocation state.',                            'category' => 'registry',  'is_enabled' => true,  'requires_hitl' => false, 'max_per_hour' => null],
            ['tool_name' => 'get_tenant',            'display_name' => 'Get Tenant',             'description' => 'Retrieves tenant record including plan, status, and company details.',                                    'category' => 'registry',  'is_enabled' => true,  'requires_hitl' => false, 'max_per_hour' => null],

            // Control — privileged, enabled by default, HITL on the destructive ones
            ['tool_name' => 'quarantine_agent',      'display_name' => 'Quarantine Agent',       'description' => 'Blocks an agent immediately across all gateway nodes via gossip mesh.',                                   'category' => 'control',   'is_enabled' => true,  'requires_hitl' => false, 'max_per_hour' => 10],
            ['tool_name' => 'release_agent',         'display_name' => 'Release Agent',          'description' => 'Releases a previously quarantined agent.',                                                                'category' => 'control',   'is_enabled' => true,  'requires_hitl' => false, 'max_per_hour' => null],
            ['tool_name' => 'trigger_rollback',      'display_name' => 'Trigger Rollback',       'description' => 'Enqueues a saga compensating transaction to reverse a harmful action.',                                   'category' => 'control',   'is_enabled' => true,  'requires_hitl' => true,  'max_per_hour' => 5],
            ['tool_name' => 'engage_ghost_mode',     'display_name' => 'Engage Ghost Mode',      'description' => 'Silently diverts agent traffic to sandbox — agent does not know it is redirected.',                        'category' => 'control',   'is_enabled' => true,  'requires_hitl' => true,  'max_per_hour' => 5],
            ['tool_name' => 'release_ghost_mode',    'display_name' => 'Release Ghost Mode',     'description' => 'Returns agent from shadow sandbox to normal routing.',                                                    'category' => 'control',   'is_enabled' => true,  'requires_hitl' => false, 'max_per_hour' => null],

            // Policy — high impact, HITL required
            ['tool_name' => 'submit_policy_revision','display_name' => 'Submit Policy Revision', 'description' => 'Creates a new inactive version of an OPA Rego security policy.',                                          'category' => 'policy',    'is_enabled' => true,  'requires_hitl' => true,  'max_per_hour' => 3],
            ['tool_name' => 'activate_policy',       'display_name' => 'Activate Policy',        'description' => 'Hot-reloads a specific policy version to take immediate effect across all nodes.',                         'category' => 'policy',    'is_enabled' => true,  'requires_hitl' => true,  'max_per_hour' => 3],
        ];

        foreach ($tools as $tool) {
            DB::table('aegis_tool_registry')->insert(array_merge($tool, [
                'conditions'  => '{}',
                'created_at'  => now(),
                'updated_at'  => now(),
            ]));
        }
    }

    public function down(): void
    {
        Schema::dropIfExists('aegis_tool_registry');
    }
};
