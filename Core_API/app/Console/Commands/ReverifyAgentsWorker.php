<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
namespace App\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use App\Models\Agent;

class ReverifyAgentsWorker extends Command
{
    protected $signature = 'cicada:reverify-agents';
    protected $description = 'Periodically re-verify active agents through the multi-agent swarm';

    public function handle(): int
    {
        // Eager-load active tools to eliminate the N+1 query pattern.
        $agents = Agent::active()
            ->verified()
            ->where('verified_at', '<', now()->subDays(7))
            ->with(['tools' => fn($q) => $q->active()])
            ->limit(50)
            ->get();

        if ($agents->isEmpty()) {
            $this->info('[REVERIFY] No agents need re-verification at this time.');
            return Command::SUCCESS;
        }

        $swarmUrl = rtrim(config('cicada.swarm_url'), '/');

        foreach ($agents as $agent) {
            $this->info("[REVERIFY] Queuing verification for agent {$agent->id} ({$agent->name})");

            // Tools are already loaded — no additional query per agent.
            $tools = $agent->tools->map(fn($t) => [
                'tool_id'          => $t->tool_id,
                'tool_name'        => $t->tool_name,
                'tool_description' => $t->tool_description,
            ])->toArray();

            $payload = [
                'tenant_id' => $agent->tenant_id,
                'agent_id' => $agent->id,
                'payload' => [
                    'agent_id' => $agent->id,
                    'agent_name' => $agent->name,
                    'description' => $agent->description ?? '',
                    'scopes' => $agent->scope_entitlements ?? [],
                    'tools' => $tools,
                    'agent_type' => $agent->agent_type ?? 'reactive',
                    'role' => $agent->role ?? 'autonomous',
                    'declared_purpose' => $agent->declared_purpose ?? '',
                    'target_model' => 'gpt-4o',
                    'expected_velocity' => $agent->expected_velocity,
                    'monthly_budget_usd' => $agent->monthly_budget_usd,
                    'ghost_mode_allowed' => $agent->ghost_mode_allowed,
                    'owner_name' => $agent->owner_name,
                    'business_unit' => $agent->business_unit,
                    'regulatory_frameworks' => $agent->regulatory_frameworks ?? [],
                ],
                'llm_model' => 'gpt-4o-mini',
                'budget_exhaustion_fallback' => 'fail_open' // Background checks should fail open so active agents aren't suddenly blocked
            ];

            // Priority queuing for critical HITL agents
            $queue = 'cicada_swarm_queue_low';
            if ($agent->trust_tier === 'restricted' || in_array('proxy:write', $payload['payload']['scopes'] ?? []) || in_array('proxy:transact', $payload['payload']['scopes'] ?? [])) {
                $queue = 'cicada_swarm_queue_high';
                $this->info("[REVERIFY] Routing agent {$agent->id} to HIGH priority queue");
            }

            try {
                \Illuminate\Support\Facades\Redis::lpush($queue, json_encode($payload));
                $this->info("[REVERIFY] Agent {$agent->id} pushed to {$queue}");
            } catch (\Exception $e) {
                $this->error("[REVERIFY] Exception queuing agent {$agent->id}: {$e->getMessage()}");
            }
        }

        $this->info('[REVERIFY] Re-verification cycle complete.');
        return Command::SUCCESS;
    }
}
