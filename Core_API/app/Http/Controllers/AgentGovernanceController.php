<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
namespace App\Http\Controllers;

use App\Models\Agent;
use App\Models\ActionLedger;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use OpenApi\Attributes as OA;

class AgentGovernanceController extends Controller
{
    #[OA\Get(
        path: '/api/v1/agents/{id}/profile',
        summary: 'Get Agent Governance Profile',
        description: 'Returns the full compliance profile and runtime telemetry of an agent.',
        tags: ['Agents']
    )]
    #[OA\Parameter(
        name: 'id',
        description: 'UUID of the agent',
        in: 'path',
        required: true,
        schema: new OA\Schema(type: 'string', format: 'uuid')
    )]
    #[OA\Parameter(
        name: 'cursor',
        description: 'Pagination cursor for the timeline',
        in: 'query',
        required: false,
        schema: new OA\Schema(type: 'string')
    )]
    #[OA\Response(
        response: 200,
        description: 'Agent governance profile returned successfully'
    )]
    #[OA\Response(
        response: 404,
        description: 'Agent not found'
    )]
    public function profile(Request $request, $id)
    {
        $agent = Agent::with(['tenant', 'tools', 'resourcePolicies'])
            ->where('id', $id)
            ->firstOrFail();

        // Use a single query with aggregation for runtime metrics (lightning fast with indexes)
        $metrics = ActionLedger::where('agent_id', $id)
            ->select([
                DB::raw('MAX(created_at) as last_seen'),
                DB::raw('COUNT(*) as total_calls'),
                DB::raw("SUM(CASE WHEN status = 'blocked' THEN 1 ELSE 0 END) as blocked_count"),
                DB::raw("SUM(CASE WHEN created_at > NOW() - INTERVAL '24 HOUR' THEN 1 ELSE 0 END) as calls_24h"),
                DB::raw("SUM(CASE WHEN status = 'blocked' AND created_at > NOW() - INTERVAL '24 HOUR' THEN 1 ELSE 0 END) as blocked_24h"),
                DB::raw('AVG(swarm_confidence_score) as avg_confidence'),
                DB::raw("COALESCE(AVG(CASE WHEN EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='action_ledger' AND column_name='semantic_alignment_score') THEN semantic_alignment_score ELSE NULL END), 0) as avg_semantic")
            ])
            ->first();

        // Timeline: cursor pagination for millions of rows
        $cursor = $request->input('cursor');
        $timeline = ActionLedger::where('agent_id', $id)
            ->orderBy('created_at', 'desc')
            ->cursorPaginate(50, ['*'], 'cursor', $cursor);

        // Tenant API key (masked for security)
        $apiKey = $agent->tenant->keys()->first();
        $provider = $apiKey ? $apiKey->provider : null;

        // Build response
        return response()->json([
            'identity' => [
                'id' => $agent->id,
                'name' => $agent->name,
                'tenant_id' => $agent->tenant_id,
                'tenant_name' => $agent->tenant->name,
                'version' => $agent->version,
                'role' => $agent->role,
                'type' => $agent->agent_type,
                'trust_tier' => $agent->trust_tier,
                'created_at' => $agent->created_at,
                'certified_at' => $agent->certified_at,
                'revoked_at' => $agent->revoked_at,
                'is_quarantined' => !is_null($agent->quarantined_at ?? null), 
            ],
            'purpose' => [
                'description' => $agent->description,
                'declared_purpose' => $agent->declared_purpose,
                'registration_statement' => $agent->registration_purpose_statement,
                'criticality' => $agent->criticality_level,
                'data_classification' => $agent->data_classification,
                'potential_impact' => $agent->potential_impact ? json_decode($agent->potential_impact) : null,
            ],
            'ownership' => [
                'owner_name' => $agent->owner_name,
                'owner_email' => $agent->owner_email,
                'business_unit' => $agent->business_unit,
                'cost_center' => $agent->cost_center,
            ],
            'permissions' => [
                'tools' => $agent->tools->pluck('tool_name'),
                'resource_policies' => $agent->resourcePolicies->map(function($policy) {
                    return [
                        'pattern' => $policy->resource_pattern,
                        'methods' => json_decode($policy->allowed_methods ?? '[]'),
                    ];
                }),
                'custom_guardrails' => $agent->custom_guardrails ? json_decode($agent->custom_guardrails) : null,
            ],
            'governance' => [
                'hitl_enabled' => (bool) $agent->hitl_enabled,
                'hitl_webhook' => $agent->hitl_webhook_url,
                'failure_scope' => $agent->failure_scope ? json_decode($agent->failure_scope) : null,
                'expected_velocity' => $agent->expected_velocity,
                'monthly_budget_usd' => $agent->monthly_budget_usd,
                'regulatory_frameworks' => $agent->regulatory_frameworks ? json_decode($agent->regulatory_frameworks) : null,
            ],
            'runtime' => [
                'last_seen_at' => $metrics->last_seen,
                'total_calls' => $metrics->total_calls,
                'calls_24h' => $metrics->calls_24h ?? 0,
                'block_rate_24h' => $metrics->calls_24h > 0 ? round($metrics->blocked_24h / $metrics->calls_24h, 4) : 0,
                'avg_swarm_confidence' => round($metrics->avg_confidence ?? 0, 2),
                'avg_semantic_alignment' => round($metrics->avg_semantic ?? 0, 2),
                'provider' => $provider,
            ],
            'timeline' => [
                'data' => $timeline->items(),
                'next_cursor' => $timeline->nextCursor()?->encode(),
                'has_more' => $timeline->hasMorePages(),
            ],
        ]);
    }
}
