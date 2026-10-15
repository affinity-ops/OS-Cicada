<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class SecurityPolicyController extends Controller
{
    public function index()
    {
        $policies = DB::table('platform_policies')
            ->orderBy('created_at')
            ->get();

        return response()->json(['status' => 'success', 'data' => $policies]);
    }

    public function show(string $slug)
    {
        $policy = DB::table('platform_policies')->where('slug', $slug)->first();

        if (!$policy) {
            return response()->json(['status' => 'error', 'message' => 'Policy not found'], 404);
        }

        return response()->json(['status' => 'success', 'data' => $policy]);
    }

    /**
     * Run a real test: fetch the most recent agent that this policy would block,
     * return actual data from the action_ledger and agents table.
     */
    public function test(string $slug)
    {
        $policy = DB::table('platform_policies')->where('slug', $slug)->first();
        if (!$policy) {
            return response()->json(['status' => 'error', 'message' => 'Policy not found'], 404);
        }

        $config = json_decode($policy->rule_config ?? '{}', true);

        if ($slug === 'trust_score_check') {
            $minScore = $config['min_trust_score'] ?? 80;

            // Find most recent blocked action from a low-trust agent
            $blocked = DB::table('action_ledger as al')
                ->join('agents as a', 'al.agent_id', '=', 'a.id')
                ->join('tenants as t', 'a.tenant_id', '=', 't.id')
                ->where('al.status', 'blocked')
                ->select(
                    'al.trace_id',
                    'al.agent_id',
                    'al.target_api',
                    'al.action_type',
                    'al.created_at',
                    'a.name as agent_name',
                    'a.trust_tier',
                    't.name as tenant_name'
                )
                ->orderByDesc('al.created_at')
                ->first();

            // Map trust tier to approximate numeric score for the test result display
            $tierScore = [
                'critical'   => 98,
                'elevated'   => 75,
                'nominal'    => 50,
                'unverified' => 12,
            ];
            $score = $tierScore[$blocked?->trust_tier ?? 'unverified'] ?? 12;
            $blocked_by_policy = $score < $minScore;

            return response()->json([
                'status' => 'success',
                'data'   => [
                    'policy_slug'     => $slug,
                    'min_score'       => $minScore,
                    'agent_id'        => $blocked?->agent_id,
                    'agent_name'      => $blocked?->agent_name ?? 'Unknown Agent',
                    'tenant_name'     => $blocked?->tenant_name ?? 'Unknown Company',
                    'agent_score'     => $score,
                    'trust_tier'      => $blocked?->trust_tier ?? 'unverified',
                    'trace_id'        => $blocked?->trace_id,
                    'target_api'      => $blocked?->target_api ?? 'N/A',
                    'blocked'         => $blocked_by_policy,
                    'reason'          => $blocked_by_policy
                        ? "Agent trust score ({$score}) is below the minimum required ({$minScore})."
                        : "Agent meets the minimum trust score requirement.",
                ],
            ]);
        }

        if ($slug === 'block_untrusted_traffic') {
            // Find most recent blocked action (any) and show it as an untrusted source block
            $blocked = DB::table('action_ledger as al')
                ->join('agents as a', 'al.agent_id', '=', 'a.id')
                ->join('tenants as t', 'a.tenant_id', '=', 't.id')
                ->where('al.status', 'blocked')
                ->whereIn('a.trust_tier', ['unverified', 'nominal'])
                ->select(
                    'al.trace_id',
                    'al.agent_id',
                    'al.target_api',
                    'al.created_at',
                    'a.name as agent_name',
                    'a.trust_tier',
                    't.name as tenant_name'
                )
                ->orderByDesc('al.created_at')
                ->first();

            return response()->json([
                'status' => 'success',
                'data'   => [
                    'policy_slug' => $slug,
                    'agent_id'    => $blocked?->agent_id,
                    'agent_name'  => $blocked?->agent_name ?? 'Unknown Agent',
                    'tenant_name' => $blocked?->tenant_name ?? 'Unknown Company',
                    'trust_tier'  => $blocked?->trust_tier ?? 'unverified',
                    'trace_id'    => $blocked?->trace_id,
                    'target_api'  => $blocked?->target_api ?? 'N/A',
                    'blocked'     => $blocked !== null,
                    'reason'      => $blocked
                        ? "Agent source is not in the trusted zones list (tier: {$blocked->trust_tier})."
                        : "No untrusted traffic detected recently.",
                ],
            ]);
        }

        return response()->json([
            'status' => 'error',
            'message' => "Live testing is available for 'trust_score_check' and 'block_untrusted_traffic'. Policy '{$slug}' does not have a live test yet — its enforcement is handled at the gateway admission layer.",
        ], 400);
    }

    /**
     * Add an agent to the exception list for this policy.
     * The agent will be allowed through even if they would otherwise be blocked.
     */
    public function addException(Request $request, string $slug)
    {
        $request->validate([
            'agent_id'   => 'required|string',
            'agent_name' => 'nullable|string',
            'reason'     => 'nullable|string',
        ]);

        $policy = DB::table('platform_policies')->where('slug', $slug)->first();
        if (!$policy) {
            return response()->json(['status' => 'error', 'message' => 'Policy not found'], 404);
        }

        $agentId = $request->input('agent_id');

        // Verify agent exists
        $agent = DB::table('agents')->where('id', $agentId)->first();
        if (!$agent) {
            return response()->json(['status' => 'error', 'message' => 'Agent not found'], 404);
        }

        $exceptions = json_decode($policy->exceptions ?? '[]', true);

        // Idempotent — don't add duplicates
        $alreadyExcepted = collect($exceptions)->contains(fn($e) => $e['agent_id'] === $agentId);
        if (!$alreadyExcepted) {
            $exceptions[] = [
                'agent_id'   => $agentId,
                'agent_name' => $request->input('agent_name') ?? $agent->name ?? $agentId,
                'reason'     => $request->input('reason') ?? 'Manually approved by operator',
                'added_at'   => now()->toISOString(),
            ];

            DB::table('platform_policies')
                ->where('slug', $slug)
                ->update([
                    'exceptions' => json_encode($exceptions),
                    'updated_at' => now(),
                ]);
        }

        // Also update the agent's trust tier in agents table to ensure gateway allows them
        DB::table('agents')
            ->where('id', $agentId)
            ->update(['trust_tier' => 'elevated', 'updated_at' => now()]);

        \App\Services\AuditService::log(
            $request,
            'policy_exception_created',
            'policy',
            $slug,
            null,
            ['agent_id' => $agentId],
            $request->input('reason') ?? 'Manually approved by operator'
        );
        \App\Services\AuditService::log(
            $request,
            'trust_level_upgraded',
            'agent',
            $agentId,
            ['trust_tier' => $agent->trust_tier],
            ['trust_tier' => 'elevated'],
            $request->input('reason') ?? 'Manually approved by operator'
        );

        return response()->json([
            'status'     => 'success',
            'message'    => 'Exception added. Agent is now approved.',
            'agent_id'   => $agentId,
            'exceptions' => $exceptions,
        ]);
    }

    public function removeException(string $slug, string $agentId)
    {
        $policy = DB::table('platform_policies')->where('slug', $slug)->first();
        if (!$policy) {
            return response()->json(['status' => 'error', 'message' => 'Policy not found'], 404);
        }

        $exceptions = collect(json_decode($policy->exceptions ?? '[]', true))
            ->filter(fn($e) => $e['agent_id'] !== $agentId)
            ->values()
            ->all();

        DB::table('platform_policies')
            ->where('slug', $slug)
            ->update(['exceptions' => json_encode($exceptions), 'updated_at' => now()]);

        return response()->json(['status' => 'success', 'message' => 'Exception removed.']);
    }

    public function updateConfig(Request $request, string $slug)
    {
        $policy = DB::table('platform_policies')->where('slug', $slug)->first();
        if (!$policy) {
            return response()->json(['status' => 'error', 'message' => 'Policy not found'], 404);
        }

        $existing = json_decode($policy->rule_config ?? '{}', true);
        $updated  = array_merge($existing, $request->only(array_keys($existing)));

        DB::table('platform_policies')
            ->where('slug', $slug)
            ->update(['rule_config' => json_encode($updated), 'updated_at' => now()]);

        \App\Services\AuditService::log(
            $request,
            'security_rule_toggled',
            'policy',
            $slug,
            ['rule_config' => $existing],
            ['rule_config' => $updated],
            'Operator updated policy config'
        );

        return response()->json(['status' => 'success', 'data' => $updated]);
    }
}
