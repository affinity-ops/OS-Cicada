<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

// AgentPolicyController manages Fine-Grained Authorization (FGA) resource
// policies for individual agents. Policies are scoped to the requesting
// tenant — a developer can only manage policies for their own agents.
//
// Resource policies add a precision layer on top of broad scope entitlements:
// an agent with proxy:write scope can be restricted to specific URL patterns
// and HTTP methods, preventing it from writing to any arbitrary endpoint.
class AgentPolicyController extends Controller
{
    // List all resource policies for a given agent.
    public function index(Request $request, string $agentId): \Illuminate\Http\JsonResponse
    {
        $tenantId = $request->attributes->get('portal_tenant_id');

        // Verify the agent belongs to this tenant before exposing its policies
        $agent = DB::table('agents')
            ->where('id', $agentId)
            ->where('tenant_id', $tenantId)
            ->first();

        if (!$agent) {
            return response()->json(['error' => 'Agent not found'], 404);
        }

        $policies = DB::table('agent_resource_policies')
            ->where('agent_id', $agentId)
            ->orderBy('created_at')
            ->get();

        return response()->json(['status' => 'success', 'data' => $policies]);
    }

    // Create a new resource policy for an agent.
    public function store(Request $request, string $agentId): \Illuminate\Http\JsonResponse
    {
        $tenantId = $request->attributes->get('portal_tenant_id');

        $agent = DB::table('agents')
            ->where('id', $agentId)
            ->where('tenant_id', $tenantId)
            ->first();

        if (!$agent) {
            return response()->json(['error' => 'Agent not found'], 404);
        }

        $validated = $request->validate([
            'resource_pattern' => 'required|string|max:500',
            // allowed_methods must be an array of valid HTTP verbs
            'allowed_methods'  => 'required|array|min:1',
            'allowed_methods.*' => 'in:GET,POST,PUT,PATCH,DELETE,HEAD,OPTIONS',
        ]);

        $id = DB::table('agent_resource_policies')->insertGetId([
            'id'               => Str::uuid(),
            'agent_id'         => $agentId,
            'resource_pattern' => $validated['resource_pattern'],
            'allowed_methods'  => json_encode($validated['allowed_methods']),
            'active'           => true,
            'created_at'       => now(),
        ]);

        return response()->json([
            'status' => 'success',
            'data'   => DB::table('agent_resource_policies')->find($id),
        ], 201);
    }

    // Toggle a policy active/inactive without deleting it.
    public function update(Request $request, string $agentId, string $policyId): \Illuminate\Http\JsonResponse
    {
        $tenantId = $request->attributes->get('portal_tenant_id');

        // Verify ownership through agent → tenant chain
        $owned = DB::table('agent_resource_policies')
            ->join('agents', 'agents.id', '=', 'agent_resource_policies.agent_id')
            ->where('agent_resource_policies.id', $policyId)
            ->where('agents.tenant_id', $tenantId)
            ->exists();

        if (!$owned) {
            return response()->json(['error' => 'Policy not found'], 404);
        }

        $validated = $request->validate(['active' => 'required|boolean']);

        DB::table('agent_resource_policies')
            ->where('id', $policyId)
            ->update(['active' => $validated['active']]);

        return response()->json(['status' => 'success']);
    }

    // Delete a resource policy permanently.
    public function destroy(Request $request, string $agentId, string $policyId): \Illuminate\Http\JsonResponse
    {
        $tenantId = $request->attributes->get('portal_tenant_id');

        $deleted = DB::table('agent_resource_policies')
            ->join('agents', 'agents.id', '=', 'agent_resource_policies.agent_id')
            ->where('agent_resource_policies.id', $policyId)
            ->where('agents.tenant_id', $tenantId)
            ->delete();

        if (!$deleted) {
            return response()->json(['error' => 'Policy not found'], 404);
        }

        return response()->json(['status' => 'success']);
    }
}
