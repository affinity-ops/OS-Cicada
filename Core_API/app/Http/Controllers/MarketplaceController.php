<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

class MarketplaceController extends Controller
{
    /**
     * List all published templates.
     */
    public function index(Request $request)
    {
        $query = DB::table('agent_templates')
            ->where('status', 'published')
            ->orderBy('is_verified', 'desc')
            ->orderBy('import_count', 'desc');
            
        // Optional search filter
        if ($request->has('search')) {
            $search = '%' . strtolower($request->query('search')) . '%';
            $query->whereRaw('LOWER(name) LIKE ?', [$search])
                  ->orWhereRaw('LOWER(description) LIKE ?', [$search]);
        }

        return response()->json([
            'status' => 'success',
            'data'   => [
                'templates' => $query->get()
            ],
        ]);
    }

    /**
     * Import a template as a new Draft Agent for the current tenant.
     */
    public function import(Request $request, string $id)
    {
        $tenantId = $request->attributes->get('portal_tenant_id');
        if (!$tenantId) {
            return response()->json(['status' => 'error', 'message' => 'Unauthorized'], 401);
        }

        $template = DB::table('agent_templates')->where('id', $id)->first();
        if (!$template || $template->status !== 'published') {
            return response()->json(['status' => 'error', 'message' => 'Template not found'], 404);
        }

        // Create a new agent record based on the template
        $newAgentId = (string) Str::uuid();
        
        DB::transaction(function() use ($template, $newAgentId, $tenantId) {
            DB::table('agents')->insert([
                'id' => $newAgentId,
                'tenant_id' => $tenantId,
                'name' => 'Imported: ' . $template->name,
                'description' => $template->description,
                'agent_type' => $template->agent_type,
                'role' => $template->role,
                'scope_entitlements' => $template->scopes ?? json_encode([]),
                'custom_guardrails' => $template->custom_guardrails,
                'trust_tier' => 'unverified',
                'approval_status' => 'pending_review',
                'pub_key_hash' => 'pending_registration',
                'created_at' => now(),
                'updated_at' => now()
            ]);
            
            DB::table('agent_templates')->where('id', $template->id)->increment('import_count');
        });

        \App\Services\AuditService::log(
            $request,
            'marketplace_template_imported',
            'agent_templates',
            $template->id,
            null,
            ['new_agent_id' => $newAgentId],
            "Tenant imported template '{$template->name}'"
        );

        return response()->json([
            'status' => 'success',
            'message' => 'Template imported successfully. Agent is now pending review.',
            'agent_id' => $newAgentId
        ], 201);
    }

    /**
     * Publish an existing agent configuration as a new template to the Marketplace.
     */
    public function publish(Request $request)
    {
        $tenantId = $request->attributes->get('portal_tenant_id');
        if (!$tenantId) {
            return response()->json(['status' => 'error', 'message' => 'Unauthorized'], 401);
        }

        $validated = $request->validate([
            'agent_id'    => 'required|uuid',
            'name'        => 'required|string|max:255',
            'description' => 'required|string',
        ]);

        // Ensure the agent exists and belongs to the tenant
        $agent = DB::table('agents')->where('id', $validated['agent_id'])->where('tenant_id', $tenantId)->first();
        if (!$agent) {
            return response()->json(['status' => 'error', 'message' => 'Agent not found'], 404);
        }

        $templateId = (string) Str::uuid();

        DB::table('agent_templates')->insert([
            'id' => $templateId,
            'name' => $validated['name'],
            'description' => $validated['description'],
            'agent_type' => $agent->agent_type,
            'role' => $agent->role,
            'scopes' => $agent->scope_entitlements,
            'custom_guardrails' => $agent->custom_guardrails,
            'tools' => json_encode([]),
            'author_tenant_id' => $tenantId,
            'is_verified' => false,
            'status' => 'published',
            'created_at' => now(),
            'updated_at' => now()
        ]);

        \App\Services\AuditService::log(
            $request,
            'marketplace_template_published',
            'agent_templates',
            $templateId,
            null,
            ['agent_id' => $agent->id],
            "Tenant published agent '{$agent->name}' as a marketplace template"
        );

        return response()->json([
            'status' => 'success',
            'message' => 'Template published to the marketplace successfully.',
            'template_id' => $templateId
        ], 201);
    }
}
