<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

class PortalController extends Controller
{
    // ─── Dashboard Summary ────────────────────────────────────────────────────

    public function summary(Request $request)
    {
        $tenantId = $request->attributes->get('portal_tenant_id');

        $totalAgents       = DB::table('agents')->where('tenant_id', $tenantId)->count();
        $certifiedAgents   = DB::table('agents')->where('tenant_id', $tenantId)->whereNotNull('certified_at')->whereNull('revoked_at')->count();
        $pendingAgents     = DB::table('agents')->where('tenant_id', $tenantId)->whereNull('certified_at')->whereNull('revoked_at')->count();
        $revokedAgents     = DB::table('agents')->where('tenant_id', $tenantId)->whereNotNull('revoked_at')->count();
        $totalTransactions = DB::table('action_ledger')->where('tenant_id', $tenantId)->count();
        $blockedToday      = DB::table('action_ledger')->where('tenant_id', $tenantId)->where('status', 'blocked')->whereDate('created_at', today())->count();

        return response()->json([
            'status' => 'success',
            'data'   => compact('totalAgents', 'certifiedAgents', 'pendingAgents', 'revokedAgents', 'totalTransactions', 'blockedToday'),
        ]);
    }

    // ─── Agent Registry ───────────────────────────────────────────────────────

    public function agents(Request $request)
    {
        $tenantId = $request->attributes->get('portal_tenant_id');

        $agents = DB::table('agents')
            ->where('tenant_id', $tenantId)
            ->orderByDesc('created_at')
            ->get()
            ->map(fn($a) => [
                'id'                     => $a->id,
                'name'                   => $a->name,
                'description'            => $a->description,
                'agent_type'             => $a->agent_type,
                'version'                => $a->version,
                'trust_tier'             => $a->trust_tier,
                'scope_entitlements'     => json_decode($a->scope_entitlements),
                'failure_scope'          => $a->failure_scope ? json_decode($a->failure_scope) : null,
                'certified_at'           => $a->certified_at,
                'recertification_due_at' => $a->recertification_due_at,
                'revoked_at'             => $a->revoked_at,
                'created_at'             => $a->created_at,
                'evar_preview'           => $a->pub_key_hash ? substr($a->pub_key_hash, 0, 40) . '...' : null,
                'status'                 => $this->agentStatus($a),
            ]);

        return response()->json(['status' => 'success', 'data' => ['agents' => $agents]]);
    }

    public function agent(Request $request, string $agentId)
    {
        $tenantId = $request->attributes->get('portal_tenant_id');

        $agent = DB::table('agents')
            ->where('id', $agentId)
            ->where('tenant_id', $tenantId)
            ->first();

        if ($agent) {
            $agent->tools = DB::table('agent_tools')
                ->where('agent_id', $agentId)
                ->get();
        }

        if (!$agent) {
            return response()->json(['status' => 'error', 'message' => 'Agent not found.'], 404);
        }

        $recentTransactions = DB::table('action_ledger')
            ->where('agent_id', $agentId)
            ->orderByDesc('created_at')
            ->limit(10)
            ->get();

        return response()->json([
            'status' => 'success',
            'data'   => [
                'agent'               => $agent,
                'recent_transactions' => $recentTransactions,
            ],
        ]);
    }

    // ─── Traffic ──────────────────────────────────────────────────────────────

    public function trafficOutbound(Request $request)
    {
        $tenantId = $request->attributes->get('portal_tenant_id');
        $page     = max(1, (int) $request->query('page', 1));
        $perPage  = 25;

        $query = DB::table('action_ledger as al')
            ->join('agents as a', 'a.id', '=', 'al.agent_id')
            ->where('al.tenant_id', $tenantId)
            ->select('al.*', 'a.name as agent_name', 'a.agent_type');

        if ($request->query('agent_id')) {
            $query->where('al.agent_id', $request->query('agent_id'));
        }
        if ($request->query('status')) {
            $query->where('al.status', $request->query('status'));
        }

        $total   = $query->count();
        $records = $query->orderByDesc('al.created_at')->offset(($page - 1) * $perPage)->limit($perPage)->get();

        return response()->json([
            'status' => 'success',
            'data'   => [
                'records'      => $records,
                'total'        => $total,
                'per_page'     => $perPage,
                'current_page' => $page,
                'last_page'    => (int) ceil($total / $perPage),
            ],
        ]);
    }

    public function trafficInbound(Request $request)
    {
        $tenantId = $request->attributes->get('portal_tenant_id');
        $page     = max(1, (int) $request->query('page', 1));
        $perPage  = 25;

        // Inbound = external agents that were validated against this tenant's Gateway installation.
        // Stored in action_ledger with action_type='inbound_agent_validation'.
        $query = DB::table('action_ledger')
            ->where('tenant_id', $tenantId)
            ->where('action_type', 'inbound_agent_validation');

        $total   = $query->count();
        $records = $query->orderByDesc('created_at')->offset(($page - 1) * $perPage)->limit($perPage)->get();

        return response()->json([
            'status' => 'success',
            'data'   => [
                'records'      => $records,
                'total'        => $total,
                'per_page'     => $perPage,
                'current_page' => $page,
                'last_page'    => (int) ceil($total / $perPage),
                'has_gateway'  => $total > 0,
            ],
        ]);
    }

    // ─── Transactions ─────────────────────────────────────────────────────────

    public function transactions(Request $request)
    {
        $tenantId = $request->attributes->get('portal_tenant_id');
        $page     = max(1, (int) $request->query('page', 1));
        $perPage  = 50;

        $query = DB::table('action_ledger as al')
            ->join('agents as a', 'a.id', '=', 'al.agent_id')
            ->where('al.tenant_id', $tenantId)
            ->select('al.*', 'a.name as agent_name', 'a.agent_type');

        if ($request->query('agent_id'))  $query->where('al.agent_id', $request->query('agent_id'));
        if ($request->query('status'))    $query->where('al.status', $request->query('status'));
        if ($request->query('date_from')) $query->whereDate('al.created_at', '>=', $request->query('date_from'));
        if ($request->query('date_to'))   $query->whereDate('al.created_at', '<=', $request->query('date_to'));
        if ($request->query('search'))    $query->where('al.target_api', 'ilike', '%' . $request->query('search') . '%');

        $total   = $query->count();
        $records = $query->orderByDesc('al.created_at')->offset(($page - 1) * $perPage)->limit($perPage)->get();

        return response()->json([
            'status' => 'success',
            'data'   => [
                'records'      => $records,
                'total'        => $total,
                'per_page'     => $perPage,
                'current_page' => $page,
                'last_page'    => (int) ceil($total / $perPage),
            ],
        ]);
    }

    // ─── Flow Data (Agent → Model → Target API) ─────────────────────────────

    /**
     * Returns aggregated agent activity for the authenticated tenant's gateway.
     *
     * Groups action_ledger records by agent → model → target_api and counts
     * decision outcomes (approved, blocked, pending_swarm, shadow_sandbox).
     *
     * Query params:
     *   date_from  (optional) — ISO date, e.g. 2026-05-01
     *   date_to    (optional) — ISO date, e.g. 2026-05-15
     *   agent_id   (optional) — filter to a single agent UUID
     *
     * Response shape:
     *   { flows: [ { agent_id, agent_name, model, target_api, approved, blocked, pending, shadow, total } ] }
     */
    public function flowData(Request $request)
    {
        $tenantId = $request->attributes->get('portal_tenant_id');

        $query = DB::table('action_ledger as al')
            ->join('agents as a', 'a.id', '=', 'al.agent_id')
            ->where('al.tenant_id', $tenantId)
            ->select(
                'al.agent_id',
                'a.name as agent_name',
                'al.model',
                'al.target_api',
                DB::raw("COUNT(*) as total"),
                DB::raw("COUNT(*) FILTER (WHERE al.status = 'approved') as approved"),
                DB::raw("COUNT(*) FILTER (WHERE al.status = 'blocked') as blocked"),
                DB::raw("COUNT(*) FILTER (WHERE al.status = 'pending_swarm') as pending"),
                DB::raw("COUNT(*) FILTER (WHERE al.status = 'shadow_sandbox') as shadow"),
            )
            ->groupBy('al.agent_id', 'a.name', 'al.model', 'al.target_api')
            ->orderByDesc(DB::raw('COUNT(*)'));

        if ($request->query('agent_id'))  $query->where('al.agent_id', $request->query('agent_id'));
        if ($request->query('date_from')) $query->whereDate('al.created_at', '>=', $request->query('date_from'));
        if ($request->query('date_to'))   $query->whereDate('al.created_at', '<=', $request->query('date_to'));

        $flows = $query->limit(500)->get();

        return response()->json([
            'status' => 'success',
            'data'   => ['flows' => $flows],
        ]);
    }

    // ─── Company / Profile ────────────────────────────────────────────────────

    public function company(Request $request)
    {
        $tenantId  = $request->attributes->get('portal_tenant_id');
        $contactId = $request->attributes->get('portal_contact_id');

        $tenant  = DB::table('tenants')->where('id', $tenantId)->first();
        $contact = DB::table('contacts')->where('id', $contactId)->first();
        $identities = DB::table('oauth_identities')->where('contact_id', $contactId)->get();

        return response()->json([
            'status' => 'success',
            'data'   => compact('tenant', 'contact', 'identities'),
        ]);
    }

    public function updateCompany(Request $request)
    {
        $tenantId  = $request->attributes->get('portal_tenant_id');
        $contactId = $request->attributes->get('portal_contact_id');

        $validated = $request->validate([
            'company_name'              => 'sometimes|string|max:255',
            'company_email'             => 'sometimes|email|max:255',
            'company_phone'             => 'sometimes|string|max:50',
            'company_address'           => 'sometimes|string',
            'company_website'           => 'sometimes|url|max:255',
            'contact_name'              => 'sometimes|string|max:255',
            'contact_phone'             => 'sometimes|string|max:50',
            'contact_role'              => 'sometimes|string|max:100',
            'ciba_notification_channel' => 'sometimes|in:dashboard,email,companion_app',
            'ciba_notification_email'   => 'sometimes|nullable|email|max:255',
        ]);

        // Build a single update array for the tenant to avoid multiple queries
        $tenantUpdate = ['updated_at' => now()];
        foreach (['company_name' => 'name', 'company_email' => 'company_email', 'company_phone' => 'company_phone', 'company_address' => 'company_address', 'company_website' => 'company_website', 'ciba_notification_channel' => 'ciba_notification_channel', 'ciba_notification_email' => 'ciba_notification_email'] as $formKey => $dbKey) {
            if (isset($validated[$formKey])) {
                $tenantUpdate[$dbKey] = $validated[$formKey];
            }
        }
        DB::table('tenants')->where('id', $tenantId)->update($tenantUpdate);

        $contactUpdate = array_filter([
            'name'       => $validated['contact_name']  ?? null,
            'phone'      => $validated['contact_phone'] ?? null,
            'role'       => $validated['contact_role']  ?? null,
            'updated_at' => now(),
        ]);
        if (count($contactUpdate) > 1) {
            DB::table('contacts')->where('id', $contactId)->update($contactUpdate);
        }

        return response()->json(['status' => 'success', 'message' => 'Details updated.']);
    }

    public function updatePlan(Request $request)
    {
        $tenantId = $request->attributes->get('portal_tenant_id');

        $validated = $request->validate([
            'plan' => 'required|in:starter,professional,enterprise',
        ]);

        DB::table('tenants')->where('id', $tenantId)->update([
            'plan'            => $validated['plan'],
            'plan_started_at' => now(),
            'updated_at'      => now(),
        ]);

        return response()->json(['status' => 'success', 'message' => 'Plan updated.', 'data' => ['plan' => $validated['plan']]]);
    }

    // ─── Private ──────────────────────────────────────────────────────────────

    private function agentStatus(object $agent): string
    {
        // approval_status is the source of truth, set by the Sentry Gateway.
        // Fall back to legacy derivation if the column hasn't been populated yet.
        if (!empty($agent->approval_status) && $agent->approval_status !== 'pending_review') {
            return $agent->approval_status;
        }

        if ($agent->revoked_at) return 'terminated';
        if (!$agent->certified_at) return 'pending_certification';
        if ($agent->recertification_due_at && now()->isAfter($agent->recertification_due_at)) return 'recertification_required';
        return 'certified';
    }

    // ─── Agent Certification Lifecycle ────────────────────────────────────────

    /**
     * Certify an agent — operator approves the agent's policy and activates its EVAR.
     * Sets certified_at, recertification_due_at (90 days), and approval_status = 'certified'.
     */
    public function certifyAgent(Request $request, string $agentId)
    {
        $tenantId  = $request->attributes->get('portal_tenant_id');
        $contactId = $request->attributes->get('portal_contact_id');
        $reason    = $request->input('reason', 'Operator certification approved');

        $agent = DB::table('agents')->where('id', $agentId)->where('tenant_id', $tenantId)->first();
        if (!$agent) {
            return response()->json(['status' => 'error', 'message' => 'Agent not found.'], 404);
        }

        if ($agent->revoked_at) {
            return response()->json(['status' => 'error', 'message' => 'Cannot certify a terminated agent. Register a new agent instead.'], 422);
        }

        $now = now();
        $recertDue = $now->copy()->addDays(90);

        DB::table('agents')->where('id', $agentId)->update([
            'certified_at'           => $now,
            'recertification_due_at' => $recertDue,
            'approval_status'        => 'certified',
            'updated_at'             => $now,
        ]);

        DB::table('certification_events')->insert([
            'id'           => (string) Str::uuid(),
            'agent_id'     => $agentId,
            'tenant_id'    => $tenantId,
            'event_type'   => 'certified',
            'performed_by' => $contactId ?? 'operator',
            'reason'       => $reason,
            'metadata'     => json_encode(['recertification_due_at' => $recertDue->toISOString()]),
            'created_at'   => $now,
        ]);

        return response()->json([
            'status'  => 'success',
            'message' => 'Agent certified. EVAR is now fully active.',
            'data'    => [
                'approval_status'        => 'certified',
                'certified_at'           => $now->toISOString(),
                'recertification_due_at' => $recertDue->toISOString(),
            ],
        ]);
    }

    /**
     * Suspend an agent — operator pauses the agent pending investigation.
     * Agent receives 403 at the Gateway proxy.
     */
    public function suspendAgent(Request $request, string $agentId)
    {
        $tenantId  = $request->attributes->get('portal_tenant_id');
        $contactId = $request->attributes->get('portal_contact_id');
        $reason    = $request->input('reason', 'Operator suspended agent');

        $agent = DB::table('agents')->where('id', $agentId)->where('tenant_id', $tenantId)->first();
        if (!$agent) {
            return response()->json(['status' => 'error', 'message' => 'Agent not found.'], 404);
        }

        $now = now();

        DB::table('agents')->where('id', $agentId)->update([
            'approval_status' => 'suspended',
            'updated_at'      => $now,
        ]);

        DB::table('certification_events')->insert([
            'id'           => (string) Str::uuid(),
            'agent_id'     => $agentId,
            'tenant_id'    => $tenantId,
            'event_type'   => 'suspended',
            'performed_by' => $contactId ?? 'operator',
            'reason'       => $reason,
            'created_at'   => $now,
        ]);

        return response()->json([
            'status'  => 'success',
            'message' => 'Agent suspended. All proxy requests will be rejected.',
            'data'    => ['approval_status' => 'suspended'],
        ]);
    }

    /**
     * Terminate an agent — permanent revocation of credentials.
     * Sets revoked_at and approval_status = 'terminated'.
     */
    public function terminateAgent(Request $request, string $agentId)
    {
        $tenantId  = $request->attributes->get('portal_tenant_id');
        $contactId = $request->attributes->get('portal_contact_id');
        $reason    = $request->input('reason', 'Operator terminated agent');

        $agent = DB::table('agents')->where('id', $agentId)->where('tenant_id', $tenantId)->first();
        if (!$agent) {
            return response()->json(['status' => 'error', 'message' => 'Agent not found.'], 404);
        }

        $now = now();

        DB::table('agents')->where('id', $agentId)->update([
            'revoked_at'      => $now,
            'approval_status' => 'terminated',
            'updated_at'      => $now,
        ]);

        DB::table('certification_events')->insert([
            'id'           => (string) Str::uuid(),
            'agent_id'     => $agentId,
            'tenant_id'    => $tenantId,
            'event_type'   => 'terminated',
            'performed_by' => $contactId ?? 'operator',
            'reason'       => $reason,
            'created_at'   => $now,
        ]);

        return response()->json([
            'status'  => 'success',
            'message' => 'Agent terminated. Credential permanently revoked.',
            'data'    => ['approval_status' => 'terminated', 'revoked_at' => $now->toISOString()],
        ]);
    }

    /**
     * Recertify an agent — operator extends certification after expiry.
     * Resets certified_at and extends recertification_due_at by 90 days.
     */
    public function recertifyAgent(Request $request, string $agentId)
    {
        $tenantId  = $request->attributes->get('portal_tenant_id');
        $contactId = $request->attributes->get('portal_contact_id');
        $reason    = $request->input('reason', 'Operator recertification approved');

        $agent = DB::table('agents')->where('id', $agentId)->where('tenant_id', $tenantId)->first();
        if (!$agent) {
            return response()->json(['status' => 'error', 'message' => 'Agent not found.'], 404);
        }

        if ($agent->revoked_at) {
            return response()->json(['status' => 'error', 'message' => 'Cannot recertify a terminated agent.'], 422);
        }

        $now = now();
        $recertDue = $now->copy()->addDays(90);

        DB::table('agents')->where('id', $agentId)->update([
            'certified_at'           => $now,
            'recertification_due_at' => $recertDue,
            'approval_status'        => 'certified',
            'updated_at'             => $now,
        ]);

        DB::table('certification_events')->insert([
            'id'           => (string) Str::uuid(),
            'agent_id'     => $agentId,
            'tenant_id'    => $tenantId,
            'event_type'   => 'recertified',
            'performed_by' => $contactId ?? 'operator',
            'reason'       => $reason,
            'metadata'     => json_encode(['recertification_due_at' => $recertDue->toISOString()]),
            'created_at'   => $now,
        ]);

        return response()->json([
            'status'  => 'success',
            'message' => 'Agent recertified. EVAR reactivated for 90 days.',
            'data'    => [
                'approval_status'        => 'certified',
                'certified_at'           => $now->toISOString(),
                'recertification_due_at' => $recertDue->toISOString(),
            ],
        ]);
    }

    /**
     * List certification events for an agent — audit trail.
     */
    public function certificationEvents(Request $request, string $agentId)
    {
        $tenantId = $request->attributes->get('portal_tenant_id');

        // Verify the agent belongs to this tenant
        $agent = DB::table('agents')->where('id', $agentId)->where('tenant_id', $tenantId)->first();
        if (!$agent) {
            return response()->json(['status' => 'error', 'message' => 'Agent not found.'], 404);
        }

        $events = DB::table('certification_events')
            ->where('agent_id', $agentId)
            ->orderByDesc('created_at')
            ->limit(50)
            ->get()
            ->map(fn($e) => [
                'id'           => $e->id,
                'event_type'   => $e->event_type,
                'performed_by' => $e->performed_by,
                'reason'       => $e->reason,
                'metadata'     => json_decode($e->metadata),
                'created_at'   => $e->created_at,
            ]);

        return response()->json([
            'status' => 'success',
            'data'   => ['events' => $events],
        ]);
    }

    // ─── Mobile Pairing ───────────────────────────────────────────────────────

    public function generatePairingToken(Request $request)
    {
        $tenantId  = $request->attributes->get('portal_tenant_id');
        $contactId = $request->attributes->get('portal_contact_id');

        // ZERO-SECRET QR EXCHANGE: Generate an ephemeral 60s challenge nonce.
        $nonce = Str::random(32);
        
        // Insert into the shared Postgres table so Go Gateway can securely verify it
        DB::table('mobile_pairing_challenges')->insert([
            'nonce'      => $nonce,
            'tenant_id'  => $tenantId,
            'contact_id' => $contactId,
            'expires_at' => now()->addSeconds(300),
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $payload = json_encode([
            'type'        => 'pairing_challenge',
            'nonce'       => $nonce,
            // Direct the app to the secure Go Gateway instead of this Laravel API
            'gateway_url' => 'http://192.168.0.35:8080/v1/mobile/pair/handshake',
            'expires_in'  => 300
        ]);

        return response()->json([
            'status' => 'success',
            'data'   => ['token' => base64_encode($payload)] // The QR code now contains NO secrets, only a routing challenge
        ]);
    }

    public function devices(Request $request)
    {
        $tenantId = $request->attributes->get('portal_tenant_id');

        // STRICT API BOUNDARY: Fetch Aegis devices from the Go Gateway internal API
        // instead of querying the Go-managed table directly.
        $gatewayUrl = env('CICADA_GATEWAY_URL', 'http://localhost:8080');
        
        try {
            $response = \Illuminate\Support\Facades\Http::timeout(5)
                ->withHeaders(['X-Cicada-Tenant-ID' => $tenantId])
                ->get("{$gatewayUrl}/v1/internal/aegis/devices");

            if ($response->successful()) {
                $devices = $response->json('data.devices') ?? [];
            } else {
                \Illuminate\Support\Facades\Log::error('Gateway API error fetching devices', ['status' => $response->status()]);
                $devices = [];
            }
        } catch (\Exception $e) {
            \Illuminate\Support\Facades\Log::error('Failed to reach Gateway for devices', ['error' => $e->getMessage()]);
            $devices = [];
        }

        return response()->json([
            'status' => 'success',
            'data'   => ['devices' => $devices],
        ]);
    }
}
