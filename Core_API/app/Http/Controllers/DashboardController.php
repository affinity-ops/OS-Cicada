<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use App\Services\AuditService;
use App\Services\AlertDispatcherService;
use App\Services\RevocationDispatcherService;
use OpenApi\Attributes as OA;

class DashboardController extends Controller
{
    public function summary()
    {
        $totalAgents      = DB::table('agents')->count();
        $totalTenants     = DB::table('tenants')->count();
        $activeTenants    = DB::table('tenants')->where('status', 'active')->count();
        $verifiedAgents   = DB::table('agents')->where('trust_tier', '!=', 'unverified')->count();
        $quarantinedAgents = DB::table('agents')->whereNotNull('revoked_at')->count();

        $activeAgents24h = DB::table('action_ledger')
            ->where('created_at', '>=', now()->subDay())
            ->distinct()
            ->count('agent_id');

        $today = now()->startOfDay();
        $approvedToday = DB::table('action_ledger')
             ->where('created_at', '>=', $today)
             ->where('status', 'approved')
             ->count();
        $blockedToday = DB::table('action_ledger')
             ->where('created_at', '>=', $today)
             ->where('status', 'blocked')
             ->count();

        $pendingHitlCount = DB::table('ciba_authorization_requests')
            ->where('status', 'pending')
            ->where('expires_at', '>', now())
            ->count();

        // ─── Recent Activity (Unified Feed) ─────────────────────────────
        // Combines BOTH data sources into a single chronological timeline:
        //   1. action_ledger — proxy decisions (approved, blocked, shadow)
        //   2. operator_alerts — threat events (canary triggers, exfiltration, etc.)
        //
        // Previously, only action_ledger was shown, so threat alerts that
        // appeared in the red "Active Threat Alerts" panel were invisible
        // in the recent activity feed. This was the core of the bug report:
        // "the ones in red do not appear on the recent incidents ledger."

        // Source 1: Action ledger (proxy decisions)
        $ledgerEntries = DB::table('action_ledger')
            ->leftJoin('agents', 'action_ledger.agent_id', '=', 'agents.id')
            ->leftJoin('tenants', 'action_ledger.tenant_id', '=', 'tenants.id')
            ->orderByDesc('action_ledger.created_at')
            ->select(
                'action_ledger.trace_id',
                'action_ledger.action_type',
                'action_ledger.target_api',
                'action_ledger.status',
                'action_ledger.created_at',
                'agents.name as agent_name',
                'tenants.name as company_name'
            )
            ->limit(15)
            ->get()
            ->map(function ($row) {
                return [
                    'id'           => $row->trace_id,
                    'source'       => 'ledger',
                    'action_type'  => $row->action_type,
                    'target_api'   => $row->target_api,
                    'status'       => $row->status,
                    'summary'      => null,
                    'severity'     => null,
                    'agent_name'   => $row->agent_name,
                    'company_name' => $row->company_name,
                    'created_at'   => $row->created_at,
                ];
            });

        // Source 2: Operator alerts — RESOLVED/DEALT-WITH threats only.
        // Open threats are shown exclusively in the Active Threat Alerts card.
        // Once an operator dismisses/resolves a threat (via the dismiss button
        // or CIBA queue), it moves from the red card into this activity feed,
        // giving operators a clear timeline of "threat appeared → dealt with."
        //
        // SORT KEY: We use resolved_at (not created_at) as the effective timestamp.
        // This ensures a threat you dismiss NOW appears at the top of the feed,
        // not buried under newer ledger entries because the alert was raised days ago.
        $alertEntries = DB::table('operator_alerts')
            ->leftJoin('agents', function ($join) {
                $join->on('operator_alerts.agent_id', '=', DB::raw('agents.id::varchar'));
            })
            ->leftJoin('tenants', function ($join) {
                $join->on('operator_alerts.tenant_id', '=', DB::raw('tenants.id::varchar'));
            })
            ->where('operator_alerts.status', '!=', 'open')
            ->orderByDesc(DB::raw('COALESCE(operator_alerts.resolved_at, operator_alerts.created_at)'))
            ->select(
                'operator_alerts.id',
                'operator_alerts.event_type',
                'operator_alerts.severity',
                'operator_alerts.summary',
                'operator_alerts.status',
                'operator_alerts.created_at',
                'operator_alerts.resolved_at',
                'agents.name as agent_name',
                'tenants.name as company_name'
            )
            ->limit(15)
            ->get()
            ->map(function ($row) {
                // Use resolved_at as the display timestamp if available,
                // otherwise fall back to created_at. This ensures recently
                // dismissed alerts appear at the top of the chronological feed.
                $effectiveTimestamp = $row->resolved_at ?? $row->created_at;
                return [
                    'id'           => $row->id,
                    'source'       => 'alert',
                    'action_type'  => $row->event_type,
                    'target_api'   => null,
                    'status'       => $row->status === 'open' ? 'threat' : 'resolved',
                    'summary'      => $row->summary,
                    'severity'     => $row->severity,
                    'agent_name'   => $row->agent_name,
                    'company_name' => $row->company_name,
                    'created_at'   => $effectiveTimestamp,
                    'original_created_at' => $row->created_at,
                ];
            });

        // Merge both sources, sort by timestamp (newest first), take top 15.
        $recentActivity = $ledgerEntries
            ->merge($alertEntries)
            ->sortByDesc('created_at')
            ->values()
            ->take(15);

        $activeThreatAlerts = DB::table('operator_alerts')
            ->leftJoin('agents', function($join) {
                $join->on('operator_alerts.agent_id', '=', DB::raw('agents.id::varchar'));
            })
            ->leftJoin('tenants', function($join) {
                $join->on('operator_alerts.tenant_id', '=', DB::raw('tenants.id::varchar'));
            })
            ->where('operator_alerts.status', 'open')
            ->orderByDesc('operator_alerts.created_at')
            ->select('operator_alerts.id', 'operator_alerts.event_type', 'operator_alerts.severity', 'operator_alerts.summary', 'operator_alerts.created_at', 'agents.name as agent_name', 'tenants.name as company_name')
            ->limit(5)
            ->get();

        // ─── Budget Warnings (agents over 80% of monthly budget) ────────
        $monthStart = now()->startOfMonth();
        $budgetWarnings = [];
        $budgetedAgents = DB::table('agents')
            ->whereNotNull('monthly_budget_usd')
            ->where('monthly_budget_usd', '>', 0)
            ->whereNull('revoked_at')
            ->select('id', 'name', 'monthly_budget_usd', 'tenant_id')
            ->get();

        // Single aggregate query for all budgeted agents — eliminates N+1.
        $agentCallCounts = DB::table('action_ledger')
            ->whereIn('agent_id', $budgetedAgents->pluck('id'))
            ->where('created_at', '>=', $monthStart)
            ->groupBy('agent_id')
            ->selectRaw('agent_id, COUNT(*) as call_count')
            ->pluck('call_count', 'agent_id');

        foreach ($budgetedAgents as $ba) {
            $callsThisMonth = (int) ($agentCallCounts[$ba->id] ?? 0);
            // Estimated cost: $0.01 per proxied call (conservative)
            $estimatedCost = round($callsThisMonth * 0.01, 2);
            $pctUsed = round(($estimatedCost / (float) $ba->monthly_budget_usd) * 100, 1);
            if ($pctUsed >= 80) {
                $budgetWarnings[] = [
                    'agent_id'       => $ba->id,
                    'agent_name'     => $ba->name ?? ('Agent-' . strtoupper(substr($ba->id, 0, 8))),
                    'budget_usd'     => (float) $ba->monthly_budget_usd,
                    'estimated_cost' => $estimatedCost,
                    'pct_used'       => $pctUsed,
                    'calls_mtd'      => $callsThisMonth,
                ];
            }
        }

        return response()->json([
            'status' => 'success',
            'data' => [
                'total_agents'       => $totalAgents,
                'total_tenants'      => $totalTenants,
                'active_tenants'     => $activeTenants,
                'active_agents_24h'  => $activeAgents24h,
                'verified_agents'    => $verifiedAgents,
                'quarantined_agents' => $quarantinedAgents,
                'approved_today'     => $approvedToday,
                'blocked_today'      => $blockedToday,
                'pending_hitl_count' => $pendingHitlCount,
                'recent_activity'    => $recentActivity,
                'active_threat_alerts'=> $activeThreatAlerts,
                'budget_warnings'    => $budgetWarnings,
            ],
        ]);
    }

    public function agents(Request $request)
    {
        $perPage    = (int) $request->query('per_page', 20);
        $trustTier  = $request->query('trust_tier');
        $query      = DB::table('agents')
            ->join('tenants', 'agents.tenant_id', '=', 'tenants.id')
            ->select(
                'agents.id',
                'agents.name',
                'tenants.name as tenant_name',
                'agents.trust_tier',
                'agents.agent_type',
                'agents.role',
                'agents.version',
                'agents.hitl_enabled',
                'agents.certified_at',
                'agents.revoked_at',
                'agents.tenant_id'
            )
            ->orderByDesc('agents.created_at');

        if ($trustTier) {
            $query->where('agents.trust_tier', $trustTier);
        }

        $agents = $query->paginate($perPage);

        return response()->json([
            'status' => 'success',
            'data'   => $agents,
        ]);
    }

    // ─── CRM: All tenants ──────────────────────────────────────────────────────

    public function companies(Request $request)
    {
        $search = $request->query('search', '');
        $plan   = $request->query('plan', '');

        $query = DB::table('tenants')
            ->leftJoin('contacts', function ($join) {
                $join->on('contacts.tenant_id', '=', 'tenants.id')
                     ->where('contacts.is_primary', true);
            })
            ->select(
                'tenants.id',
                'tenants.name',
                'tenants.status',
                'tenants.plan',
                'tenants.company_email',
                'tenants.plan_started_at',
                'tenants.created_at',
                'contacts.name as contact_name',
                'contacts.email as contact_email',
                'contacts.avatar_url as contact_avatar',
                DB::raw('(SELECT COUNT(*) FROM agents WHERE agents.tenant_id = tenants.id) as agent_count'),
                DB::raw('(SELECT COUNT(*) FROM agents WHERE agents.tenant_id = tenants.id AND agents.revoked_at IS NULL AND agents.trust_tier != \'unverified\') as certified_count')
            )
            ->orderByDesc('tenants.created_at');

        if ($search) {
            $query->where(function ($q) use ($search) {
                $q->whereILike('tenants.name', "%{$search}%")
                  ->orWhereILike('tenants.company_email', "%{$search}%")
                  ->orWhereILike('contacts.email', "%{$search}%");
            });
        }

        if ($plan) {
            $query->where('tenants.plan', $plan);
        }

        $companies = $query->paginate(20);

        return response()->json(['status' => 'success', 'data' => $companies]);
    }

    public function company(string $id)
    {
        $tenant = DB::table('tenants')->where('id', $id)->first();
        if (!$tenant) {
            return response()->json(['error' => 'Not found'], 404);
        }

        $contacts = DB::table('contacts')
            ->where('tenant_id', $id)
            ->orderByDesc('is_primary')
            ->get();

        $agents = DB::table('agents')
            ->where('tenant_id', $id)
            ->orderByDesc('created_at')
            ->get([
                'id', 'name', 'agent_type', 'version', 'trust_tier',
                'scope_entitlements', 'certified_at', 'recertification_due_at',
                'revoked_at', 'created_at',
            ]);

        $recentActions = DB::table('action_ledger')
            ->whereIn('agent_id', $agents->pluck('id'))
            ->orderByDesc('created_at')
            ->limit(20)
            ->get(['trace_id', 'agent_id', 'action_type', 'status', 'target_api', 'created_at']);

        return response()->json([
            'status' => 'success',
            'data'   => [
                'tenant'         => $tenant,
                'contacts'       => $contacts,
                'agents'         => $agents,
                'recent_actions' => $recentActions,
            ],
        ]);
    }

    // ─── Stage 8: Threat Signals for Aegis-0 ─────────────────────────────────
    //
    // Returns aggregated anomaly counts across all 10 threat vectors (V01–V10).
    // Aegis-0 polls this endpoint every 60 seconds. Each signal maps to a
    // specific section in Cicada_Documentation/threat_surface_map.md.
    //
    // Signals are counts over a rolling window (default 60 min) rather than
    // all-time totals so Aegis-0 reflects current platform state, not history.
    public function threatSignals(Request $request): \Illuminate\Http\JsonResponse
    {
        $windowMinutes = (int) $request->query('window', 60);
        $since = now()->subMinutes($windowMinutes);

        // V01: Registrations per tenant spike
        $v01 = DB::table('action_ledger')
            ->where('action_type', 'agent_provisioned')
            ->where('created_at', '>=', $since)
            ->selectRaw('agent_id, COUNT(*) as cnt')
            ->groupBy('agent_id')
            ->orderByDesc('cnt')
            ->limit(1)
            ->value('cnt') ?? 0;

        // V02: Admission attempts for revoked agents
        $v02 = DB::table('action_ledger')
            ->join('agents', 'action_ledger.agent_id', '=', 'agents.id')
            ->whereNotNull('agents.revoked_at')
            ->where('action_ledger.created_at', '>=', $since)
            ->count();

        // V03: OAuth state mismatches (logged as auth_error in ledger)
        $v03 = DB::table('action_ledger')
            ->where('action_type', 'oauth_state_mismatch')
            ->where('created_at', '>=', $since)
            ->count();

        // V04: Swarm HMAC failures
        $v04 = DB::table('action_ledger')
            ->where('action_type', 'swarm_hmac_failure')
            ->where('created_at', '>=', $since)
            ->count();

        // V05: Duplicate rollback IDs
        $v05 = DB::table('action_ledger')
            ->where('action_type', 'rollback_triggered')
            ->where('created_at', '>=', $since)
            ->selectRaw('trace_id, COUNT(*) as cnt')
            ->groupBy('trace_id')
            ->havingRaw('COUNT(*) > 1')
            ->count();

        // V06: Ledger anomalies — approved status with no swarm score on
        //      write/transact actions (should always have a score)
        $v06 = DB::table('action_ledger')
            ->where('status', 'approved')
            ->whereNull('swarm_confidence_score')
            ->whereIn('action_type', ['proxy:write', 'proxy:transact'])
            ->where('created_at', '>=', $since)
            ->count();

        // V07: Confidence variance anomaly — agents with high score variance
        $v07 = DB::table('action_ledger')
            ->where('created_at', '>=', $since)
            ->whereNotNull('swarm_confidence_score')
            ->selectRaw('agent_id, STDDEV(swarm_confidence_score) as variance, COUNT(*) as calls')
            ->groupBy('agent_id')
            ->havingRaw('STDDEV(swarm_confidence_score) > 0.15 AND COUNT(*) >= 5')
            ->count();

        // V08: Role violations from Gateway
        $v08 = DB::table('action_ledger')
            ->where('status', 'blocked')
            ->whereRaw("payload_hash LIKE '%role_violation%'")
            ->where('created_at', '>=', $since)
            ->count();

        // V09: Token IP anomalies — agents whose tokens are used from multiple
        //      distinct source IPs within the rolling window (credential theft/replay)
        $v09 = DB::table('token_usage_logs')
            ->where('created_at', '>=', $since)
            ->selectRaw('agent_id, COUNT(DISTINCT source_ip) as ip_count')
            ->groupBy('agent_id')
            ->havingRaw('COUNT(DISTINCT source_ip) > 1')
            ->count();

        // V10: Undeclared tool calls
        $v10 = DB::table('action_ledger')
            ->where('action_type', 'undeclared_tool_call')
            ->where('created_at', '>=', $since)
            ->count();

        // Circuit breaker trips in the window (bonus signal for Aegis-0)
        $circuitBreakerTrips = DB::table('action_ledger')
            ->where('action_type', 'circuit_breaker_trip')
            ->where('created_at', '>=', $since)
            ->count();

        return response()->json([
            'status' => 'success',
            'data'   => [
                'window_minutes'         => $windowMinutes,
                'generated_at'           => now()->toIso8601String(),
                'signals'                => [
                    'v01_registrations_per_tenant_1h'  => (int) $v01,
                    'v02_revoked_admission_attempts'   => (int) $v02,
                    'v03_oauth_state_mismatches'       => (int) $v03,
                    'v04_swarm_result_hmac_failures'   => (int) $v04,
                    'v05_duplicate_rollback_ids'       => (int) $v05,
                    'v06_ledger_anomalies'             => (int) $v06,
                    'v07_confidence_variance_anomaly'  => (int) $v07,
                    'v08_role_violations'              => (int) $v08,
                    'v09_token_ip_anomalies'           => (int) $v09,
                    'v10_undeclared_tool_calls'        => (int) $v10,
                ],
                'circuit_breaker_trips'  => (int) $circuitBreakerTrips,
            ],
        ]);
    }

    public function updateTenantNotes(Request $request, string $id)
    {
        $validated = $request->validate(['admin_notes' => 'nullable|string|max:5000']);
        DB::table('tenants')->where('id', $id)->update([
            'admin_notes' => $validated['admin_notes'] ?? null,
        ]);
        return response()->json(['status' => 'success']);
    }

    // ─── Immutable Action Ledger (paginated) ──────────────────────────────────
    public function logs(Request $request)
    {
        $perPage = min((int) $request->query('per_page', 50), 200);
        $status  = $request->query('status');
        $agentId = $request->query('agent_id');

        $query = DB::table('action_ledger')
            ->leftJoin('tenants', 'action_ledger.tenant_id', '=', 'tenants.id')
            ->leftJoin('agents', 'action_ledger.agent_id', '=', 'agents.id');

        // Build SELECT list — some columns may not exist yet (Gateway migrations 005/006).
        $selectCols = [
            'action_ledger.trace_id',
            'action_ledger.agent_id',
            'action_ledger.tenant_id',
            'tenants.name as tenant_name',
            'agents.name as agent_name',
            'agents.trust_tier',
            'action_ledger.action_type',
            'action_ledger.target_api',
            'action_ledger.status',
            'action_ledger.swarm_confidence_score',
            'action_ledger.created_at',
            'action_ledger.policy_violations',
        ];

        // Detect optional columns and include them if present.
        $optionalCols = ['semantic_alignment_score', 'reason', 'evidence'];
        foreach ($optionalCols as $col) {
            $exists = DB::selectOne(
                "SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'action_ledger' AND column_name = ?) AS exists",
                [$col]
            )->exists ?? false;
            if ($exists) {
                $selectCols[] = "action_ledger.{$col}";
            }
        }

        $query->select($selectCols)
            ->orderByDesc('action_ledger.created_at');

        if ($status)  $query->where('action_ledger.status', $status);
        if ($agentId) $query->where('action_ledger.agent_id', $agentId);

        $paginated = $query->paginate($perPage);

        return response()->json([
            'status' => 'success', 
            'data' => $paginated,
            'notice' => 'Records older than 90 days have been automatically archived to cold storage.'
        ]);
    }

    // ─── Single trace detail ──────────────────────────────────────────────────
    public function logDetail(string $traceId)
    {
        $entry = DB::table('action_ledger')
            ->leftJoin('tenants', 'action_ledger.tenant_id', '=', 'tenants.id')
            ->leftJoin('agents', 'action_ledger.agent_id', '=', 'agents.id')
            ->select(
                'action_ledger.*',
                'tenants.name as tenant_name',
                'agents.name as agent_name',
                'agents.trust_tier',
                'agents.scope_entitlements'
            )
            ->where('action_ledger.trace_id', $traceId)
            ->first();

        if (!$entry) {
            return response()->json(['error' => 'Trace not found'], 404);
        }

        return response()->json(['status' => 'success', 'data' => $entry]);
    }

    // ─── Nodes: tenants + their agents with action stats ─────────────────────
    public function nodes()
    {
        $tenants = DB::table('tenants')
            ->leftJoin('contacts', function ($join) {
                $join->on('contacts.tenant_id', '=', 'tenants.id')
                     ->where('contacts.is_primary', true);
            })
            ->select(
                'tenants.id',
                'tenants.name',
                'tenants.company_email',
                'contacts.name as contact_name',
                'contacts.email as contact_email'
            )
            ->where('tenants.status', 'active')
            ->get();

        // Batch-load all agents for all active tenants in a single query.
        $allAgents = DB::table('agents')
            ->whereIn('tenant_id', $tenants->pluck('id'))
            ->get([
                'id', 'name', 'pub_key_hash', 'trust_tier', 'scope_entitlements',
                'certified_at', 'recertification_due_at', 'revoked_at',
                'agent_type', 'version', 'created_at', 'tenant_id',
            ])
            ->groupBy('tenant_id');

        // Batch-load stats for all agents — single aggregate query.
        $allAgentIds = collect($allAgents)->flatten()->pluck('id');

        $agentStats = DB::table('action_ledger')
            ->whereIn('agent_id', $allAgentIds)
            ->groupBy('agent_id')
            ->selectRaw("agent_id, COUNT(*) as total, SUM(CASE WHEN status = 'blocked' THEN 1 ELSE 0 END) as blocked, MAX(created_at) as last_seen")
            ->get()
            ->keyBy('agent_id');

        // Batch-load recent anomalies (last 5 blocked per agent).
        // Using a window function to rank within each agent, then filter.
        $anomaliesRaw = DB::table(DB::raw("(
            SELECT agent_id, action_type,
                   ROW_NUMBER() OVER (PARTITION BY agent_id ORDER BY created_at DESC) as rn
            FROM action_ledger
            WHERE status = 'blocked' AND agent_id IN ('" . $allAgentIds->implode("','") . "')
        ) ranked"))
            ->where('rn', '<=', 5)
            ->get();

        $anomaliesByAgent = $anomaliesRaw->groupBy('agent_id')
            ->map(fn($items) => $items->pluck('action_type')->toArray());

        $result = [];
        foreach ($tenants as $tenant) {
            $agents = $allAgents[$tenant->id] ?? collect();

            $agentData = [];
            foreach ($agents as $agent) {
                $stat    = $agentStats[$agent->id] ?? null;
                $total   = (int) ($stat->total ?? 0);
                $blocked = (int) ($stat->blocked ?? 0);
                $lastSeen = $stat->last_seen ?? null;
                $anomalies = $anomaliesByAgent[$agent->id] ?? [];

                $score   = $this->trustTierToScore($agent->trust_tier);
                $fp      = $total > 0 ? round(($blocked / $total) * 100, 2) . '%' : '0.00%';

                $agentData[] = [
                    'id'                => $agent->id,
                    'name'              => $agent->name ?? ('Agent-' . strtoupper(substr($agent->id, 0, 8))),
                    'evar_token'        => substr($agent->pub_key_hash, 0, 40) . '...',
                    'first_seen'        => $agent->created_at,
                    'last_seen'         => $lastSeen,
                    'status'            => $agent->revoked_at ? 'Revoked' : 'Active',
                    'revocation_reason' => $agent->revoked_at ? 'Revoked by operator' : null,
                    'trust_score'       => $score,
                    'trust_tier'        => $agent->trust_tier,
                    'certification_level' => $this->trustTierLabel($agent->trust_tier),
                    'declared_scopes'   => json_decode($agent->scope_entitlements ?? '[]', true),
                    'approved_scopes'   => json_decode($agent->scope_entitlements ?? '[]', true),
                    'denied_scopes'     => [],
                    'spend_limits'      => 'N/A',
                    'rollback'          => 'N/A',
                    'total_actions'     => $total,
                    'blocked_actions'   => $blocked,
                    'allowed_actions'   => $total - $blocked,
                    'anomalies'         => $anomalies,
                    'sandbox_status'    => $agent->revoked_at ? 'Suspended / Quarantined' : 'Active - Monitoring',
                    'false_positive_rate' => $fp,
                ];
            }

            $scores      = array_column($agentData, 'trust_score');
            $globalScore = count($scores) > 0 ? round(array_sum($scores) / count($scores), 1) : 0;

            $result[] = [
                'id'                 => $tenant->id,
                'name'               => $tenant->name,
                'email'              => $tenant->company_email ?? $tenant->contact_email ?? '',
                'owner_name'         => $tenant->contact_name ?? 'N/A',
                'global_trust_score' => $globalScore,
                'agents'             => $agentData,
            ];
        }

        return response()->json(['status' => 'success', 'data' => $result]);
    }

    // ─── Verified Agent Registry ──────────────────────────────────────────────
    public function registry(Request $request)
    {
        $search = $request->query('search', '');

        $query = DB::table('agents')
            ->join('tenants', 'agents.tenant_id', '=', 'tenants.id')
            ->select(
                'agents.id',
                'agents.name',
                'agents.owner_name',
                'agents.owner_email',
                'agents.business_unit',
                'agents.criticality_level',
                'agents.data_classification',
                'agents.monthly_budget_usd',
                'agents.cost_center',
                'agents.declared_purpose',
                'agents.regulatory_frameworks',
                'agents.registration_purpose_statement',
                'agents.potential_impact',
                'agents.expected_velocity',
                'agents.pub_key_hash',
                'agents.trust_tier',
                'agents.scope_entitlements',
                'agents.hitl_enabled',
                'agents.hitl_webhook_url',
                'agents.revoked_at',
                'agents.certified_at',
                'agents.recertification_due_at',
                'agents.created_at',
                'agents.agent_type',
                'agents.role',
                'agents.orchestrator_id',
                'agents.version',
                'tenants.id as tenant_id',
                'tenants.name as tenant_name'
            )
            ->orderByDesc('agents.created_at');

        if ($search) {
            $query->where(function ($q) use ($search) {
                $q->whereILike('agents.name', "%{$search}%")
                  ->orWhereILike('agents.pub_key_hash', "%{$search}%")
                  ->orWhereILike('tenants.name', "%{$search}%");
            });
        }

        $paginator = $query->paginate(20);
        
        // Pre-load resource policies, tools, and block counts for all agents
        // on this page — eliminates the N+1 (3 queries per agent × 20 per page).
        $agentIds = $paginator->pluck('id');

        $policiesByAgent = DB::table('agent_resource_policies')
            ->whereIn('agent_id', $agentIds)
            ->where('active', true)
            ->get(['agent_id', 'resource_pattern', 'allowed_methods'])
            ->groupBy('agent_id');

        $toolsByAgent = DB::table('agent_tools')
            ->whereIn('agent_id', $agentIds)
            ->where('is_active', true)
            ->get(['agent_id', 'tool_name'])
            ->groupBy('agent_id');

        $blockCountsByAgent = DB::table('action_ledger')
            ->whereIn('agent_id', $agentIds)
            ->where('status', 'blocked')
            ->where('created_at', '>=', now()->subDays(7))
            ->groupBy('agent_id')
            ->selectRaw('agent_id, COUNT(*) as block_count')
            ->pluck('block_count', 'agent_id');

        foreach ($paginator as $agent) {
            $agent->resource_policies = $policiesByAgent[$agent->id] ?? collect();
            $agent->tools = ($toolsByAgent[$agent->id] ?? collect())->pluck('tool_name');

            // ─── Governance Score (0–100) ────────────────────────────────────
            // Shifted weight toward actual security verification (Swarm) rather than
            // just static form completeness.
            $score = 0;
            if (!empty($agent->owner_name))                                        $score += 10;
            if (!empty($agent->declared_purpose))                                  $score += 10;
            if (!empty($agent->criticality_level) && !empty($agent->data_classification)) $score += 10;
            
            // HITL for high/critical agents
            $isHighCrit = in_array($agent->criticality_level, ['high', 'critical']);
            if ($isHighCrit && $agent->hitl_enabled)                               $score += 10;
            elseif (!$isHighCrit)                                                  $score += 10;
            
            // Low drift check: 0 blocks = 20 pts, < 5 blocks = 10 pts
            $recentBlocks = (int) ($blockCountsByAgent[$agent->id] ?? 0);
            if ($recentBlocks == 0)                                                $score += 20;
            elseif ($recentBlocks < 5)                                             $score += 10;

            // Swarm Verification: Up to 40 points based on confidence score
            $swarmConfidence = $agent->swarm_confidence_score ?? 0.0;
            $score += (int) round($swarmConfidence * 40);

            $agent->governance_score = min(100, $score);
        }

        return response()->json(['status' => 'success', 'data' => $paginator]);
    }

    // ─── Shadow Sandbox / Ghost Mode ──────────────────────────────────────────
    public function toggleShadowMode(Request $request)
    {
        $validated = $request->validate([
            'agent_ids' => 'required|array',
            'agent_ids.*' => 'uuid',
            'action' => 'required|in:activate,release'
        ]);

        $redis = \Illuminate\Support\Facades\Redis::connection();
        $ttl = 4 * 3600; // 4 hours

        $successful = 0;
        foreach ($validated['agent_ids'] as $agentId) {
            $key = "cicada:ghost:{$agentId}";
            if ($validated['action'] === 'activate') {
                // Must ensure ghost_mode_allowed is true
                $allowed = DB::table('agents')->where('id', $agentId)->value('ghost_mode_allowed');
                if ($allowed) {
                    $redis->setex($key, $ttl, "1");
                    $successful++;
                }
            } else {
                $redis->del($key);
                $successful++;
            }
        }

        return response()->json([
            'status' => 'success',
            'message' => "Successfully processed shadow mode for {$successful} agents"
        ]);
    }

    public function sandboxEvents(Request $request)
    {
        try {
            $sandboxHost = config('cicada.sandbox_url');
            $response = \Illuminate\Support\Facades\Http::timeout(5)->get("{$sandboxHost}/sandbox/events");

            if (!$response->successful()) {
                return response()->json([
                    'events'  => [],
                    'count'   => 0,
                    'summary' => $this->emptySandboxSummary(),
                    'error'   => 'sandbox returned ' . $response->status(),
                ], 200);
            }

            $data   = $response->json();
            $events = $data['events'] ?? [];

            // ── Collect unique agent IDs for bulk name resolution ─────────
            $agentIds = array_unique(array_filter(array_column($events, 'agent_id')));
            $agentNames = [];
            if (!empty($agentIds)) {
                $agents = DB::table('agents')
                    ->whereIn('id', $agentIds)
                    ->pluck('name', 'id')
                    ->toArray();
                $agentNames = $agents;
            }

            // ── Enrich each event ────────────────────────────────────────
            $highRiskCount    = 0;
            $quarantineCount  = 0;
            $uniqueAgents     = [];
            $activityByHour   = [];

            foreach ($events as &$evt) {
                // Normalise timestamp field for the dashboard.
                // The sandbox SQLite uses 'recorded_at'; the dashboard
                // expects 'created_at'. We provide both for compatibility.
                $evt['created_at'] = $evt['recorded_at'] ?? '';

                // Resolve agent name from the agents table. Falls back to
                // a truncated UUID prefix if the agent is unknown.
                $aid = $evt['agent_id'] ?? '';
                $evt['agent_name'] = $agentNames[$aid]
                    ?? ('Agent-' . strtoupper(substr($aid, 0, 8)));

                // Parse findings from JSON string to structured array
                // so the dashboard can render individual rule matches.
                $findingsRaw = $evt['findings'] ?? '[]';
                if (is_string($findingsRaw)) {
                    $parsed = json_decode($findingsRaw, true);
                    $evt['findings_parsed'] = is_array($parsed) ? $parsed : [];
                } else {
                    $evt['findings_parsed'] = [];
                }

                // ── Aggregate summary stats ──────────────────────────────
                $score = (float) ($evt['anomaly_score'] ?? 0);
                if ($score >= 0.70) $highRiskCount++;
                if ($score >= 0.85) $quarantineCount++;
                if ($aid) $uniqueAgents[$aid] = true;

                // ── Activity by hour (for the timeline chart) ────────────
                $ts = $evt['recorded_at'] ?? '';
                if ($ts) {
                    try {
                        $hour = (new \DateTime($ts))->format('Y-m-d H:00');
                        if (!isset($activityByHour[$hour])) {
                            $activityByHour[$hour] = ['hour' => $hour, 'count' => 0, 'high_risk' => 0];
                        }
                        $activityByHour[$hour]['count']++;
                        if ($score >= 0.70) $activityByHour[$hour]['high_risk']++;
                    } catch (\Exception $e) {
                        // Skip malformed timestamps silently.
                    }
                }
            }
            unset($evt); // Break reference from foreach

            // Sort activity timeline chronologically.
            ksort($activityByHour);

            return response()->json([
                'events'  => $events,
                'count'   => count($events),
                'summary' => [
                    'total_events'    => count($events),
                    'unique_agents'   => count($uniqueAgents),
                    'high_risk_count' => $highRiskCount,
                    'quarantine_count'=> $quarantineCount,
                ],
                'activity_timeline' => array_values($activityByHour),
            ]);
        } catch (\Exception $e) {
            return response()->json([
                'events'  => [],
                'count'   => 0,
                'summary' => $this->emptySandboxSummary(),
                'error'   => 'sandbox unreachable',
            ], 200);
        }
    }

    /**
     * Returns a zeroed summary object for error/empty states so the
     * dashboard can render stat cards without null checks.
     */
    private function emptySandboxSummary(): array
    {
        return [
            'total_events'     => 0,
            'unique_agents'    => 0,
            'high_risk_count'  => 0,
            'quarantine_count' => 0,
        ];
    }


    // ─── Compensating Transactions (Sagas) ───────────────────────────────────
    public function sagas(Request $request)
    {
        $perPage = min((int) $request->query('per_page', 50), 200);

        $sagas = DB::table('action_ledger')
            ->leftJoin('tenants', 'action_ledger.tenant_id', '=', 'tenants.id')
            ->leftJoin('agents', 'action_ledger.agent_id', '=', 'agents.id')
            ->select(
                'action_ledger.trace_id',
                'action_ledger.agent_id',
                'agents.name as agent_name',
                'action_ledger.tenant_id',
                'tenants.name as tenant_name',
                'action_ledger.action_type',
                'action_ledger.target_api',
                'action_ledger.status',
                'action_ledger.policy_violations',
                'action_ledger.created_at'
            )
            ->whereIn('action_ledger.action_type', [
                'rollback_triggered',
                'circuit_breaker_trip',
                'hitl_rejected',
                'saga_compensated',
            ])
            ->orderByDesc('action_ledger.created_at')
            ->paginate($perPage);

        return response()->json(['status' => 'success', 'data' => $sagas]);
    }

    // ─── Shadow Discovery: ghost-mode and sandbox-anomaly agents ─────────────
    public function discovery()
    {
        $since = now()->subHours(24);

        $ghostAgents = DB::table('action_ledger')
            ->join('agents', 'action_ledger.agent_id', '=', 'agents.id')
            ->leftJoin('tenants', 'action_ledger.tenant_id', '=', 'tenants.id')
            ->select(
                'action_ledger.agent_id',
                DB::raw("COALESCE(agents.name, 'Agent-' || LEFT(action_ledger.agent_id::text, 8)) as agent_name"),
                'action_ledger.tenant_id',
                'tenants.name as tenant_name',
                'action_ledger.target_api',
                DB::raw('COUNT(*) as intercept_count'),
                DB::raw('MAX(action_ledger.created_at) as last_seen'),
                DB::raw("SUM(CASE WHEN action_ledger.status = 'blocked' THEN 1 ELSE 0 END) as block_count")
            )
            ->where('action_ledger.status', 'shadow_sandbox')
            ->where('action_ledger.created_at', '>=', $since)
            ->groupBy('action_ledger.agent_id', 'agents.name', 'action_ledger.tenant_id', 'tenants.name', 'action_ledger.target_api')
            ->orderByDesc('block_count')
            ->limit(20)
            ->get();

        $sandboxAnomalies = DB::table('action_ledger')
            ->join('agents', 'action_ledger.agent_id', '=', 'agents.id')
            ->select(
                'action_ledger.trace_id',
                'action_ledger.agent_id',
                DB::raw("COALESCE(agents.name, 'Agent-' || LEFT(action_ledger.agent_id::text, 8)) as agent_name"),
                'action_ledger.target_api',
                'action_ledger.policy_violations',
                'action_ledger.created_at'
            )
            ->where('action_ledger.action_type', 'sandbox_anomaly')
            ->orderByDesc('action_ledger.created_at')
            ->limit(10)
            ->get();

        return response()->json([
            'status' => 'success',
            'data'   => [
                'ghost_agents'      => $ghostAgents,
                'sandbox_anomalies' => $sandboxAnomalies,
                'total_ghost'       => $ghostAgents->count(),
            ],
        ]);
    }

    // ─── Verification Swarm Compute Metrics ───────────────────────────────────
    public function computeMetrics()
    {
        $since      = now()->subHour();
        $sinceMin   = now()->subMinute();

        $totalActions   = DB::table('action_ledger')->where('created_at', '>=', $since)->count();
        $blockedActions = DB::table('action_ledger')->where('created_at', '>=', $since)->where('status', 'blocked')->count();
        $activeAgents   = DB::table('agents')->whereNull('revoked_at')->count();
        $recentBlocked  = DB::table('action_ledger')->where('created_at', '>=', $sinceMin)->where('status', 'blocked')->count();
        $verifiedHops   = DB::table('action_ledger')->where('created_at', '>=', $since)->whereNotNull('swarm_confidence_score')->count();

        $recentActions = DB::table('action_ledger')
            ->leftJoin('agents', 'action_ledger.agent_id', '=', 'agents.id')
            ->select(
                'action_ledger.trace_id',
                'action_ledger.action_type',
                'action_ledger.target_api',
                'action_ledger.status',
                'action_ledger.swarm_confidence_score',
                'action_ledger.created_at',
                DB::raw("COALESCE(agents.name, 'Agent-' || LEFT(action_ledger.agent_id::text, 8)) as agent_name")
            )
            ->where('action_ledger.created_at', '>=', $since)
            ->orderByDesc('action_ledger.created_at')
            ->limit(20)
            ->get();

        return response()->json([
            'status' => 'success',
            'data'   => [
                'active_instances'  => $activeAgents,
                'threat_velocity'   => round($recentBlocked / 60, 3),
                'active_threads'    => $totalActions,
                'system_load'       => $totalActions > 0 ? round(($blockedActions / $totalActions) * 100, 1) : 0,
                'verification_hops' => $verifiedHops,
                'recent_actions'    => $recentActions,
            ],
        ]);
    }

    // ─── Vault Keys: tenant key metadata + credential lifecycle indicators (S2.5) ─
    //
    // Returns key metadata (never raw payloads) with lifecycle health indicators:
    //   - age_days: how old the key is since creation or last rotation
    //   - health_status: 'healthy' | 'warning' | 'critical' | 'expired'
    //   - last_rotated_at: timestamp of the most recent rotation (null = never rotated)
    //   - rotation_count: how many times this key has been rotated (from audit trail)
    //   - last_used_at: when an agent last used this key's provider (from action_ledger)
    //   - days_until_expiry: days remaining before the key enters 'expired' status
    //
    // Health thresholds (configurable via CICADA_KEY_MAX_AGE_DAYS, default 90):
    //   - healthy:  age < 60% of max
    //   - warning:  age between 60% and 85% of max
    //   - critical: age between 85% and 100% of max
    //   - expired:  age >= max
    public function vaultKeys()
    {
        $maxAgeDays     = (int) env('CICADA_KEY_MAX_AGE_DAYS', 90);
        $warningPct     = 0.60;  // 60% of max age → warning
        $criticalPct    = 0.85;  // 85% of max age → critical

        $keys = DB::table('tenant_keys')
            ->join('tenants', 'tenant_keys.tenant_id', '=', 'tenants.id')
            ->select(
                'tenant_keys.id',
                'tenant_keys.tenant_id',
                'tenants.name as tenant_name',
                'tenant_keys.provider',
                'tenant_keys.created_at',
                'tenant_keys.updated_at'
            )
            ->orderByDesc('tenant_keys.created_at')
            ->get();

        // ── Lifecycle enrichment per key ─────────────────────────────────────
        foreach ($keys as $key) {
            // Effective age: measured from last rotation (updated_at) or creation.
            $effectiveDate = $key->updated_at ?? $key->created_at;
            $ageDays       = max(0, (int) now()->diffInDays($effectiveDate));

            // Health classification based on configurable thresholds.
            if ($ageDays >= $maxAgeDays) {
                $health = 'expired';
            } elseif ($ageDays >= (int) ($maxAgeDays * $criticalPct)) {
                $health = 'critical';
            } elseif ($ageDays >= (int) ($maxAgeDays * $warningPct)) {
                $health = 'warning';
            } else {
                $health = 'healthy';
            }

            // Rotation count: how many 'api_key_rotated' audit entries exist
            // for this tenant + provider combination.
            $rotationCount = DB::table('operator_audit_log')
                ->where('action', 'api_key_rotated')
                ->where('entity_id', 'like', $key->tenant_id . ':' . $key->provider . '%')
                ->count();

            // Last rotation: the most recent 'api_key_rotated' event.
            $lastRotated = DB::table('operator_audit_log')
                ->where('action', 'api_key_rotated')
                ->where('entity_id', 'like', $key->tenant_id . ':' . $key->provider . '%')
                ->max('created_at');

            // Last used: the most recent action_ledger entry for any agent belonging
            // to this tenant (proxy for provider usage — we don't track per-key usage
            // at this level since keys are decrypted only in the Swarm).
            $lastUsed = DB::table('action_ledger')
                ->where('tenant_id', $key->tenant_id)
                ->max('created_at');

            $key->age_days         = $ageDays;
            $key->health_status    = $health;
            $key->max_age_days     = $maxAgeDays;
            $key->days_until_expiry = max(0, $maxAgeDays - $ageDays);
            $key->last_rotated_at  = $lastRotated;
            $key->rotation_count   = $rotationCount;
            $key->last_used_at     = $lastUsed;
        }

        // ── Fleet-level summary stats ────────────────────────────────────────
        $healthCounts = [
            'healthy'  => $keys->where('health_status', 'healthy')->count(),
            'warning'  => $keys->where('health_status', 'warning')->count(),
            'critical' => $keys->where('health_status', 'critical')->count(),
            'expired'  => $keys->where('health_status', 'expired')->count(),
        ];

        $accessLog = DB::table('action_ledger')
            ->leftJoin('tenants', 'action_ledger.tenant_id', '=', 'tenants.id')
            ->select(
                'action_ledger.trace_id',
                'action_ledger.action_type',
                'tenants.name as tenant_name',
                'action_ledger.status',
                'action_ledger.created_at'
            )
            ->whereIn('action_ledger.action_type', [
                'key_rotation', 'key_access', 'agent_provisioned', 'vault_sync',
                'api_key_rotated',
            ])
            ->orderByDesc('action_ledger.created_at')
            ->limit(10)
            ->get();

        return response()->json([
            'status' => 'success',
            'data'   => [
                'keys'           => $keys,
                'total_keys'     => $keys->count(),
                'health_summary' => $healthCounts,
                'max_age_days'   => $maxAgeDays,
                'access_log'     => $accessLog,
            ],
        ]);
    }

    public function rotateVaultKey(Request $request, string $id)
    {
        $key = DB::table('tenant_keys')->where('id', $id)->first();
        if (!$key) {
            return response()->json(['status' => 'error', 'message' => 'Key not found'], 404);
        }

        DB::table('tenant_keys')->where('id', $id)->update([
            'updated_at' => now(),
        ]);

        \App\Services\AuditService::log(
            $request,
            'api_key_rotated',
            'vault',
            $key->tenant_id . ':' . $key->provider,
            null,
            null,
            "Operator forced rotation of {$key->provider} key for tenant {$key->tenant_id}"
        );

        return response()->json(['status' => 'success', 'message' => 'Key rotated successfully.']);
    }

    // ─── Alerts: recent security events for notification bell ─────────────────
    public function alerts()
    {
        $since = now()->subHour();

        $recentBlocked = DB::table('action_ledger')
            ->leftJoin('tenants', 'action_ledger.tenant_id', '=', 'tenants.id')
            ->leftJoin('agents', 'action_ledger.agent_id', '=', 'agents.id')
            ->select(
                'action_ledger.trace_id',
                'action_ledger.action_type',
                'action_ledger.target_api',
                'action_ledger.status',
                'action_ledger.created_at',
                'tenants.name as tenant_name',
                DB::raw("COALESCE(agents.name, 'Agent-' || LEFT(action_ledger.agent_id::text, 8)) as agent_name")
            )
            ->where('action_ledger.status', 'blocked')
            ->where('action_ledger.created_at', '>=', $since)
            ->orderByDesc('action_ledger.created_at')
            ->limit(10)
            ->get();

        $circuitTrips     = DB::table('action_ledger')->where('action_type', 'circuit_breaker_trip')->where('created_at', '>=', $since)->count();
        $sandboxAnomalies = DB::table('action_ledger')->where('action_type', 'sandbox_anomaly')->where('created_at', '>=', $since)->count();

        return response()->json([
            'status' => 'success',
            'data'   => [
                'unread_count'      => $recentBlocked->count() + $circuitTrips + $sandboxAnomalies,
                'alerts'            => $recentBlocked,
                'circuit_breaker_trips' => $circuitTrips,
                'sandbox_anomalies' => $sandboxAnomalies,
            ],
        ]);
    }

    // ─── Helpers ──────────────────────────────────────────────────────────────

    private function trustTierToScore(string $tier): float
    {
        return match($tier) {
            'critical' => 98.0,
            'elevated' => 82.5,
            'nominal'  => 60.0,
            default    => 14.0,
        };
    }

    private function trustTierLabel(string $tier): string
    {
        return match($tier) {
            'critical' => 'Tier 1 - Critical Core',
            'elevated' => 'Tier 2 - Elevated Access',
            'nominal'  => 'Tier 3 - Nominal',
            default    => 'Unverified',
        };
    }

    public function saveAegisDirectives(Request $request)
    {
        $promptData = $request->input('prompt_data');
        $oldState = DB::table('platform_policies')->where('slug', 'aegis_directives')->first();

        // Persist to a simple key-value config store in the DB
        DB::table('platform_policies')
            ->where('slug', 'aegis_directives')
            ->updateOrInsert(
                ['slug' => 'aegis_directives'],
                ['name' => 'Aegis Directives', 'rule_config' => json_encode(['prompt' => $promptData]), 'updated_at' => now()]
            );

        AuditService::log(
            $request,
            'security_rule_toggled',
            'policy',
            'aegis_directives',
            $oldState ? ['rule_config' => $oldState->rule_config] : null,
            ['rule_config' => json_encode(['prompt' => $promptData])],
            'Operator saved Aegis Directives'
        );

        return response()->json(['status' => 'success']);
    }

    public function releaseAegisAlert(Request $request, string $id)
    {
        $oldState = DB::table('action_ledger')->where('trace_id', $id)->first();

        // Log the dismissal in action_ledger if the trace exists
        DB::table('action_ledger')
            ->where('trace_id', $id)
            ->update(['status' => 'operator_released', 'updated_at' => now()]);

        if ($oldState) {
            AuditService::log(
                $request,
                'alert_rule_modified', // Closest match, though technically releasing an alert
                'agent', 
                $oldState->agent_id,
                ['status' => $oldState->status],
                ['status' => 'operator_released'],
                'Operator released Aegis alert for trace ' . $id
            );
        }

        return response()->json(['status' => 'success', 'message' => 'Alert dismissed.']);
    }

    // ─── Aegis Configuration Reads ────────────────────────────────────────────

    /**
     * GET /aegis/directives
     * Loads the operator's saved Aegis instructions from platform_policies.
     * Returns the raw prompt text so the frontend can hydrate the textarea.
     */
    public function getAegisDirectives()
    {
        $row = DB::table('platform_policies')
            ->where('slug', 'aegis_directives')
            ->first();

        if (!$row) {
            return response()->json([
                'status' => 'success',
                'data'   => ['prompt_data' => null],
            ]);
        }

        $config = json_decode($row->rule_config, true);

        return response()->json([
            'status' => 'success',
            'data'   => [
                'prompt_data' => $config['prompt'] ?? null,
                'updated_at'  => $row->updated_at,
            ],
        ]);
    }

    /**
     * GET /aegis/model
     * Loads the operator's saved Aegis model selection from platform_policies.
     */
    public function getAegisModel()
    {
        $row = DB::table('platform_policies')
            ->where('slug', 'aegis_model')
            ->first();

        if (!$row) {
            return response()->json([
                'status' => 'success',
                'data'   => ['model_id' => 'deepseek/deepseek-r1'],
            ]);
        }

        $config = json_decode($row->rule_config, true);

        return response()->json([
            'status' => 'success',
            'data'   => [
                'model_id'   => $config['model_id'] ?? 'deepseek/deepseek-r1',
                'updated_at' => $row->updated_at,
            ],
        ]);
    }

    /**
     * POST /aegis/model
     * Persists the operator's Aegis model selection.
     */
    public function saveAegisModel(Request $request)
    {
        $modelId = $request->input('model_id');
        if (!$modelId || !is_string($modelId)) {
            return response()->json(['status' => 'error', 'message' => 'model_id required'], 422);
        }

        $oldState = DB::table('platform_policies')->where('slug', 'aegis_model')->first();

        DB::table('platform_policies')
            ->updateOrInsert(
                ['slug' => 'aegis_model'],
                ['name' => 'Aegis Model', 'rule_config' => json_encode(['model_id' => $modelId]), 'updated_at' => now()]
            );

        AuditService::log(
            $request,
            'security_rule_toggled',
            'policy',
            'aegis_model',
            $oldState ? ['rule_config' => $oldState->rule_config] : null,
            ['rule_config' => json_encode(['model_id' => $modelId])],
            'Operator changed Aegis model to ' . $modelId
        );

        return response()->json(['status' => 'success']);
    }

    /**
     * GET /aegis/alerts
     * Returns active Aegis-related entries from the action_ledger that haven't
     * been dismissed by the operator.
     */
    public function getAegisAlerts()
    {
        // Fetch recent Aegis-triggered actions that are still active
        $alerts = DB::table('action_ledger')
            ->whereIn('action_type', [
                'aegis_directive',
                'aegis_quarantine',
                'aegis_ghost_mode',
                'aegis_rollback',
                'aegis_triggered_rollback',
                // Layer 1d skill routing exceptions
                'skill_blocked',
                'skill_schema_violation',
                'skill_delegation_blocked',
                // Anti-Rot memory flush signals
                'memory_flush',
            ])
            ->where('status', '!=', 'operator_released')
            ->orderByDesc('created_at')
            ->limit(20)
            ->get()
            ->map(function ($row) {
                return [
                    'id'          => $row->trace_id ?? $row->id,
                    'action_type' => $row->action_type,
                    'agent_id'    => $row->agent_id,
                    'tenant_id'   => $row->tenant_id,
                    'status'      => $row->status,
                    'target_api'  => $row->target_api ?? null,
                    'created_at'  => $row->created_at,
                ];
            });

        return response()->json([
            'status' => 'success',
            'data'   => $alerts,
        ]);
    }

    /**
     * GET /aegis/activity
     * Returns the most recent Aegis reasoning/action entries from the ledger
     * for the Reasoning and Action Taken panels.
     */
    public function getAegisActivity()
    {
        // Most recent aegis-triggered events for the reasoning/action panels
        $entries = DB::table('action_ledger')
            ->where(function ($q) {
            $q->where('action_type', 'like', 'aegis_%')
                  ->orWhere('action_type', 'like', 'quarantine%')
                  ->orWhere('action_type', 'like', 'ghost_mode%')
                  // Layer 1d skill routing events
                  ->orWhere('action_type', 'like', 'skill_%')
                  // Anti-Rot memory flush events
                  ->orWhere('action_type', 'like', 'memory_flush%');
            })
            ->orderByDesc('created_at')
            ->limit(10)
            ->get()
            ->map(function ($row) {
                return [
                    'trace_id'    => $row->trace_id ?? null,
                    'action_type' => $row->action_type,
                    'agent_id'    => $row->agent_id,
                    'tenant_id'   => $row->tenant_id,
                    'target_api'  => $row->target_api ?? null,
                    'status'      => $row->status,
                    'created_at'  => $row->created_at,
                ];
            });

        return response()->json([
            'status' => 'success',
            'data'   => $entries,
        ]);
    }

    // ─── Aegis Model List Proxy ──────────────────────────────────────────────

    /**
     * GET /aegis/models
     * Proxies the OpenRouter model list server-side so the browser doesn't need
     * to make a cross-origin request (which CSP blocks).
     * Caches the response for 5 minutes to avoid hammering OpenRouter.
     */
    public function listAegisModels()
    {
        $cacheKey = 'aegis_openrouter_models';
        $cached = \Illuminate\Support\Facades\Cache::get($cacheKey);

        if ($cached) {
            return response()->json([
                'status' => 'success',
                'data'   => $cached,
            ]);
        }

        try {
            $response = \Illuminate\Support\Facades\Http::timeout(10)
                ->get('https://openrouter.ai/api/v1/models');

            if ($response->successful()) {
                $models = collect($response->json('data') ?? [])
                    ->map(fn($m) => [
                        'id'   => $m['id'] ?? '',
                        'name' => $m['name'] ?? $m['id'] ?? '',
                    ])
                    ->filter(fn($m) => !empty($m['id']))
                    ->values()
                    ->all();

                \Illuminate\Support\Facades\Cache::put($cacheKey, $models, now()->addMinutes(5));

                return response()->json([
                    'status' => 'success',
                    'data'   => $models,
                ]);
            }
        } catch (\Throwable $e) {
            // Fail gracefully — return empty list
        }

        return response()->json([
            'status' => 'success',
            'data'   => [],
        ]);
    }

    // ─── Aegis Rules Engine ──────────────────────────────────────────────────

    /**
     * GET /aegis/rules
     * Returns all Aegis rules ordered by priority (highest first).
     */
    public function getAegisRules()
    {
        $rules = DB::table('aegis_rules')
            ->orderByDesc('priority')
            ->orderBy('name')
            ->get();

        return response()->json(['status' => 'success', 'data' => $rules]);
    }

    /**
     * POST /aegis/rules
     * Creates a new custom rule.
     */
    public function createAegisRule(Request $request)
    {
        $name     = $request->input('name');
        $category = $request->input('category');
        $ruleType = $request->input('rule_type');
        $config   = $request->input('rule_config');

        if (!$name || !$category || !$ruleType || !$config) {
            return response()->json(['status' => 'error', 'message' => 'name, category, rule_type, and rule_config required'], 422);
        }

        $allowedCategories = ['permission', 'threshold', 'scope', 'escalation', 'rate_limit', 'custom'];
        if (!in_array($category, $allowedCategories, true)) {
            return response()->json(['status' => 'error', 'message' => 'Invalid category'], 422);
        }

        $slug = \Illuminate\Support\Str::slug($name, '_');
        $existing = DB::table('aegis_rules')->where('slug', $slug)->exists();
        if ($existing) {
            $slug .= '_' . substr(md5((string) now()), 0, 6);
        }

        DB::table('aegis_rules')->insert([
            'slug'        => $slug,
            'name'        => $name,
            'category'    => $category,
            'rule_type'   => $ruleType,
            'rule_config' => is_string($config) ? $config : json_encode($config),
            'description' => $request->input('description', ''),
            'is_active'   => true,
            'is_system'   => false,
            'priority'    => (int) $request->input('priority', 50),
            'created_at'  => now(),
            'updated_at'  => now(),
        ]);

        AuditService::log(
            $request,
            'security_rule_toggled',
            'policy',
            $slug,
            null,
            ['name' => $name, 'category' => $category, 'rule_config' => $config],
            'Operator created Aegis rule: ' . $name
        );

        return response()->json(['status' => 'success']);
    }

    /**
     * PATCH /aegis/rules/{id}
     * Updates a rule's config, active state, or priority.
     */
    public function updateAegisRule(Request $request, string $id)
    {
        $row = DB::table('aegis_rules')->where('id', $id)->first();
        if (!$row) {
            return response()->json(['status' => 'error', 'message' => 'Rule not found'], 404);
        }

        $updates = [];
        if ($request->has('is_active'))   $updates['is_active']   = (bool) $request->input('is_active');
        if ($request->has('rule_config')) {
            $config = $request->input('rule_config');
            $updates['rule_config'] = is_string($config) ? $config : json_encode($config);
        }
        if ($request->has('priority'))    $updates['priority']    = (int) $request->input('priority');
        if ($request->has('name'))        $updates['name']        = $request->input('name');
        if ($request->has('description')) $updates['description'] = $request->input('description');

        if (empty($updates)) {
            return response()->json(['status' => 'error', 'message' => 'No fields to update'], 422);
        }

        $updates['updated_at'] = now();
        DB::table('aegis_rules')->where('id', $id)->update($updates);

        AuditService::log(
            $request,
            'security_rule_toggled',
            'policy',
            $row->slug,
            ['is_active' => $row->is_active, 'rule_config' => $row->rule_config],
            $updates,
            'Operator updated Aegis rule: ' . $row->name
        );

        return response()->json(['status' => 'success']);
    }

    /**
     * DELETE /aegis/rules/{id}
     * Deletes a custom rule. System rules cannot be deleted (only toggled).
     */
    public function deleteAegisRule(Request $request, string $id)
    {
        $row = DB::table('aegis_rules')->where('id', $id)->first();
        if (!$row) {
            return response()->json(['status' => 'error', 'message' => 'Rule not found'], 404);
        }
        if ($row->is_system) {
            return response()->json(['status' => 'error', 'message' => 'System rules cannot be deleted. Disable instead.'], 403);
        }

        DB::table('aegis_rules')->where('id', $id)->delete();

        AuditService::log(
            $request,
            'security_rule_toggled',
            'policy',
            $row->slug,
            ['name' => $row->name, 'rule_config' => $row->rule_config],
            null,
            'Operator deleted Aegis rule: ' . $row->name
        );

        return response()->json(['status' => 'success']);
    }

    // ─── Aegis Tool Registry ─────────────────────────────────────────────────

    /**
     * GET /aegis/tools
     * Returns all tools from the registry with operator settings.
     */
    public function getAegisTools()
    {
        $tools = DB::table('aegis_tool_registry')
            ->orderByRaw("CASE category WHEN 'telemetry' THEN 1 WHEN 'registry' THEN 2 WHEN 'control' THEN 3 WHEN 'policy' THEN 4 ELSE 5 END")
            ->orderBy('display_name')
            ->get();

        return response()->json(['status' => 'success', 'data' => $tools]);
    }

    /**
     * PATCH /aegis/tools/{id}
     * Updates a tool's enabled state, HITL requirement, or rate limit.
     */
    public function updateAegisTool(Request $request, string $id)
    {
        $row = DB::table('aegis_tool_registry')->where('id', $id)->first();
        if (!$row) {
            return response()->json(['status' => 'error', 'message' => 'Tool not found'], 404);
        }

        $updates = [];
        if ($request->has('is_enabled'))    $updates['is_enabled']    = (bool) $request->input('is_enabled');
        if ($request->has('requires_hitl')) $updates['requires_hitl'] = (bool) $request->input('requires_hitl');
        if ($request->has('max_per_hour'))  $updates['max_per_hour']  = $request->input('max_per_hour') !== null ? (int) $request->input('max_per_hour') : null;

        if (empty($updates)) {
            return response()->json(['status' => 'error', 'message' => 'No fields to update'], 422);
        }

        $updates['updated_at'] = now();
        DB::table('aegis_tool_registry')->where('id', $id)->update($updates);

        AuditService::log(
            $request,
            'security_rule_toggled',
            'policy',
            $row->tool_name,
            ['is_enabled' => $row->is_enabled, 'requires_hitl' => $row->requires_hitl, 'max_per_hour' => $row->max_per_hour],
            $updates,
            'Operator updated Aegis tool: ' . $row->display_name
        );

        return response()->json(['status' => 'success']);
    }

    // ─── Aegis Trace Log ─────────────────────────────────────────────────────

    /**
     * GET /aegis/traces
     * Returns paginated reasoning cycles (grouped by trace_id).
     */
    public function getAegisTraces(Request $request)
    {
        $limit = min((int) ($request->query('limit', 20)), 50);
        $offset = max((int) ($request->query('offset', 0)), 0);

        // Get distinct trace_ids ordered by most recent
        $traceIds = DB::table('aegis_trace_log')
            ->select('trace_id', DB::raw('MAX(created_at) as latest'), DB::raw('SUM(tokens_in) as total_tokens_in'), DB::raw('SUM(tokens_out) as total_tokens_out'), DB::raw('SUM(duration_ms) as total_duration_ms'))
            ->groupBy('trace_id')
            ->orderByDesc('latest')
            ->offset($offset)
            ->limit($limit)
            ->get();

        // Batch-load all steps for the fetched trace IDs in a single query — eliminates N+1.
        $allSteps = DB::table('aegis_trace_log')
            ->whereIn('trace_id', $traceIds->pluck('trace_id'))
            ->orderBy('step_order')
            ->get()
            ->groupBy('trace_id');

        // Assemble trace summaries from the pre-loaded steps.
        $traces = $traceIds->map(function ($t) use ($allSteps) {
            $steps = $allSteps[$t->trace_id] ?? collect();

            $trigger = $steps->firstWhere('step', 'trigger');
            $decision = $steps->firstWhere('step', 'decision');
            $gate = $steps->firstWhere('step', 'gate');
            $result = $steps->firstWhere('step', 'result');

            return [
                'trace_id'        => $t->trace_id,
                'created_at'      => $t->latest,
                'total_tokens_in' => $t->total_tokens_in,
                'total_tokens_out'=> $t->total_tokens_out,
                'duration_ms'     => $t->total_duration_ms,
                'step_count'      => $steps->count(),
                'trigger'         => $trigger ? json_decode($trigger->content, true) : null,
                'decision'        => $decision ? json_decode($decision->content, true) : null,
                'gate_passed'     => $gate ? (json_decode($gate->content, true)['blocked_by'] ?? null) === null : null,
                'outcome'         => $result ? json_decode($result->content, true)['status'] ?? 'unknown' : 'pending',
                'model_id'        => $steps->first()?->model_id ?? null,
            ];
        });

        return response()->json(['status' => 'success', 'data' => $traces]);
    }

    /**
     * GET /aegis/traces/{traceId}
     * Returns the full step-by-step detail for one reasoning cycle.
     */
    public function getAegisTraceDetail(string $traceId)
    {
        $steps = DB::table('aegis_trace_log')
            ->where('trace_id', $traceId)
            ->orderBy('step_order')
            ->get()
            ->map(function ($row) {
                return [
                    'id'         => $row->id,
                    'step'       => $row->step,
                    'step_order' => $row->step_order,
                    'content'    => json_decode($row->content, true),
                    'model_id'   => $row->model_id,
                    'tokens_in'  => $row->tokens_in,
                    'tokens_out' => $row->tokens_out,
                    'duration_ms'=> $row->duration_ms,
                    'created_at' => $row->created_at,
                ];
            });

        if ($steps->isEmpty()) {
            return response()->json(['status' => 'error', 'message' => 'Trace not found'], 404);
        }

        return response()->json(['status' => 'success', 'data' => $steps]);
    }

    // ─── Aegis System Prompt Assembly ─────────────────────────────────────────

    /**
     * GET /aegis/system-prompt
     * Assembles the full system prompt for Aegis from rules + directives + tools.
     * Called by the Gateway before each inference cycle.
     */
    public function getAegisSystemPrompt()
    {
        // Section 1: Active rules
        $rules = DB::table('aegis_rules')
            ->where('is_active', true)
            ->orderByDesc('priority')
            ->get();

        $rulesText = $rules->map(function ($r) {
            $config = json_decode($r->rule_config, true);
            $value = '';
            if (isset($config['enabled'])) {
                $value = $config['enabled'] ? 'ENFORCED' : 'DISABLED';
            } elseif (isset($config['value'])) {
                $value = $config['value'] . (isset($config['unit']) ? ' ' . $config['unit'] : '');
            } elseif (isset($config['allowed'])) {
                $value = implode(', ', $config['allowed']);
            }
            return "- RULE [{$r->category}] {$r->name}: {$value}" . ($r->description ? " — {$r->description}" : '');
        })->implode("\n");

        // Section 2: Tool permissions
        $tools = DB::table('aegis_tool_registry')->get();

        $enabledTools  = $tools->where('is_enabled', true)->pluck('tool_name')->implode(', ');
        $disabledTools = $tools->where('is_enabled', false)->pluck('tool_name')->implode(', ');
        $hitlTools     = $tools->where('requires_hitl', true)->where('is_enabled', true)->pluck('tool_name')->implode(', ');

        // Section 3: Operator directives
        $directives = DB::table('platform_policies')
            ->where('slug', 'aegis_directives')
            ->first();
        $directivesText = '';
        if ($directives) {
            $config = json_decode($directives->rule_config, true);
            $directivesText = $config['prompt'] ?? '';
        }

        // Assemble
        $prompt = "═══════════════════════════════════════════════\n";
        $prompt .= "CICADA AEGIS-0 SYSTEM DIRECTIVES\n";
        $prompt .= "═══════════════════════════════════════════════\n\n";

        $prompt .= "[IDENTITY]\n";
        $prompt .= "You are Aegis, the security AI assistant for the Cicada Cloud platform.\n";
        $prompt .= "You monitor agent activity, detect threats, and enforce security policies.\n";
        $prompt .= "You do NOT operate the agent swarm — you govern it.\n\n";

        $prompt .= "[RULES — " . $rules->count() . " active]\n";
        $prompt .= $rulesText ?: "No rules configured.";
        $prompt .= "\n\n";

        $prompt .= "[TOOLS]\n";
        $prompt .= "Available: " . ($enabledTools ?: 'none') . "\n";
        if ($disabledTools) {
            $prompt .= "Disabled (DO NOT CALL): " . $disabledTools . "\n";
        }
        if ($hitlTools) {
            $prompt .= "HITL Required (must request operator approval before executing): " . $hitlTools . "\n";
        }
        $prompt .= "\n";

        $prompt .= "[OPERATOR DIRECTIVES]\n";
        $prompt .= $directivesText ?: "No directives set.";
        $prompt .= "\n";

        return response()->json([
            'status' => 'success',
            'data'   => [
                'system_prompt' => $prompt,
                'token_estimate' => (int) (strlen($prompt) / 4), // rough approximation
                'rules_count'    => $rules->count(),
                'tools_enabled'  => $tools->where('is_enabled', true)->count(),
                'tools_disabled' => $tools->where('is_enabled', false)->count(),
            ],
        ]);
    }

    // ─── Aegis Trace Retention Setting ────────────────────────────────────────

    /**
     * GET /aegis/settings
     * Returns Aegis configuration settings (trace retention, etc.).
     */
    public function getAegisSettings()
    {
        $row = DB::table('platform_policies')
            ->where('slug', 'aegis_settings')
            ->first();

        $defaults = ['trace_retention_days' => 30];

        if ($row) {
            $config = json_decode($row->rule_config, true);
            return response()->json(['status' => 'success', 'data' => array_merge($defaults, $config)]);
        }

        return response()->json(['status' => 'success', 'data' => $defaults]);
    }

    /**
     * POST /aegis/settings
     * Updates Aegis configuration settings.
     */
    public function saveAegisSettings(Request $request)
    {
        $retentionDays = $request->input('trace_retention_days');
        if ($retentionDays !== null && !in_array((int) $retentionDays, [30, 60, 90], true)) {
            return response()->json(['status' => 'error', 'message' => 'trace_retention_days must be 30, 60, or 90'], 422);
        }

        $config = [];
        if ($retentionDays !== null) $config['trace_retention_days'] = (int) $retentionDays;

        $oldState = DB::table('platform_policies')->where('slug', 'aegis_settings')->first();

        DB::table('platform_policies')
            ->updateOrInsert(
                ['slug' => 'aegis_settings'],
                ['name' => 'Aegis Settings', 'rule_config' => json_encode($config), 'updated_at' => now()]
            );

        AuditService::log(
            $request,
            'security_rule_toggled',
            'policy',
            'aegis_settings',
            $oldState ? ['rule_config' => $oldState->rule_config] : null,
            ['rule_config' => json_encode($config)],
            'Operator updated Aegis settings'
        );

        return response()->json(['status' => 'success']);
    }

    // ─── HITL Approval Queue ──────────────────────────────────────────────────

    /**
     * GET /api/v1/admin/hitl/queue
     *
     * Returns pending HITL calls first (time-sensitive), then the last 50 resolved
     * HITL events for context. Operators must be able to approve/reject pending
     * calls before the gateway's 60-second timeout expires.
     */
    public function hitlQueue(): \Illuminate\Http\JsonResponse
    {
        $pending = DB::table('action_ledger')
            ->leftJoin('agents', 'action_ledger.agent_id', '=', 'agents.id')
            ->leftJoin('tenants', 'agents.tenant_id', '=', 'tenants.id')
            ->where('action_ledger.action_type', 'hitl_pending')
            ->select(
                'action_ledger.trace_id',
                'action_ledger.agent_id',
                'action_ledger.target_api',
                'action_ledger.action_type',
                'action_ledger.status',
                'action_ledger.policy_violations',
                'action_ledger.created_at',
                'agents.name as agent_name',
                'agents.trust_tier',
                'agents.hitl_enabled',
                'tenants.name as company_name',
            )
            ->orderBy('action_ledger.created_at')
            ->get();

        $resolved = DB::table('action_ledger')
            ->leftJoin('agents', 'action_ledger.agent_id', '=', 'agents.id')
            ->leftJoin('tenants', 'agents.tenant_id', '=', 'tenants.id')
            ->whereIn('action_ledger.action_type', ['hitl_approved', 'hitl_rejected', 'hitl_timeout'])
            ->select(
                'action_ledger.trace_id',
                'action_ledger.agent_id',
                'action_ledger.target_api',
                'action_ledger.action_type',
                'action_ledger.status',
                'action_ledger.policy_violations',
                'action_ledger.created_at',
                'agents.name as agent_name',
                'agents.trust_tier',
                'tenants.name as company_name',
            )
            ->orderByDesc('action_ledger.created_at')
            ->limit(50)
            ->get();

        return response()->json([
            'status'   => 'success',
            'pending'  => $pending,
            'resolved' => $resolved,
        ]);
    }

    #[OA\Post(
        path: '/api/v1/admin/hitl/{traceId}/approve',
        summary: 'Approve a blocked Human-in-the-Loop action',
        description: 'Operator overrides a swarm block and approves the action for execution.',
        tags: ['Governance']
    )]
    #[OA\Parameter(
        name: 'traceId',
        description: 'UUID of the trace to approve',
        in: 'path',
        required: true,
        schema: new OA\Schema(type: 'string', format: 'uuid')
    )]
    #[OA\Response(
        response: 200,
        description: 'Action approved successfully'
    )]
    public function hitlApprove(string $traceId): \Illuminate\Http\JsonResponse
    {
        $updated = DB::table('action_ledger')
            ->where('trace_id', $traceId)
            ->where('action_type', 'hitl_pending')
            ->update([
                'action_type' => 'hitl_approved',
                'status'      => 'approved',
            ]);

        if (!$updated) {
            return response()->json(['error' => 'HITL event not found or already resolved.'], 404);
        }

        AuditService::log(request(), 'hitl_approved', 'action_ledger', $traceId, null, ['status' => 'approved'], 'Operator approved HITL event');

        return response()->json(['status' => 'success', 'message' => 'Approved.']);
    }

    #[OA\Post(
        path: '/api/v1/admin/hitl/{traceId}/reject',
        summary: 'Reject a blocked Human-in-the-Loop action',
        description: 'Operator denies a swarm block permanently, enforcing the block.',
        tags: ['Governance']
    )]
    #[OA\Parameter(
        name: 'traceId',
        description: 'UUID of the trace to reject',
        in: 'path',
        required: true,
        schema: new OA\Schema(type: 'string', format: 'uuid')
    )]
    #[OA\Response(
        response: 200,
        description: 'Action rejected successfully'
    )]
    public function hitlReject(string $traceId): \Illuminate\Http\JsonResponse
    {
        $updated = DB::table('action_ledger')
            ->where('trace_id', $traceId)
            ->where('action_type', 'hitl_pending')
            ->update([
                'action_type' => 'hitl_rejected',
                'status'      => 'blocked',
            ]);

        if (!$updated) {
            return response()->json(['error' => 'HITL event not found or already resolved.'], 404);
        }

        $trace = DB::table('action_ledger')->where('trace_id', $traceId)->first();
        if ($trace) {
            AlertDispatcherService::dispatch(
                'swarm_block_manual_reject',
                $trace->tenant_id,
                $trace->agent_id ?? 'unknown',
                ['trace_id' => $traceId]
            );

            // H2.3: Cross-system revocation — notify external IdPs/SIEMs that
            // this agent's action was manually rejected by an operator.
            RevocationDispatcherService::dispatch(
                'operator_quarantine',
                $trace->tenant_id,
                $trace->agent_id ?? 'unknown',
                [
                    'reason'   => 'Operator manually rejected HITL event',
                    'trace_id' => $traceId,
                ]
            );
        }

        AuditService::log(request(), 'hitl_denied', 'action_ledger', $traceId, null, ['status' => 'blocked'], 'Operator rejected HITL event');

        return response()->json(['status' => 'success', 'message' => 'Rejected.']);
    }

    // ─── Policy Violation Trends (30 day, daily) ─────────────────────────────
    public function violationTrends(): \Illuminate\Http\JsonResponse
    {
        $since = now()->subDays(30)->startOfDay();

        $rows = DB::table('action_ledger')
            ->select(
                DB::raw("date_trunc('day', created_at)::date as day"),
                'policy_violations'
            )
            ->where('status', 'blocked')
            ->where('created_at', '>=', $since)
            ->whereNotNull('policy_violations')
            ->orderBy('day')
            ->get();

        // Aggregate: { "2026-04-01": { "scope_violation": 3, "role_violation": 1 }, ... }
        $buckets = [];
        foreach ($rows as $row) {
            $day = $row->day;
            $violations = json_decode($row->policy_violations, true);
            if (!is_array($violations)) continue;

            // Handle both flat arrays ["scope_violation"] and keyed objects {"scope_violation": true}
            $keys = array_is_list($violations) ? $violations : array_keys($violations);
            foreach ($keys as $key) {
                $key = strtolower(trim($key));
                if (!isset($buckets[$day])) $buckets[$day] = [];
                $buckets[$day][$key] = ($buckets[$day][$key] ?? 0) + 1;
            }
        }

        // Build a series-friendly structure
        $allKeys = [];
        foreach ($buckets as $dayCounts) {
            foreach (array_keys($dayCounts) as $k) $allKeys[$k] = true;
        }

        $series = [];
        foreach (array_keys($allKeys) as $violationType) {
            $points = [];
            for ($d = $since->copy(); $d->lte(now()); $d->addDay()) {
                $dayStr = $d->format('Y-m-d');
                $points[] = ['date' => $dayStr, 'count' => $buckets[$dayStr][$violationType] ?? 0];
            }
            $series[] = ['key' => $violationType, 'data' => $points];
        }

        return response()->json(['status' => 'success', 'data' => $series]);
    }

    // ─── Operator Audit Logs (SOC2 compliance) ──────────────────────────────
    public function auditLogs(Request $request): \Illuminate\Http\JsonResponse
    {
        $validated = $request->validate([
            'action_type' => 'nullable|string|max:100',
            'operator'    => 'nullable|string|min:3|max:255',
            'from'        => 'nullable|date',
            'to'          => 'nullable|date',
            'per_page'    => 'nullable|integer|min:1|max:200',
        ]);

        $query = DB::table('operator_audit_log')
            ->select([
                'id',
                'operator_id',
                'operator_label as operator_email',
                'action as action_type',
                'entity_type as target_type',
                'entity_id as target_id',
                'before_state as previous_state',
                'after_state as new_state',
                'ip_address',
                'notes as justification',
                'user_agent',
                'session_id',
                'created_at',
            ])
            ->orderByDesc('created_at');

        // Filter: action (maps from frontend's action_type parameter)
        if (!empty($validated['action_type'])) {
            $query->where('action', $validated['action_type']);
        }

        // Filter: operator_label (min 3 chars required to prevent enumeration)
        if (!empty($validated['operator'])) {
            $query->where('operator_label', 'ilike', '%' . $validated['operator'] . '%');
        }

        // Filter: date range
        if (!empty($validated['from'])) {
            $query->where('created_at', '>=', $validated['from']);
        }
        if (!empty($validated['to'])) {
            $query->where('created_at', '<=', $validated['to']);
        }

        $perPage = min((int) ($validated['per_page'] ?? 50), 200);

        return response()->json([
            'status' => 'success',
            'data'   => $query->paginate($perPage),
        ]);
    }

    /**
     * Flag an action_ledger entry as a false positive.
     * This is used for gathering feedback to fine-tune the Tier 1 semantic engine.
     */
    public function flagFalsePositive(Request $request, string $traceId)
    {
        $updated = DB::table('action_ledger')
            ->where('trace_id', $traceId)
            ->update(['is_false_positive' => true]);

        if (!$updated) {
            return response()->json(['status' => 'error', 'message' => 'Trace not found'], 404);
        }

        \App\Services\AuditService::log(
            $request,
            'trace_flagged_false_positive',
            'action_ledger',
            $traceId,
            null,
            ['is_false_positive' => true],
            'Operator flagged blocked action as false positive for model retraining'
        );

        return response()->json([
            'status' => 'success',
            'message' => 'Trace flagged as false positive for semantic retraining.',
        ]);
    }

    /**
     * Proxy the Sentry Gateway's /metrics endpoint so the dashboard can fetch
     * real cache hit/miss ratios and latency data without direct access to :8080.
     */
    public function gatewayMetrics(): \Illuminate\Http\JsonResponse
    {
        $gatewayUrl = env('SENTRY_GATEWAY_URL', 'http://localhost:8080');
        try {
            $response = \Illuminate\Support\Facades\Http::timeout(0.5)
                ->get("{$gatewayUrl}/metrics");

            if ($response->successful()) {
                return response()->json($response->json());
            }

            return response()->json([
                'error' => 'Gateway returned ' . $response->status(),
            ], 502);
        } catch (\Exception $e) {
            return response()->json([
                'error' => 'Gateway unreachable: ' . $e->getMessage(),
            ], 503);
        }
    }

    /**
     * Export flagged false positive payloads for fine-tuning the nomic-embed-text weights.
     */
    public function exportRetrainingDataset()
    {
        $dataset = DB::table('action_ledger')
            ->where('is_false_positive', true)
            ->where('status', 'blocked')
            ->select(
                'trace_id',
                'agent_id',
                'target_api',
                'action_type',
                'payload_hash',
                'human_user_context',
                'reasoning_trace',
                'semantic_alignment_score'
            )
            ->get();

        // Convert to JSONL format for easy ingestion by ML pipelines
        $jsonl = '';
        foreach ($dataset as $row) {
            $jsonl .= json_encode($row) . "\n";
        }

        return response($jsonl)
            ->header('Content-Type', 'application/jsonl')
            ->header('Content-Disposition', 'attachment; filename="cicada_retraining_dataset_' . now()->format('Y_m_d') . '.jsonl"');
    }

    // ─── Dismiss / Resolve Threat Alert ────────────────────────────────────
    //
    // Transitions an operator_alert from 'open' to 'resolved'. This allows
    // operators to clear dealt-with alerts from the Global Overview's Active
    // Threat Alerts panel. The alert is not deleted — it remains in the table
    // for audit trail purposes with resolved_at timestamp and resolved_by
    // operator reference.
    //
    // Route: POST /api/v1/admin/alerts/{id}/dismiss
    // Auth:  operator.auth middleware (Zone 4)
    //
    public function dismissAlert(string $id)
    {
        // Validate the alert exists and is currently open.
        $alert = DB::table('operator_alerts')
            ->where('id', $id)
            ->where('status', 'open')
            ->first();

        if (!$alert) {
            return response()->json([
                'status' => 'error',
                'error'  => 'Alert not found or already resolved.',
            ], 404);
        }

        // Transition the alert to resolved state.
        // The schema supports: open → acknowledged → resolved.
        // Dismissing from the dashboard skips 'acknowledged' and goes
        // directly to 'resolved' since the operator is actively clearing it.
        DB::table('operator_alerts')
            ->where('id', $id)
            ->update([
                'status'      => 'resolved',
                'resolved_at' => now(),
                'updated_at'  => now(),
            ]);

        // Record the dismissal in the operator audit log for traceability.
        if (class_exists(\App\Services\AuditService::class)) {
            try {
                app(AuditService::class)->log('alert_dismissed', [
                    'alert_id'   => $id,
                    'event_type' => $alert->event_type,
                    'severity'   => $alert->severity,
                    'summary'    => $alert->summary,
                ]);
            } catch (\Throwable $e) {
                // Audit logging failure should not block the dismiss operation.
                \Illuminate\Support\Facades\Log::warning('Audit log failed for alert dismissal', [
                    'alert_id' => $id,
                    'error'    => $e->getMessage(),
                ]);
            }
        }

        return response()->json([
            'status'  => 'success',
            'message' => 'Alert resolved successfully.',
        ]);
    }
}
