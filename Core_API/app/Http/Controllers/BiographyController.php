<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use App\Services\AuditService;
use App\Services\AlertDispatcherService;
use App\Services\RevocationDispatcherService;
use OpenApi\Attributes as OA;

/**
 * BiographyController — complete lifecycle data for a single agent.
 *
 * GET /api/v1/agents/{id}/biography  — full seven-section biography in one call
 * GET /api/v1/agents/{id}/timeline   — paginated chronological event feed
 */
class BiographyController extends Controller
{
    /**
     * Discover which columns actually exist in the action_ledger table.
     * Gateway migrations 003-006 progressively add columns; this lets the
     * controller work regardless of which migrations have been applied.
     */
    private function ledgerColumns(): array
    {
        static $cols = null;
        if ($cols === null) {
            $rows = DB::select(
                "SELECT column_name FROM information_schema.columns WHERE table_name = 'action_ledger'"
            );
            $cols = array_map(fn($r) => $r->column_name, $rows);
        }
        return $cols;
    }

    /** Filter a desired column list to only those that exist in the table. */
    private function safeCols(array $desired): array
    {
        $available = $this->ledgerColumns();
        return array_values(array_filter($desired, fn($c) => in_array($c, $available)));
    }

    /**
     * GET /api/v1/agents/biographies
     *
     * Paginated list of all agents (registered + shadow) with summary data for
     * the biography listing cards: name, company, lifecycle state, trust tier,
     * last active timestamp, call counts.
     */
    #[OA\Get(
        path: '/api/v1/agents/biographies',
        summary: 'List agent biographies',
        description: 'Paginated list of all agents with summary data for listing cards.',
        tags: ['Agents']
    )]
    #[OA\Parameter(name: 'per_page', in: 'query', required: false, schema: new OA\Schema(type: 'integer', default: 24))]
    #[OA\Parameter(name: 'trust_tier', in: 'query', required: false, schema: new OA\Schema(type: 'string'))]
    #[OA\Parameter(name: 'search', in: 'query', required: false, schema: new OA\Schema(type: 'string'))]
    #[OA\Response(response: 200, description: 'Success')]
    public function list(Request $request): \Illuminate\Http\JsonResponse
    {
        $perPage   = min((int) $request->query('per_page', 24), 100);
        $trustTier = $request->query('trust_tier');
        $search    = $request->query('search', '');

        $query = DB::table('agents')
            ->leftJoin('tenants', 'agents.tenant_id', '=', 'tenants.id')
            ->leftJoin(
                DB::raw('(SELECT agent_id, MAX(created_at) as last_active, COUNT(*) as total_calls FROM action_ledger GROUP BY agent_id) as ledger_summary'),
                'ledger_summary.agent_id', '=', 'agents.id'
            )
            ->select(
                'agents.id',
                'agents.name',
                'agents.agent_type',
                'agents.role',
                'agents.trust_tier',
                'agents.scope_entitlements',
                'agents.hitl_enabled',
                'agents.revoked_at',
                'agents.created_at',
                'agents.owner_name',
                'agents.business_unit',
                'agents.criticality_level',
                'agents.data_classification',
                'agents.version',
                'tenants.name as tenant_name',
                'tenants.id as tenant_id',
                'ledger_summary.last_active',
                'ledger_summary.total_calls',
            )
            ->orderByDesc('agents.created_at');

        if ($trustTier) {
            $query->where('agents.trust_tier', $trustTier);
        }

        if ($search) {
            $query->where(function ($q) use ($search) {
                $q->whereILike('agents.name', "%{$search}%")
                  ->orWhereILike('tenants.name', "%{$search}%");
            });
        }

        $agents = $query->paginate($perPage);

        return response()->json(['status' => 'success', 'data' => $agents]);
    }

    /**
     * POST /api/v1/agents/{id}/quarantine
     *
     * Hard-stop: sets revoked_at and logs a circuit_breaker_trip event to the
     * action_ledger. The gossip mesh quarantine is triggered from the operator
     * dashboard directly via the Sentry Gateway MCP endpoint; this records the
     * operator decision in the central ledger for audit purposes.
     */
    #[OA\Post(
        path: '/api/v1/agents/{id}/quarantine',
        summary: 'Quarantine an agent',
        description: 'Hard-stop: sets revoked_at and logs a circuit breaker trip event.',
        tags: ['Governance']
    )]
    #[OA\Parameter(name: 'id', in: 'path', required: true, schema: new OA\Schema(type: 'string', format: 'uuid'))]
    #[OA\Response(response: 200, description: 'Agent quarantined')]
    public function quarantine(string $id): \Illuminate\Http\JsonResponse
    {
        $agent = DB::table('agents')->where('id', $id)->first();
        if (!$agent) {
            return response()->json(['error' => 'Agent not found'], 404);
        }

        DB::table('agents')->where('id', $id)->update(['revoked_at' => now()]);

        DB::table('action_ledger')->insert([
            'tenant_id'   => $agent->tenant_id,
            'agent_id'    => $id,
            'action_type' => 'operator_quarantine',
            'payload_hash'=> hash('sha256', 'operator_quarantine_' . $id),
            'target_api'  => 'cicada://operator/quarantine',
            'status'      => 'blocked',
            'created_at'  => now(),
        ]);

        AuditService::log(request(), 'agent_quarantined', 'agent', $id, ['revoked_at' => $agent->revoked_at], ['revoked_at' => now()], 'Operator quarantined agent');

        AlertDispatcherService::dispatch(
            'agent_quarantined',
            $agent->tenant_id,
            $id,
            ['reason' => 'Operator manually revoked agent credential']
        );

        // ── Cross-System Revocation (H2.3) ────────────────────────────────────
        // Fire outbound CAEP revocation events to configured external IdP/SIEM
        // endpoints. This closes the gap where a quarantined agent may still hold
        // live OAuth tokens for external services (Slack, Stripe, GitHub, etc.).
        RevocationDispatcherService::dispatch(
            'operator_quarantine',
            $agent->tenant_id,
            $id,
            [
                'reason'       => 'Operator manually quarantined agent via dashboard',
                'initiator'    => 'operator_dashboard',
                'agent_name'   => $agent->name ?? $id,
            ]
        );

        return response()->json(['status' => 'success', 'message' => 'Agent quarantined.']);
    }

    /**
     * GET /api/v1/agents/{id}/biography
     *
     * Returns every piece of data the platform holds about one agent, structured
     * as the seven biography sections the operator dashboard renders.
     */
    #[OA\Get(
        path: '/api/v1/agents/{id}/biography',
        summary: 'Get full agent biography',
        description: 'Returns every piece of data the platform holds about one agent (seven sections).',
        tags: ['Agents']
    )]
    #[OA\Parameter(name: 'id', in: 'path', required: true, schema: new OA\Schema(type: 'string', format: 'uuid'))]
    #[OA\Response(response: 200, description: 'Success')]
    public function biography(string $id): \Illuminate\Http\JsonResponse
    {
        $agent = DB::table('agents')
            ->leftJoin('tenants', 'agents.tenant_id', '=', 'tenants.id')
            ->where('agents.id', $id)
            ->select(
                'agents.*',
                'tenants.name as tenant_name',
                'tenants.plan as tenant_plan',
                'tenants.company_email as tenant_email',
            )
            ->first();

        if (!$agent) {
            return response()->json(['error' => 'Agent not found'], 404);
        }

        $has = fn(string $col) => in_array($col, $this->ledgerColumns());

        // ── Section 1: Identity ───────────────────────────────────────────────
        $tools = DB::table('agent_tools')
            ->where('agent_id', $id)
            ->where('is_active', true)
            ->get(['tool_id', 'tool_name', 'tool_description']);

        $resourcePolicies = DB::table('agent_resource_policies')
            ->where('agent_id', $id)
            ->where('active', true)
            ->get(['resource_pattern', 'allowed_methods']);

        // ── Section 2: Certification ──────────────────────────────────────────
        $certEvent = DB::table('action_ledger')
            ->where('agent_id', $id)
            ->whereIn('action_type', ['agent_certified', 'certification', 'swarm_vote'])
            ->orderByDesc('created_at')
            ->first();

        $swarmHistory = DB::table('action_ledger')
            ->where('agent_id', $id)
            ->whereNotNull('swarm_confidence_score')
            ->orderByDesc('created_at')
            ->limit(20)
            ->pluck('swarm_confidence_score');

        $swarmMean = $swarmHistory->count() > 0
            ? round($swarmHistory->avg(), 4)
            : null;

        // ── Section 3: Behavioural Baseline ──────────────────────────────────
        $calls24h = DB::table('action_ledger')
            ->where('agent_id', $id)
            ->where('created_at', '>=', now()->subDay())
            ->count();

        $calls7d = DB::table('action_ledger')
            ->where('agent_id', $id)
            ->where('created_at', '>=', now()->subDays(7))
            ->count();

        $alignmentScores = collect();
        if ($has('semantic_alignment_score')) {
            $alignmentScores = DB::table('action_ledger')
                ->where('agent_id', $id)
                ->whereNotNull('semantic_alignment_score')
                ->orderByDesc('created_at')
                ->limit(20)
                ->pluck('semantic_alignment_score', 'created_at');
        }

        $targetDistribution = DB::table('action_ledger')
            ->where('agent_id', $id)
            ->select('target_api', DB::raw('COUNT(*) as call_count'))
            ->groupBy('target_api')
            ->orderByDesc('call_count')
            ->limit(10)
            ->get();

        // ── Section 4: Lifecycle Timeline (first 50) ─────────────────────────
        $timelineCols = $this->safeCols([
            'trace_id', 'action_type', 'status', 'target_api',
            'swarm_confidence_score', 'policy_violations',
            'reasoning_trace', 'semantic_alignment_score', 'created_at',
        ]);

        $timeline = DB::table('action_ledger')
            ->where('agent_id', $id)
            ->orderBy('created_at')
            ->limit(50)
            ->get($timelineCols);

        $totalEvents = DB::table('action_ledger')->where('agent_id', $id)->count();

        // ── Section 5: Execution Deep-Dive (last 100 calls) ──────────────────
        $execCols = $this->safeCols([
            'trace_id', 'action_type', 'status', 'target_api',
            'payload_hash', 'swarm_confidence_score', 'semantic_alignment_score',
            'policy_violations', 'reasoning_trace', 'created_at',
        ]);

        $execution = DB::table('action_ledger')
            ->where('agent_id', $id)
            ->orderByDesc('created_at')
            ->limit(100)
            ->get($execCols);

        // ── Section 6: HITL History ───────────────────────────────────────────
        $hitlCols = $this->safeCols([
            'trace_id', 'action_type', 'status', 'target_api',
            'policy_violations', 'created_at',
        ]);

        $hitlEvents = DB::table('action_ledger')
            ->where('agent_id', $id)
            ->whereIn('action_type', ['hitl_pending', 'hitl_approved', 'hitl_rejected', 'hitl_timeout'])
            ->orderByDesc('created_at')
            ->get($hitlCols);

        // ── Section 7: Canary Token Status ───────────────────────────────────
        $canaryEvents = DB::table('action_ledger')
            ->where('agent_id', $id)
            ->whereIn('action_type', ['canary_issued', 'canary_triggered', 'canary_revoked'])
            ->orderByDesc('created_at')
            ->get(['trace_id', 'action_type', 'status', 'created_at']);

        // ── Section 8: User-Context Attribution (H2.1) ───────────────────────
        // Surfaces the end-users on whose behalf this agent has acted. Answers
        // the question "Agent X performed this action on behalf of Customer Y"
        // — critical for SOX, HIPAA, and PCI-DSS auditing.
        $userContextAttribution = collect();
        if (Schema::hasColumn('action_ledger', 'human_user_context')) {
            $userContextAttribution = DB::table('action_ledger')
                ->where('agent_id', $id)
                ->whereNotNull('human_user_context')
                ->whereRaw("human_user_context::text != '\"\"' AND human_user_context::text != '{}' AND human_user_context::text != ''")
                ->select(
                    'human_user_context',
                    DB::raw('COUNT(*) as action_count'),
                    DB::raw('MIN(created_at) as first_seen'),
                    DB::raw('MAX(created_at) as last_seen')
                )
                ->groupBy('human_user_context')
                ->orderByDesc('last_seen')
                ->limit(50)
                ->get()
                ->map(function ($row) {
                    // Parse JSONB user context into structured fields.
                    $parsed = json_decode($row->human_user_context, true);
                    return [
                        'user_subject'  => $parsed['sub'] ?? $row->human_user_context,
                        'user_email'    => $parsed['email'] ?? null,
                        'user_name'     => $parsed['name'] ?? null,
                        'issuer'        => $parsed['iss'] ?? null,
                        'verified'      => $parsed['verified'] ?? false,
                        'action_count'  => $row->action_count,
                        'first_seen'    => $row->first_seen,
                        'last_seen'     => $row->last_seen,
                    ];
                });
        }

        return response()->json([
            'status' => 'success',
            'data' => [
                'identity' => [
                    'agent'            => $agent,
                    'tools'            => $tools,
                    'resource_policies'=> $resourcePolicies,
                ],
                'certification' => [
                    'cert_event'    => $certEvent,
                    'swarm_history' => $swarmHistory,
                    'swarm_mean'    => $swarmMean,
                ],
                'baseline' => [
                    'calls_24h'           => $calls24h,
                    'calls_7d'            => $calls7d,
                    'alignment_scores'    => $alignmentScores,
                    'target_distribution' => $targetDistribution,
                ],
                'lifecycle' => [
                    'events'       => $timeline,
                    'total_events' => $totalEvents,
                    'has_more'     => $totalEvents > 50,
                ],
                'execution'          => $execution,
                'hitl'               => $hitlEvents,
                'canary'             => $canaryEvents,
                'user_attribution'   => $userContextAttribution,
            ],
        ]);
    }

    /**
     * GET /api/v1/agents/{id}/timeline
     *
     * Paginated chronological event feed for infinite-scroll biography timeline.
     * Supports cursor-based pagination via ?cursor=<created_at>&limit=<n>.
     */
    #[OA\Get(
        path: '/api/v1/agents/{id}/timeline',
        summary: 'Agent timeline',
        description: 'Paginated chronological event feed for infinite-scroll biography timeline.',
        tags: ['Agents']
    )]
    #[OA\Parameter(name: 'id', in: 'path', required: true, schema: new OA\Schema(type: 'string', format: 'uuid'))]
    #[OA\Parameter(name: 'limit', in: 'query', required: false, schema: new OA\Schema(type: 'integer', default: 50))]
    #[OA\Parameter(name: 'cursor', in: 'query', required: false, schema: new OA\Schema(type: 'string'))]
    #[OA\Response(response: 200, description: 'Success')]
    public function timeline(string $id, Request $request): \Illuminate\Http\JsonResponse
    {
        if (!DB::table('agents')->where('id', $id)->exists()) {
            return response()->json(['error' => 'Agent not found'], 404);
        }

        $limit  = min((int) $request->query('limit', 50), 200);
        $cursor = $request->query('cursor'); // ISO-8601 timestamp

        $cols = $this->safeCols([
            'trace_id', 'action_type', 'status', 'target_api',
            'swarm_confidence_score', 'semantic_alignment_score',
            'policy_violations', 'reasoning_trace', 'created_at',
        ]);

        $query = DB::table('action_ledger')
            ->where('agent_id', $id)
            ->orderBy('created_at')
            ->select($cols);

        if ($cursor) {
            $query->where('created_at', '>', $cursor);
        }

        $events = $query->limit($limit + 1)->get();

        $hasMore = $events->count() > $limit;
        if ($hasMore) {
            $events = $events->take($limit);
        }

        $nextCursor = $hasMore ? $events->last()?->created_at : null;

        return response()->json([
            'status'      => 'success',
            'agent_id'    => $id,
            'events'      => $events->values(),
            'has_more'    => $hasMore,
            'next_cursor' => $nextCursor,
        ]);
    }
}
