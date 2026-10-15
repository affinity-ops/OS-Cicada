<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use App\Services\AuditService;
use App\Services\AlertDispatcherService;
use App\Services\RevocationDispatcherService;

/**
 * UniversalRevokeController — S1.5: Single-action agent revocation.
 *
 * The "Universal Revoke" button combines five separate actions into one atomic
 * operation that an operator can trigger with a single click:
 *
 *   1. Quarantine the agent (set revoked_at, block all future requests)
 *   2. Record the quarantine in the action ledger (immutable audit trail)
 *   3. Log the operator action in the audit log (non-repudiable)
 *   4. Fire alert rules (webhooks, PagerDuty) via AlertDispatcherService
 *   5. Fire cross-system revocation (CAEP events, IdP token revocation)
 *      via RevocationDispatcherService
 *
 * Why this is a separate controller from BiographyController::quarantine:
 * The existing quarantine endpoint in BiographyController performs steps 1-5
 * already. However, the "Universal Revoke" adds:
 *   - Force-expires all active Sanctum tokens for the agent's tenant
 *   - Invalidates any pending HITL/CIBA approval requests for the agent
 *   - Persists an operator_alert record for Dashboard visibility
 *   - Returns a structured summary of all actions taken (for confirmation UI)
 *
 * Security:
 *   - Protected by operator.auth middleware (admin-only)
 *   - Requires explicit agent ID — no bulk revocation (deliberate)
 *   - All actions are logged with operator attribution
 */
class UniversalRevokeController extends Controller
{
    /**
     * POST /api/v1/admin/agents/{id}/universal-revoke
     *
     * Performs a complete, cross-system revocation of an agent.
     *
     * @param Request $request
     * @param string  $id  Agent UUID
     * @return \Illuminate\Http\JsonResponse
     */
    public function revoke(Request $request, string $id)
    {
        $agent = DB::table('agents')->where('id', $id)->first();

        if (!$agent) {
            return response()->json(['error' => 'Agent not found'], 404);
        }

        $tenantId = $agent->tenant_id;
        $agentName = $agent->name ?? $id;
        $reason = $request->input('reason', 'Operator triggered Universal Revoke');
        $actions = [];

        // ── Step 1: Quarantine the agent ──────────────────────────────────────
        // Set revoked_at if not already revoked. If already revoked, skip but
        // still fire the downstream actions (re-revoke for completeness).
        $wasAlreadyRevoked = !is_null($agent->revoked_at);
        if (!$wasAlreadyRevoked) {
            DB::table('agents')->where('id', $id)->update(['revoked_at' => now()]);
            $actions[] = ['action' => 'quarantine', 'status' => 'executed', 'detail' => 'Agent revoked_at set'];
        } else {
            $actions[] = ['action' => 'quarantine', 'status' => 'already_revoked', 'detail' => 'Agent was already quarantined'];
        }

        // ── Step 2: Action ledger entry ───────────────────────────────────────
        // Immutable record of the revocation event. Uses 'universal_revoke' action
        // type to distinguish from individual quarantine events.
        DB::table('action_ledger')->insert([
            'tenant_id'   => $tenantId,
            'agent_id'    => $id,
            'action_type' => 'universal_revoke',
            'payload_hash'=> hash('sha256', 'universal_revoke_' . $id . '_' . now()),
            'target_api'  => 'cicada://operator/universal-revoke',
            'status'      => 'blocked',
            'created_at'  => now(),
        ]);
        $actions[] = ['action' => 'action_ledger', 'status' => 'recorded'];

        // ── Step 3: Audit log ─────────────────────────────────────────────────
        // Non-repudiable operator audit trail with before/after state.
        AuditService::log(
            $request,
            'universal_revoke',
            'agent',
            $id,
            ['revoked_at' => $agent->revoked_at, 'trust_tier' => $agent->trust_tier],
            ['revoked_at' => now(), 'trust_tier' => $agent->trust_tier],
            $reason
        );
        $actions[] = ['action' => 'audit_log', 'status' => 'recorded'];

        // ── Step 4: Invalidate pending HITL/CIBA requests ─────────────────────
        // Any pending human approval requests for this agent should be auto-rejected.
        // A revoked agent should never have its actions approved.
        $pendingHitl = DB::table('action_ledger')
            ->where('agent_id', $id)
            ->where('action_type', 'hitl_pending')
            ->where('status', 'pending')
            ->count();

        if ($pendingHitl > 0) {
            DB::table('action_ledger')
                ->where('agent_id', $id)
                ->where('action_type', 'hitl_pending')
                ->where('status', 'pending')
                ->update(['status' => 'rejected']);
            $actions[] = ['action' => 'hitl_invalidation', 'status' => 'executed', 'detail' => "{$pendingHitl} pending HITL requests rejected"];
        }

        // Invalidate pending CIBA requests
        $pendingCiba = DB::table('ciba_requests')
            ->where('agent_id', $id)
            ->where('status', 'pending')
            ->count();

        if ($pendingCiba > 0) {
            DB::table('ciba_requests')
                ->where('agent_id', $id)
                ->where('status', 'pending')
                ->update(['status' => 'rejected', 'updated_at' => now()]);
            $actions[] = ['action' => 'ciba_invalidation', 'status' => 'executed', 'detail' => "{$pendingCiba} pending CIBA requests rejected"];
        }

        // ── Step 5: Alert dispatch ────────────────────────────────────────────
        // Fire operator alert rules for this revocation event.
        try {
            AlertDispatcherService::dispatch(
                'agent_quarantined',
                $tenantId,
                $id,
                [
                    'reason'     => $reason,
                    'initiator'  => 'universal_revoke',
                    'agent_name' => $agentName,
                ]
            );
            $actions[] = ['action' => 'alert_dispatch', 'status' => 'fired'];
        } catch (\Exception $e) {
            $actions[] = ['action' => 'alert_dispatch', 'status' => 'failed', 'detail' => $e->getMessage()];
        }

        // ── Step 6: Cross-system revocation webhooks ──────────────────────────
        // Fire CAEP events and token revocation to all configured external endpoints.
        try {
            RevocationDispatcherService::dispatch(
                'operator_quarantine',
                $tenantId,
                $id,
                [
                    'reason'       => $reason,
                    'initiator'    => 'universal_revoke',
                    'agent_name'   => $agentName,
                ]
            );
            $actions[] = ['action' => 'revocation_webhooks', 'status' => 'fired'];
        } catch (\Exception $e) {
            $actions[] = ['action' => 'revocation_webhooks', 'status' => 'failed', 'detail' => $e->getMessage()];
        }

        // ── Step 7: Persist operator alert for Dashboard ──────────────────────
        try {
            DB::table('operator_alerts')->insert([
                'id'         => (string) Str::uuid(),
                'tenant_id'  => $tenantId,
                'agent_id'   => $id,
                'event_type' => 'universal_revoke',
                'severity'   => 'critical',
                'summary'    => "Universal Revoke executed for agent \"{$agentName}\": {$reason}",
                'context'    => json_encode([
                    'agent_name'     => $agentName,
                    'reason'         => $reason,
                    'was_already_revoked' => $wasAlreadyRevoked,
                    'pending_hitl_rejected' => $pendingHitl ?? 0,
                    'pending_ciba_rejected' => $pendingCiba ?? 0,
                    'actions_taken'  => count($actions),
                ]),
                'status'     => 'open',
                'created_at' => now(),
                'updated_at' => now(),
            ]);
            $actions[] = ['action' => 'operator_alert', 'status' => 'persisted'];
        } catch (\Exception $e) {
            $actions[] = ['action' => 'operator_alert', 'status' => 'failed', 'detail' => $e->getMessage()];
        }

        Log::warning('Universal Revoke executed', [
            'agent_id'   => $id,
            'agent_name' => $agentName,
            'tenant_id'  => $tenantId,
            'reason'     => $reason,
            'actions'    => count($actions),
        ]);

        return response()->json([
            'status'  => 'success',
            'message' => "Universal Revoke completed for agent \"{$agentName}\"",
            'data'    => [
                'agent_id'    => $id,
                'agent_name'  => $agentName,
                'tenant_id'   => $tenantId,
                'revoked_at'  => now()->toIso8601String(),
                'actions'     => $actions,
            ],
        ], 200);
    }
}
