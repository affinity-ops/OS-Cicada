<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
namespace App\Services;

use Illuminate\Support\Facades\DB;
use Illuminate\Http\Request;

/**
 * AuditService
 *
 * Records operator actions in the operator_audit_log table for SOC2 compliance.
 * Every destructive or state-changing admin action must call this service to
 * create an immutable audit trail of WHO did WHAT to WHICH entity, WHEN.
 */
class AuditService
{
    /**
     * Log a mutating action performed by a human operator.
     * 
     * @param Request     $request        The current HTTP request (for IP and auth context)
     * @param string      $actionType     e.g., 'hitl_approved', 'agent_quarantined', 'policy_exception_created'
     * @param string      $targetType     e.g., 'agent', 'policy', 'tenant'
     * @param string      $targetId       The UUID or ID of the affected entity
     * @param array|null  $previousState  Snapshot before the change
     * @param array|null  $newState       Snapshot after the change
     * @param string|null $justification  Text reason if required for high-risk actions
     */
    public static function log(
        Request $request,
        string  $actionType,
        string  $targetType,
        string  $targetId,
        ?array  $previousState = null,
        ?array  $newState      = null,
        ?string $justification = null
    ): void {
        // Fallback to central root credential if no multi-user operator ID is supplied.
        // In Cicada's current V1 architecture, the single hardware WebAuthn key acts as root.
        $operatorId = $request->header('X-Operator-Id');
        if (!$operatorId) {
            $rootCred = DB::table('operator_credentials')->first();
            $operatorId = $rootCred ? $rootCred->id : null;
        }

        $operatorEmail = $request->header('X-Operator-Email', 'root_admin@cicada.local');

        DB::table('operator_audit_log')->insert([
            'operator_id'    => $operatorId,
            'operator_label' => $operatorEmail,
            'action'         => $actionType,
            'entity_type'    => $targetType,
            'entity_id'      => $targetId,
            'before_state'   => $previousState ? json_encode($previousState) : null,
            'after_state'    => $newState ? json_encode($newState) : null,
            'notes'          => $justification,
            'ip_address'     => $request->ip(),
            'user_agent'     => $request->userAgent(),
            'session_id'     => $request->cookie('operator_session') ? substr(hash('sha256', $request->cookie('operator_session')), 0, 16) : null,
            'created_at'     => now()
        ]);
    }
}
