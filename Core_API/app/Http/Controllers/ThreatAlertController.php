<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use App\Services\AlertDispatcherService;

/**
 * ThreatAlertController — Gateway-to-Core unified threat alert receiver.
 *
 * This controller receives structured threat alerts from the Sentry Gateway
 * (exfiltration, injection, semantic mismatch, velocity) and routes them through 
 * the existing AlertDispatcherService to configured webhook/PagerDuty destinations.
 *
 * Security:
 * - Protected by gateway.auth middleware (X-Gateway-Secret header)
 * - Only callable from the Sentry Gateway binary
 * - Input validated and sanitised before persistence
 */
class ThreatAlertController extends Controller
{
    /**
     * Receive and route a unified threat alert from the Sentry Gateway.
     *
     * @param Request $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function receive(Request $request)
    {
        $validated = $request->validate([
            'event_type'             => 'required|string',
            'tenant_id'              => 'required|string|max:100',
            'agent_id'               => 'required|string|max:100',
            'context'                => 'required|array',
            'context.severity'       => 'required|string|in:critical,high,medium,low',
            'context.target_url'     => 'nullable|string|max:2000',
            'context.finding_summary'=> 'required|string|max:5000',
            'context.action'         => 'required|string|max:2000',
            'context.trace_id'       => 'nullable|string|max:100',
            'timestamp'              => 'nullable|string',
            'source'                 => 'nullable|string',
        ]);

        $eventType = $validated['event_type'];
        $tenantId  = $validated['tenant_id'];
        $agentId   = $validated['agent_id'];
        $context   = $validated['context'];

        // Step 1: Persist the alert for Dashboard visibility.
        // The operator_alerts table feeds the Dashboard's alerts page.
        try {
            DB::table('operator_alerts')->insert([
                'id'         => (string) \Illuminate\Support\Str::uuid(),
                'tenant_id'  => $tenantId,
                'agent_id'   => $agentId,
                'event_type' => $eventType,
                'severity'   => $context['severity'],
                'summary'    => $context['finding_summary'],
                'context'    => json_encode($context),
                'status'     => 'open',
                'created_at' => now(),
                'updated_at' => now(),
            ]);
        } catch (\Exception $e) {
            // If the operator_alerts table doesn't exist yet, log and continue.
            // The AlertDispatcherService will still fire webhooks.
            Log::warning('Failed to persist threat alert — operator_alerts table may not exist', [
                'error' => $e->getMessage(),
            ]);
        }

        // Step 2: Route through AlertDispatcherService.
        // This fires webhooks to any alert rules matching the event_type.
        AlertDispatcherService::dispatch($eventType, $tenantId, $agentId, $context);

        Log::info('Threat alert received and dispatched', [
            'event_type' => $eventType,
            'tenant_id'  => $tenantId,
            'agent_id'   => $agentId,
            'severity'   => $context['severity'],
        ]);

        return response()->json(['status' => 'accepted'], 200);
    }
}
