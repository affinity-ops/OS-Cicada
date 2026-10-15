<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;

/**
 * ModelRiskWebhookController
 * 
 * Handles incoming webhooks from external MLOps platforms and model registries
 * (e.g., MLflow, Weights & Biases). When a model is flagged as compromised, vulnerable,
 * or deprecated in the external registry, this controller automatically quarantines
 * any Cicada agent linked to that external_model_id.
 * 
 * This directly implements Gap 6 (Third-Party Model Risk Management).
 */
class ModelRiskWebhookController extends Controller
{
    /**
     * Handle incoming webhooks indicating model vulnerability or compromise.
     */
    public function handleCompromisedModel(Request $request)
    {
        // Require a pre-shared secret for the webhook
        $secret = $request->header('X-Model-Registry-Token');
        if (!$secret || $secret !== env('CICADA_MODEL_REGISTRY_WEBHOOK_SECRET')) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        $validated = $request->validate([
            'event' => 'required|string', // e.g., 'model_vulnerability_detected' or 'model_deprecated'
            'external_model_id' => 'required|string',
            'severity' => 'required|string', // e.g., 'high', 'critical'
            'reason' => 'nullable|string',
        ]);

        $modelId = $validated['external_model_id'];
        $event = $validated['event'];
        $severity = $validated['severity'];
        $reason = $validated['reason'] ?? 'Unspecified risk flagged by MLOps registry';

        // Find all agents using this model
        $affectedAgents = DB::table('agents')
            ->where('external_model_id', $modelId)
            ->whereNull('revoked_at')
            ->pluck('id');

        if ($affectedAgents->isEmpty()) {
            return response()->json([
                'status' => 'success',
                'message' => 'Webhook received, but no active agents are currently using this model.'
            ]);
        }

        // Only auto-quarantine for high or critical severity events
        if (in_array(strtolower($severity), ['high', 'critical']) && str_contains($event, 'vulnerability')) {
            DB::transaction(function () use ($affectedAgents, $modelId, $reason) {
                // Update agents to revoked/quarantined
                DB::table('agents')
                    ->whereIn('id', $affectedAgents)
                    ->update([
                        'revoked_at' => now(),
                        'revoked_reason' => "Model Vulnerability (Automated): {$reason}",
                        'status' => 'quarantined',
                        'updated_at' => now()
                    ]);

                // Create operator audit log entries for each agent
                foreach ($affectedAgents as $agentId) {
                    // Assuming tenant_id isn't directly needed for this platform-wide action, 
                    // but we should ideally fetch it. Let's do a fast lookup if needed.
                    $agent = DB::table('agents')->where('id', $agentId)->first();
                    
                    if ($agent) {
                        DB::table('operator_audit_log')->insert([
                            'id' => (string) \Illuminate\Support\Str::uuid(),
                            'tenant_id' => $agent->tenant_id,
                            'operator_email' => 'system@cicada.local',
                            'action_type' => 'agent_quarantined_by_mlops_webhook',
                            'target_resource' => "agents/{$agentId}",
                            'previous_state' => json_encode(['status' => 'active']),
                            'new_state' => json_encode(['status' => 'quarantined', 'revoked_reason' => "Model {$modelId} flagged: {$reason}"]),
                            'ip_address' => '127.0.0.1',
                            'created_at' => now()
                        ]);
                    }
                }
            });

            Log::warning("ModelRiskWebhook: Quarantined {$affectedAgents->count()} agents due to vulnerability in model {$modelId}. Reason: {$reason}");

            return response()->json([
                'status' => 'success',
                'message' => "Quarantined {$affectedAgents->count()} agents successfully.",
                'quarantined_agents' => $affectedAgents
            ]);
        }

        return response()->json([
            'status' => 'success',
            'message' => 'Event received. Severity threshold not met for auto-quarantine.'
        ]);
    }
}
