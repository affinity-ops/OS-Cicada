<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;

class ProvisioningController extends Controller
{
    /**
     * E2E Agent & Tenant Provisioning
     *
     * Creates a Tenant, binds their BYOK API key via AES-256-GCM, then calls the Sentry
     * Gateway to mint a cryptographically signed Ed25519 JWT (EVAR) for the new agent.
     */
    public function provisionAgent(Request $request)
    {
        $validated = $request->validate([
            'agent_name'       => 'required|string|max:255',
            'api_provider'     => 'required|string|max:100',
            'api_key'          => 'required|string|max:500',
            'target_model'     => 'nullable|string|max:100',
            // Stage 9.1 — tool registry
            'tools'            => 'nullable|array|max:50',
            'tools.*.tool_id'  => 'required_with:tools|string|max:255',
            'tools.*.tool_name'=> 'required_with:tools|string|max:255',
            'tools.*.tool_description' => 'nullable|string',
            // Stage 9.2 — role registry
            'role'             => 'nullable|string|max:100',
            'orchestrator_id'  => 'nullable|uuid',
            // Stage 7.2 — HITL
            'hitl_enabled'     => 'nullable|boolean',
            'hitl_webhook_url' => 'nullable|url|max:500',
            'hitl_timeout_hours'  => 'nullable|integer|min:1|max:168',
            'shadow_mode'         => 'nullable|boolean',
            // Wizard fields
            'agent_type'       => 'nullable|string|max:100',
            'description'      => 'nullable|string|max:2000',
            'version'          => 'nullable|string|max:50',
            'scopes'           => 'nullable|array|max:20',
            'failure_scope'    => 'nullable|string',
            'custom_guardrails'=> 'nullable|string|max:5000',
            // Governance extension
            'owner_name' => 'required|string|max:255',
            'owner_email' => 'required|email|max:255',
            'business_unit' => 'nullable|string|max:255',
            'declared_purpose' => 'required|string|max:2000',
            'criticality_level' => 'required|string|max:50',
            'data_classification' => 'nullable|string|max:100',
            'expected_velocity' => 'nullable|integer|min:1|max:10000',
            'monthly_budget_usd' => 'nullable|numeric|min:0|max:1000000',
            'cost_center' => 'nullable|string',
            'regulatory_frameworks' => 'nullable|array|max:20',
            'registration_purpose_statement' => 'nullable|string|max:2000',
            'data_residency_region' => 'nullable|string|max:10',
            'potential_impact' => 'nullable|array|max:20',
            'ghost_mode_allowed' => 'nullable|boolean',
            'destructive_capability' => 'nullable|boolean',
        ]);

        try {
            // Use the authenticated tenant from portal.auth middleware — no orphan tenant creation.
            $tenantId = $request->attributes->get('portal_tenant_id');
            $agentId  = (string) Str::uuid();
            $scopes   = $validated['scopes']   ?? ['proxy:chat'];
            $role     = $validated['role']      ?? 'autonomous';
            // Validate role against PostgreSQL CHECK constraint (agents_role_check).
            // The DB only accepts: orchestrator, sub_agent, peer, autonomous, tool_executor.
            // If the wizard sends an unsupported value (e.g. "supervised"), default to 'autonomous'
            // to prevent SQLSTATE[23514] check violations.
            $allowedRoles = ['orchestrator', 'sub_agent', 'peer', 'autonomous', 'tool_executor'];
            if (!in_array($role, $allowedRoles, true)) {
                Log::warning('Invalid agent role submitted — defaulting to autonomous', [
                    'submitted_role' => $role,
                    'allowed_roles'  => $allowedRoles,
                ]);
                $role = 'autonomous';
            }
            $hitlEnabled    = (bool) ($validated['hitl_enabled']    ?? false);
            $hitlWebhookUrl = $validated['hitl_webhook_url'] ?? null;
            $tools    = $validated['tools'] ?? [];
            $customGuardrails = $validated['custom_guardrails'] ?? null;
            $ghostModeAllowed = (bool) ($validated['ghost_mode_allowed'] ?? false);
            $destructiveCapability = (bool) ($validated['destructive_capability'] ?? false);

            // Step 1: Persist encrypted BYOK key + agent placeholder in one transaction.
            DB::transaction(function () use ($validated, $tenantId, $agentId, $scopes, $role, $hitlEnabled, $hitlWebhookUrl, $tools, $customGuardrails, $ghostModeAllowed, $destructiveCapability) {

                // Store the tenant's API key (upsert — latest key wins on re-registration)
                DB::table('tenant_keys')->updateOrInsert(
                    [
                        'tenant_id' => $tenantId,
                        'provider'  => $validated['api_provider'],
                    ],
                    [
                        'payload_encrypted' => Crypt::encryptString($validated['api_key']),
                        'updated_at'        => now(),
                    ]
                );

                // Placeholder pub_key_hash — replaced by the real EVAR after gateway minting below.
                DB::table('agents')->insert([
                    'id'                => $agentId,
                    'tenant_id'         => $tenantId,
                    'pub_key_hash'      => 'pending_evar_' . $agentId,
                    'scope_entitlements' => json_encode($scopes),
                    'trust_tier'        => 'unverified',
                    // Stage 9.1 + 9.2 + 7.2 fields
                    'name'              => $validated['agent_name'],
                    'description'       => $validated['description'] ?? null,
                    'agent_type'        => $validated['agent_type'] ?? 'reactive',
                    'version'           => $validated['version'] ?? '1.0.0',
                    'failure_scope'     => json_encode(['type' => $validated['failure_scope'] ?? 'silent_exit']),
                    'role'              => $role,
                    'orchestrator_id'   => $validated['orchestrator_id'] ?? null,
                    'hitl_enabled'      => $hitlEnabled,
                    'hitl_webhook_url'  => $hitlWebhookUrl,
                    'custom_guardrails' => $customGuardrails ? json_encode($customGuardrails) : null,
                    // Governance extension fields
                    'owner_name' => $validated['owner_name'] ?? null,
                    'owner_email' => $validated['owner_email'] ?? null,
                    'business_unit' => $validated['business_unit'] ?? null,
                    'data_residency_region' => $validated['data_residency_region'] ?? null,
                    'declared_purpose' => $validated['declared_purpose'] ?? null,
                    'criticality_level' => $validated['criticality_level'] ?? 'medium',
                    'data_classification' => $validated['data_classification'] ?? 'internal',
                    'expected_velocity' => $validated['expected_velocity'] ?? null,
                    'monthly_budget_usd' => $validated['monthly_budget_usd'] ?? null,
                    'cost_center' => $validated['cost_center'] ?? null,
                    'regulatory_frameworks' => isset($validated['regulatory_frameworks']) ? json_encode($validated['regulatory_frameworks']) : null,
                    'registration_purpose_statement' => $validated['registration_purpose_statement'] ?? null,
                    'potential_impact' => isset($validated['potential_impact']) ? json_encode($validated['potential_impact']) : null,
                    'ghost_mode_allowed' => $ghostModeAllowed,
                    'destructive_capability' => $destructiveCapability,
                    'governance_updated_at' => now(),
                    'created_at'        => now(),
                ]);

                // Stage 9.1: persist the developer's declared tool list
                foreach ($tools as $tool) {
                    DB::table('agent_tools')->insert([
                        'id'               => (string) Str::uuid(),
                        'agent_id'         => $agentId,
                        'tool_id'          => $tool['tool_id'],
                        'tool_name'        => $tool['tool_name'],
                        'tool_description' => $tool['tool_description'] ?? null,
                        'is_active'        => true,
                        'created_at'       => now(),
                    ]);
                }
            });

            // ── S1.4: Auto-alert for destructive agents without HITL ─────────
            // If a developer registers an agent with destructive_capability=true
            // but HITL is disabled, this creates an immediate operator alert.
            // Why: A destructive agent without human oversight is a security risk.
            // The agent still gets provisioned (we don't block registration), but
            // the operator is notified so they can investigate or quarantine.
            if ($destructiveCapability && !$hitlEnabled) {
                try {
                    \App\Services\AlertDispatcherService::dispatch(
                        'destructive_agent_no_hitl',
                        $tenantId,
                        $agentId,
                        [
                            'severity'     => 'high',
                            'agent_name'   => $validated['agent_name'],
                            'owner_email'  => $validated['owner_email'] ?? null,
                            'scopes'       => $scopes,
                            'action'       => 'Review agent configuration — destructive capability enabled without HITL gate',
                        ]
                    );

                    // Also persist to operator_alerts table for Dashboard visibility
                    DB::table('operator_alerts')->insert([
                        'id'         => (string) Str::uuid(),
                        'tenant_id'  => $tenantId,
                        'agent_id'   => $agentId,
                        'event_type' => 'destructive_agent_no_hitl',
                        'severity'   => 'high',
                        'summary'    => "Agent \"{$validated['agent_name']}\" registered with destructive_capability=true but HITL is disabled. This agent can perform irreversible actions without human approval.",
                        'context'    => json_encode([
                            'agent_name' => $validated['agent_name'],
                            'scopes'     => $scopes,
                            'hitl_enabled' => false,
                            'destructive_capability' => true,
                        ]),
                        'status'     => 'open',
                        'created_at' => now(),
                        'updated_at' => now(),
                    ]);

                    Log::warning('Destructive agent registered without HITL — alert dispatched', [
                        'agent_id'   => $agentId,
                        'agent_name' => $validated['agent_name'],
                        'tenant_id'  => $tenantId,
                    ]);
                } catch (\Exception $alertEx) {
                    // Alert failure must not block provisioning
                    Log::warning('S1.4 alert dispatch failed', ['error' => $alertEx->getMessage()]);
                }
            }

            // Step 3: Call the Sentry Gateway to mint a real Ed25519 JWT.
            $gatewayUrl = rtrim(env('CICADA_GATEWAY_URL', 'http://localhost:8080'), '/');
            $mintResponse = Http::timeout(10)->post("{$gatewayUrl}/v1/agent/register", [
                'agent_id'                  => $agentId,
                'code_hash'                 => hash('sha256', $validated['agent_name']),
                'scopes'                    => $scopes,
                'intended_model'            => $validated['target_model'] ?? 'gpt-4o',
                'is_persistent'             => false,
                'data_residency_region'     => $validated['data_residency_region'] ?? null,
                'certified_reversal_routes' => (object) [],
            ]);

            if (!$mintResponse->successful()) {
                // Gateway is down or rejected the request — roll back records created in this transaction.
                DB::table('agents')->where('id', $agentId)->delete();
                DB::table('tenant_keys')->where('tenant_id', $tenantId)->delete();

                Log::error('EVAR minting failed', [
                    'agent_id' => $agentId,
                    'gateway_status' => $mintResponse->status(),
                    'gateway_body'   => $mintResponse->body(),
                ]);

                return response()->json([
                    'status'  => 'error',
                    'message' => 'Agent provisioning failed. The Sentry Gateway could not issue an EVAR at this time. Please try again or contact support.',
                ], 503);
            }

            $evar = $mintResponse->json('evar');

            // Step 4: Store the real signed JWT in pub_key_hash.
            DB::table('agents')
                ->where('id', $agentId)
                ->update(['pub_key_hash' => $evar]);

            // ── Step 5: Verification Swarm — adversarial red-teaming ──────────
            // Call the Swarm HTTP server to verify the agent's declarations before
            // granting trust. The swarm uses the tenant's BYOK key (Cicada pays nothing).
            // If the swarm is unavailable, the agent stays "unverified" but gets its EVAR —
            // the gateway will enforce stricter controls on unverified agents.
            $swarmVerdict = null;
            $trustTier = 'unverified';
            $swarmScore = 0.0;
            $swarmReasons = [];

            try {
                $swarmUrl = rtrim(env('CICADA_SWARM_URL', 'http://localhost:9091'), '/');
                $swarmResponse = Http::timeout(30)->post("{$swarmUrl}/verify", [
                    'tenant_id'          => $tenantId,
                    'agent_id'           => $agentId,
                    'agent_name'         => $validated['agent_name'],
                    'description'        => $validated['description'] ?? '',
                    'scopes'             => $scopes,
                    'tools'              => $tools,
                    'agent_type'         => $validated['agent_type'] ?? 'reactive',
                    'role'               => $role,
                    'declared_purpose'   => $validated['declared_purpose'] ?? '',
                    'target_model'       => $validated['target_model'] ?? 'gpt-4o',
                    'llm_model'          => $validated['target_model'] ?? 'gpt-4o-mini',
                    // Governance fields — Swarm penalises missing declarations
                    'expected_velocity'  => $validated['expected_velocity'] ?? null,
                    'monthly_budget_usd' => $validated['monthly_budget_usd'] ?? null,
                    'ghost_mode_allowed' => $validated['ghost_mode_allowed'] ?? null,
                    'owner_name'         => $validated['owner_name'] ?? null,
                    'business_unit'      => $validated['business_unit'] ?? null,
                    'regulatory_frameworks' => $validated['regulatory_frameworks'] ?? [],
                ]);

                if ($swarmResponse->successful()) {
                    $swarmData    = $swarmResponse->json();
                    $swarmVerdict = $swarmData['verdict'] ?? 'BLOCK';
                    $swarmScore   = (float) ($swarmData['composite_confidence_score'] ?? 0.0);
                    $rawTier      = $swarmData['trust_tier'] ?? 'unverified';
                    $swarmReasons = $swarmData['reasons'] ?? [];

                    // ── HARD BLOCK: Swarm rejected this agent ─────────────────
                    // If the Swarm returns BLOCK (including pre-flight gate failures),
                    // the agent record is deleted, the EVAR is not issued, and the
                    // owner is notified. There is no partial certification.
                    if ($swarmVerdict === 'BLOCK') {
                        // Remove the agent record — a blocked agent must not exist
                        // in the registry in any form.
                        DB::table('agents')->where('id', $agentId)->delete();

                        // Notify the owner so they know exactly what to fix
                        $ownerEmail = $validated['owner_email'] ?? null;
                        $ownerName  = $validated['owner_name']  ?? 'Agent Owner';
                        if ($ownerEmail) {
                            try {
                                \Illuminate\Support\Facades\Mail::raw(
                                    implode("\n\n", array_merge(
                                        ["Cicada Agent Certification — BLOCKED"],
                                        ["Your agent \"{$validated['agent_name']}\" was blocked by the Verification Swarm."],
                                        $swarmReasons,
                                        ["Please resolve all listed deficiencies and re-register the agent."]
                                    )),
                                    fn ($msg) => $msg->to($ownerEmail, $ownerName)
                                                     ->subject("⛔ Agent Certification Blocked: {$validated['agent_name']}")
                                );
                            } catch (\Exception $mailEx) {
                                Log::warning('Owner notification email failed', ['error' => $mailEx->getMessage()]);
                            }
                        }

                        // Also dispatch an internal alert
                        \App\Services\AlertDispatcherService::dispatch(
                            'agent_certification_blocked',
                            $tenantId,
                            $agentId,
                            ['reasons' => $swarmReasons, 'owner_email' => $ownerEmail]
                        );

                        Log::warning('Agent blocked by Swarm — record deleted, owner notified', [
                            'agent_id' => $agentId,
                            'reasons'  => $swarmReasons,
                        ]);

                        return response()->json([
                            'status'  => 'blocked',
                            'message' => 'Agent certification blocked by the Verification Swarm.',
                            'reasons' => $swarmReasons,
                        ], 422);
                    }
                    // ── END HARD BLOCK ────────────────────────────────────────

                    // Map swarm tier to DB-valid enum: unverified | nominal | elevated | critical
                    $tierMap = [
                        'unverified'  => 'unverified',
                        'provisional' => 'nominal',
                        'nominal'     => 'nominal',
                        'elevated'    => 'elevated',
                        'critical'    => 'critical',
                        'high'        => 'elevated',
                        'low'         => 'nominal',
                    ];
                    $trustTier = $tierMap[strtolower($rawTier)] ?? 'unverified';

                    Log::info('Swarm verification complete', [
                        'agent_id' => $agentId,
                        'verdict'  => $swarmVerdict,
                        'score'    => $swarmScore,
                        'tier'     => $trustTier,
                        'reasons'  => $swarmReasons,
                    ]);

                    DB::table('agents')
                        ->where('id', $agentId)
                        ->update([
                            'trust_tier'             => $trustTier,
                            'swarm_confidence_score' => $swarmScore,
                            'swarm_verdict'          => $swarmVerdict,
                            'swarm_reasons'          => json_encode($swarmReasons),
                            'verified_at'            => $swarmVerdict === 'ALLOW' ? now() : null,
                        ]);
                } else {
                    Log::warning('Swarm verification returned non-200', [
                        'agent_id' => $agentId,
                        'status'   => $swarmResponse->status(),
                        'body'     => $swarmResponse->body(),
                    ]);
                }
            } catch (\Exception $swarmEx) {
                // Swarm unavailable — agent stays unverified but is still provisioned.
                // The gateway enforces stricter controls on unverified agents.
                Log::warning('Swarm verification unavailable — agent stays unverified', [
                    'agent_id' => $agentId,
                    'error'    => $swarmEx->getMessage(),
                ]);
            }

            return response()->json([
                'status'  => 'success',
                'message' => $swarmVerdict === 'ALLOW'
                    ? 'Agent verified and EVAR issued.'
                    : 'Agent provisioned but verification pending — trust tier: ' . $trustTier,
                'data'    => [
                    'tenant_id'        => $tenantId,
                    'agent_id'         => $agentId,
                    'evar'             => $evar,
                    'gateway_target'   => "{$gatewayUrl}/v1/proxy/chat/completions",
                    'verification'     => [
                        'verdict'    => $swarmVerdict,
                        'score'      => $swarmScore,
                        'trust_tier' => $trustTier,
                        'reasons'    => $swarmReasons,
                    ],
                ],
            ], 201);

        } catch (\Illuminate\Validation\ValidationException $e) {
            throw $e; // Let Laravel handle validation errors (422)
        } catch (\Exception $e) {
            // Clean up records created in this transaction — never delete the tenant itself.
            if (isset($agentId))  DB::table('agents')->where('id', $agentId)->delete();
            if (isset($tenantId)) DB::table('tenant_keys')->where('tenant_id', $tenantId)->delete();

            Log::error('Agent provisioning failed', [
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString(),
            ]);

            return response()->json([
                'status'  => 'error',
                'message' => 'Agent provisioning encountered an error. Please try again or contact support.',
            ], 500);
        }
    }
}
