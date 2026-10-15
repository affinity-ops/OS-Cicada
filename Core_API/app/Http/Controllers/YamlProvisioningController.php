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
use Symfony\Component\Yaml\Yaml;

class YamlProvisioningController extends Controller
{
    /**
     * E2E Agent Provisioning from cicada.yaml
     *
     * Parses the scaffolded cicada.yaml file, maps its compliance/security parameters
     * to the database, binds the BYOK key, and mints an EVAR via the Sentry Gateway.
     */
    public function provisionFromYaml(Request $request)
    {
        $validated = $request->validate([
            'api_provider' => 'required|string|max:100',
            'api_key'      => 'required|string|max:500',
            'target_model' => 'nullable|string|max:100',
            'yaml_content' => 'required|string|max:50000',
        ]);

        try {
            // Parse the YAML using Symfony's Yaml component
            $policy = Yaml::parse($validated['yaml_content']);

            if (!isset($policy['apiVersion']) || $policy['apiVersion'] !== 'cicada/v1') {
                return response()->json(['status' => 'error', 'message' => 'Invalid or unsupported API version in cicada.yaml'], 400);
            }

            $tenantId = $request->attributes->get('portal_tenant_id');
            $agentId  = (string) Str::uuid();

            // Extract from YAML
            $identity = $policy['identity'] ?? [];
            $enforcement = $policy['enforcement'] ?? [];
            $tools = $policy['tools'] ?? [];
            $compliance = $policy['compliance'] ?? [];

            // Compile scopes dynamically based on required permissions for tools
            // (In a real implementation, you might map specific tools to specific scopes. Defaulting to proxy:chat and proxy:write if tools exist).
            $scopes = ['proxy:chat'];
            if (!empty($tools)) {
                $scopes[] = 'proxy:write';
            }

            DB::transaction(function () use ($validated, $policy, $tenantId, $agentId, $identity, $enforcement, $tools, $compliance, $scopes) {

                // 1. Store the BYOK key
                DB::table('tenant_keys')->insert([
                    'tenant_id'         => $tenantId,
                    'provider'          => $validated['api_provider'],
                    'payload_encrypted' => Crypt::encryptString($validated['api_key']),
                    'created_at'        => now(),
                    'updated_at'        => now(),
                ]);

                // 2. Insert Agent record with all governance/compliance flags
                DB::table('agents')->insert([
                    'id'                => $agentId,
                    'tenant_id'         => $tenantId,
                    'pub_key_hash'      => 'pending_evar_' . $agentId,
                    'scope_entitlements' => json_encode($scopes),
                    'trust_tier'        => 'unverified',
                    
                    // Identity
                    'name'              => $identity['name'] ?? 'yaml-provisioned-agent',
                    'description'       => $identity['description'] ?? null,
                    'agent_type'        => $identity['type'] ?? 'autonomous',
                    'role'              => $identity['role'] ?? 'processor',
                    
                    // Governance metadata
                    'owner_email'       => $identity['owner'] ?? null,
                    'business_unit'     => $identity['business_unit'] ?? null,
                    'data_classification' => $identity['data_classification'] ?? 'internal',
                    'criticality_level'   => $identity['criticality'] ?? 'medium',
                    
                    // Enforcement
                    'hitl_enabled'      => isset($enforcement['hitl']['enabled']) ? (bool) $enforcement['hitl']['enabled'] : false,
                    'hitl_webhook_url'  => $enforcement['hitl']['webhook_url'] ?? null,
                    'hitl_timeout_hours'=> isset($enforcement['hitl']['timeout_seconds']) ? floor($enforcement['hitl']['timeout_seconds'] / 3600) : 24,
                    'shadow_mode'       => isset($enforcement['shadow_mode']) ? (bool) $enforcement['shadow_mode'] : false,
                    'destructive_capability' => isset($enforcement['destructive_capability']) ? (bool) $enforcement['destructive_capability'] : false,
                    'data_residency_region'  => $enforcement['data_residency_region'] ?? null,
                    
                    // Compliance
                    'regulatory_frameworks' => isset($compliance['frameworks']) ? json_encode($compliance['frameworks']) : null,
                    'cost_center'       => $compliance['cost_centre'] ?? null,
                    'monthly_budget_usd'=> $compliance['budget_cap_usd'] ?? null,
                    'external_model_id' => $compliance['external_model_id'] ?? null,
                    
                    'created_at'        => now(),
                    'governance_updated_at' => now(),
                ]);

                // 3. Register declared tools
                foreach ($tools as $tool) {
                    DB::table('agent_tools')->insert([
                        'id'               => (string) Str::uuid(),
                        'agent_id'         => $agentId,
                        'tool_id'          => $tool['name'] ?? 'unknown',
                        'tool_name'        => $tool['name'] ?? 'unknown',
                        'tool_description' => $tool['description'] ?? null,
                        'is_active'        => true,
                        'created_at'       => now(),
                    ]);
                }
            });

            // ── S1.4: Auto-alert for destructive agents without HITL ─────────
            // Same check as ProvisioningController — destructive + no HITL = alert.
            $destructiveCapability = isset($enforcement['destructive_capability']) ? (bool) $enforcement['destructive_capability'] : false;
            $hitlEnabled = isset($enforcement['hitl']['enabled']) ? (bool) $enforcement['hitl']['enabled'] : false;

            if ($destructiveCapability && !$hitlEnabled) {
                try {
                    \App\Services\AlertDispatcherService::dispatch(
                        'destructive_agent_no_hitl',
                        $tenantId,
                        $agentId,
                        [
                            'severity'     => 'high',
                            'agent_name'   => $identity['name'] ?? 'yaml-provisioned-agent',
                            'scopes'       => $scopes,
                            'source'       => 'yaml_provisioning',
                            'action'       => 'Review agent configuration — destructive capability enabled without HITL gate',
                        ]
                    );

                    DB::table('operator_alerts')->insert([
                        'id'         => (string) Str::uuid(),
                        'tenant_id'  => $tenantId,
                        'agent_id'   => $agentId,
                        'event_type' => 'destructive_agent_no_hitl',
                        'severity'   => 'high',
                        'summary'    => 'Agent "' . ($identity['name'] ?? 'yaml-agent') . '" provisioned via YAML with destructive_capability=true but HITL is disabled.',
                        'context'    => json_encode([
                            'agent_name' => $identity['name'] ?? 'yaml-agent',
                            'scopes'     => $scopes,
                            'hitl_enabled' => false,
                            'destructive_capability' => true,
                            'source' => 'yaml_provisioning',
                        ]),
                        'status'     => 'open',
                        'created_at' => now(),
                        'updated_at' => now(),
                    ]);
                } catch (\Exception $alertEx) {
                    Log::warning('S1.4 YAML alert dispatch failed', ['error' => $alertEx->getMessage()]);
                }
            }

            // 4. Call the Sentry Gateway to mint an EVAR
            $gatewayUrl = rtrim(env('CICADA_GATEWAY_URL', 'http://localhost:8080'), '/');
            $mintResponse = Http::timeout(10)->post("{$gatewayUrl}/v1/agent/register", [
                'agent_id'                  => $agentId,
                'code_hash'                 => hash('sha256', $identity['name'] ?? 'yaml-agent'),
                'scopes'                    => $scopes,
                'intended_model'            => $validated['target_model'] ?? 'gpt-4o',
                'is_persistent'             => false,
                'data_residency_region'     => $enforcement['data_residency_region'] ?? null,
                'certified_reversal_routes' => (object) [],
            ]);

            if (!$mintResponse->successful()) {
                DB::table('agents')->where('id', $agentId)->delete();
                DB::table('tenant_keys')->where('tenant_id', $tenantId)->delete();

                Log::error('EVAR minting failed via YAML endpoint', [
                    'agent_id' => $agentId,
                    'gateway_status' => $mintResponse->status(),
                    'gateway_body'   => $mintResponse->body(),
                ]);

                return response()->json([
                    'status'  => 'error',
                    'message' => 'Sentry Gateway failed to issue EVAR.',
                ], 503);
            }

            $evar = $mintResponse->json('evar');

            // 5. Update pub_key_hash with real JWT
            DB::table('agents')->where('id', $agentId)->update(['pub_key_hash' => $evar]);

            return response()->json([
                'status'  => 'success',
                'message' => 'Agent provisioned from policy and EVAR issued.',
                'data'    => [
                    'tenant_id' => $tenantId,
                    'agent_id'  => $agentId,
                    'evar'      => $evar,
                    'gateway_target' => "{$gatewayUrl}/v1/proxy/chat/completions",
                ],
            ], 201);

        } catch (\Exception $e) {
            if (isset($agentId))  DB::table('agents')->where('id', $agentId)->delete();
            if (isset($tenantId)) DB::table('tenant_keys')->where('tenant_id', $tenantId)->delete();

            Log::error('YAML provisioning error', ['error' => $e->getMessage()]);

            return response()->json([
                'status'  => 'error',
                'message' => 'Failed to parse policy or provision agent: ' . $e->getMessage()
            ], 500);
        }
    }
}
