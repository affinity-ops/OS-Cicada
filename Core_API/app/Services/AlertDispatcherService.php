<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
namespace App\Services;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Throwable;

class AlertDispatcherService
{
    /**
     * Dispatches an external webhook if an active alert rule matches the given event type.
     * 
     * @param string $eventType e.g. 'agent_quarantined', 'swarm_block_manual_reject'
     * @param string $tenantId The UUID of the tenant involved
     * @param string $agentId The UUID of the agent causing the event
     * @param array  $context Specific context (like trace_id or reason)
     */
    public static function dispatch(string $eventType, string $tenantId, string $agentId, array $context = []): void
    {
        try {
            // Find enabled rules for this event type
            $rules = DB::table('alert_rules')
                ->where('event_type', $eventType)
                ->where('enabled', true)
                ->get();

            if ($rules->isEmpty()) {
                return;
            }

            $payload = [
                'event_type' => $eventType,
                'tenant_id' => $tenantId,
                'agent_id' => $agentId,
                'context' => $context,
                'timestamp' => now()->toIso8601String(),
                'source' => 'Cicada-Core-API'
            ];

            foreach ($rules as $rule) {
                if ($rule->channel === 'webhook' || $rule->channel === 'pagerduty') {
                    // Runtime SSRF guard: skip destinations that resolve to private IPs.
                    // This catches rules created before input validation was added.
                    $parsedUrl = parse_url($rule->destination);
                    $host = $parsedUrl['host'] ?? null;
                    if (!$host || in_array(strtolower($host), ['localhost', '127.0.0.1', '::1', '0.0.0.0'])) {
                        Log::warning("AlertDispatcher: blocked SSRF attempt to [{$rule->destination}]");
                        continue;
                    }
                    $resolvedIp = gethostbyname($host);
                    if (filter_var($resolvedIp, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
                        Log::warning("AlertDispatcher: blocked dispatch to private IP [{$resolvedIp}] for destination [{$rule->destination}]");
                        continue;
                    }

                    // Fire-and-forget HTTP POST
                    Http::timeout(3)
                        ->withHeaders([
                            'Content-Type' => 'application/json',
                            'User-Agent' => 'Cicada-Alert-Dispatcher/1.0'
                        ])
                        ->post($rule->destination, $payload);
                        
                    Log::info("Dispatched Alert Rule [{$rule->id}] for event [{$eventType}] to [{$rule->destination}]");
                }
            }
        } catch (Throwable $e) {
            // Never fail the main request if an alert fails to dispatch
            Log::error("AlertDispatcherService failed: " . $e->getMessage());
        }
    }
}
