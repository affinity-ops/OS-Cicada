<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
namespace App\Services;

use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Schema;
use Throwable;

/**
 * RevocationDispatcherService — Cross-System Revocation (H2.3).
 *
 * When Cicada quarantines an agent, the agent may still hold independent OAuth
 * tokens for Slack, Stripe, GitHub, etc. This service dispatches outbound
 * revocation events to configured external IdP/SIEM endpoints so those systems
 * can revoke the agent's sessions universally.
 *
 * Wire format follows the IETF Shared Signals Framework (SSF) / Continuous
 * Access Evaluation Protocol (CAEP) standard. IdPs that support CAEP (Okta,
 * Microsoft Entra, Google Workspace) can consume these events natively.
 *
 * @see https://openid.net/specs/openid-caep-specification-1_0.html
 */
class RevocationDispatcherService
{
    /**
     * Maximum consecutive failures before a webhook is auto-disabled.
     * After this threshold, an alert is raised and the webhook stops firing.
     */
    private const MAX_CONSECUTIVE_FAILURES = 5;

    /**
     * Dispatch a cross-system revocation event to all configured webhooks
     * for the given tenant that subscribe to the specified event type.
     *
     * This method is fire-and-forget: failures are logged but never propagate
     * to the caller. A webhook delivery failure must never prevent internal
     * quarantine from completing.
     *
     * @param string $eventType  One of: agent_quarantined, circuit_breaker_trip,
     *                           operator_quarantine, attestation_failed, canary_triggered
     * @param string $tenantId   UUID of the tenant
     * @param string $agentId    UUID of the quarantined agent
     * @param array  $context    Additional context (reason, trace_id, etc.)
     */
    public static function dispatch(string $eventType, string $tenantId, string $agentId, array $context = []): void
    {
        try {
            // Guard: if revocation_webhooks table doesn't exist yet (migration pending),
            // skip silently. This prevents crashes during rolling deployments.
            if (!Schema::hasTable('revocation_webhooks')) {
                return;
            }

            // Fetch enabled webhooks for this tenant that subscribe to this event type.
            $webhooks = DB::table('revocation_webhooks')
                ->where('tenant_id', $tenantId)
                ->where('enabled', true)
                ->whereJsonContains('event_types', $eventType)
                ->get();

            if ($webhooks->isEmpty()) {
                return;
            }

            // Build the CAEP-compatible Security Event Token (SET) payload.
            // This follows the IETF SSF/CAEP wire format so IdPs can consume
            // these events natively without custom integration code.
            $caepPayload = self::buildCaepEvent($eventType, $tenantId, $agentId, $context);

            foreach ($webhooks as $webhook) {
                try {
                    self::deliverWebhook($webhook, $caepPayload);
                } catch (Throwable $e) {
                    self::recordFailure($webhook, $e->getMessage());
                }
            }
        } catch (Throwable $e) {
            // Never fail the main quarantine operation if revocation dispatch fails.
            Log::error("RevocationDispatcherService: top-level failure: " . $e->getMessage());
        }
    }

    /**
     * Build a CAEP-compatible Security Event Token (SET) payload.
     *
     * Format follows OpenID CAEP specification 1.0:
     * - `iss`: Cicada instance identifier
     * - `iat`: Event timestamp
     * - `jti`: Unique event identifier
     * - `events`: CAEP event body keyed by event URI
     *
     * @see https://openid.net/specs/openid-caep-specification-1_0.html#section-3
     */
    private static function buildCaepEvent(string $eventType, string $tenantId, string $agentId, array $context): array
    {
        $eventUri = match ($eventType) {
            'agent_quarantined', 'operator_quarantine'
                => 'https://schemas.openid.net/secevent/caep/event-type/session-revoked',
            'circuit_breaker_trip'
                => 'https://schemas.openid.net/secevent/caep/event-type/credential-change',
            'attestation_failed'
                => 'https://schemas.openid.net/secevent/caep/event-type/assurance-level-change',
            'canary_triggered'
                => 'https://schemas.openid.net/secevent/caep/event-type/token-claims-change',
            default
                => 'https://schemas.openid.net/secevent/caep/event-type/session-revoked',
        };

        return [
            'iss'    => config('app.url', 'https://cicada.cloud'),
            'iat'    => now()->timestamp,
            'jti'    => (string) \Illuminate\Support\Str::uuid(),
            'aud'    => $tenantId,
            'events' => [
                $eventUri => [
                    'subject' => [
                        'subject_type' => 'agent',
                        'agent_id'     => $agentId,
                        'tenant_id'    => $tenantId,
                    ],
                    'event_timestamp' => now()->toIso8601String(),
                    'reason_admin'    => [
                        'en' => $context['reason'] ?? "Agent $agentId has been quarantined by Cicada governance platform.",
                    ],
                    'initiating_entity' => $context['initiator'] ?? 'cicada-governance',
                    'cicada_context'    => [
                        'event_type'   => $eventType,
                        'trace_id'     => $context['trace_id'] ?? null,
                        'risk_score'   => $context['risk_score'] ?? null,
                        'reason_codes' => $context['reason_codes'] ?? [],
                    ],
                ],
            ],
        ];
    }

    /**
     * Deliver a webhook payload to the configured endpoint with authentication.
     *
     * @throws \Exception on delivery failure
     */
    private static function deliverWebhook(object $webhook, array $payload): void
    {
        // SSRF protection: validate the endpoint URL at runtime.
        // This catches endpoints that were valid at creation but now resolve to private IPs.
        $parsedUrl = parse_url($webhook->endpoint_url);
        $host = $parsedUrl['host'] ?? null;

        if (!$host || in_array(strtolower($host), ['localhost', '127.0.0.1', '::1', '0.0.0.0'])) {
            Log::warning("RevocationDispatcher: blocked SSRF attempt to [{$webhook->endpoint_url}]");
            self::recordFailure($webhook, 'SSRF protection: localhost destination blocked');
            return;
        }

        $resolvedIp = gethostbyname($host);
        if (filter_var($resolvedIp, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
            Log::warning("RevocationDispatcher: blocked dispatch to private IP [{$resolvedIp}] for [{$webhook->endpoint_url}]");
            self::recordFailure($webhook, "SSRF protection: resolved to private IP $resolvedIp");
            return;
        }

        // Build the HTTP request with appropriate authentication.
        $request = Http::timeout(5)
            ->withHeaders([
                'Content-Type' => 'application/json',
                'User-Agent'   => 'Cicada-Revocation-Dispatcher/1.0',
            ]);

        $secret = null;
        if ($webhook->auth_secret) {
            try {
                $secret = Crypt::decryptString($webhook->auth_secret);
            } catch (Throwable $e) {
                Log::error("RevocationDispatcher: failed to decrypt auth_secret for webhook {$webhook->id}");
                $secret = $webhook->auth_secret; // fallback to raw if not encrypted
            }
        }

        switch ($webhook->auth_method) {
            case 'bearer_token':
                if ($secret) {
                    $request = $request->withToken($secret);
                }
                break;

            case 'hmac_sha256':
                if ($secret) {
                    $bodyJson = json_encode($payload);
                    $signature = hash_hmac('sha256', $bodyJson, $secret);
                    $request = $request->withHeaders([
                        'X-Cicada-Signature' => "sha256=$signature",
                    ]);
                }
                break;

            case 'none':
            default:
                // No authentication — not recommended but supported.
                break;
        }

        $response = $request->post($webhook->endpoint_url, $payload);

        if ($response->successful()) {
            self::recordSuccess($webhook);
            Log::info("RevocationDispatcher: delivered to [{$webhook->name}] ({$webhook->endpoint_url}) — HTTP {$response->status()}");
        } else {
            throw new \Exception("HTTP {$response->status()}: {$response->body()}");
        }
    }

    /**
     * Record a successful delivery — reset failure counter and update timestamp.
     */
    private static function recordSuccess(object $webhook): void
    {
        DB::table('revocation_webhooks')
            ->where('id', $webhook->id)
            ->update([
                'last_success_at'      => now(),
                'consecutive_failures' => 0,
                'last_failure_reason'  => null,
                'updated_at'           => now(),
            ]);
    }

    /**
     * Record a delivery failure — increment counter and auto-disable if threshold exceeded.
     */
    private static function recordFailure(object $webhook, string $reason): void
    {
        $failures = ($webhook->consecutive_failures ?? 0) + 1;

        $update = [
            'consecutive_failures' => $failures,
            'last_failure_reason'  => substr($reason, 0, 500),
            'updated_at'           => now(),
        ];

        // Auto-disable after MAX_CONSECUTIVE_FAILURES to prevent alert fatigue
        // and wasted HTTP calls to permanently-dead endpoints.
        if ($failures >= self::MAX_CONSECUTIVE_FAILURES) {
            $update['enabled'] = false;
            Log::error("RevocationDispatcher: webhook [{$webhook->name}] auto-disabled after {$failures} consecutive failures");

            // Raise an alert so the operator knows a revocation channel is down.
            AlertDispatcherService::dispatch(
                'revocation_webhook_disabled',
                $webhook->tenant_id,
                $webhook->id,
                [
                    'webhook_name'  => $webhook->name,
                    'endpoint_url'  => $webhook->endpoint_url,
                    'last_failure'  => $reason,
                    'failure_count' => $failures,
                ]
            );
        }

        DB::table('revocation_webhooks')
            ->where('id', $webhook->id)
            ->update($update);

        Log::warning("RevocationDispatcher: delivery to [{$webhook->name}] failed ({$failures}/{" . self::MAX_CONSECUTIVE_FAILURES . "}): {$reason}");
    }
}
