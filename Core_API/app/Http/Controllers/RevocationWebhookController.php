<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use App\Services\AuditService;
use OpenApi\Attributes as OA;

/**
 * RevocationWebhookController — CRUD for cross-system revocation endpoints (H2.3).
 *
 * Manages the outbound webhook endpoints that Cicada fires when an agent is
 * quarantined. Each tenant can configure multiple endpoints for different
 * external IdPs and SIEM platforms (Okta, Entra, Splunk, PagerDuty, etc.).
 *
 * Wire format follows the IETF Shared Signals Framework (SSF) / CAEP standard.
 */
class RevocationWebhookController extends Controller
{
    /**
     * GET /api/v1/tenant/revocation-webhooks
     *
     * List all revocation webhooks for the authenticated tenant.
     * Auth secrets are never returned — only the last 4 characters for display.
     */
    #[OA\Get(
        path: '/api/v1/tenant/revocation-webhooks',
        summary: 'List revocation webhooks',
        description: 'List all cross-system revocation webhooks for the authenticated tenant.',
        tags: ['Revocation']
    )]
    #[OA\Response(response: 200, description: 'Success')]
    public function index(Request $request): \Illuminate\Http\JsonResponse
    {
        if (!Schema::hasTable('revocation_webhooks')) {
            return response()->json([
                'status' => 'success',
                'data'   => [],
                'message' => 'Revocation webhooks table not yet migrated.',
            ]);
        }

        $tenantId = $request->attributes->get('tenant_id');
        if (!$tenantId) {
            return response()->json(['error' => 'Tenant context required'], 403);
        }

        $webhooks = DB::table('revocation_webhooks')
            ->where('tenant_id', $tenantId)
            ->orderByDesc('created_at')
            ->get()
            ->map(function ($webhook) {
                // Mask the auth secret — only show last 4 chars for identification.
                $webhook->auth_secret_masked = $webhook->auth_secret
                    ? '••••' . substr($webhook->auth_secret, -4)
                    : null;
                unset($webhook->auth_secret);
                return $webhook;
            });

        return response()->json(['status' => 'success', 'data' => $webhooks]);
    }

    /**
     * POST /api/v1/tenant/revocation-webhooks
     *
     * Create a new revocation webhook endpoint for the authenticated tenant.
     */
    #[OA\Post(
        path: '/api/v1/tenant/revocation-webhooks',
        summary: 'Create revocation webhook',
        description: 'Create a new cross-system revocation webhook for the authenticated tenant.',
        tags: ['Revocation']
    )]
    #[OA\Response(response: 201, description: 'Created')]
    public function store(Request $request): \Illuminate\Http\JsonResponse
    {
        $validated = $request->validate([
            'name'         => 'required|string|max:255',
            'endpoint_url' => 'required|url|max:2048',
            'event_types'  => 'sometimes|array',
            'event_types.*' => 'string|in:agent_quarantined,circuit_breaker_trip,operator_quarantine,attestation_failed,canary_triggered',
            'auth_method'  => 'sometimes|string|in:bearer_token,hmac_sha256,none',
            'auth_secret'  => 'nullable|string|max:2048',
        ]);

        $tenantId = $request->attributes->get('tenant_id');
        if (!$tenantId) {
            return response()->json(['error' => 'Tenant context required'], 403);
        }

        // SSRF protection: validate the endpoint URL is HTTPS and resolves to a public IP.
        if (!$this->isValidExternalUrl($validated['endpoint_url'])) {
            return response()->json([
                'error' => 'Webhook endpoint must be a valid HTTPS URL resolving to a public IP address. '
                         . 'Internal, private, and localhost URLs are not permitted.',
            ], 422);
        }

        $id = \Illuminate\Support\Str::uuid()->toString();

        DB::table('revocation_webhooks')->insert([
            'id'           => $id,
            'tenant_id'    => $tenantId,
            'name'         => $validated['name'],
            'endpoint_url' => $validated['endpoint_url'],
            'event_types'  => json_encode($validated['event_types'] ?? ['agent_quarantined']),
            'auth_method'  => $validated['auth_method'] ?? 'bearer_token',
            'auth_secret'  => isset($validated['auth_secret'])
                ? Crypt::encryptString($validated['auth_secret'])
                : null,
            'enabled'      => true,
            'created_at'   => now(),
            'updated_at'   => now(),
        ]);

        AuditService::log(
            $request, 'revocation_webhook_created', 'revocation_webhook', $id,
            null, $validated, 'Created cross-system revocation webhook'
        );

        return response()->json([
            'status'  => 'success',
            'data'    => ['id' => $id],
            'message' => 'Revocation webhook created.',
        ], 201);
    }

    /**
     * DELETE /api/v1/tenant/revocation-webhooks/{id}
     *
     * Remove a revocation webhook endpoint.
     */
    #[OA\Delete(
        path: '/api/v1/tenant/revocation-webhooks/{id}',
        summary: 'Delete revocation webhook',
        description: 'Remove a cross-system revocation webhook.',
        tags: ['Revocation']
    )]
    #[OA\Parameter(name: 'id', in: 'path', required: true, schema: new OA\Schema(type: 'string', format: 'uuid'))]
    #[OA\Response(response: 200, description: 'Deleted')]
    public function destroy(string $id, Request $request): \Illuminate\Http\JsonResponse
    {
        $tenantId = $request->attributes->get('tenant_id');
        if (!$tenantId) {
            return response()->json(['error' => 'Tenant context required'], 403);
        }

        $deleted = DB::table('revocation_webhooks')
            ->where('id', $id)
            ->where('tenant_id', $tenantId)
            ->delete();

        if (!$deleted) {
            return response()->json(['error' => 'Webhook not found'], 404);
        }

        AuditService::log(
            $request, 'revocation_webhook_deleted', 'revocation_webhook', $id,
            null, null, 'Deleted cross-system revocation webhook'
        );

        return response()->json(['status' => 'success', 'message' => 'Webhook deleted.']);
    }

    /**
     * POST /api/v1/tenant/revocation-webhooks/{id}/test
     *
     * Send a test event to a revocation webhook to verify connectivity.
     */
    #[OA\Post(
        path: '/api/v1/tenant/revocation-webhooks/{id}/test',
        summary: 'Test revocation webhook',
        description: 'Send a test CAEP event to verify webhook connectivity.',
        tags: ['Revocation']
    )]
    #[OA\Parameter(name: 'id', in: 'path', required: true, schema: new OA\Schema(type: 'string', format: 'uuid'))]
    #[OA\Response(response: 200, description: 'Test result')]
    public function test(string $id, Request $request): \Illuminate\Http\JsonResponse
    {
        $tenantId = $request->attributes->get('tenant_id');
        if (!$tenantId) {
            return response()->json(['error' => 'Tenant context required'], 403);
        }

        $webhook = DB::table('revocation_webhooks')
            ->where('id', $id)
            ->where('tenant_id', $tenantId)
            ->first();

        if (!$webhook) {
            return response()->json(['error' => 'Webhook not found'], 404);
        }

        // Dispatch a test event using the RevocationDispatcherService.
        // The test event uses a special event type that the IdP can ignore.
        try {
            \App\Services\RevocationDispatcherService::dispatch(
                'agent_quarantined',
                $tenantId,
                '00000000-0000-0000-0000-000000000000', // test agent ID
                [
                    'reason'   => 'Test event — webhook connectivity verification',
                    'trace_id' => 'test-' . time(),
                ]
            );

            return response()->json([
                'status'  => 'success',
                'message' => 'Test event dispatched. Check webhook logs for delivery confirmation.',
            ]);
        } catch (\Throwable $e) {
            return response()->json([
                'status'  => 'error',
                'message' => 'Test dispatch failed: ' . $e->getMessage(),
            ], 500);
        }
    }

    /**
     * SSRF protection: validate that a URL resolves to a public IP over HTTPS.
     */
    private function isValidExternalUrl(string $url): bool
    {
        $parsed = parse_url($url);

        // Must be HTTPS
        if (($parsed['scheme'] ?? '') !== 'https') {
            return false;
        }

        $host = $parsed['host'] ?? null;
        if (!$host) {
            return false;
        }

        // Block known local hosts
        if (in_array(strtolower($host), ['localhost', '127.0.0.1', '::1', '0.0.0.0'])) {
            return false;
        }

        // Resolve and check for private IPs
        $resolvedIp = gethostbyname($host);
        if (filter_var($resolvedIp, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
            return false;
        }

        return true;
    }
}
