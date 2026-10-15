<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use App\Services\AuditService;
use OpenApi\Attributes as OA;

/**
 * AlertRuleController — CRUD for operator-configured security alert rules.
 *
 * GET    /api/v1/admin/alert-rules           — list all rules
 * POST   /api/v1/admin/alert-rules           — create a new rule
 * PATCH  /api/v1/admin/alert-rules/{id}      — toggle enabled/disabled
 * DELETE /api/v1/admin/alert-rules/{id}      — delete a rule
 */
class AlertRuleController extends Controller
{
    #[OA\Get(
        path: '/api/v1/admin/alert-rules',
        summary: 'List alert rules',
        description: 'Returns all operator-configured alert rules.',
        tags: ['Alerts']
    )]
    #[OA\Response(response: 200, description: 'Success')]
    public function index(): \Illuminate\Http\JsonResponse
    {
        $rules = DB::table('alert_rules')
            ->orderByDesc('created_at')
            ->get();

        return response()->json(['status' => 'success', 'data' => $rules]);
    }

    #[OA\Post(
        path: '/api/v1/admin/alert-rules',
        summary: 'Create an alert rule',
        tags: ['Alerts']
    )]
    #[OA\RequestBody(
        required: true,
        content: new OA\JsonContent(
            properties: [
                new OA\Property(property: 'event_type', type: 'string'),
                new OA\Property(property: 'channel', type: 'string', enum: ['email', 'webhook', 'aegis']),
                new OA\Property(property: 'destination', type: 'string')
            ]
        )
    )]
    #[OA\Response(response: 201, description: 'Rule created')]
    public function store(Request $request): \Illuminate\Http\JsonResponse
    {
        $validated = $request->validate([
            'event_type'  => 'required|string|max:100',
            'channel'     => 'required|in:email,webhook,aegis,pagerduty',
            'destination' => 'required|string|max:500',
        ]);

        // SSRF protection: validate webhook/pagerduty destinations
        if (in_array($validated['channel'], ['webhook', 'pagerduty'])) {
            if (!$this->isExternalUrl($validated['destination'])) {
                return response()->json([
                    'error' => 'Webhook destination must be a valid HTTPS URL pointing to a public host. Internal, private, and localhost URLs are not permitted.',
                ], 422);
            }
        }

        DB::table('alert_rules')->insert([
            'event_type'  => $validated['event_type'],
            'channel'     => $validated['channel'],
            'destination' => $validated['destination'],
            'enabled'     => true,
            'created_at'  => now(),
            'updated_at'  => now(),
        ]);

        AuditService::log(request(), 'alert_rule_modified', 'alert_rule', 'new', null, $validated, 'Operator created alert rule');

        return response()->json(['status' => 'success', 'message' => 'Rule created.'], 201);
    }

    #[OA\Patch(
        path: '/api/v1/admin/alert-rules/{id}',
        summary: 'Toggle an alert rule',
        tags: ['Alerts']
    )]
    #[OA\Parameter(name: 'id', in: 'path', required: true, schema: new OA\Schema(type: 'string', format: 'uuid'))]
    #[OA\Response(response: 200, description: 'Rule toggled')]
    public function toggle(string $id): \Illuminate\Http\JsonResponse
    {
        $rule = DB::table('alert_rules')->where('id', $id)->first();
        if (!$rule) {
            return response()->json(['error' => 'Rule not found.'], 404);
        }

        DB::table('alert_rules')->where('id', $id)->update([
            'enabled'    => !$rule->enabled,
            'updated_at' => now(),
        ]);

        AuditService::log(request(), 'alert_rule_modified', 'alert_rule', $id, ['enabled' => $rule->enabled], ['enabled' => !$rule->enabled], 'Operator toggled alert rule');

        return response()->json(['status' => 'success', 'enabled' => !$rule->enabled]);
    }

    #[OA\Delete(
        path: '/api/v1/admin/alert-rules/{id}',
        summary: 'Delete an alert rule',
        tags: ['Alerts']
    )]
    #[OA\Parameter(name: 'id', in: 'path', required: true, schema: new OA\Schema(type: 'string', format: 'uuid'))]
    #[OA\Response(response: 200, description: 'Rule deleted')]
    public function destroy(string $id): \Illuminate\Http\JsonResponse
    {
        $deleted = DB::table('alert_rules')->where('id', $id)->delete();
        if (!$deleted) {
            return response()->json(['error' => 'Rule not found.'], 404);
        }

        AuditService::log(request(), 'alert_rule_modified', 'alert_rule', $id, null, null, 'Operator deleted alert rule');

        return response()->json(['status' => 'success', 'message' => 'Rule deleted.']);
    }

    /**
     * SSRF protection: ensure webhook destination URLs are external HTTPS endpoints.
     * Blocks private IP ranges, localhost, link-local, and non-HTTPS schemes.
     */
    private function isExternalUrl(string $url): bool
    {
        $parsed = parse_url($url);

        // Must be a valid URL with scheme and host
        if (!$parsed || !isset($parsed['scheme'], $parsed['host'])) {
            return false;
        }

        // Must be HTTPS (allow HTTP only in local development)
        if ($parsed['scheme'] !== 'https' && !app()->environment('local', 'testing')) {
            return false;
        }

        $host = strtolower($parsed['host']);

        // Block localhost and loopback
        if (in_array($host, ['localhost', '127.0.0.1', '::1', '0.0.0.0'])) {
            return false;
        }

        // Resolve the hostname and check the IP
        $ip = gethostbyname($host);
        if ($ip === $host) {
            // DNS resolution failed — could be a trap domain, reject
            return false;
        }

        // Block private and reserved IP ranges (RFC 1918, RFC 6598, link-local, AWS metadata)
        $blockedRanges = [
            '10.0.0.0/8',
            '172.16.0.0/12',
            '192.168.0.0/16',
            '169.254.0.0/16',    // Link-local / AWS metadata
            '100.64.0.0/10',     // Carrier-grade NAT
            '127.0.0.0/8',       // Loopback
            '0.0.0.0/8',         // Current network
        ];

        foreach ($blockedRanges as $range) {
            [$network, $bits] = explode('/', $range);
            $networkLong = ip2long($network);
            $ipLong = ip2long($ip);
            $mask = -1 << (32 - (int) $bits);
            if (($ipLong & $mask) === ($networkLong & $mask)) {
                return false;
            }
        }

        return true;
    }
}
