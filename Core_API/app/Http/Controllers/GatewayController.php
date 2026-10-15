<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
namespace App\Http\Controllers;

use Carbon\Carbon;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class GatewayController extends Controller
{
    // Number of missed intervals before a gateway is considered DEGRADED.
    private const DEGRADED_MULTIPLIER = 1;
    // Number of missed intervals before a gateway is considered OFFLINE.
    private const OFFLINE_MULTIPLIER = 3;
    // Default interval in seconds if the gateway doesn't report one.
    private const DEFAULT_INTERVAL_SECONDS = 10800; // 3 hours

    /**
     * POST /api/v1/gateway/heartbeat
     *
     * Called by every Sentry Gateway installation on its configured interval.
     * Upserts the gateway_instances record, recomputes status, and returns
     * any pending operator directives that the gateway should act on.
     *
     * Authentication: X-Gateway-ID header identifies the installation.
     * No operator auth required — this endpoint is gateway-to-platform only.
     */
    public function heartbeat(Request $request): \Illuminate\Http\JsonResponse
    {
        $data = $request->validate([
            'gateway_id'               => 'required|string|max:255',
            'tenant_id'                => 'sometimes|string|max:255',
            'gateway_version'          => 'sometimes|string|max:50',
            'uptime_seconds'           => 'sometimes|integer|min:0',
            'agents_registered'        => 'sometimes|integer|min:0',
            'calls_last_window'        => 'sometimes|integer|min:0',
            'calls_blocked_last_window'=> 'sometimes|integer|min:0',
            'tls_enabled'              => 'sometimes|boolean',
            'mtls_enabled'             => 'sometimes|boolean',
            'canary_tokens_active'     => 'sometimes|integer|min:0',
            'quarantined_agents'       => 'sometimes|integer|min:0',
            'redis_healthy'            => 'sometimes|boolean',
            'postgres_healthy'         => 'sometimes|boolean',
            'region'                   => 'sometimes|string|max:100',
            'country'                  => 'sometimes|string|max:100',
            'metadata'                 => 'sometimes|array',
        ]);

        $gatewayId = $data['gateway_id'];
        $now = Carbon::now();

        // Resolve tenant from gateway_id. If no tenant is associated yet,
        // default to the system tenant (or null). Gateways self-register on
        // first heartbeat and are matched to a tenant manually by the operator.
        // Enterprise Gateways will explicitly supply their tenant_id from their .lic file.
        $existing = DB::table('gateway_instances')
            ->where('gateway_id', $gatewayId)
            ->first();

        // Determine reporting interval from uptime — we infer the interval from
        // the last_seen_at delta rather than trusting the gateway to report it.
        $intervalSeconds = self::DEFAULT_INTERVAL_SECONDS;
        if ($existing && $existing->last_seen_at) {
            $delta = $now->diffInSeconds(Carbon::parse($existing->last_seen_at));
            if ($delta > 60 && $delta < 86400) {
                $intervalSeconds = $delta;
            }
        }

        $status = 'online';

        $upsertData = [
            'gateway_id'                => $gatewayId,
            'tenant_id'                 => $data['tenant_id'] ?? $existing?->tenant_id ?? $this->defaultTenantId(),
            'gateway_version'           => $data['gateway_version'] ?? 'unknown',
            'agents_registered'         => $data['agents_registered'] ?? 0,
            'calls_last_window'         => $data['calls_last_window'] ?? 0,
            'calls_blocked_last_window' => $data['calls_blocked_last_window'] ?? 0,
            'tls_enabled'               => $data['tls_enabled'] ?? false,
            'mtls_enabled'              => $data['mtls_enabled'] ?? false,
            'canary_tokens_active'      => $data['canary_tokens_active'] ?? 0,
            'quarantined_agents'        => $data['quarantined_agents'] ?? 0,
            'status'                    => $status,
            'last_seen_at'              => $now,
            'ip_address'                => $request->ip(),
            'region'                    => $data['region'] ?? null,
            'country'                   => $data['country'] ?? $existing?->country ?? null,
            'metadata'                  => isset($data['metadata']) ? json_encode($data['metadata']) : null,
        ];

        if ($existing) {
            DB::table('gateway_instances')
                ->where('gateway_id', $gatewayId)
                ->update($upsertData);
        } else {
            $upsertData['first_registered_at'] = $now;
            DB::table('gateway_instances')->insert($upsertData);
        }

        // Return operator directives. Currently returns empty directives;
        // future: query a gateway_directives table for pending instructions.
        return response()->json([
            'status'     => 'ok',
            'gateway_id' => $gatewayId,
            'directives' => [
                'quarantine_agents' => [],
                'revoke_agents'     => [],
                'reload_policy'     => false,
                'message'           => '',
            ],
        ]);
    }

    /**
     * GET /api/v1/admin/gateways
     *
     * Returns all registered gateway instances with computed health status.
     * Filterable by ?status=online|degraded|offline and ?country=XX.
     * Used by the Gateway Fleet view on the Global Overview dashboard.
     */
    public function index(Request $request): \Illuminate\Http\JsonResponse
    {
        $query = DB::table('gateway_instances')
            ->leftJoin('tenants', 'gateway_instances.tenant_id', '=', 'tenants.id')
            ->select(
                'gateway_instances.*',
                'tenants.name as company_name',
            );

        if ($status = $request->query('status')) {
            $query->where('gateway_instances.status', $status);
        }
        if ($country = $request->query('country')) {
            $query->where('gateway_instances.country', $country);
        }
        if ($tenantId = $request->query('tenant_id')) {
            $query->where('gateway_instances.tenant_id', $tenantId);
        }

        $gateways = $query->orderByDesc('gateway_instances.last_seen_at')->get();

        // Recompute live status for each gateway based on last_seen_at.
        // The stored status is set at heartbeat time; this recalculates it
        // in real time so the dashboard always reflects the current health
        // without waiting for the next heartbeat to update the record.
        $now = Carbon::now();
        $gateways = $gateways->map(function ($gw) use ($now) {
            $liveStatus = 'offline';
            if ($gw->last_seen_at) {
                $ageSeconds = $now->diffInSeconds(Carbon::parse($gw->last_seen_at));
                $interval   = self::DEFAULT_INTERVAL_SECONDS;
                if ($ageSeconds <= $interval * self::DEGRADED_MULTIPLIER) {
                    $liveStatus = 'online';
                } elseif ($ageSeconds <= $interval * self::OFFLINE_MULTIPLIER) {
                    $liveStatus = 'degraded';
                }
            }
            $gw->live_status = $liveStatus;
            return $gw;
        });

        $summary = [
            'total'    => $gateways->count(),
            'online'   => $gateways->where('live_status', 'online')->count(),
            'degraded' => $gateways->where('live_status', 'degraded')->count(),
            'offline'  => $gateways->where('live_status', 'offline')->count(),
        ];

        return response()->json([
            'status'   => 'success',
            'summary'  => $summary,
            'gateways' => $gateways->values(),
        ]);
    }

    private function defaultTenantId(): string
    {
        $tenant = DB::table('tenants')->orderBy('created_at')->first();
        return $tenant?->id ?? '00000000-0000-0000-0000-000000000000';
    }
}
