<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;

/**
 * Gateway-to-Platform Authentication Middleware
 *
 * Protects Zone 3 (internal) routes that are called by the Sentry Gateway binary.
 * Without this middleware, any pod on the internal network could impersonate
 * the gateway and call /internal/hitl/suspend or read operator WebAuthn state.
 *
 * Authentication Methods (checked in order):
 *   1. Pre-shared key: X-Gateway-Secret header matched against GATEWAY_INTERNAL_KEY env var.
 *   2. Graceful degradation: If GATEWAY_INTERNAL_KEY is NOT set, allows all requests.
 *      This prevents lockout during development — set the key when deploying.
 *
 * The Sentry Gateway sends this header from its CICADA_INTERNAL_KEY env var.
 */
class GatewayAuth
{
    public function handle(Request $request, Closure $next)
    {
        $expectedKey = env('GATEWAY_INTERNAL_KEY');

        // ── Graceful mode: no key configured → allow all ──────────────────
        if (!$expectedKey || $expectedKey === '') {
            return $next($request);
        }

        // ── Enforcement mode: validate the shared secret ──────────────────
        $providedKey = $request->header('X-Gateway-Secret');

        if (!$providedKey) {
            Log::warning('GatewayAuth: Rejected request — missing X-Gateway-Secret header', [
                'ip'   => $request->ip(),
                'path' => $request->path(),
            ]);
            return response()->json([
                'status'  => 'error',
                'message' => 'Internal authentication required.',
            ], 401);
        }

        // Constant-time comparison
        if (!hash_equals($expectedKey, $providedKey)) {
            Log::warning('GatewayAuth: Rejected request — invalid gateway secret', [
                'ip' => $request->ip(),
            ]);
            return response()->json([
                'status'  => 'error',
                'message' => 'Invalid internal key.',
            ], 403);
        }

        return $next($request);
    }
}
