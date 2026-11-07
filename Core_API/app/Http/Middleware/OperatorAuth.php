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
 * Operator Authentication Middleware
 *
 * Protects all operator/admin API routes. Supports two authentication methods:
 *
 *   1. Pre-shared key: X-Operator-Key header matched against OPERATOR_API_KEY env var.
 *      Set the same key in the Dashboard's NEXT_PUBLIC_OPERATOR_KEY env var.
 *
 *   2. No key configured: requests pass through ONLY when APP_ENV is local or
 *      testing (so a fresh clone works). In any other environment the route
 *      returns 503 — admin routes never run unauthenticated in a deployment.
 *
 * Usage in routes:
 *   Route::middleware('operator.auth')->group(function () { ... });
 */
class OperatorAuth
{
    public function handle(Request $request, Closure $next)
    {
        $expectedKey = env('OPERATOR_API_KEY');

        // ── No key configured ─────────────────────────────────────────────
        // Previously this allowed ALL requests in every environment, leaving
        // quarantine, universal-revoke and other admin routes open in any
        // deployment that forgot the key. Now it only passes through in
        // local/testing, and fails closed everywhere else.
        if (!$expectedKey || $expectedKey === '') {
            if (app()->environment(['local', 'testing'])) {
                Log::warning('OperatorAuth: OPERATOR_API_KEY not set — admin routes open because APP_ENV=' . app()->environment() . '. Set OPERATOR_API_KEY before deploying.');
                return $next($request);
            }
            Log::error('OperatorAuth: OPERATOR_API_KEY not set outside local/testing — refusing admin request.');
            return response()->json([
                'status'  => 'error',
                'message' => 'Operator authentication is not configured on this server (OPERATOR_API_KEY).',
            ], 503);
        }

        // ── Enforcement mode: key is configured → validate ────────────────
        $providedKey = $request->header('X-Operator-Key');

        if (!$providedKey) {
            return response()->json([
                'status'  => 'error',
                'message' => 'Operator authentication required. Provide X-Operator-Key header.',
            ], 401);
        }

        // Constant-time comparison to prevent timing attacks
        if (!hash_equals($expectedKey, $providedKey)) {
            Log::warning('OperatorAuth: Invalid operator key attempt', [
                'ip' => $request->ip(),
            ]);
            return response()->json([
                'status'  => 'error',
                'message' => 'Invalid operator key.',
            ], 403);
        }

        return $next($request);
    }
}
