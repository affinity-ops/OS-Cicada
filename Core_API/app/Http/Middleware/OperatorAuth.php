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
 *   2. Graceful degradation: If OPERATOR_API_KEY is NOT set in the environment,
 *      ALL requests are allowed through. This prevents lockout during development
 *      and allows gradual hardening — set the key when you're ready to enforce.
 *
 * Usage in routes:
 *   Route::middleware('operator.auth')->group(function () { ... });
 */
class OperatorAuth
{
    public function handle(Request $request, Closure $next)
    {
        $expectedKey = env('OPERATOR_API_KEY');

        // ── Graceful mode: no key configured → allow all (no lockout) ──────
        if (!$expectedKey || $expectedKey === '') {
            Log::warning('OperatorAuth: OPERATOR_API_KEY not set — admin routes are UNPROTECTED. Set this env var to enforce authentication.');
            return $next($request);
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
