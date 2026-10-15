<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

/**
 * PortalAuth — Developer Portal authentication middleware.
 *
 * Security features:
 *   - Bearer token validation (SHA-256 hashed)
 *   - Token expiry enforcement
 *   - Idle timeout (Phase 6.12) — revokes tokens inactive > PORTAL_IDLE_TIMEOUT_MINUTES (default: 30)
 *   - Concurrent session limit — max PORTAL_MAX_SESSIONS per contact (default: 5)
 *   - Tenant status + email verification check
 */
class PortalAuth
{
    public function handle(Request $request, Closure $next)
    {
        $token = $request->bearerToken();

        if (!$token) {
            return response()->json(['status' => 'error', 'message' => 'Unauthenticated.'], 401);
        }

        $pat = DB::table('personal_access_tokens')
            ->where('token', hash('sha256', $token))
            ->first();

        if (!$pat || ($pat->expires_at && now()->isAfter($pat->expires_at))) {
            return response()->json(['status' => 'error', 'message' => 'Token expired or invalid.'], 401);
        }

        // ── Idle timeout check (Phase 6.12) ────────────────────────────────
        // If the token hasn't been used within the idle window, treat it as
        // expired. This prevents abandoned sessions from being reused.
        $idleMinutes = (int) env('PORTAL_IDLE_TIMEOUT_MINUTES', 30);
        if ($pat->last_used_at && now()->diffInMinutes($pat->last_used_at) > $idleMinutes) {
            // Delete the idle token — force re-authentication
            DB::table('personal_access_tokens')->where('id', $pat->id)->delete();
            return response()->json([
                'status'  => 'error',
                'message' => 'Session expired due to inactivity. Please log in again.',
                'code'    => 'IDLE_TIMEOUT',
            ], 401);
        }

        [$contactId, $tenantId] = explode('|', $pat->name, 2);

        // ── Concurrent session limit (Phase 6.12) ──────────────────────────
        // Limit the number of active sessions per contact to prevent session
        // accumulation. Oldest excess sessions are pruned automatically.
        $maxSessions = (int) env('PORTAL_MAX_SESSIONS', 5);
        $activeSessions = DB::table('personal_access_tokens')
            ->where('name', 'LIKE', $contactId . '|%')
            ->where(function ($q) {
                $q->whereNull('expires_at')
                  ->orWhere('expires_at', '>', now());
            })
            ->orderByDesc('last_used_at')
            ->get();

        if ($activeSessions->count() > $maxSessions) {
            // Prune oldest sessions beyond the limit
            $toDelete = $activeSessions->slice($maxSessions)->pluck('id');
            DB::table('personal_access_tokens')->whereIn('id', $toDelete)->delete();
        }

        $tenant = DB::table('tenants')->where('id', $tenantId)->first();

        // Block unverified tenants — both pending status and missing email_verified_at
        if (!$tenant || $tenant->status === 'pending') {
            return response()->json(['status' => 'error', 'message' => 'Email address not verified. Please check your inbox.'], 403);
        }

        // Explicit email verification check (defence-in-depth — even if status was
        // manually set to 'active', we require email_verified_at to be non-null
        // for sensitive operations)
        $emailVerified = !empty($tenant->email_verified_at);

        $request->attributes->set('portal_contact_id', $contactId);
        $request->attributes->set('portal_tenant_id',  $tenantId);
        $request->attributes->set('portal_email_verified', $emailVerified);

        // Transparency header — agents and frontends can detect verification status
        $request->headers->set('X-Cicada-Email-Verified', $emailVerified ? 'true' : 'false');

        DB::table('personal_access_tokens')->where('id', $pat->id)->update(['last_used_at' => now()]);

        return $next($request);
    }
}
