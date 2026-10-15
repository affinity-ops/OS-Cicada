<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

/**
 * EnsureEmailVerified middleware.
 *
 * Blocks sensitive operations (agent provisioning, CIBA responses, API key binding)
 * unless the tenant's email has been cryptographically verified via the verification
 * token flow in CompanyController::verify().
 *
 * This is applied AFTER PortalAuth (which populates portal_email_verified).
 *
 * Route registration:
 *   Route::post('/provision/agent', [...])->middleware(['portal.auth', 'verified.email']);
 *
 * Phase 6.6 — Security Hardening
 */
class EnsureEmailVerified
{
    /**
     * Sensitive operations that require a verified email address.
     * If this middleware is applied to a route group, ALL routes in that group
     * will require verification. For granular control, apply per-route.
     */
    public function handle(Request $request, Closure $next)
    {
        $emailVerified = $request->attributes->get('portal_email_verified', false);

        if (!$emailVerified) {
            return response()->json([
                'status'  => 'error',
                'message' => 'Email verification required. Please verify your email address before performing this operation.',
                'code'    => 'EMAIL_NOT_VERIFIED',
                'action'  => 'Check your inbox for the verification link, or request a new one via /api/v1/provision/resend-verification.',
            ], 403);
        }

        return $next($request);
    }
}
