// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { NextResponse } from 'next/server';

/**
 * Server-side auth callback handler (BFF pattern).
 *
 * This replaces the previous client-side callback that used document.cookie
 * (non-HttpOnly, XSS-vulnerable). The auth flow now works as follows:
 *
 *   1. The OIDC/dev-login redirect sends token+tenant as query params to this route
 *   2. This server-side handler verifies the token against the Sentry Gateway
 *   3. On success, it sets the operator_session cookie as HttpOnly + Secure + Strict
 *   4. It redirects the browser to the dashboard
 *
 * The token is NEVER exposed to client-side JavaScript.
 */

const GATEWAY_URL = process.env.CICADA_GATEWAY_URL || process.env.NEXT_PUBLIC_GATEWAY_URL || 'http://localhost:8080';

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const token = searchParams.get('token');
  const tenant = searchParams.get('tenant');

  if (!token) {
    return NextResponse.redirect(new URL('/login?error=missing_token', request.url));
  }

  // ── Verify the token against the Sentry Gateway ────────────────────────
  // This is the critical security step: we confirm the token is a valid,
  // non-expired portal session before granting access. Previously, the
  // client-side callback set operator_session=authenticated without any
  // server-side verification.
  try {
    const verifyRes = await fetch(`${GATEWAY_URL}/v1/federation/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token }),
    });

    if (!verifyRes.ok) {
      console.error('[AUTH] Token verification failed:', verifyRes.status);
      return NextResponse.redirect(new URL('/login?error=invalid_token', request.url));
    }

    // Token is valid — extract claims for session context
    const claims = await verifyRes.json();
    console.log(`[AUTH] Token verified for ${claims.email || claims.sub || 'unknown'} (tenant: ${tenant || claims.tenant_id || 'unknown'})`);
  } catch (err) {
    // If the gateway is unreachable (e.g. local dev without gateway running),
    // check if we're in development mode and the token is non-empty.
    // In production, this MUST fail-closed.
    const isDev = process.env.NODE_ENV === 'development';
    if (!isDev) {
      console.error('[AUTH] Gateway unreachable in production — denying access:', err);
      return NextResponse.redirect(new URL('/login?error=gateway_unavailable', request.url));
    }
    console.warn('[AUTH] Gateway unreachable in dev mode — allowing token without verification');
  }

  // ── Set HttpOnly session cookie (server-side only) ─────────────────────
  // This cookie is:
  //   - HttpOnly: cannot be read by client-side JavaScript (XSS-proof)
  //   - Secure: only sent over HTTPS (in production)
  //   - SameSite=Strict: not sent on cross-origin requests (CSRF-proof)
  //   - Signed: the value is the actual JWT token, not a plain string
  //
  // The middleware verifies this cookie's value is a non-empty JWT,
  // not the previous insecure 'authenticated' string.
  const isProduction = process.env.NODE_ENV === 'production';

  const response = NextResponse.redirect(new URL('/', request.url));

  response.cookies.set('operator_session', token, {
    httpOnly: true,
    secure: isProduction,
    sameSite: 'strict',
    maxAge: 86400, // 24 hours
    path: '/',
  });

  // Store tenant context in a separate HttpOnly cookie if provided
  if (tenant) {
    response.cookies.set('cicada_tenant', tenant, {
      httpOnly: true,
      secure: isProduction,
      sameSite: 'strict',
      maxAge: 86400,
      path: '/',
    });
  }

  return response;
}
