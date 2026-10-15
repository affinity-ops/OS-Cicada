// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

/**
 * Operator session middleware.
 *
 * Validates the operator_session cookie on every protected route. The cookie
 * is set as HttpOnly by the server-side auth callback (/api/auth/callback)
 * or the WebAuthn login verify handler (/api/webauthn/login/verify).
 *
 * Validation levels:
 *   1. Cookie must exist
 *   2. Cookie value must not be empty
 *   3. Cookie value must look like a JWT (three dot-separated base64 segments)
 *      OR be the legacy 'authenticated' value (for WebAuthn sessions that
 *      haven't been migrated yet)
 *
 * Full cryptographic verification of the JWT happens at the API layer
 * (Sentry Gateway's /v1/federation/verify), not in the edge middleware,
 * because middleware runs in a restricted runtime without access to
 * crypto libraries or the Gateway network.
 */
export function middleware(request: NextRequest) {
  const path = request.nextUrl.pathname;

  // Allow explicit unauthenticated access to auth flows and API routes
  if (
    path.startsWith('/api/webauthn') ||
    path.startsWith('/api/auth') ||
    path === '/login' ||
    path.startsWith('/auth/callback')
  ) {
    return NextResponse.next();
  }

  // Validate operator session cookie
  const session = request.cookies.get('operator_session');
  if (!session || !session.value) {
    return NextResponse.redirect(new URL('/login', request.url));
  }

  // Accept either a JWT token (three base64url segments separated by dots)
  // or the legacy 'authenticated' value from the WebAuthn flow.
  const value = session.value;
  const isJWT = value.split('.').length === 3;
  const isLegacy = value === 'authenticated';

  if (!isJWT && !isLegacy) {
    // Invalid session format — clear the cookie and redirect to login
    const response = NextResponse.redirect(new URL('/login', request.url));
    response.cookies.delete('operator_session');
    return response;
  }

  return NextResponse.next();
}

export const config = {
  matcher: ['/((?!api|_next/static|_next/image|_next/webpack-hmr|favicon.ico).*)'],
};
