// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

'use client';

import { useEffect } from 'react';

/**
 * Auth callback handler for the Operator Dashboard.
 *
 * External auth redirects (OIDC, dev-login) send credentials as URL fragment
 * parameters: /auth/callback#token=xxx&tenant=yyy
 *
 * This client-side page extracts those parameters from the hash fragment
 * (which is never sent to the server by browsers) and redirects to the
 * server-side API route /api/auth/callback?token=xxx&tenant=yyy which:
 *
 *   1. Verifies the token against the Sentry Gateway
 *   2. Sets an HttpOnly + Secure + SameSite=Strict cookie
 *   3. Redirects to the dashboard
 *
 * The token is NEVER stored in sessionStorage, localStorage, or a non-HttpOnly
 * cookie. It exists only briefly in the URL fragment (client-side only) before
 * being handed off to the server-side handler.
 *
 * Security note: URL fragments (#hash) are not sent to the server in HTTP
 * requests, so external auth providers use them to prevent token leakage
 * in server logs and proxies. We bridge from fragment → server-side route
 * via client-side redirect.
 */
export default function AuthCallback() {
  useEffect(() => {
    const hash = window.location.hash.substring(1);
    const params = new URLSearchParams(hash);
    const token = params.get('token');
    const tenant = params.get('tenant');

    if (token) {
      // Redirect to server-side BFF handler that sets HttpOnly cookies.
      // The token is passed as a query param over the internal Next.js
      // API route (same origin, never exposed to external network).
      const callbackUrl = new URL('/api/auth/callback', window.location.origin);
      callbackUrl.searchParams.set('token', token);
      if (tenant) {
        callbackUrl.searchParams.set('tenant', tenant);
      }
      window.location.href = callbackUrl.toString();
    } else {
      window.location.href = '/login?error=missing_token';
    }
  }, []);

  return (
    <div className="min-h-screen bg-[#090909] flex items-center justify-center font-technical">
      <div className="text-center">
        <span className="material-symbols-outlined text-[48px] text-primary animate-spin mb-4">sync</span>
        <p className="text-white text-sm uppercase tracking-widest">Authenticating...</p>
      </div>
    </div>
  );
}
