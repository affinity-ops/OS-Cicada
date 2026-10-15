// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

'use client';

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';

/**
 * OAuth callback landing page.
 *
 * Laravel redirects here with the token in the URL fragment:
 *   /auth/callback#token=<value>&tenant=<uuid>&plan=<tier>
 *
 * Fragments never hit server logs. We extract the token client-side,
 * persist it to localStorage, then redirect into the portal.
 */
export default function AuthCallback() {
  const router = useRouter();

  useEffect(() => {
    const fragment = window.location.hash.slice(1);
    const params = new URLSearchParams(fragment);

    const token  = params.get('token');
    const tenant = params.get('tenant');
    const plan   = params.get('plan');

    if (!token || !tenant) {
      router.replace('/login?error=oauth_failed');
      return;
    }

    localStorage.setItem('cicada_token', token);
    localStorage.setItem('cicada_tenant', tenant);
    localStorage.setItem('cicada_plan', plan ?? 'starter');

    router.replace('/dashboard');
  }, [router]);

  return (
    <div className="min-h-screen flex items-center justify-center bg-background">
      <div className="text-center space-y-4">
        <div className="w-12 h-12 border-2 border-primary border-t-transparent rounded-full animate-spin mx-auto" />
        <p className="text-on-surface-muted text-sm font-technical">Verifying identity...</p>
      </div>
    </div>
  );
}
