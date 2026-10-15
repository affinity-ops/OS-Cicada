// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

'use client';

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';

export default function GatewayAuthCallback() {
  const router = useRouter();

  useEffect(() => {
    const fragment = window.location.hash.slice(1);
    const params   = new URLSearchParams(fragment);
    const token    = params.get('token');
    const tenant   = params.get('tenant');
    const plan     = params.get('plan');

    if (!token || !tenant) {
      router.replace('/login?error=oauth_failed');
      return;
    }

    localStorage.setItem('cicada_gw_token',  token);
    localStorage.setItem('cicada_gw_tenant', tenant);
    localStorage.setItem('cicada_gw_plan',   plan ?? 'starter');

    router.replace('/overview');
  }, [router]);

  return (
    <div className="min-h-screen flex items-center justify-center bg-background">
      <div className="text-center space-y-4">
        <div className="w-12 h-12 border-2 border-primary border-t-transparent rounded-full animate-spin mx-auto" />
        <p className="text-on-surface-muted text-sm font-technical">Authenticating gateway operator...</p>
      </div>
    </div>
  );
}
