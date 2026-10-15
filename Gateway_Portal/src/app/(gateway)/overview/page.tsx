// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

'use client';

import React, { useEffect, useState } from 'react';
import Link from 'next/link';
import { useSession } from '../layout';

const CORE_API = process.env.NEXT_PUBLIC_CORE_API_URL || 'http://localhost:8000';
const GW_URL   = process.env.NEXT_PUBLIC_GATEWAY_URL  || 'http://localhost:8080';

interface Summary {
  totalAgents: number; certifiedAgents: number; pendingAgents: number;
  revokedAgents: number; totalTransactions: number; blockedToday: number;
}

function KPI({ label, value, icon, accent }: { label: string; value: number | string; icon: string; accent?: string }) {
  return (
    <div className="bg-surface-raised border border-[rgba(255,159,74,0.08)] rounded-2xl p-6">
      <span className={`material-symbols-outlined text-2xl ${accent ?? 'text-primary'}`}>{icon}</span>
      <p className="text-3xl font-black font-headline mt-3">{value}</p>
      <p className="text-xs font-technical text-on-surface-muted uppercase tracking-widest mt-1">{label}</p>
    </div>
  );
}

export default function GatewayOverview() {
  const session = useSession();
  const [summary, setSummary] = useState<Summary | null>(null);
  const [gwOnline, setGwOnline] = useState<boolean | null>(null);

  useEffect(() => {
    if (!session) return;

    fetch(`${CORE_API}/api/v1/portal/summary`, {
      headers: { Authorization: `Bearer ${session.token}`, Accept: 'application/json' },
    }).then(r => r.json()).then(({ data }) => setSummary(data));

    fetch(`${GW_URL}/health`, { signal: AbortSignal.timeout(3000) })
      .then(() => setGwOnline(true))
      .catch(() => setGwOnline(false));
  }, [session]);

  return (
    <div className="p-8 space-y-8">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-3xl font-black font-headline tracking-tighter">
            Gateway Overview
          </h1>
          <p className="text-on-surface-muted text-sm mt-1">{session?.tenant.name}</p>
        </div>
        <div className={`flex items-center gap-2 px-4 py-2 rounded-full border text-sm font-technical ${
          gwOnline === null ? 'border-white/10 text-on-surface-muted' :
          gwOnline ? 'border-green-500/30 bg-green-500/10 text-green-400' :
          'border-red-500/30 bg-red-500/10 text-red-400'
        }`}>
          <div className={`w-2 h-2 rounded-full ${gwOnline ? 'bg-green-400 animate-pulse' : gwOnline === false ? 'bg-red-400' : 'bg-gray-400'}`} />
          {gwOnline === null ? 'Checking…' : gwOnline ? 'Gateway Online' : 'Gateway Offline'}
        </div>
      </div>

      <div className="grid grid-cols-3 gap-4">
        <KPI label="Certified Agents"    value={summary?.certifiedAgents   ?? '—'} icon="verified"      accent="text-green-400" />
        <KPI label="Pending Cert."       value={summary?.pendingAgents      ?? '—'} icon="pending"       accent="text-yellow-400" />
        <KPI label="Terminated"          value={summary?.revokedAgents      ?? '—'} icon="cancel"        accent="text-gray-500" />
        <KPI label="Total Transactions"  value={summary?.totalTransactions  ?? '—'} icon="receipt_long" />
        <KPI label="Blocked Today"       value={summary?.blockedToday       ?? '—'} icon="block"         accent="text-red-400" />
        <KPI label="Total Agents"        value={summary?.totalAgents        ?? '—'} icon="smart_toy" />
      </div>

      <div>
        <h2 className="text-sm font-technical text-on-surface-muted uppercase tracking-widest mb-3">Quick Actions</h2>
        <div className="grid grid-cols-2 gap-3">
          {[
            { href: '/inbound',  icon: 'call_received', label: 'Inbound Traffic',    desc: 'Monitor agents arriving at your Gateway' },
            { href: '/outbound', icon: 'call_made',     label: 'Outbound Traffic',   desc: 'Your agents going out to other systems' },
            { href: '/threats',  icon: 'security',      label: 'Threat Intelligence',desc: 'Anomalies, blocks, and suspicious patterns' },
            { href: '/policy',   icon: 'policy',        label: 'Policy Management',  desc: 'Configure OPA rules and trust thresholds' },
          ].map(a => (
            <Link key={a.href} href={a.href}
              className="flex items-center gap-4 p-5 bg-surface-raised border border-[rgba(255,159,74,0.08)] rounded-xl hover:border-primary/30 transition-colors"
            >
              <span className="material-symbols-outlined text-primary text-2xl">{a.icon}</span>
              <div>
                <p className="font-headline font-bold text-sm">{a.label}</p>
                <p className="text-xs text-on-surface-muted">{a.desc}</p>
              </div>
            </Link>
          ))}
        </div>
      </div>
    </div>
  );
}
