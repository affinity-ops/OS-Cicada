// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

'use client';

import React, { useEffect, useState } from 'react';
import Link from 'next/link';
import { useSession } from '../layout';

const CORE_API = process.env.NEXT_PUBLIC_CORE_API_URL || 'http://localhost:8000';

interface Summary {
  totalAgents: number; certifiedAgents: number; pendingAgents: number;
  revokedAgents: number; totalTransactions: number; blockedToday: number;
}

function StatCard({ label, value, icon, accent }: { label: string; value: number | string; icon: string; accent?: string }) {
  return (
    <div className="bg-surface-raised border border-[rgba(255,159,74,0.08)] rounded-2xl p-6">
      <div className="flex items-start justify-between mb-4">
        <span className={`material-symbols-outlined text-2xl ${accent ?? 'text-primary'}`}>{icon}</span>
      </div>
      <p className="text-3xl font-black font-headline">{value}</p>
      <p className="text-xs font-technical text-on-surface-muted uppercase tracking-widest mt-1">{label}</p>
    </div>
  );
}

export default function Dashboard() {
  const session = useSession();
  const [summary, setSummary] = useState<Summary | null>(null);

  useEffect(() => {
    if (!session) return;
    fetch(`${CORE_API}/api/v1/portal/summary`, {
      headers: { Authorization: `Bearer ${session.token}`, Accept: 'application/json' },
    }).then(r => r.json()).then(({ data }) => setSummary(data));
  }, [session]);

  return (
    <div className="p-8 space-y-8">
      <div>
        <h1 className="text-3xl font-black font-headline tracking-tighter">
          Welcome back, <span className="text-primary">{session?.contact.name.split(' ')[0]}</span>
        </h1>
        <p className="text-on-surface-muted text-sm mt-1">{session?.tenant.name}</p>
      </div>

      {/* KPIs */}
      <div className="grid grid-cols-3 gap-4">
        <StatCard label="Total Agents"      value={summary?.totalAgents ?? '—'}       icon="smart_toy" />
        <StatCard label="Certified"         value={summary?.certifiedAgents ?? '—'}    icon="verified" accent="text-green-400" />
        <StatCard label="Pending Cert."     value={summary?.pendingAgents ?? '—'}      icon="pending" accent="text-yellow-400" />
        <StatCard label="Transactions"      value={summary?.totalTransactions ?? '—'}  icon="receipt_long" />
        <StatCard label="Blocked Today"     value={summary?.blockedToday ?? '—'}       icon="block" accent="text-red-400" />
        <StatCard label="Terminated"        value={summary?.revokedAgents ?? '—'}      icon="cancel" accent="text-gray-500" />
      </div>

      {/* Quick actions */}
      <div>
        <h2 className="text-sm font-technical text-on-surface-muted uppercase tracking-widest mb-3">Quick Actions</h2>
        <div className="grid grid-cols-2 gap-3">
          {[
            { href: '/agents/register', icon: 'add_circle',   label: 'Register an Agent',      desc: 'Step-by-step provisioning wizard' },
            { href: '/agents',          icon: 'smart_toy',    label: 'View Registry',           desc: 'Check certification status' },
            { href: '/transactions',    icon: 'receipt_long', label: 'Transaction History',     desc: 'Full ledger of agent actions' },
            { href: '/account/company', icon: 'business',     label: 'Update Company Details',  desc: 'Profile and contact info' },
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
