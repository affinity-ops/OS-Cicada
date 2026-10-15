// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

'use client';

import React, { useState } from 'react';
import { useSession } from '../../layout';

const CORE_API = process.env.NEXT_PUBLIC_CORE_API_URL || 'http://localhost:8000';

const PLANS = [
  {
    id:    'starter',
    label: 'Starter (Standalone)',
    price: 'Open Source',
    features: [
      'Up to 5 registered agents',
      'Standard Verification Swarm',
      '50,000 gateway transactions/mo quota',
      'Community support',
    ],
  },
  {
    id:    'professional',
    label: 'Professional (Connected Mesh)',
    price: 'Self-Hosted',
    popular: true,
    features: [
      'Up to 25 registered agents',
      'Priority Verification Swarm',
      '500,000 gateway transactions/mo quota',
      'Inbound Gateway installation',
      'P2P Gossip Mesh synchronization',
    ],
  },
  {
    id:    'enterprise',
    label: 'Enterprise (Sovereign Cluster)',
    price: 'Cluster Tier',
    features: [
      'Unlimited agents',
      'Dedicated Swarm cluster',
      'Unlimited transactions',
      'Multi-region Gateway deployment',
      'PQC Hybrid node attestation',
      'Air-gapped Gateway option',
    ],
  },
];

export default function Billing() {
  const session = useSession();
  const [saving, setSaving]   = useState(false);
  const [saved, setSaved]     = useState(false);
  const currentPlan = session?.tenant.plan ?? 'starter';

  async function changePlan(plan: string) {
    if (plan === currentPlan || plan === 'enterprise') return;
    setSaving(true);
    setSaved(false);
    try {
      const res = await fetch(`${CORE_API}/api/v1/portal/billing/plan`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json', Authorization: `Bearer ${session?.token}` },
        body: JSON.stringify({ plan }),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        console.error('Plan change failed:', body.message || res.statusText);
        setSaving(false);
        return;
      }
      setSaved(true);
      setTimeout(() => setSaved(false), 3000);
      localStorage.setItem('cicada_plan', plan);
    } catch (e) {
      console.error('Plan change request failed:', e);
    }
    setSaving(false);
  }

  return (
    <div className="p-8 space-y-8">
      <div>
        <h1 className="text-3xl font-black font-headline tracking-tighter">Billing & Plan</h1>
        <p className="text-on-surface-muted text-sm mt-1">
          Current plan: <span className="text-primary font-technical uppercase">{currentPlan}</span>
        </p>
      </div>

      {saved && (
        <p className="text-sm text-green-400 bg-green-500/10 border border-green-500/20 rounded-lg p-3">
          Plan updated. Changes take effect immediately.
        </p>
      )}

      <div className="grid grid-cols-3 gap-5">
        {PLANS.map(plan => {
          const isCurrent = plan.id === currentPlan;
          return (
            <div key={plan.id}
              className={`relative flex flex-col bg-surface-raised border rounded-2xl p-6 transition-colors ${
                isCurrent ? 'border-primary' : plan.popular ? 'border-primary/30' : 'border-[rgba(255,159,74,0.08)]'
              }`}
            >
              {plan.popular && (
                <div className="absolute -top-3 left-1/2 -translate-x-1/2 px-3 py-1 bg-primary text-black text-[10px] font-technical uppercase tracking-widest rounded-full">
                  Most Popular
                </div>
              )}
              {isCurrent && (
                <div className="absolute -top-3 right-4 px-3 py-1 bg-green-500 text-black text-[10px] font-technical uppercase tracking-widest rounded-full">
                  Active
                </div>
              )}

              <h2 className="text-xl font-headline font-black mb-1">{plan.label}</h2>
              <p className="text-2xl font-headline font-black text-primary mb-4">{plan.price}</p>

              <ul className="space-y-2 flex-1 mb-6">
                {plan.features.map(f => (
                  <li key={f} className="flex items-start gap-2 text-xs text-on-surface-muted">
                    <span className="material-symbols-outlined text-primary text-[14px] mt-0.5 flex-shrink-0">check_circle</span>
                    {f}
                  </li>
                ))}
              </ul>

              {plan.id === 'enterprise' ? (
                <a href="mailto:sales@cicada.io"
                  className="w-full py-3 border border-primary/30 text-primary rounded-xl font-headline font-bold text-sm text-center hover:bg-primary/5 transition-colors block"
                >
                  Contact Sales
                </a>
              ) : isCurrent ? (
                <div className="w-full py-3 bg-primary/10 text-primary rounded-xl font-headline font-bold text-sm text-center">
                  Current Plan
                </div>
              ) : (
                <button onClick={() => changePlan(plan.id)} disabled={saving}
                  className="w-full py-3 bg-primary text-black rounded-xl font-headline font-bold text-sm hover:brightness-110 disabled:opacity-50 transition-all"
                >
                  {saving ? 'Updating…' : `Switch to ${plan.label}`}
                </button>
              )}
            </div>
          );
        })}
      </div>

      <div className="bg-surface-raised border border-[rgba(255,159,74,0.08)] rounded-2xl p-6">
        <h2 className="font-headline font-bold mb-1">Need to cancel?</h2>
        <p className="text-sm text-on-surface-muted">Contact us at <span className="text-primary">support@cicada.io</span> and we will handle it promptly. Your agent data is retained for 30 days after cancellation.</p>
      </div>
    </div>
  );
}
