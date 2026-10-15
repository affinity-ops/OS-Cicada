// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

'use client';

import React, { useState } from 'react';

const POLICIES = [
  { id: 'min_trust_tier',     label: 'Minimum Trust Tier',         description: 'Reject any inbound agent below this trust tier.',         type: 'select',  options: ['unverified', 'nominal', 'elevated', 'critical'], default: 'nominal' },
  { id: 'max_scope',          label: 'Maximum Permitted Scope',    description: 'Block agents claiming scopes beyond this level.',         type: 'select',  options: ['proxy:read', 'proxy:chat', 'proxy:write', 'proxy:transact'], default: 'proxy:chat' },
  { id: 'swarm_threshold',    label: 'Swarm Confidence Threshold', description: 'Minimum Swarm confidence score to admit an agent (0–1).', type: 'number',  default: '0.6' },
  { id: 'anomaly_threshold',  label: 'Anomaly Block Threshold',    description: 'Anomaly score above which the agent is sandboxed.',       type: 'number',  default: '0.35' },
  { id: 'allow_unverified',   label: 'Allow Unverified Agents',    description: 'Permit agents without a valid EVAR (not recommended).',   type: 'toggle',  default: false },
  { id: 'shadow_on_block',    label: 'Shadow Sandbox on Block',    description: 'Route blocked agents to the honeypot instead of hard-rejecting.', type: 'toggle', default: true },
];

export default function PolicyManagement() {
  const [values, setValues] = useState<Record<string, any>>(() =>
    Object.fromEntries(POLICIES.map(p => [p.id, p.default]))
  );
  const [saved, setSaved] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const CORE_API = process.env.NEXT_PUBLIC_CORE_API_URL || 'http://localhost:8000';

  async function save() {
    setSaving(true);
    setError(null);
    try {
      const res = await fetch(`${CORE_API}/api/v1/gateway/config`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ policies: values }),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.message || `HTTP ${res.status}`);
      }
      setSaved(true);
      setTimeout(() => setSaved(false), 3000);
    } catch (e: any) {
      setError(e.message || 'Failed to save policy');
      console.error('Policy save failed:', e);
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="p-8 max-w-2xl space-y-6">
      <div>
        <h1 className="text-3xl font-black font-headline tracking-tighter">Policy Management</h1>
        <p className="text-on-surface-muted text-sm mt-1">
          Configure the rules your Gateway enforces against every inbound agent.
          Changes take effect on the next Gateway process cycle.
        </p>
      </div>

      <div className="bg-surface-raised border border-[rgba(255,159,74,0.08)] rounded-2xl divide-y divide-[rgba(255,255,255,0.04)]">
        {POLICIES.map(policy => (
          <div key={policy.id} className="flex items-start justify-between p-5 gap-6">
            <div className="flex-1 min-w-0">
              <p className="font-headline font-bold text-sm">{policy.label}</p>
              <p className="text-xs text-on-surface-muted mt-0.5">{policy.description}</p>
            </div>
            <div className="flex-shrink-0">
              {policy.type === 'select' && (
                <select value={values[policy.id]} onChange={e => setValues(v => ({ ...v, [policy.id]: e.target.value }))}
                  className="bg-black/60 border border-white/10 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-primary transition-colors font-technical"
                >
                  {policy.options!.map(o => <option key={o} value={o}>{o}</option>)}
                </select>
              )}
              {policy.type === 'number' && (
                <input type="number" min="0" max="1" step="0.05" value={values[policy.id]}
                  onChange={e => setValues(v => ({ ...v, [policy.id]: e.target.value }))}
                  className="w-24 bg-black/60 border border-white/10 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-primary transition-colors font-technical text-center"
                />
              )}
              {policy.type === 'toggle' && (
                <button onClick={() => setValues(v => ({ ...v, [policy.id]: !v[policy.id] }))}
                  className={`relative w-12 h-6 rounded-full transition-colors ${values[policy.id] ? 'bg-primary' : 'bg-white/20'}`}
                >
                  <div className={`absolute top-1 w-4 h-4 rounded-full bg-white transition-transform ${values[policy.id] ? 'translate-x-7' : 'translate-x-1'}`} />
                </button>
              )}
            </div>
          </div>
        ))}
      </div>

      <div className="bg-yellow-500/10 border border-yellow-500/20 rounded-xl p-4">
        <p className="text-xs text-yellow-400 font-technical">
          Policy changes are stored in your Gateway configuration. They do not retroactively affect past transactions recorded in the ledger.
        </p>
      </div>

      {saved && <p className="text-sm text-green-400 bg-green-500/10 border border-green-500/20 rounded-lg p-3">Policy saved. Gateway will apply on next cycle.</p>}
      {error && <p className="text-sm text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg p-3">Save failed: {error}</p>}

      <button onClick={save} disabled={saving}
        className="px-6 py-3 bg-primary text-black rounded-xl font-headline font-bold hover:brightness-110 transition-all disabled:opacity-50"
      >
        {saving ? 'Saving…' : 'Save Policy'}
      </button>
    </div>
  );
}
