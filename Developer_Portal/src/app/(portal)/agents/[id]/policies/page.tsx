// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

'use client';

import React, { useEffect, useState } from 'react';
import Link from 'next/link';
import { useParams } from 'next/navigation';
import { useSession } from '../../../layout';

const CORE_API = process.env.NEXT_PUBLIC_CORE_API_URL || 'http://localhost:8000';

const HTTP_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'];

export default function AgentPolicies() {
  const { id } = useParams<{ id: string }>();
  const session = useSession();
  const [policies, setPolicies] = useState<any[]>([]);
  const [loading, setLoading]   = useState(true);
  const [pattern, setPattern]   = useState('');
  const [methods, setMethods]   = useState<string[]>(['GET']);
  const [saving, setSaving]     = useState(false);
  const [error, setError]       = useState('');

  function headers() {
    return { Authorization: `Bearer ${session?.token}`, 'Content-Type': 'application/json' };
  }

  function load() {
    if (!session) return;
    fetch(`${CORE_API}/api/v1/portal/agents/${id}/policies`, { headers: headers() })
      .then(r => r.json())
      .then(({ data }) => { setPolicies(data ?? []); setLoading(false); });
  }

  useEffect(() => { load(); }, [session]);

  async function addPolicy(e: React.FormEvent) {
    e.preventDefault();
    if (!pattern.trim() || methods.length === 0) return;
    setSaving(true);
    setError('');
    const res = await fetch(`${CORE_API}/api/v1/portal/agents/${id}/policies`, {
      method: 'POST',
      headers: headers(),
      body: JSON.stringify({ resource_pattern: pattern.trim(), allowed_methods: methods }),
    });
    setSaving(false);
    if (res.ok) { setPattern(''); setMethods(['GET']); load(); }
    else { const j = await res.json(); setError(j.message ?? 'Failed to add policy'); }
  }

  async function togglePolicy(policyId: string, active: boolean) {
    await fetch(`${CORE_API}/api/v1/portal/agents/${id}/policies/${policyId}`, {
      method: 'PATCH',
      headers: headers(),
      body: JSON.stringify({ active }),
    });
    load();
  }

  async function deletePolicy(policyId: string) {
    await fetch(`${CORE_API}/api/v1/portal/agents/${id}/policies/${policyId}`, {
      method: 'DELETE',
      headers: headers(),
    });
    load();
  }

  function toggleMethod(m: string) {
    setMethods(prev => prev.includes(m) ? prev.filter(x => x !== m) : [...prev, m]);
  }

  return (
    <div className="p-8 space-y-8 max-w-3xl">
      <div className="flex items-center gap-2 text-sm text-on-surface-muted">
        <Link href="/agents" className="hover:text-on-surface transition-colors">Agents</Link>
        <span className="material-symbols-outlined text-[16px]">chevron_right</span>
        <span className="text-on-surface">Resource Policies</span>
      </div>

      <div>
        <h1 className="text-3xl font-black font-headline tracking-tighter">Resource Policies</h1>
        <p className="text-on-surface-muted text-sm mt-1">
          Fine-grained control over which URLs and HTTP methods this agent may call.
          Policies add precision on top of scope entitlements — an agent with <code className="font-technical text-primary text-xs">proxy:write</code> scope
          can be restricted to specific endpoints only.
        </p>
      </div>

      {/* How it works */}
      <div className="bg-primary/5 border border-primary/20 rounded-xl p-4 text-sm text-on-surface-muted space-y-1">
        <p className="font-headline font-bold text-on-surface text-sm">How resource policies work</p>
        <p>If no policies are set, the agent is governed by scope entitlements alone (existing behaviour).</p>
        <p>Once any policy is added, the Gateway checks every inbound call against this list. Calls to URLs not matching an active policy are denied, regardless of scope.</p>
        <p>Patterns support a single trailing wildcard: <code className="font-technical text-primary text-xs">https://api.stripe.com/v1/charges*</code></p>
      </div>

      {/* Add policy form */}
      <form onSubmit={addPolicy} className="bg-surface-raised border border-[rgba(255,159,74,0.08)] rounded-2xl p-6 space-y-4">
        <h2 className="font-headline font-bold">Add Policy</h2>

        <div>
          <label className="text-[10px] uppercase font-technical text-on-surface-muted tracking-widest block mb-1">
            URL Pattern
          </label>
          <input
            value={pattern}
            onChange={e => setPattern(e.target.value)}
            placeholder="https://api.example.com/v1/resource*"
            className="w-full bg-black/40 border border-white/10 rounded-xl px-4 py-2.5 text-sm font-technical focus:outline-none focus:border-primary transition-colors"
          />
        </div>

        <div>
          <label className="text-[10px] uppercase font-technical text-on-surface-muted tracking-widest block mb-2">
            Allowed HTTP Methods
          </label>
          <div className="flex gap-2 flex-wrap">
            {HTTP_METHODS.map(m => (
              <button key={m} type="button" onClick={() => toggleMethod(m)}
                className={`px-3 py-1.5 rounded-lg text-xs font-technical transition-colors ${
                  methods.includes(m)
                    ? 'bg-primary text-black'
                    : 'bg-white/5 text-on-surface-muted hover:bg-white/10'
                }`}
              >{m}</button>
            ))}
          </div>
        </div>

        {error && <p className="text-sm text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg p-3">{error}</p>}

        <button type="submit" disabled={saving || !pattern.trim() || methods.length === 0}
          className="px-5 py-2.5 bg-primary text-black rounded-xl text-sm font-headline font-bold hover:brightness-110 disabled:opacity-50 transition-all"
        >
          {saving ? 'Adding…' : 'Add Policy'}
        </button>
      </form>

      {/* Policy list */}
      {loading ? (
        <div className="flex items-center justify-center py-12">
          <div className="w-6 h-6 border-2 border-primary border-t-transparent rounded-full animate-spin" />
        </div>
      ) : policies.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-12 bg-surface-raised border border-[rgba(255,159,74,0.08)] rounded-2xl">
          <span className="material-symbols-outlined text-on-surface-muted text-4xl mb-2">policy</span>
          <p className="text-on-surface-muted text-sm">No policies yet — agent is governed by scopes only.</p>
        </div>
      ) : (
        <div className="bg-surface-raised border border-[rgba(255,159,74,0.08)] rounded-2xl overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-white/5 text-[10px] font-technical uppercase tracking-widest text-on-surface-muted">
                <th className="text-left px-5 py-3">Pattern</th>
                <th className="text-left px-5 py-3">Methods</th>
                <th className="text-left px-5 py-3">Status</th>
                <th className="px-5 py-3" />
              </tr>
            </thead>
            <tbody>
              {policies.map((p: any) => {
                const methodList: string[] = typeof p.allowed_methods === 'string'
                  ? JSON.parse(p.allowed_methods)
                  : p.allowed_methods ?? [];
                return (
                  <tr key={p.id} className="border-b border-white/[0.04] hover:bg-white/[0.02]">
                    <td className="px-5 py-3 font-technical text-xs text-primary truncate max-w-[280px]">{p.resource_pattern}</td>
                    <td className="px-5 py-3">
                      <div className="flex gap-1 flex-wrap">
                        {methodList.map((m: string) => (
                          <span key={m} className="text-[10px] font-technical px-1.5 py-0.5 rounded bg-white/5 text-on-surface-muted">{m}</span>
                        ))}
                      </div>
                    </td>
                    <td className="px-5 py-3">
                      <button onClick={() => togglePolicy(p.id, !p.active)}
                        className={`relative w-10 h-5 rounded-full transition-colors ${p.active ? 'bg-primary' : 'bg-white/20'}`}
                      >
                        <div className={`absolute top-0.5 w-4 h-4 rounded-full bg-white transition-transform ${p.active ? 'translate-x-5' : 'translate-x-0.5'}`} />
                      </button>
                    </td>
                    <td className="px-5 py-3 text-right">
                      <button onClick={() => deletePolicy(p.id)}
                        className="text-red-400/60 hover:text-red-400 transition-colors"
                      >
                        <span className="material-symbols-outlined text-[18px]">delete</span>
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
