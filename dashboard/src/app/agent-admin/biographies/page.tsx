// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

'use client';
import { operatorFetch } from '@/lib/operatorFetch';

import { useState, useEffect, useCallback } from 'react';
import { TopAppBar } from '../../../components/TopAppBar';
import { Sidebar } from '../../../components/Sidebar';
import Link from 'next/link';

const CORE_API = process.env.NEXT_PUBLIC_CORE_API_URL || 'http://localhost:8000';

const TRUST_COLOUR: Record<string, string> = {
  unverified: 'text-gray-400  bg-gray-400/10  border-gray-400/20',
  nominal:    'text-sky-400   bg-sky-400/10   border-sky-400/20',
  elevated:   'text-yellow-400 bg-yellow-400/10 border-yellow-400/20',
  critical:   'text-red-400   bg-red-400/10   border-red-400/20',
};

const LIFECYCLE_LABEL: Record<string, { label: string; color: string }> = {
  active:       { label: 'Active',      color: 'text-emerald-400' },
  quarantined:  { label: 'Quarantined', color: 'text-red-400 animate-pulse' },
  revoked:      { label: 'Revoked',     color: 'text-red-500' },
  unverified:   { label: 'Unverified',  color: 'text-gray-400' },
  nominal:      { label: 'Active',      color: 'text-emerald-400' },
  elevated:     { label: 'Elevated',    color: 'text-yellow-400' },
  critical:     { label: 'Critical',    color: 'text-red-400' },
};

interface AgentCard {
  id: string;
  name: string | null;
  agent_type: string | null;
  role: string | null;
  version: string | null;
  trust_tier: string;
  scope_entitlements: string | null;
  hitl_enabled: boolean;
  revoked_at: string | null;
  created_at: string;
  tenant_name: string | null;
  tenant_id: string;
  last_active: string | null;
  total_calls: number | null;
  owner_name: string | null;
  business_unit: string | null;
  criticality_level: string | null;
  data_classification: string | null;
}

function fmt(ts: string | null | undefined) {
  if (!ts) return 'Never';
  const d = new Date(ts);
  const now = Date.now();
  const diff = Math.floor((now - d.getTime()) / 1000);
  if (diff < 60)  return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff/60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff/3600)}h ago`;
  return d.toLocaleDateString('en-GB', { day: 'numeric', month: 'short' });
}

export default function AgentBiographies() {
  const [agents, setAgents] = useState<AgentCard[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [trustFilter, setTrustFilter] = useState('');
  const [page, setPage] = useState(1);
  const [lastPage, setLastPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [debouncedSearch, setDebouncedSearch] = useState('');

  useEffect(() => {
    const t = setTimeout(() => setDebouncedSearch(search), 300);
    return () => clearTimeout(t);
  }, [search]);

  const fetch_ = useCallback(async () => {
    setLoading(true);
    const params = new URLSearchParams({ per_page: '24', page: String(page) });
    if (debouncedSearch) params.set('search', debouncedSearch);
    if (trustFilter) params.set('trust_tier', trustFilter);

    const json = await operatorFetch(`${CORE_API}/api/v1/agents/biographies?${params}`, {
      headers: { Accept: 'application/json' },
    }).then(r => r.json()).catch(() => null);

    if (json?.status === 'success') {
      setAgents(json.data.data ?? []);
      setLastPage(json.data.last_page ?? 1);
      setTotal(json.data.total ?? 0);
    }
    setLoading(false);
  }, [page, debouncedSearch, trustFilter]);

  useEffect(() => { fetch_(); }, [fetch_]);

  const lifecycleState = (agent: AgentCard) => {
    if (agent.revoked_at) return { label: 'Revoked', color: 'text-red-500' };
    const lc = LIFECYCLE_LABEL[agent.trust_tier];
    return lc ?? { label: 'Unknown', color: 'text-neutral-500' };
  };

  return (
    <div className="min-h-screen bg-[#070707] text-white flex font-sans">
      <Sidebar />
      <div className="flex-1 flex flex-col h-screen overflow-hidden" style={{ paddingLeft: 'var(--sidebar-width, 18rem)', transition: 'padding-left 300ms' }}>
        <TopAppBar />

        <main className="flex-1 overflow-y-auto p-6 lg:p-10 mt-16">

          {/* Header */}
          <div className="mb-8 mt-4">
            <h1 className="text-3xl font-headline font-black uppercase tracking-tighter text-white mb-2">
              Agent Biographies
            </h1>
            <p className="text-sm font-technical text-neutral-400 max-w-2xl">
              Every agent registered on the platform — name, company, lifecycle state, trust tier, last active. Click any card to open the full biography.
            </p>
          </div>

          {/* Filters */}
          <div className="flex flex-col sm:flex-row gap-3 mb-6">
            <div className="relative flex-1 max-w-sm">
              <span className="material-symbols-outlined absolute left-3 top-1/2 -translate-y-1/2 text-neutral-500 text-[18px]">search</span>
              <input
                type="text"
                value={search}
                onChange={e => { setSearch(e.target.value); setPage(1); }}
                placeholder="Search agents or companies…"
                className="w-full pl-9 pr-4 py-2.5 bg-white/5 border border-white/10 rounded-xl text-sm font-technical text-white placeholder-neutral-600 focus:outline-none focus:border-orange-500/50"
              />
            </div>
            <select
              value={trustFilter}
              onChange={e => { setTrustFilter(e.target.value); setPage(1); }}
              className="px-4 py-2.5 bg-white/5 border border-white/10 rounded-xl text-sm font-technical text-white focus:outline-none focus:border-orange-500/50"
            >
              <option value="">All trust tiers</option>
              <option value="unverified">Unverified</option>
              <option value="nominal">Nominal</option>
              <option value="elevated">Elevated</option>
              <option value="critical">Critical</option>
            </select>
            <div className="text-xs font-technical text-neutral-500 self-center ml-auto">
              {total.toLocaleString()} agents
            </div>
          </div>

          {/* Cards */}
          {loading ? (
            <div className="flex flex-col items-center justify-center py-24 gap-4">
              <div className="w-8 h-8 border-2 border-orange-500/20 border-t-orange-500 rounded-full animate-spin" />
              <p className="text-xs font-technical text-neutral-500 animate-pulse">Loading agent biographies…</p>
            </div>
          ) : agents.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-24 gap-4 text-neutral-600">
              <span className="material-symbols-outlined text-5xl opacity-20">manage_history</span>
              <p className="text-sm font-technical">No agents match your filter.</p>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-4 gap-4">
              {agents.map(agent => {
                const lc = lifecycleState(agent);
                const trustStyle = TRUST_COLOUR[agent.trust_tier] ?? TRUST_COLOUR.unverified;
                const scopes: string[] = (() => { try { return JSON.parse(agent.scope_entitlements || '[]'); } catch { return []; } })();
                return (
                  <Link
                    key={agent.id}
                    href={`/registry/${agent.id}`}
                    className="group block bg-neutral-900/60 border border-white/5 rounded-2xl p-5 hover:border-orange-500/30 hover:bg-white/[0.02] transition-all relative overflow-hidden"
                  >
                    {agent.revoked_at && (
                      <div className="absolute inset-0 bg-red-500/5 pointer-events-none" />
                    )}
                    <div className="absolute right-0 top-0 w-24 h-24 bg-orange-500/5 rounded-full blur-2xl pointer-events-none opacity-0 group-hover:opacity-100 transition-opacity" />

                    <div className="flex items-start justify-between mb-3 relative">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className={`text-[10px] font-bold uppercase tracking-widest px-2 py-0.5 rounded border font-technical ${trustStyle}`}>
                          {agent.trust_tier}
                        </span>
                        {agent.role && agent.role !== 'autonomous' && (
                          <span className="text-[10px] font-bold uppercase tracking-widest px-2 py-0.5 rounded border font-technical text-blue-400 bg-blue-500/10 border-blue-500/20">
                            {agent.role}
                          </span>
                        )}
                      </div>
                      <span className={`text-[10px] font-bold font-technical ${lc.color}`}>{lc.label}</span>
                    </div>

                    <div className="mb-3 relative">
                      <h3 className="text-base font-bold font-headline text-white group-hover:text-orange-400 transition-colors line-clamp-1">
                        {agent.name ?? <span className="text-neutral-500 italic">Unnamed</span>}
                      </h3>
                      <p className="text-xs text-neutral-500 font-technical mt-0.5 line-clamp-1">{agent.tenant_name ?? '—'}</p>
                    </div>

                    <div className="grid grid-cols-2 gap-2 text-xs font-technical mb-4">
                      <div>
                        <p className="text-[10px] uppercase text-neutral-600 mb-0.5">Last Active</p>
                        <p className="text-white">{fmt(agent.last_active)}</p>
                      </div>
                      <div>
                        <p className="text-[10px] uppercase text-neutral-600 mb-0.5">Total Calls</p>
                        <p className="text-white">{(agent.total_calls ?? 0).toLocaleString()}</p>
                      </div>
                    </div>

                    {scopes.length > 0 && (
                      <div className="flex flex-wrap gap-1 mb-3">
                        {scopes.slice(0, 3).map((s: string) => (
                          <span key={s} className="text-[9px] px-1.5 py-0.5 rounded bg-orange-500/10 border border-orange-500/20 text-orange-400 font-technical">
                            {s}
                          </span>
                        ))}
                        {scopes.length > 3 && (
                          <span className="text-[9px] px-1.5 py-0.5 rounded bg-white/5 border border-white/10 text-neutral-500 font-technical">
                            +{scopes.length - 3}
                          </span>
                        )}
                      </div>
                    )}

                    {(agent.business_unit || agent.criticality_level || agent.data_classification) && (
                      <div className="flex flex-wrap gap-1 mb-3">
                        {agent.criticality_level && (
                          <span className="text-[9px] px-1.5 py-0.5 rounded bg-white/5 border border-white/10 text-neutral-400 font-technical uppercase">
                            {agent.criticality_level}
                          </span>
                        )}
                        {agent.data_classification && (
                          <span className="text-[9px] px-1.5 py-0.5 rounded bg-white/5 border border-white/10 text-neutral-400 font-technical uppercase">
                            {agent.data_classification}
                          </span>
                        )}
                        {agent.business_unit && (
                          <span className="text-[9px] px-1.5 py-0.5 rounded bg-blue-500/10 border border-blue-500/20 text-blue-400 font-technical">
                            {agent.business_unit}
                          </span>
                        )}
                      </div>
                    )}

                    <div className="flex items-center justify-between text-[10px] font-technical text-neutral-600">
                      <div className="flex gap-2">
                        {agent.hitl_enabled && (
                          <span className="flex items-center gap-1 text-purple-400">
                            <span className="material-symbols-outlined text-[12px]">person_check</span>HITL
                          </span>
                        )}
                        {agent.agent_type && (
                          <span className="text-neutral-500">{agent.agent_type}</span>
                        )}
                        {agent.version && (
                          <span className="text-neutral-600">v{agent.version}</span>
                        )}
                      </div>
                      <span className="material-symbols-outlined text-[16px] text-neutral-700 group-hover:text-orange-400 transition-colors">arrow_forward</span>
                    </div>
                  </Link>
                );
              })}
            </div>
          )}

          {/* Pagination */}
          {lastPage > 1 && (
            <div className="flex items-center justify-center gap-3 mt-8">
              <button
                onClick={() => setPage(p => Math.max(1, p - 1))}
                disabled={page === 1}
                className="px-4 py-2 text-xs font-technical rounded-xl bg-white/5 border border-white/10 text-neutral-400 hover:text-white disabled:opacity-30 transition-all"
              >
                Previous
              </button>
              <span className="text-xs font-technical text-neutral-500">
                Page {page} of {lastPage}
              </span>
              <button
                onClick={() => setPage(p => Math.min(lastPage, p + 1))}
                disabled={page === lastPage}
                className="px-4 py-2 text-xs font-technical rounded-xl bg-white/5 border border-white/10 text-neutral-400 hover:text-white disabled:opacity-30 transition-all"
              >
                Next
              </button>
            </div>
          )}

        </main>
      </div>
    </div>
  );
}
