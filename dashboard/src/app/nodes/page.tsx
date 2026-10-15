// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

'use client';
import { operatorFetch } from '@/lib/operatorFetch';

import { useState, useEffect, useMemo, Suspense } from 'react';
import Link from 'next/link';
import { useSearchParams } from 'next/navigation';
import { Sidebar } from '../../components/Sidebar';
import { TopAppBar } from '../../components/TopAppBar';
import { useToast } from '../../components/ToastContext';
import { CreatorDetailPanel, CreatorAccount, CreatorAgent } from '../../components/CreatorDetailPanel';

const API = process.env.NEXT_PUBLIC_CORE_API_URL ?? 'http://localhost:8000';
const PAGE_SIZE = 25;

interface ApiAgent {
  id: string;
  name: string | null;
  evar_token: string;
  first_seen: string | null;
  last_seen: string | null;
  status: string;
  revocation_reason: string | null;
  trust_score: number;
  trust_tier: string;
  certification_level: string;
  declared_scopes: string[];
  approved_scopes: string[];
  denied_scopes: string[];
  spend_limits: string;
  rollback: string;
  total_actions: number;
  blocked_actions: number;
  allowed_actions: number;
  anomalies: string[];
  sandbox_status: string;
  false_positive_rate: string;
}

interface ApiTenant {
  id: string;
  name: string;
  email: string;
  owner_name: string;
  global_trust_score: number;
  agents: ApiAgent[];
}

function toScopes(v: unknown): string[] {
  if (Array.isArray(v)) return v;
  if (typeof v === 'string' && v.trim().startsWith('[')) { try { return JSON.parse(v); } catch { /* fall through */ } }
  if (typeof v === 'string' && v.trim()) return v.split(',').map(s => s.trim()).filter(Boolean);
  return [];
}

type FlatAgent = ApiAgent & { tenantId: string; tenantName: string; tenantEmail: string };
type SortKey = 'trustScore' | 'blockedActions' | 'totalActions' | 'lastSeen' | 'tenantName' | 'name';
type TierFilter = 'all' | 'critical' | 'elevated' | 'nominal' | 'unverified';
type StatusFilter = 'all' | 'Active' | 'Revoked';
type ViewMode = 'table' | 'grouped';

function toCreatorAccount(t: ApiTenant): CreatorAccount {
  return {
    id: t.id, name: t.name, email: t.email ?? '', ownerName: t.owner_name ?? 'N/A',
    globalTrustScore: t.global_trust_score,
    agents: t.agents.map((a): CreatorAgent => ({
      id: a.id, name: a.name ?? `Agent-${a.id.substring(0, 8).toUpperCase()}`,
      evarToken: a.evar_token, firstSeen: a.first_seen ?? '', lastSeen: a.last_seen ?? '',
      status: (a.status as CreatorAgent['status']) ?? 'Active',
      revocationReason: a.revocation_reason ?? undefined,
      trustScore: a.trust_score, certificationLevel: a.certification_level,
      declaredScopes: toScopes(a.declared_scopes), approvedScopes: toScopes(a.approved_scopes),
      deniedScopes: toScopes(a.denied_scopes), spendLimits: a.spend_limits, rollback: a.rollback,
      totalActions: a.total_actions, allowedActions: a.allowed_actions,
      blockedActions: a.blocked_actions, anomalies: a.anomalies,
      sandboxStatus: a.sandbox_status, falsePositiveRate: a.false_positive_rate,
    })),
  };
}

const TIER_BADGE: Record<string, string> = {
  critical:   'bg-red-500/10 border-red-500/20 text-red-400',
  elevated:   'bg-orange-500/10 border-orange-500/20 text-orange-400',
  nominal:    'bg-emerald-500/10 border-emerald-500/20 text-emerald-400',
  unverified: 'bg-neutral-800 border-neutral-700 text-neutral-500',
};

const TIER_DOT: Record<string, string> = {
  critical: 'bg-red-500', elevated: 'bg-orange-500', nominal: 'bg-emerald-500', unverified: 'bg-neutral-600',
};

function agentDisplayName(a: ApiAgent) {
  return a.name ?? `Agent-${a.id.substring(0, 8).toUpperCase()}`;
}

function AgentRegistryContent() {
  const searchParams = useSearchParams();
  const { showToast } = useToast();

  const [tenants, setTenants]   = useState<ApiTenant[]>([]);
  const [creators, setCreators] = useState<CreatorAccount[]>([]);
  const [loading, setLoading]   = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  const [search, setSearch]         = useState('');
  const [tierFilter, setTierFilter] = useState<TierFilter>('all');
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all');
  const [viewMode, setViewMode]     = useState<ViewMode>('table');
  const [sortKey, setSortKey]       = useState<SortKey>('tenantName');
  const [sortAsc, setSortAsc]       = useState(true);
  const [page, setPage]             = useState(1);

  const [selectedCreatorId, setSelectedCreatorId] = useState<string | null>(null);
  const [initialAgentId, setInitialAgentId]       = useState<string | null>(null);
  const [quarantining, setQuarantining]           = useState<string | null>(null);

  // ── Deep-linking: auto-open agent detail panel from query params ──────────
  // Supports /nodes?agent=<agentId> (e.g. from ZTNA Posture page "View" link)
  const deepLinkAgentId = searchParams.get('agent');

  // After initial data load, check if there's a deep-link agent ID in the URL.
  // If so, find the tenant that owns the agent and open the detail panel.
  useEffect(() => {
    if (!deepLinkAgentId || tenants.length === 0 || selectedCreatorId) return;
    for (const tenant of tenants) {
      const matchedAgent = tenant.agents.find(a => a.id === deepLinkAgentId);
      if (matchedAgent) {
        setSelectedCreatorId(tenant.id);
        setInitialAgentId(matchedAgent.id);
        break;
      }
    }
  }, [deepLinkAgentId, tenants, selectedCreatorId]);

  // ── Quarantine: hard-stop an agent with proper feedback ───────────────────
  const quarantine = async (agentId: string) => {
    if (!confirm('Hard-stop this agent? This sets revoked_at immediately and cannot be undone from this view.')) return;
    setQuarantining(agentId);
    try {
      const res = await operatorFetch(`${API}/api/v1/agents/${agentId}/quarantine`, {
        method: 'POST',
        headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        },
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        console.error('Quarantine failed:', res.status, body);
        showToast(`Quarantine failed: ${body.error ?? res.statusText}`);
      } else {
        showToast('Agent quarantined successfully. Gossip mesh propagation in progress.');
      }
    } catch (err) {
      console.error('Quarantine network error:', err);
      showToast('Quarantine request failed — network error. Check API connectivity.');
    }
    await loadData();
    setQuarantining(null);
  };

  const loadData = () =>
    operatorFetch(`${API}/api/v1/nodes`)
      .then(r => r.json())
      .then(body => {
        if (body.status === 'success') {
          const data = body.data as ApiTenant[];
          setTenants(data);
          setCreators(data.map(toCreatorAccount));
        }
      })
      .catch(() => {});

  useEffect(() => { loadData().finally(() => setLoading(false)); }, []);

  const refresh = () => {
    setRefreshing(true);
    loadData().finally(() => setRefreshing(false));
  };

  const flatAgents: FlatAgent[] = useMemo(
    () => tenants.flatMap(t => t.agents.map(a => ({ ...a, tenantId: t.id, tenantName: t.name, tenantEmail: t.email }))),
    [tenants],
  );

  const filtered = useMemo(() => {
    const q = search.toLowerCase().trim();
    return flatAgents.filter(a => {
      if (tierFilter !== 'all' && a.trust_tier !== tierFilter) return false;
      if (statusFilter !== 'all' && a.status !== statusFilter) return false;
      if (q && !agentDisplayName(a).toLowerCase().includes(q) && !a.id.toLowerCase().includes(q) && !a.tenantName.toLowerCase().includes(q)) return false;
      return true;
    });
  }, [flatAgents, search, tierFilter, statusFilter]);

  const sorted = useMemo(() => {
    return [...filtered].sort((a, b) => {
      let cmp = 0;
      switch (sortKey) {
        case 'name':          cmp = agentDisplayName(a).localeCompare(agentDisplayName(b)); break;
        case 'tenantName':    cmp = a.tenantName.localeCompare(b.tenantName); break;
        case 'trustScore':    cmp = b.trust_score - a.trust_score; break;
        case 'totalActions':  cmp = b.total_actions - a.total_actions; break;
        case 'blockedActions':cmp = b.blocked_actions - a.blocked_actions; break;
        case 'lastSeen':      cmp = (b.last_seen ?? '').localeCompare(a.last_seen ?? ''); break;
      }
      return sortAsc ? cmp : -cmp;
    });
  }, [filtered, sortKey, sortAsc]);

  const totalPages = Math.max(1, Math.ceil(sorted.length / PAGE_SIZE));
  const pageAgents = sorted.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  const setSort = (key: SortKey) => {
    if (sortKey === key) setSortAsc(v => !v);
    else { setSortKey(key); setSortAsc(true); }
    setPage(1);
  };

  const resetFilters = () => { setSearch(''); setTierFilter('all'); setStatusFilter('all'); setPage(1); };

  const totalAgents   = flatAgents.length;
  const activeAgents  = flatAgents.filter(a => a.status === 'Active').length;
  const revokedAgents = flatAgents.filter(a => a.status === 'Revoked').length;
  const criticalCount = flatAgents.filter(a => a.trust_tier === 'critical').length;

  const activeCreator = creators.find(c => c.id === selectedCreatorId) ?? null;

  const SortHeader = ({ label, col }: { label: string; col: SortKey }) => (
    <th
      className="px-4 py-3 text-left text-[10px] font-technical uppercase tracking-wider text-neutral-500 cursor-pointer hover:text-neutral-300 select-none whitespace-nowrap"
      onClick={() => setSort(col)}
    >
      <span className="flex items-center gap-1">
        {label}
        {sortKey === col
          ? <span className="material-symbols-outlined text-[12px] text-orange-400">{sortAsc ? 'arrow_upward' : 'arrow_downward'}</span>
          : <span className="material-symbols-outlined text-[12px] opacity-20">unfold_more</span>}
      </span>
    </th>
  );

  return (
    <>
      <Sidebar />
      <TopAppBar />
      <CreatorDetailPanel
        isOpen={selectedCreatorId !== null}
        onClose={() => { setSelectedCreatorId(null); setInitialAgentId(null); }}
        creator={activeCreator}
        initialAgentId={initialAgentId}
      />

      <main className="pt-24 pb-16 px-10 min-h-screen transition-all duration-300" style={{ marginLeft: 'var(--sidebar-width, 18rem)' }}>

        {/* Page header */}
        <div className="flex flex-col md:flex-row justify-between items-start md:items-end gap-4 mb-8">
          <div>
            <h1 className="text-4xl font-black font-headline tracking-tighter text-on-surface mb-1">Agent Registry</h1>
            <p className="text-neutral-500 font-technical text-sm">All registered agents across every company on the platform.</p>
          </div>
          <div className="flex items-center gap-3 flex-shrink-0">
            {/* Live KPIs */}
            <div className="flex gap-5 px-5 py-3 bg-[#131313] border border-white/5 rounded-xl">
              <div className="text-center">
                <p className="font-technical text-lg font-bold text-on-surface leading-none">{totalAgents}</p>
                <p className="font-technical text-[10px] text-neutral-500 uppercase tracking-wider mt-1">Total</p>
              </div>
              <div className="w-px bg-white/5"></div>
              <div className="text-center">
                <p className="font-technical text-lg font-bold text-emerald-400 leading-none">{activeAgents}</p>
                <p className="font-technical text-[10px] text-neutral-500 uppercase tracking-wider mt-1">Active</p>
              </div>
              <div className="w-px bg-white/5"></div>
              <div className="text-center">
                <p className={`font-technical text-lg font-bold leading-none ${revokedAgents > 0 ? 'text-red-400' : 'text-neutral-500'}`}>{revokedAgents}</p>
                <p className="font-technical text-[10px] text-neutral-500 uppercase tracking-wider mt-1">Revoked</p>
              </div>
              {criticalCount > 0 && <>
                <div className="w-px bg-white/5"></div>
                <div className="text-center">
                  <p className="font-technical text-lg font-bold text-red-400 leading-none animate-pulse">{criticalCount}</p>
                  <p className="font-technical text-[10px] text-neutral-500 uppercase tracking-wider mt-1">Critical</p>
                </div>
              </>}
            </div>
            <button onClick={refresh} disabled={refreshing}
              className="p-3 bg-white/5 hover:bg-white/10 border border-white/10 rounded-xl text-neutral-400 transition-colors disabled:opacity-50">
              <span className={`material-symbols-outlined text-[18px] ${refreshing ? 'animate-spin' : ''}`}>sync</span>
            </button>
          </div>
        </div>

        {/* Search + filters toolbar */}
        <div className="flex flex-wrap gap-3 mb-6">
          {/* Search */}
          <div className="relative flex-1 min-w-[220px]">
            <span className="material-symbols-outlined absolute left-3 top-1/2 -translate-y-1/2 text-neutral-500 text-[18px] pointer-events-none">search</span>
            <input
              type="text"
              value={search}
              onChange={e => { setSearch(e.target.value); setPage(1); }}
              placeholder="Search agent name, ID, or company…"
              className="w-full bg-[#131313] border border-white/10 rounded-xl pl-9 pr-4 py-2.5 font-technical text-sm text-on-surface placeholder:text-neutral-600 focus:outline-none focus:border-orange-500/50"
            />
            {search && (
              <button onClick={() => { setSearch(''); setPage(1); }} className="absolute right-3 top-1/2 -translate-y-1/2 text-neutral-500 hover:text-neutral-300">
                <span className="material-symbols-outlined text-[16px]">close</span>
              </button>
            )}
          </div>

          {/* Trust tier filter */}
          <div className="flex p-1 bg-[#131313] border border-white/5 rounded-xl gap-0.5">
            {(['all', 'critical', 'elevated', 'nominal', 'unverified'] as TierFilter[]).map(t => (
              <button key={t} onClick={() => { setTierFilter(t); setPage(1); }}
                className={`px-3 py-1.5 rounded-lg font-technical text-[11px] font-bold uppercase tracking-wide transition-colors ${tierFilter === t ? 'bg-orange-500/20 text-orange-400' : 'text-neutral-500 hover:text-neutral-300'}`}>
                {t === 'all' ? 'All Tiers' : t}
              </button>
            ))}
          </div>

          {/* Status filter */}
          <div className="flex p-1 bg-[#131313] border border-white/5 rounded-xl gap-0.5">
            {(['all', 'Active', 'Revoked'] as StatusFilter[]).map(s => (
              <button key={s} onClick={() => { setStatusFilter(s); setPage(1); }}
                className={`px-3 py-1.5 rounded-lg font-technical text-[11px] font-bold uppercase tracking-wide transition-colors ${statusFilter === s ? 'bg-orange-500/20 text-orange-400' : 'text-neutral-500 hover:text-neutral-300'}`}>
                {s === 'all' ? 'All Status' : s}
              </button>
            ))}
          </div>

          {/* View toggle */}
          <div className="flex p-1 bg-[#131313] border border-white/5 rounded-xl gap-0.5">
            <button onClick={() => setViewMode('table')}
              className={`px-3 py-1.5 rounded-lg transition-colors ${viewMode === 'table' ? 'bg-orange-500/20 text-orange-400' : 'text-neutral-500 hover:text-neutral-300'}`}>
              <span className="material-symbols-outlined text-[16px]">table_rows</span>
            </button>
            <button onClick={() => setViewMode('grouped')}
              className={`px-3 py-1.5 rounded-lg transition-colors ${viewMode === 'grouped' ? 'bg-orange-500/20 text-orange-400' : 'text-neutral-500 hover:text-neutral-300'}`}>
              <span className="material-symbols-outlined text-[16px]">grid_view</span>
            </button>
          </div>
        </div>

        {/* Results count */}
        <div className="flex items-center justify-between mb-4">
          <p className="font-technical text-xs text-neutral-500">
            {loading ? 'Loading…' : `${filtered.length} agent${filtered.length !== 1 ? 's' : ''} ${filtered.length !== totalAgents ? `(filtered from ${totalAgents})` : ''}`}
          </p>
          {(search || tierFilter !== 'all' || statusFilter !== 'all') && (
            <button onClick={resetFilters} className="font-technical text-xs text-orange-400 hover:text-orange-300 transition-colors">
              Clear filters
            </button>
          )}
        </div>

        {loading && <div className="py-20 text-center text-neutral-500 font-technical text-xs animate-pulse">Loading registry…</div>}

        {!loading && filtered.length === 0 && (
          <div className="py-20 flex flex-col items-center text-neutral-600 gap-3">
            <span className="material-symbols-outlined text-5xl opacity-20">search_off</span>
            <p className="font-technical text-xs">No agents match your search.</p>
            <button onClick={resetFilters} className="text-orange-400 text-xs font-technical hover:text-orange-300">Clear filters</button>
          </div>
        )}

        {/* ── TABLE VIEW ── */}
        {!loading && filtered.length > 0 && viewMode === 'table' && (
          <div className="bg-[#131313] border border-white/5 rounded-2xl overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-white/5">
                    <SortHeader label="Company"      col="tenantName"     />
                    <SortHeader label="Agent"        col="name"           />
                    <th className="px-4 py-3 text-left text-[10px] font-technical uppercase tracking-wider text-neutral-500 whitespace-nowrap">Trust Tier</th>
                    <SortHeader label="Trust Score"  col="trustScore"     />
                    <SortHeader label="Total Calls"  col="totalActions"   />
                    <SortHeader label="Blocked"      col="blockedActions" />
                    <th className="px-4 py-3 text-left text-[10px] font-technical uppercase tracking-wider text-neutral-500 whitespace-nowrap">Scopes</th>
                    <SortHeader label="Last Seen"    col="lastSeen"       />
                    <th className="px-4 py-3 text-left text-[10px] font-technical uppercase tracking-wider text-neutral-500">Status</th>
                    <th className="px-4 py-3"></th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5">
                  {pageAgents.map(a => {
                    const blockRate = a.total_actions > 0
                      ? ((a.blocked_actions / a.total_actions) * 100).toFixed(1)
                      : '0.0';
                    return (
                      <tr key={a.id} className="hover:bg-white/[0.03] transition-colors">
                        <td className="px-4 py-3">
                          <p className="font-headline font-bold text-xs text-on-surface">{a.tenantName}</p>
                          <p className="font-technical text-[10px] text-neutral-600">{a.tenantEmail}</p>
                        </td>
                        <td className="px-4 py-3">
                          <p className="font-bold text-xs text-on-surface">{agentDisplayName(a)}</p>
                          <p className="font-technical text-[10px] text-neutral-600 mt-0.5">{a.id.substring(0, 18)}…</p>
                        </td>
                        <td className="px-4 py-3">
                          <span className={`flex items-center gap-1.5 w-fit px-2 py-0.5 rounded border font-technical text-[10px] font-bold uppercase ${TIER_BADGE[a.trust_tier] ?? TIER_BADGE.unverified}`}>
                            <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${TIER_DOT[a.trust_tier] ?? TIER_DOT.unverified}`}></span>
                            {a.trust_tier}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            <div className="w-14 h-1.5 bg-white/5 rounded-full overflow-hidden">
                              <div className={`h-full rounded-full ${a.trust_tier === 'nominal' ? 'bg-emerald-500' : a.trust_tier === 'critical' ? 'bg-red-500' : 'bg-orange-500'}`}
                                style={{ width: `${a.trust_score}%` }}></div>
                            </div>
                            <span className="font-technical text-xs text-neutral-300">{a.trust_score}%</span>
                          </div>
                        </td>
                        <td className="px-4 py-3 font-technical text-xs text-neutral-300">{a.total_actions.toLocaleString()}</td>
                        <td className="px-4 py-3">
                          <span className={`font-technical text-xs font-bold ${a.blocked_actions > 0 ? 'text-red-400' : 'text-neutral-500'}`}>
                            {a.blocked_actions.toLocaleString()}
                            {a.total_actions > 0 && <span className="text-neutral-600 font-normal ml-1">({blockRate}%)</span>}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex flex-wrap gap-1">
                            {toScopes(a.declared_scopes).slice(0, 2).map(s => (
                              <span key={s} className="px-1.5 py-0.5 bg-white/5 border border-white/10 rounded font-technical text-[9px] text-neutral-400">{s}</span>
                            ))}
                            {toScopes(a.declared_scopes).length > 2 && (
                              <span className="px-1.5 py-0.5 bg-white/5 border border-white/10 rounded font-technical text-[9px] text-neutral-500">+{toScopes(a.declared_scopes).length - 2}</span>
                            )}
                          </div>
                        </td>
                        <td className="px-4 py-3 font-technical text-xs text-neutral-500 whitespace-nowrap">
                          {a.last_seen ? new Date(a.last_seen).toLocaleDateString() : '—'}
                        </td>
                        <td className="px-4 py-3">
                          <span className={`flex items-center gap-1 font-technical text-[10px] font-bold uppercase ${a.status === 'Active' ? 'text-emerald-400' : 'text-red-400'}`}>
                            <span className={`w-1.5 h-1.5 rounded-full ${a.status === 'Active' ? 'bg-emerald-500' : 'bg-red-500'}`}></span>
                            {a.status}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            <button
                              onClick={() => { setSelectedCreatorId(a.tenantId); setInitialAgentId(a.id); }}
                              className="px-3 py-1 bg-white/5 hover:bg-white/10 border border-white/10 rounded-lg font-technical text-[10px] text-neutral-400 hover:text-on-surface transition-colors whitespace-nowrap"
                            >
                              View
                            </button>
                            {a.status !== 'Revoked' && (
                              <button
                                onClick={() => quarantine(a.id)}
                                disabled={quarantining === a.id}
                                title="Hard-stop agent"
                                className="px-2 py-1 bg-red-500/10 hover:bg-red-500/20 border border-red-500/20 rounded-lg font-technical text-[10px] text-red-400 transition-colors disabled:opacity-50 whitespace-nowrap flex items-center gap-1"
                              >
                                <span className="material-symbols-outlined text-[12px]">{quarantining === a.id ? 'sync' : 'block'}</span>
                                {quarantining === a.id ? '…' : 'Stop'}
                              </button>
                            )}
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            {/* Pagination */}
            {totalPages > 1 && (
              <div className="px-4 py-3 border-t border-white/5 flex items-center justify-between">
                <p className="font-technical text-xs text-neutral-500">
                  Page {page} of {totalPages} · {filtered.length} agents
                </p>
                <div className="flex gap-2">
                  <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1}
                    className="px-3 py-1.5 bg-white/5 border border-white/10 rounded-lg font-technical text-xs text-neutral-400 disabled:opacity-30 hover:bg-white/10 transition-colors">
                    Previous
                  </button>
                  {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
                    const p = totalPages <= 5 ? i + 1 : page <= 3 ? i + 1 : page >= totalPages - 2 ? totalPages - 4 + i : page - 2 + i;
                    return (
                      <button key={p} onClick={() => setPage(p)}
                        className={`w-8 h-8 rounded-lg font-technical text-xs transition-colors ${p === page ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30' : 'bg-white/5 border border-white/10 text-neutral-400 hover:bg-white/10'}`}>
                        {p}
                      </button>
                    );
                  })}
                  <button onClick={() => setPage(p => Math.min(totalPages, p + 1))} disabled={page === totalPages}
                    className="px-3 py-1.5 bg-white/5 border border-white/10 rounded-lg font-technical text-xs text-neutral-400 disabled:opacity-30 hover:bg-white/10 transition-colors">
                    Next
                  </button>
                </div>
              </div>
            )}
          </div>
        )}

        {/* ── GROUPED VIEW ── */}
        {!loading && filtered.length > 0 && viewMode === 'grouped' && (
          <div className="space-y-8">
            {tenants
              .filter(t => t.agents.some(a => filtered.find(f => f.id === a.id)))
              .map(tenant => {
                const visibleAgents = tenant.agents.filter(a => filtered.find(f => f.id === a.id));
                return (
                  <section key={tenant.id}>
                    <div className="flex items-center justify-between mb-3 pb-3 border-b border-white/5">
                      <div className="flex items-center gap-3">
                        <span className="material-symbols-outlined text-[18px] text-orange-500">domain</span>
                        <div>
                          <h2 className="font-headline font-bold text-on-surface">{tenant.name}</h2>
                          <p className="font-technical text-[11px] text-neutral-500">{tenant.email} · {visibleAgents.length} agent{visibleAgents.length !== 1 ? 's' : ''} · Trust {tenant.global_trust_score}%</p>
                        </div>
                      </div>
                      <button onClick={() => { setSelectedCreatorId(tenant.id); setInitialAgentId(null); }}
                        className="px-3 py-1.5 bg-white/5 hover:bg-white/10 border border-white/10 rounded-lg font-technical text-[11px] text-neutral-400 hover:text-on-surface transition-colors">
                        Company Detail
                      </button>
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
                      {visibleAgents.map(a => {
                        const blockRate = a.total_actions > 0 ? ((a.blocked_actions / a.total_actions) * 100).toFixed(1) : '0.0';
                        const theme = TIER_BADGE[a.trust_tier] ?? TIER_BADGE.unverified;
                        return (
                          <div key={a.id} className="bg-[#131313] border border-white/5 hover:border-white/10 rounded-2xl p-5 flex flex-col gap-4 transition-colors">
                            <div className="flex items-start justify-between gap-2">
                              <div className="min-w-0">
                                <p className="font-headline font-bold text-on-surface truncate">{agentDisplayName(a)}</p>
                                <p className="font-technical text-[10px] text-neutral-600 mt-0.5">{a.id.substring(0, 16)}…</p>
                              </div>
                              <span className={`px-2 py-0.5 rounded border font-technical text-[10px] font-bold uppercase flex-shrink-0 ${theme}`}>{a.trust_tier}</span>
                            </div>
                            <div>
                              <div className="flex justify-between mb-1">
                                <span className="font-technical text-[10px] text-neutral-500">Trust</span>
                                <span className="font-technical text-[10px] font-bold text-neutral-300">{a.trust_score}%</span>
                              </div>
                              <div className="h-1 w-full bg-white/5 rounded-full overflow-hidden">
                                <div className={`h-full rounded-full ${a.trust_tier === 'nominal' ? 'bg-emerald-500' : a.trust_tier === 'critical' ? 'bg-red-500' : 'bg-orange-500'}`}
                                  style={{ width: `${a.trust_score}%` }}></div>
                              </div>
                            </div>
                            <div className="grid grid-cols-3 gap-1 text-center py-2 border-y border-white/5">
                              <div><p className="font-technical text-sm font-bold text-on-surface">{a.total_actions}</p><p className="font-technical text-[9px] text-neutral-600 uppercase">Total</p></div>
                              <div><p className="font-technical text-sm font-bold text-emerald-400">{a.allowed_actions}</p><p className="font-technical text-[9px] text-neutral-600 uppercase">Allowed</p></div>
                              <div><p className={`font-technical text-sm font-bold ${a.blocked_actions > 0 ? 'text-red-400' : 'text-neutral-500'}`}>{a.blocked_actions}</p><p className="font-technical text-[9px] text-neutral-600 uppercase">{blockRate}% blk</p></div>
                            </div>
                            <div className="flex items-center justify-between">
                              <p className="font-technical text-[10px] text-neutral-600">
                                {a.last_seen ? new Date(a.last_seen).toLocaleDateString() : 'Never seen'}
                              </p>
                              <div className="flex items-center gap-2">
                                <button onClick={() => { setSelectedCreatorId(tenant.id); setInitialAgentId(a.id); }}
                                  className="px-3 py-1 bg-white/5 hover:bg-white/10 border border-white/10 rounded-lg font-technical text-[10px] text-neutral-400 hover:text-on-surface transition-colors">
                                  View
                                </button>
                                {a.status !== 'Revoked' && (
                                  <button
                                    onClick={() => quarantine(a.id)}
                                    disabled={quarantining === a.id}
                                    title="Hard-stop agent"
                                    className="px-2 py-1 bg-red-500/10 hover:bg-red-500/20 border border-red-500/20 rounded-lg font-technical text-[10px] text-red-400 transition-colors disabled:opacity-50 flex items-center gap-1"
                                  >
                                    <span className="material-symbols-outlined text-[12px]">{quarantining === a.id ? 'sync' : 'block'}</span>
                                    {quarantining === a.id ? '…' : 'Stop'}
                                  </button>
                                )}
                              </div>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </section>
                );
              })}
          </div>
        )}

        {/* Register Agent FAB */}
        <div className="fixed bottom-8 right-8 z-50">
          <a href={`${process.env.NEXT_PUBLIC_DEV_PORTAL_URL ?? 'http://localhost:3001'}/agents/register`} target="_blank" rel="noopener noreferrer"
            className="flex items-center gap-3 px-6 py-4 bg-[#1a1a1a] border border-orange-500/30 hover:border-orange-500/60 rounded-2xl shadow-2xl transition-all hover:scale-105 active:scale-95 group">
            <span className="material-symbols-outlined text-orange-500 group-hover:rotate-90 transition-transform duration-300">add</span>
            <span className="font-headline font-bold text-sm uppercase tracking-widest text-on-surface">Register Agent</span>
          </a>
        </div>
      </main>
    </>
  );
}

/**
 * Default export wraps the component in Suspense because useSearchParams()
 * requires it for Next.js static pre-rendering.
 */
export default function AgentRegistry() {
  return (
    <Suspense>
      <AgentRegistryContent />
    </Suspense>
  );
}
