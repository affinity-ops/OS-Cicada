// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

'use client';
import { operatorFetch } from '@/lib/operatorFetch';
import { useState, useEffect } from 'react';
import Link from 'next/link';
import { useToast } from '../../components/ToastContext';
import { Sidebar } from '../../components/Sidebar';
import { TopAppBar } from '../../components/TopAppBar';

interface RegistryAgent {
  id: string;
  name: string | null;
  owner_name: string | null;
  owner_email: string | null;
  business_unit: string | null;
  criticality_level: string | null;
  data_classification: string | null;
  declared_purpose: string | null;
  regulatory_frameworks: string | null;
  registration_purpose_statement: string | null;
  potential_impact: string | null;
  expected_velocity: number | null;
  monthly_budget_usd: string | null;
  cost_center: string | null;
  scope_entitlements: string | null;
  tenant_name: string;
  tenant_id: string;
  trust_tier: string;
  agent_type: string | null;
  role: string | null;
  version: string | null;
  hitl_enabled: boolean;
  hitl_webhook_url: string | null;
  certified_at: string | null;
  recertification_due_at: string | null;
  revoked_at: string | null;
  governance_score?: number;
}

const API = process.env.NEXT_PUBLIC_CORE_API_URL ?? 'http://localhost:8000';

const tierBadge: Record<string, { label: string; cls: string; }> = {
  critical:   { label: 'CRITICAL',   cls: 'bg-emerald-500/10 text-emerald-500 border-emerald-500/20' },
  elevated:   { label: 'ELEVATED',   cls: 'bg-orange-500/10 text-orange-400 border-orange-500/20' },
  nominal:    { label: 'NOMINAL',    cls: 'bg-blue-500/10 text-blue-400 border-blue-500/20' },
  unverified: { label: 'UNVERIFIED', cls: 'bg-neutral-500/10 text-neutral-400 border-neutral-500/20' },
};

export default function VerifiedAgentRegistry() {
  const { showToast } = useToast();
  const [agents, setAgents] = useState<RegistryAgent[]>([]);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<Set<string>>(new Set());

  const toggleSelect = (id: string) => {
    setSelected(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  };

  const toggleAll = () => {
    if (selected.size === agents.length) setSelected(new Set());
    else setSelected(new Set(agents.map(a => a.id)));
  };

  const bulkShadowMode = async () => {
    if (selected.size === 0) { showToast('No agents selected.'); return; }
    
    setLoading(true);
    try {
      const resp = await operatorFetch(`${API}/api/v1/agents/shadow-mode`, {
        method: 'POST',
        body: JSON.stringify({
          agent_ids: Array.from(selected),
          action: 'activate'
        })
      });
      const data = await resp.json();
      if (data.status === 'success') {
        showToast(data.message);
        setSelected(new Set());
        load();
      } else {
        showToast('Failed to toggle shadow mode.');
      }
    } catch (err) {
      showToast('Error communicating with core api');
    }
  };

  const load = () => {
    setLoading(true);
    operatorFetch(`${API}/api/v1/registry?per_page=100`)
      .then(r => r.json())
      .then(body => { if (body.status === 'success') setAgents(body.data.data ?? []); })
      .catch(() => showToast('Failed to load agent registry.'))
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, []);

  return (
    <>
      <Sidebar />
      <TopAppBar />
      <main className="pt-24 pb-12 px-8 min-h-screen transition-all duration-300" style={{ marginLeft: 'var(--sidebar-width, 18rem)' }}>
        <section className="mb-10 w-full mx-auto">
          <div className="flex justify-between items-end mb-8">
            <div>
              <h1 className="text-4xl font-black font-headline tracking-tighter text-white mb-2">Governance Registry</h1>
              <p className="text-neutral-400 font-technical text-sm pb-4">
                Global index mapping all core identity, role, and compliance schemas directly from PostgreSQL.
              </p>
            </div>
            <div className="flex gap-3 items-center">
              {selected.size > 0 && (
                <button onClick={bulkShadowMode}
                  className="bg-amber-500/10 border border-amber-500/30 text-amber-400 uppercase tracking-widest font-bold text-xs py-2 px-6 rounded-md hover:bg-amber-500/20 transition-all shadow-[0_0_15px_rgba(245,158,11,0.15)] flex items-center gap-2">
                  <span className="material-symbols-outlined text-[14px]">visibility</span>
                  Toggle Shadow Mode ({selected.size})
                </button>
              )}
              <button onClick={load}
                className="bg-[#fd8b00]/10 border border-[#fd8b00]/30 text-[#fd8b00] uppercase tracking-widest font-bold text-xs py-2 px-6 rounded-md hover:bg-[#fd8b00]/20 transition-all shadow-[0_0_15px_rgba(253,139,0,0.15)]">
                Refresh Telemetry
              </button>
            </div>
          </div>

          <div className="bg-[#121212] border border-white/10 rounded-2xl overflow-hidden shadow-2xl">
            {loading ? (
               <div className="py-20 flex justify-center items-center text-neutral-500 font-technical text-sm uppercase tracking-widest">
                 Connecting to Postgres Ledger...
               </div>
            ) : agents.length === 0 ? (
               <div className="py-20 flex justify-center items-center text-neutral-500 font-technical text-sm uppercase tracking-widest">
                 No provisioned agents in database.
               </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="bg-[#1a1a1a] border-b border-white/5 text-[10px] uppercase tracking-widest font-bold text-neutral-500 font-technical">
                      <th className="px-4 py-4 w-10">
                        <input type="checkbox" checked={selected.size === agents.length && agents.length > 0}
                          onChange={toggleAll}
                          className="w-3.5 h-3.5 accent-amber-500 cursor-pointer" />
                      </th>
                      <th className="px-6 py-4">Identity / Target Name</th>
                      <th className="px-6 py-4">Role & App Type</th>
                      <th className="px-6 py-4">Version</th>
                      <th className="px-6 py-4">Gov Score</th>
                      <th className="px-6 py-4">Trust Tier</th>
                      <th className="px-6 py-4">Criticality</th>
                      <th className="px-6 py-4">Class</th>
                      <th className="px-6 py-4">Business Unit</th>
                      <th className="px-6 py-4 whitespace-nowrap text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-white/5">
                    {agents.map(agent => {
                      const badge = tierBadge[agent.trust_tier] ?? tierBadge.unverified;
                      
                      const resolvedName = agent.name || agent.owner_name || `Agent-${agent.id.substring(0,8)}`;
                      const resolvedType = agent.agent_type || 'N/A';
                      const resolvedRole = agent.role || 'N/A';
                      const resolvedVersion = agent.version ? `v${agent.version}` : 'N/A';

                      return (
                        <tr key={agent.id} className={`hover:bg-white/[0.03] transition-colors ${selected.has(agent.id) ? 'bg-amber-500/5' : ''}`}>
                          <td className="px-4 py-4 w-10">
                            <input type="checkbox" checked={selected.has(agent.id)}
                              onChange={() => toggleSelect(agent.id)}
                              className="w-3.5 h-3.5 accent-amber-500 cursor-pointer" />
                          </td>
                          <td className="px-6 py-4">
                            <div className="font-technical text-[13px] text-white font-bold whitespace-nowrap mb-1 flex items-center">
                              <span className="material-symbols-outlined text-[14px] text-orange-500 mr-2 opacity-80">smart_toy</span>
                              {resolvedName}
                            </div>
                            <div className="font-technical text-[10px] text-neutral-500 uppercase tracking-widest flex items-center gap-1">
                              <span className="material-symbols-outlined text-[10px]">domain</span> {agent.tenant_name}
                            </div>
                          </td>
                          
                          <td className="px-6 py-4 font-technical">
                            <div className="text-[11px] font-bold text-neutral-300 uppercase tracking-wider mb-1">
                              {resolvedRole}
                            </div>
                            <div className="text-[10px] text-neutral-500 uppercase">
                              Type: {resolvedType}
                            </div>
                          </td>

                          <td className="px-6 py-4 font-technical text-xs text-neutral-400">
                             {resolvedVersion}
                          </td>

                          <td className="px-6 py-4">
                            {(() => {
                              const gs = agent.governance_score ?? 0;
                              const gsColor = gs >= 80 ? 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20'
                                : gs >= 50 ? 'text-orange-400 bg-orange-500/10 border-orange-500/20'
                                : 'text-red-400 bg-red-500/10 border-red-500/20';
                              return (
                                <div className="flex items-center gap-2">
                                  <span className={`border text-[11px] font-technical px-2.5 py-1 font-black tracking-tight rounded-lg ${gsColor}`}>
                                    {gs}
                                  </span>
                                  <div className="w-12 h-1.5 rounded-full bg-white/10 overflow-hidden">
                                    <div className={`h-full rounded-full transition-all ${gs >= 80 ? 'bg-emerald-500' : gs >= 50 ? 'bg-orange-500' : 'bg-red-500'}`}
                                      style={{ width: `${gs}%` }} />
                                  </div>
                                </div>
                              );
                            })()}
                          </td>

                          <td className="px-6 py-4">
                            <span className={`border text-[9px] font-technical px-2 py-0.5 font-bold tracking-widest rounded ${badge.cls}`}>
                              {badge.label}
                            </span>
                          </td>

                          <td className="px-6 py-4">
                            <span className="border text-[9px] font-technical px-2 py-0.5 font-bold tracking-widest rounded uppercase bg-neutral-900 border-neutral-700 text-neutral-400">
                              {agent.criticality_level || 'N/A'}
                            </span>
                          </td>

                          <td className="px-6 py-4">
                            <span className="border text-[9px] font-technical px-2 py-0.5 font-bold tracking-widest rounded uppercase text-neutral-400 border-neutral-800">
                              {agent.data_classification || 'N/A'}
                            </span>
                          </td>

                          <td className="px-6 py-4 font-technical text-xs text-neutral-400">
                            {agent.business_unit || 'N/A'}
                          </td>

                          <td className="px-6 py-4 text-right">
                            <Link
                              href={`/registry/${agent.id}`}
                              className="inline-flex items-center px-4 py-1.5 bg-[#1a1a1a] hover:bg-neutral-800 border border-neutral-700 hover:border-neutral-500 text-[10px] font-bold text-white transition-all uppercase tracking-widest rounded whitespace-nowrap shadow-sm"
                            >
                              Profile
                            </Link>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
            
            {!loading && agents.length > 0 && (
               <div className="px-6 py-4 border-t border-white/5 flex justify-between items-center bg-[#151515]">
                 <p className="text-[10px] font-technical text-neutral-500 uppercase tracking-widest">Verified PostgreSQL Records: {agents.length}</p>
                 <div className="text-[10px] font-technical text-neutral-500 italic">Mapping core schema with governance extensions.</div>
               </div>
            )}
          </div>
        </section>
      </main>
    </>
  );
}
