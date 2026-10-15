// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

'use client';
import { operatorFetch } from '@/lib/operatorFetch';
import { useState, useEffect } from 'react';
import Link from 'next/link';
import { Sidebar } from '../../../components/Sidebar';
import { TopAppBar } from '../../../components/TopAppBar';

interface RogueEntry {
  trace_id: string;
  agent_id: string;
  agent_name: string | null;
  tenant_name: string | null;
  action_type: string;
  status: string;
  policy_violations: string | null;
  swarm_confidence_score: number | null;
  target_api: string;
  created_at: string;
}

const API = process.env.NEXT_PUBLIC_CORE_API_URL ?? 'http://localhost:8000';

export default function RogueRegistry() {
  const [entries, setEntries] = useState<RogueEntry[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    operatorFetch(`${API}/api/v1/logs?status=blocked&per_page=50`)
      .then(r => r.json())
      .then(body => setEntries(body.data?.data ?? []))
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  const parseViolations = (v: string | null): string[] => {
    try { return v ? JSON.parse(v) : []; } catch { return []; }
  };

  return (
    <>
      <Sidebar />
      <TopAppBar />
      <main className="pt-24 px-8 pb-12 min-h-screen bg-background transition-all duration-300" style={{ marginLeft: 'var(--sidebar-width, 18rem)' }}>
        <div className="max-w-[95%] mx-auto space-y-8">

          {/* Header */}
          <div className="flex flex-col md:flex-row justify-between items-start md:items-end gap-4">
            <div>
              <h1 className="text-5xl font-black font-headline tracking-tighter">Rogue <span className="text-orange-500">Registry</span></h1>
              <p className="text-neutral-400 mt-2 max-w-2xl">Every agent that was blocked by the Gateway — failed authentication, revoked tokens, unauthorised calls, policy violations. This is your audit trail of threats stopped.</p>
            </div>
            <div className="flex items-center gap-2 px-4 py-2 bg-red-500/10 border border-red-500/20 rounded-xl">
              <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse"></span>
              <span className="font-technical text-xs text-red-400 font-bold">{entries.length} blocked events recorded</span>
            </div>
          </div>

          {/* Help Panel */}
          <div className="bg-blue-500/5 border border-blue-500/20 rounded-2xl p-6 flex gap-4">
            <span className="material-symbols-outlined text-blue-400 flex-shrink-0 mt-0.5">info</span>
            <div className="space-y-1">
              <p className="font-bold text-blue-300 text-sm">How to use this screen</p>
              <p className="text-neutral-400 text-sm">This registry captures every agent the Gateway blocked. Each row shows the agent ID, what it tried to do, why it was blocked, and the exact timestamp. Click any row to see the full pipeline trace. Use the &ldquo;Ask Aegis&rdquo; button to get a plain-English explanation of any threat pattern, or to trigger a revocation.</p>
            </div>
          </div>

          {/* Table */}
          <div className="bg-[#131313] border border-white/5 rounded-2xl overflow-hidden">
            <div className="px-6 py-4 border-b border-white/5 flex justify-between items-center">
              <h2 className="font-headline font-bold">Blocked Agent Events</h2>
              <Link href="/aegis" className="flex items-center gap-2 px-4 py-2 bg-blue-500/10 border border-blue-500/20 text-blue-400 rounded-lg text-xs font-bold hover:bg-blue-500/20 transition-colors">
                <span className="material-symbols-outlined text-[16px]">trip_origin</span>
                Ask Aegis to Analyse
              </Link>
            </div>
            {loading && <div className="p-12 text-center text-neutral-500 font-technical text-xs animate-pulse">Scanning rogue registry...</div>}
            {!loading && entries.length === 0 && (
              <div className="p-12 text-center text-neutral-600 font-technical text-xs">
                <span className="material-symbols-outlined text-4xl opacity-20 block mb-2">check_circle</span>
                No blocked events. All agents are operating within policy.
              </div>
            )}
            {entries.length > 0 && (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="text-[10px] font-technical uppercase text-neutral-500 border-b border-white/5">
                      <th className="px-6 py-3 text-left">Agent / Company</th>
                      <th className="px-6 py-3 text-left">Action Type</th>
                      <th className="px-6 py-3 text-left">Reason</th>
                      <th className="px-6 py-3 text-left">Target</th>
                      <th className="px-6 py-3 text-left">Risk Score</th>
                      <th className="px-6 py-3 text-left">Time</th>
                      <th className="px-6 py-3 text-left">Trace</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-white/5">
                    {entries.map(e => {
                      const violations = parseViolations(e.policy_violations);
                      const reason = violations[0] ?? e.action_type;
                      const score = e.swarm_confidence_score;
                      return (
                        <tr key={e.trace_id} className="hover:bg-white/5 transition-colors">
                          <td className="px-6 py-4">
                            <p className="font-technical text-xs text-white font-bold">{e.agent_name ?? e.agent_id.substring(0, 16) + '…'}</p>
                            {e.tenant_name && <p className="font-technical text-[10px] text-neutral-500 mt-0.5">{e.tenant_name}</p>}
                          </td>
                          <td className="px-6 py-4"><span className="px-2 py-1 bg-white/5 rounded font-technical text-[10px] text-neutral-400">{e.action_type}</span></td>
                          <td className="px-6 py-4"><span className="px-2 py-1 bg-red-500/10 border border-red-500/20 rounded font-technical text-[10px] text-red-400">{reason}</span></td>
                          <td className="px-6 py-4 font-technical text-xs text-neutral-500 max-w-[200px] truncate">{e.target_api}</td>
                          <td className="px-6 py-4">
                            <span className={`font-technical text-xs font-bold ${score !== null && score > 0.7 ? 'text-red-400' : score !== null && score > 0.4 ? 'text-orange-400' : 'text-neutral-400'}`}>
                              {score !== null ? `${Math.round(score * 100)}%` : '—'}
                            </span>
                          </td>
                          <td className="px-6 py-4 font-technical text-xs text-neutral-500">{new Date(e.created_at).toLocaleString()}</td>
                          <td className="px-6 py-4">
                            <Link href={`/pipeline?trace=${e.trace_id}`} className="text-orange-400 hover:text-orange-300 font-technical text-xs underline">View</Link>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      </main>
    </>
  );
}
