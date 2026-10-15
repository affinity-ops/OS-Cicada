// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

'use client';
import { operatorFetch } from '@/lib/operatorFetch';
import { useState, useEffect } from 'react';
import Link from 'next/link';
import { Sidebar } from '../../../components/Sidebar';
import { TopAppBar } from '../../../components/TopAppBar';

interface BaselineAgent {
  agent_id: string;
  agent_name: string | null;
  trust_tier: string;
  total_calls: number;
  blocked_calls: number;
  avg_confidence: number;
  calls_last_hour: number;
  block_ratio: number;
  expected_velocity: number | null;
  velocity_deviation: number | null;
  deviation: 'critical' | 'elevated' | 'nominal' | 'insufficient_data';
  created_at: string;
}

interface RegistryAgent {
  id: string;
  name: string | null;
  trust_tier: string;
  created_at: string;
  expected_velocity: number | null;
}

interface LedgerRow {
  agent_id: string;
  status: string;
  swarm_confidence_score: number | null;
  created_at: string;
}

const API = process.env.NEXT_PUBLIC_CORE_API_URL ?? 'http://localhost:8000';

function computeDeviation(blockRatio: number, avgConf: number, totalCalls: number, velDev: number | null = null): BaselineAgent['deviation'] {
  if (totalCalls < 5) return 'insufficient_data';
  if (blockRatio >= 0.3 || avgConf < 0.4 || (velDev !== null && velDev > 0.5)) return 'critical';
  if (blockRatio >= 0.15 || avgConf < 0.55 || (velDev !== null && velDev > 0.3)) return 'elevated';
  return 'nominal';
}

const deviationColour = (d: string) => ({
  critical:          'text-red-400 bg-red-500/10 border-red-500/20',
  elevated:          'text-orange-400 bg-orange-500/10 border-orange-500/20',
  nominal:           'text-emerald-400 bg-emerald-500/10 border-emerald-500/20',
  insufficient_data: 'text-neutral-500 bg-white/5 border-white/10',
}[d] ?? 'text-neutral-500');

const deviationLabel = (d: string) => ({
  critical:          'Critical Deviation',
  elevated:          'Elevated Risk',
  nominal:           'Normal Behaviour',
  insufficient_data: 'Insufficient Data',
}[d] ?? d);

export default function BehaviourBaselines() {
  const [baselines, setBaselines] = useState<BaselineAgent[]>([]);
  const [loading, setLoading]     = useState(true);
  const [sortKey, setSortKey]     = useState<'deviation' | 'block_ratio' | 'avg_confidence'>('deviation');

  useEffect(() => {
    Promise.all([
      operatorFetch(`${API}/api/v1/registry?per_page=100`).then(r => r.json()),
      operatorFetch(`${API}/api/v1/logs?per_page=1000`).then(r => r.json()),
    ]).then(([agentsBody, logsBody]) => {
      const agents: RegistryAgent[] = agentsBody.data?.data ?? agentsBody.data ?? [];
      const logs: LedgerRow[] = logsBody.data?.data ?? [];
      const oneHourAgo = Date.now() - 3600000;

      const computed: BaselineAgent[] = agents.map(a => {
        const agentLogs = logs.filter(l => l.agent_id === a.id);
        const blocked   = agentLogs.filter(l => l.status === 'blocked').length;
        const scored    = agentLogs.filter(l => l.swarm_confidence_score !== null);
        const avgConf   = scored.length ? scored.reduce((s, l) => s + (l.swarm_confidence_score ?? 0), 0) / scored.length : 0.5;
        const lastHour  = agentLogs.filter(l => new Date(l.created_at).getTime() > oneHourAgo).length;
        const blockRatio = agentLogs.length ? blocked / agentLogs.length : 0;
        const velDev     = a.expected_velocity && a.expected_velocity > 0
          ? (lastHour - a.expected_velocity) / a.expected_velocity
          : null;

        return {
          agent_id:           a.id,
          agent_name:         a.name,
          trust_tier:         a.trust_tier,
          total_calls:        agentLogs.length,
          blocked_calls:      blocked,
          avg_confidence:     avgConf,
          calls_last_hour:    lastHour,
          block_ratio:        blockRatio,
          expected_velocity:  a.expected_velocity ?? null,
          velocity_deviation: velDev,
          deviation:          computeDeviation(blockRatio, avgConf, agentLogs.length, velDev),
          created_at:         a.created_at,
        };
      });

      const order = { critical: 0, elevated: 1, nominal: 2, insufficient_data: 3 };
      setBaselines(computed.sort((a, b) => order[a.deviation] - order[b.deviation]));
    })
    .catch(() => {})
    .finally(() => setLoading(false));
  }, []);

  const sorted = [...baselines].sort((a, b) => {
    if (sortKey === 'deviation') return ({ critical: 0, elevated: 1, nominal: 2, insufficient_data: 3 }[a.deviation] ?? 3) - ({ critical: 0, elevated: 1, nominal: 2, insufficient_data: 3 }[b.deviation] ?? 3);
    if (sortKey === 'block_ratio') return b.block_ratio - a.block_ratio;
    return a.avg_confidence - b.avg_confidence;
  });

  const critCount = baselines.filter(b => b.deviation === 'critical').length;
  const elevCount = baselines.filter(b => b.deviation === 'elevated').length;

  return (
    <>
      <Sidebar />
      <TopAppBar />
      <main className="pt-24 px-8 pb-12 min-h-screen bg-background transition-all duration-300" style={{ marginLeft: 'var(--sidebar-width, 18rem)' }}>
        <div className="max-w-[95%] mx-auto space-y-8">

          <div className="flex flex-col md:flex-row justify-between items-start md:items-end gap-4">
            <div>
              <h1 className="text-5xl font-black font-headline tracking-tighter">Behaviour <span className="text-orange-500">Baselines</span></h1>
              <p className="text-neutral-400 mt-2 max-w-2xl">Continuous behavioural scoring for every registered agent. Block ratio, confidence score, and call velocity — combined into a single deviation signal.</p>
            </div>
            {!loading && (critCount > 0 || elevCount > 0) && (
              <div className="flex gap-3">
                {critCount > 0 && (
                  <div className="flex items-center gap-2 px-4 py-2 bg-red-500/10 border border-red-500/20 rounded-xl">
                    <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse"></span>
                    <span className="font-technical text-xs text-red-400 font-bold">{critCount} critical</span>
                  </div>
                )}
                {elevCount > 0 && (
                  <div className="flex items-center gap-2 px-4 py-2 bg-orange-500/10 border border-orange-500/20 rounded-xl">
                    <span className="w-2 h-2 rounded-full bg-orange-500"></span>
                    <span className="font-technical text-xs text-orange-400 font-bold">{elevCount} elevated</span>
                  </div>
                )}
              </div>
            )}
          </div>

          <div className="bg-blue-500/5 border border-blue-500/20 rounded-2xl p-6 flex gap-4">
            <span className="material-symbols-outlined text-blue-400 flex-shrink-0 mt-0.5">info</span>
            <div>
              <p className="font-bold text-blue-300 text-sm">How to use this screen</p>
              <p className="text-neutral-400 text-sm mt-1">
                Each agent is scored against three metrics: block ratio (how often it gets blocked), average verification confidence (how suspicious the swarm thinks its calls are), and call volume in the last hour (velocity spike detection). Agents that cross any threshold are flagged. &ldquo;Critical Deviation&rdquo; means the circuit breaker may already have tripped — check that agent immediately. Click &ldquo;Ask Aegis&rdquo; to get a plain-English explanation of why an agent is flagged.
              </p>
            </div>
          </div>

          {/* Threshold reference */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {[
              { label: 'Block Ratio',      critical: '≥ 30%',  elevated: '≥ 15%', icon: 'block',      colour: 'red' },
              { label: 'Avg Confidence',   critical: '< 0.40', elevated: '< 0.55', icon: 'psychology',  colour: 'orange' },
              { label: 'Data Requirement', critical: '5+ calls', elevated: '5+ calls', icon: 'query_stats', colour: 'blue' },
            ].map(t => (
              <div key={t.label} className={`bg-${t.colour}-500/5 border border-${t.colour}-500/20 rounded-xl p-4`}>
                <div className="flex items-center gap-2 mb-2">
                  <span className={`material-symbols-outlined text-${t.colour}-400 text-[18px]`}>{t.icon}</span>
                  <p className={`font-bold text-${t.colour}-300 text-sm`}>{t.label}</p>
                </div>
                <div className="space-y-1 text-xs font-technical">
                  <p className="text-red-400">Critical: {t.critical}</p>
                  <p className="text-orange-400">Elevated: {t.elevated}</p>
                </div>
              </div>
            ))}
          </div>

          {/* Sort controls */}
          <div className="flex items-center gap-2">
            <span className="text-xs font-technical text-neutral-500 uppercase tracking-wider">Sort by:</span>
            {(['deviation', 'block_ratio', 'avg_confidence'] as const).map(k => (
              <button key={k} onClick={() => setSortKey(k)}
                className={`px-3 py-1.5 rounded-lg text-xs font-technical font-bold transition-colors ${sortKey === k ? 'bg-orange-500/20 text-orange-400' : 'bg-white/5 text-neutral-400 hover:bg-white/10'}`}>
                {k === 'deviation' ? 'Risk Level' : k === 'block_ratio' ? 'Block Rate' : 'Confidence'}
              </button>
            ))}
          </div>

          {/* Baseline table */}
          <div className="bg-[#131313] border border-white/5 rounded-2xl overflow-hidden">
            <div className="px-6 py-4 border-b border-white/5 flex justify-between items-center">
              <h2 className="font-headline font-bold">Agent Baselines ({baselines.length})</h2>
              <Link href="/aegis?context=baseline_review" className="flex items-center gap-2 px-3 py-2 bg-blue-500/10 border border-blue-500/20 text-blue-400 rounded-lg text-xs font-bold hover:bg-blue-500/20 transition-colors">
                <span className="material-symbols-outlined text-[14px]">trip_origin</span>Ask Aegis to Review All
              </Link>
            </div>
            {loading && <div className="p-12 text-center text-neutral-500 font-technical text-xs animate-pulse">Computing baselines…</div>}
            {!loading && baselines.length === 0 && (
              <div className="p-12 text-center text-neutral-600 font-technical text-xs">
                <span className="material-symbols-outlined text-4xl opacity-20 block mb-2">insights</span>
                No agents registered yet. Register an agent to begin baseline tracking.
              </div>
            )}
            {sorted.length > 0 && (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="text-[10px] font-technical uppercase text-neutral-500 border-b border-white/5">
                      <th className="px-6 py-3 text-left">Agent</th>
                      <th className="px-6 py-3 text-left">Status</th>
                      <th className="px-6 py-3 text-left">Calls</th>
                      <th className="px-6 py-3 text-left">Block Rate</th>
                      <th className="px-6 py-3 text-left">Avg Confidence</th>
                      <th className="px-6 py-3 text-left">Last Hour</th>
                      <th className="px-6 py-3 text-left">Deviation</th>
                      <th className="px-6 py-3 text-left">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-white/5">
                    {sorted.map(b => (
                      <tr key={b.agent_id} className={`hover:bg-white/5 transition-colors ${b.deviation === 'critical' ? 'bg-red-500/5' : ''}`}>
                        <td className="px-6 py-4">
                          <p className="font-technical text-xs text-white font-bold">{b.agent_name ?? b.agent_id.substring(0, 16) + '…'}</p>
                          {b.expected_velocity != null && (
                            <p className="font-technical text-[10px] text-neutral-500 mt-0.5">
                              Expected: {b.expected_velocity}/hr
                              {b.velocity_deviation !== null && (
                                <span className={b.velocity_deviation > 0.3 ? ' text-orange-400' : ' text-neutral-600'}>
                                  {' '}({b.velocity_deviation > 0 ? '+' : ''}{Math.round(b.velocity_deviation * 100)}% drift)
                                </span>
                              )}
                            </p>
                          )}
                        </td>
                        <td className="px-6 py-4">
                          <span className={`px-2 py-1 rounded font-technical text-[10px] font-bold uppercase ${
                            { critical: 'text-red-400', elevated: 'text-orange-400', nominal: 'text-emerald-400', unverified: 'text-neutral-500' }[b.trust_tier] ?? 'text-neutral-500'
                          }`}>{b.trust_tier}</span>
                        </td>
                        <td className="px-6 py-4 font-technical text-xs text-neutral-400">{b.total_calls}</td>
                        <td className="px-6 py-4">
                          <div className="flex items-center gap-2">
                            <div className="w-16 h-1.5 bg-white/10 rounded-full overflow-hidden">
                              <div className={`h-full rounded-full ${b.block_ratio >= 0.3 ? 'bg-red-500' : b.block_ratio >= 0.15 ? 'bg-orange-500' : 'bg-emerald-500'}`}
                                style={{ width: `${Math.min(b.block_ratio * 100, 100)}%` }}></div>
                            </div>
                            <span className={`font-technical text-xs font-bold ${b.block_ratio >= 0.3 ? 'text-red-400' : b.block_ratio >= 0.15 ? 'text-orange-400' : 'text-emerald-400'}`}>
                              {Math.round(b.block_ratio * 100)}%
                            </span>
                          </div>
                        </td>
                        <td className="px-6 py-4">
                          <div className="flex items-center gap-2">
                            <div className="w-16 h-1.5 bg-white/10 rounded-full overflow-hidden">
                              <div className={`h-full rounded-full ${b.avg_confidence < 0.4 ? 'bg-red-500' : b.avg_confidence < 0.55 ? 'bg-orange-500' : 'bg-emerald-500'}`}
                                style={{ width: `${b.avg_confidence * 100}%` }}></div>
                            </div>
                            <span className={`font-technical text-xs font-bold ${b.avg_confidence < 0.4 ? 'text-red-400' : b.avg_confidence < 0.55 ? 'text-orange-400' : 'text-emerald-400'}`}>
                              {Math.round(b.avg_confidence * 100)}%
                            </span>
                          </div>
                        </td>
                        <td className="px-6 py-4 font-technical text-xs text-neutral-400">{b.calls_last_hour}</td>
                        <td className="px-6 py-4">
                          <span className={`px-2 py-1 rounded border text-[10px] font-technical font-bold uppercase ${deviationColour(b.deviation)}`}>
                            {deviationLabel(b.deviation)}
                          </span>
                        </td>
                        <td className="px-6 py-4">
                          <div className="flex gap-2">
                            <Link href={`/agent-admin/biographies`} className="text-neutral-500 hover:text-orange-400 font-technical text-[10px] transition-colors">History</Link>
                            <span className="text-white/10">|</span>
                            <Link href={`/aegis?context=agent:${b.agent_id}`} className="text-blue-400 hover:text-blue-300 font-technical text-[10px] transition-colors">Aegis</Link>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* Circuit breaker note */}
          {critCount > 0 && (
            <div className="bg-red-500/5 border border-red-500/20 rounded-2xl p-6 flex gap-4">
              <span className="material-symbols-outlined text-red-400 flex-shrink-0 mt-0.5">electric_bolt</span>
              <div>
                <p className="font-bold text-red-300 text-sm">{critCount} agent{critCount > 1 ? 's' : ''} at critical deviation</p>
                <p className="text-neutral-400 text-sm mt-1">
                  The automated circuit breaker may have already tripped for these agents. Check their biographies for a <span className="font-technical text-xs bg-white/5 px-1 rounded">circuit_breaker_trip</span> event. If not tripped, review manually and consider revoking the agent token until the root cause is understood.
                </p>
                <div className="mt-3 flex gap-3">
                  <Link href="/agent-admin/biographies" className="flex items-center gap-1.5 text-red-400 hover:text-red-300 text-xs font-bold font-technical transition-colors">
                    <span className="material-symbols-outlined text-[14px]">manage_history</span>View Biographies
                  </Link>
                  <Link href="/aegis?context=critical_deviation" className="flex items-center gap-1.5 text-blue-400 hover:text-blue-300 text-xs font-bold font-technical transition-colors">
                    <span className="material-symbols-outlined text-[14px]">trip_origin</span>Ask Aegis to Investigate
                  </Link>
                </div>
              </div>
            </div>
          )}
        </div>
      </main>
    </>
  );
}
