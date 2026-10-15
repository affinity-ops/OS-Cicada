// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

'use client';
import { operatorFetch } from '@/lib/operatorFetch';
import { useState, useEffect } from 'react';
import Link from 'next/link';
import { Sidebar } from '../../../components/Sidebar';
import { TopAppBar } from '../../../components/TopAppBar';

interface LedgerRow {
  trace_id: string;
  agent_id: string;
  tenant_id?: string;
  action_type: string;
  status: string;
  policy_violations: string | null;
  swarm_confidence_score: number | null;
  target_api: string;
  created_at: string;
}

interface ThreatCluster {
  key: string;
  label: string;
  count: number;
  agentCount: number;
  tenantCount: number;
  firstSeen: string;
  lastSeen: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  exampleTrace: string;
}

interface AttackSignal {
  key: string;
  label: string;
  countLast24h: number;
  countPrev24h: number;
  trend: 'rising' | 'stable' | 'falling';
  lastHit: string | null;
}

interface TrendSeries {
  key: string;
  data: { date: string; count: number }[];
}

const API = process.env.NEXT_PUBLIC_CORE_API_URL ?? 'http://localhost:8000';

interface ThreatSignals {
  window_minutes: number;
  generated_at: string;
  signals: Record<string, number>;
  circuit_breaker_trips: number;
}

const VIOLATION_LABELS: Record<string, string> = {
  cross_agent_context_contamination:  'Cross-Agent Context Contamination',
  cross_agent_semantic_contamination: 'Cross-Agent Semantic Contamination',
  scope_violation:                    'Scope Escalation Probe',
  role_violation:                     'Role Policy Violation',
  circuit_breaker_trip:               'Circuit Breaker Trip',
  pii_in_response:                    'PII Leak Detected',
  rogue_agent_detected:               'Rogue Agent Detected',
  memory_contamination:               'Memory Contamination',
  hitl_rejected:                      'HITL Rejection',
  invalid_evar:                       'Invalid / Revoked Token',
  token_revoked:                      'Invalid / Revoked Token',
};

function labelFor(key: string): string {
  return VIOLATION_LABELS[key] ?? key.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

function parseViolations(raw: string | null, fallback: string): string[] {
  try { const v = JSON.parse(raw ?? '[]'); return Array.isArray(v) && v.length > 0 ? v : [fallback]; }
  catch { return [fallback]; }
}

function computeSeverity(count: number, agentCount: number, lastSeen: string): ThreatCluster['severity'] {
  const hoursSince = (Date.now() - new Date(lastSeen).getTime()) / 3_600_000;
  if (agentCount >= 3 || (count >= 5 && hoursSince < 24)) return 'critical';
  if (agentCount >= 2 || (count >= 3 && hoursSince < 48)) return 'high';
  if (hoursSince < 168) return 'medium';
  return 'low';
}

function computeTrend(current: number, previous: number): AttackSignal['trend'] {
  if (current === 0 && previous === 0) return 'stable';
  if (previous === 0 || current > previous * 1.2) return 'rising';
  if (current < previous * 0.8) return 'falling';
  return 'stable';
}

function buildClusters(rows: LedgerRow[]): ThreatCluster[] {
  const map = new Map<string, {
    count: number; agents: Set<string>; tenants: Set<string>;
    firstSeen: string; lastSeen: string; exampleTrace: string;
  }>();

  rows.forEach(row => {
    parseViolations(row.policy_violations, row.action_type).forEach(raw => {
      const key = raw.toLowerCase().trim();
      if (!map.has(key)) {
        map.set(key, { count: 0, agents: new Set(), tenants: new Set(), firstSeen: row.created_at, lastSeen: row.created_at, exampleTrace: row.trace_id });
      }
      const c = map.get(key)!;
      c.count++;
      c.agents.add(row.agent_id);
      if (row.tenant_id) c.tenants.add(row.tenant_id);
      if (new Date(row.created_at) < new Date(c.firstSeen)) c.firstSeen = row.created_at;
      if (new Date(row.created_at) > new Date(c.lastSeen))  c.lastSeen  = row.created_at;
    });
  });

  const ORDER = { critical: 0, high: 1, medium: 2, low: 3 } as const;
  return Array.from(map.entries())
    .map(([key, c]) => {
      const severity = computeSeverity(c.count, c.agents.size, c.lastSeen);
      return { key, label: labelFor(key), count: c.count, agentCount: c.agents.size, tenantCount: c.tenants.size, firstSeen: c.firstSeen, lastSeen: c.lastSeen, severity, exampleTrace: c.exampleTrace };
    })
    .sort((a, b) => ORDER[a.severity] - ORDER[b.severity] || b.count - a.count);
}

function buildSignals(rows: LedgerRow[]): AttackSignal[] {
  const now     = Date.now();
  const cut24   = now - 86_400_000;
  const cut48   = now - 172_800_000;

  const map = new Map<string, { last24: number; prev24: number; lastHit: string | null }>();

  rows.forEach(row => {
    parseViolations(row.policy_violations, row.action_type).forEach(raw => {
      const key = raw.toLowerCase().trim();
      if (!map.has(key)) map.set(key, { last24: 0, prev24: 0, lastHit: null });
      const s = map.get(key)!;
      const ts = new Date(row.created_at).getTime();
      if (ts > cut24)       s.last24++;
      else if (ts > cut48)  s.prev24++;
      if (!s.lastHit || ts > new Date(s.lastHit).getTime()) s.lastHit = row.created_at;
    });
  });

  return Array.from(map.entries())
    .map(([key, s]) => ({
      key,
      label:        labelFor(key),
      countLast24h: s.last24,
      countPrev24h: s.prev24,
      trend:        computeTrend(s.last24, s.prev24),
      lastHit:      s.lastHit,
    }))
    .sort((a, b) => b.countLast24h - a.countLast24h || b.countPrev24h - a.countPrev24h);
}

const SEVERITY_CLASSES = {
  critical: 'text-red-400 bg-red-500/10 border-red-500/20',
  high:     'text-orange-400 bg-orange-500/10 border-orange-500/20',
  medium:   'text-yellow-400 bg-yellow-500/10 border-yellow-500/20',
  low:      'text-neutral-400 bg-white/5 border-white/10',
} as const;

const TREND_ICON  = { rising: 'trending_up', stable: 'trending_flat', falling: 'trending_down' } as const;
const TREND_CLASS = { rising: 'text-red-400', stable: 'text-neutral-400', falling: 'text-emerald-400' } as const;

const VECTOR_LABELS: Record<string, string> = {
  v01_registrations_per_tenant_1h:  'V01 — Registration Spike',
  v02_revoked_admission_attempts:   'V02 — Revoked Agent Probe',
  v03_oauth_state_mismatches:       'V03 — OAuth State Mismatch',
  v04_swarm_result_hmac_failures:   'V04 — Swarm HMAC Failure',
  v05_duplicate_rollback_ids:       'V05 — Duplicate Rollback ID',
  v06_ledger_anomalies:             'V06 — Ledger Anomaly',
  v07_confidence_variance_anomaly:  'V07 — Confidence Variance',
  v08_role_violations:              'V08 — Role Violation',
  v09_token_ip_anomalies:           'V09 — Token IP Anomaly',
  v10_undeclared_tool_calls:        'V10 — Undeclared Tool Call',
};

const CHART_COLORS = [
  '#f87171', '#fb923c', '#fbbf24', '#34d399', '#60a5fa',
  '#a78bfa', '#f472b6', '#38bdf8', '#4ade80', '#e879f9',
];

/* ===== Violation Trend Line Chart (pure SVG) ===== */
function ViolationTrendChart({ series }: { series: TrendSeries[] }) {
  if (series.length === 0) {
    return (
      <div className="px-5 py-8 text-center text-neutral-600 font-technical text-xs">
        <span className="material-symbols-outlined text-3xl opacity-20 block mb-2">show_chart</span>
        No violation trend data for the last 30 days.
      </div>
    );
  }

  const W = 800, H = 200, PAD_L = 50, PAD_R = 20, PAD_T = 10, PAD_B = 30;
  const innerW = W - PAD_L - PAD_R;
  const innerH = H - PAD_T - PAD_B;

  let maxCount = 1;
  series.forEach(s => s.data.forEach(d => { if (d.count > maxCount) maxCount = d.count; }));
  const numDays = series[0]?.data.length ?? 30;

  const toX = (i: number) => PAD_L + (i / Math.max(numDays - 1, 1)) * innerW;
  const toY = (v: number) => PAD_T + innerH - (v / maxCount) * innerH;

  const yTicks = [0, Math.round(maxCount * 0.25), Math.round(maxCount * 0.5), Math.round(maxCount * 0.75), maxCount];
  const xLabels = series[0]?.data.filter((_, i) => i % 7 === 0 || i === numDays - 1) ?? [];

  return (
    <div className="w-full overflow-x-auto">
      <svg viewBox={`0 0 ${W} ${H}`} className="w-full min-w-[600px]" preserveAspectRatio="xMidYMid meet">
        {yTicks.map(t => (
          <g key={t}>
            <line x1={PAD_L} x2={W - PAD_R} y1={toY(t)} y2={toY(t)}
              stroke="rgba(255,255,255,0.05)" strokeDasharray="4,4" />
            <text x={PAD_L - 8} y={toY(t) + 4} textAnchor="end"
              fill="#555" fontSize="9" fontFamily="monospace">{t}</text>
          </g>
        ))}
        {xLabels.map((d, i) => {
          const idx = series[0]?.data.indexOf(d) ?? 0;
          return (
            <text key={i} x={toX(idx)} y={H - 5} textAnchor="middle"
              fill="#555" fontSize="8" fontFamily="monospace">
              {new Date(d.date).toLocaleDateString('en-GB', { day: '2-digit', month: 'short' })}
            </text>
          );
        })}
        {series.map((s, si) => {
          const color = CHART_COLORS[si % CHART_COLORS.length];
          const pathD = s.data.map((d, i) => `${i === 0 ? 'M' : 'L'}${toX(i).toFixed(1)},${toY(d.count).toFixed(1)}`).join(' ');
          return (
            <g key={s.key}>
              <path d={pathD} fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" opacity="0.9" />
              {s.data.map((d, i) => d.count > 0 ? (
                <circle key={i} cx={toX(i)} cy={toY(d.count)} r="2.5" fill={color} opacity="0.8" />
              ) : null)}
            </g>
          );
        })}
      </svg>
      <div className="flex flex-wrap gap-4 px-5 py-3 border-t border-white/5">
        {series.map((s, si) => (
          <div key={s.key} className="flex items-center gap-2">
            <span className="w-3 h-3 rounded-sm" style={{ backgroundColor: CHART_COLORS[si % CHART_COLORS.length] }} />
            <span className="text-[10px] font-technical text-neutral-400">{labelFor(s.key)}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function ThreatCorrelation() {
  const [clusters, setClusters]       = useState<ThreatCluster[]>([]);
  const [signals, setSignals]         = useState<AttackSignal[]>([]);
  const [totalBlocked, setTotal]      = useState(0);
  const [loading, setLoading]         = useState(true);
  const [briefing, setBriefing]       = useState<string | null>(null);
  const [aegisVectors, setAegisVectors] = useState<ThreatSignals | null>(null);
  const [trendSeries, setTrendSeries] = useState<TrendSeries[]>([]);

  useEffect(() => {
    Promise.all([
      operatorFetch(`${API}/api/v1/logs?status=blocked&per_page=1000`).then(r => r.json()),
      operatorFetch(`${API}/api/v1/admin/threat-signals`).then(r => r.json()).catch(() => null),
      operatorFetch(`${API}/api/v1/admin/violation-trends`).then(r => r.json()).catch(() => null),
    ]).then(([logsBody, signalsBody, trendsBody]) => {
      const rows: LedgerRow[] = logsBody.data?.data ?? [];
      setTotal(rows.length);
      setClusters(buildClusters(rows));
      setSignals(buildSignals(rows));
      if (signalsBody?.status === 'success') setAegisVectors(signalsBody.data);
      if (trendsBody?.status === 'success') setTrendSeries(trendsBody.data ?? []);
    })
    .catch(() => {})
    .finally(() => setLoading(false));
  }, []);

  const generateBriefing = () => {
    if (clusters.length === 0) {
      setBriefing(`Aegis-0 Threat Briefing — ${new Date().toLocaleString()}\n\nNo blocked events are recorded in the platform ledger. All agents are currently operating within policy. Continue monitoring — this screen will populate automatically as events occur.`);
      return;
    }
    const top = clusters[0];
    const rising = signals.filter(s => s.trend === 'rising').map(s => s.label).join(', ') || 'none';
    setBriefing(
      `Aegis-0 Threat Briefing — ${new Date().toLocaleString()}\n\n` +
      `${clusters.length} distinct attack pattern${clusters.length > 1 ? 's' : ''} detected across ${totalBlocked} blocked events.\n\n` +
      `Highest severity: "${top.label}" — ${top.count} event${top.count > 1 ? 's' : ''} affecting ${top.agentCount} agent${top.agentCount > 1 ? 's' : ''}` +
      (top.tenantCount > 0 ? ` across ${top.tenantCount} tenant${top.tenantCount > 1 ? 's' : ''}` : '') +
      `. First observed ${new Date(top.firstSeen).toLocaleDateString()}, last seen ${new Date(top.lastSeen).toLocaleString()}.\n\n` +
      `Currently rising vectors: ${rising}.\n\n` +
      `Recommended action: review Agent Biographies for agents involved in the highest-severity cluster and consider circuit breaker escalation for tenants with 3 or more affected agents. Continue in Aegis Chat for a full narrative assessment.`
    );
  };

  return (
    <>
      <Sidebar />
      <TopAppBar />
      <main className="pt-24 px-8 pb-12 min-h-screen bg-background transition-all duration-300" style={{ marginLeft: 'var(--sidebar-width, 18rem)' }}>
        <div className="max-w-[95%] mx-auto space-y-8">

          <div className="flex flex-col md:flex-row justify-between items-start md:items-end gap-4">
            <div>
              <h1 className="text-5xl font-black font-headline tracking-tighter">Threat <span className="text-orange-500">Correlation</span></h1>
              <p className="text-neutral-400 mt-2 max-w-2xl">Attack patterns grouped across the whole fleet — a single attacker probing multiple agents shows up here as one cluster, not dozens of disconnected events.</p>
            </div>
            {!loading && (
              <div className={`flex items-center gap-2 px-4 py-2 rounded-xl border ${totalBlocked > 0 ? 'bg-red-500/10 border-red-500/20' : 'bg-emerald-500/10 border-emerald-500/20'}`}>
                <span className={`w-2 h-2 rounded-full ${totalBlocked > 0 ? 'bg-red-500 animate-pulse' : 'bg-emerald-500'}`}></span>
                <span className={`font-technical text-xs font-bold ${totalBlocked > 0 ? 'text-red-400' : 'text-emerald-400'}`}>
                  {totalBlocked > 0 ? `${totalBlocked} blocked events correlated` : 'No blocked events'}
                </span>
              </div>
            )}
          </div>

          <div className="bg-blue-500/5 border border-blue-500/20 rounded-2xl p-6 flex gap-4">
            <span className="material-symbols-outlined text-blue-400 flex-shrink-0 mt-0.5">info</span>
            <div>
              <p className="font-bold text-blue-300 text-sm">How to use this screen</p>
              <p className="text-neutral-400 text-sm mt-1">
                Every blocked event is parsed for its violation type and grouped into clusters. The signal panel on the left shows which attack vectors are trending up in the last 24 hours compared to the previous 24. Severity is computed from the number of unique agents affected and how recently the pattern last fired. Click &ldquo;Generate Aegis Briefing&rdquo; to produce a shareable threat summary.
              </p>
            </div>
          </div>

          {/* Aegis V01–V10 Server-Side Threat Vectors */}
          {aegisVectors && (
            <div className="bg-[#131313] border border-white/5 rounded-2xl overflow-hidden">
              <div className="px-5 py-4 border-b border-white/5 flex items-center justify-between">
                <h2 className="font-headline font-bold text-sm flex items-center gap-2">
                  <span className="material-symbols-outlined text-orange-500 text-[16px]">trip_origin</span>
                  Aegis-0 Threat Vectors — Server Analysis ({aegisVectors.window_minutes}m window)
                </h2>
                <span className="text-[10px] font-technical text-neutral-500">{new Date(aegisVectors.generated_at).toLocaleTimeString()}</span>
              </div>
              <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 divide-x divide-y divide-white/5">
                {Object.entries(aegisVectors.signals).map(([key, count]) => (
                  <div key={key} className="px-4 py-3">
                    <p className="text-[9px] font-technical text-neutral-500 uppercase tracking-wider mb-1">{VECTOR_LABELS[key] ?? key}</p>
                    <p className={`text-xl font-black font-headline ${count > 0 ? 'text-red-400' : 'text-emerald-500'}`}>{count as number}</p>
                  </div>
                ))}
                <div className="px-4 py-3">
                  <p className="text-[9px] font-technical text-neutral-500 uppercase tracking-wider mb-1">Circuit Breaker Trips</p>
                  <p className={`text-xl font-black font-headline ${aegisVectors.circuit_breaker_trips > 0 ? 'text-orange-400' : 'text-emerald-500'}`}>
                    {aegisVectors.circuit_breaker_trips}
                  </p>
                </div>
              </div>
            </div>
          )}

          {/* Policy Violation Trends (30 day line chart) */}
          <div className="bg-[#131313] border border-white/5 rounded-2xl overflow-hidden">
            <div className="px-5 py-4 border-b border-white/5 flex items-center justify-between">
              <h2 className="font-headline font-bold text-sm flex items-center gap-2">
                <span className="material-symbols-outlined text-blue-400 text-[16px]">show_chart</span>
                Policy Violation Trends — 30 Day
              </h2>
              <span className="text-[10px] font-technical text-neutral-500">Daily counts by violation type</span>
            </div>
            {loading ? (
              <div className="p-8 text-center text-neutral-500 font-technical text-xs animate-pulse">Loading trend data…</div>
            ) : (
              <ViolationTrendChart series={trendSeries} />
            )}
          </div>

          {loading ? (
            <div className="bg-[#131313] border border-white/5 rounded-2xl p-12 text-center text-neutral-500 font-technical text-xs animate-pulse">
              Correlating threat data…
            </div>
          ) : (
            <div className="grid grid-cols-12 gap-6">

              {/* Signal panel */}
              <div className="col-span-4 space-y-4">
                <div className="bg-[#131313] border border-white/5 rounded-2xl overflow-hidden">
                  <div className="px-5 py-4 border-b border-white/5 flex justify-between items-center">
                    <h2 className="font-headline font-bold text-sm">Attack Vectors (24h)</h2>
                    <span className="text-[10px] font-technical text-neutral-500">vs prior 24h</span>
                  </div>
                  {signals.length === 0 ? (
                    <div className="px-5 py-8 text-center text-neutral-600 font-technical text-xs">
                      <span className="material-symbols-outlined text-3xl opacity-20 block mb-2">check_circle</span>
                      No attack vectors detected.
                    </div>
                  ) : (
                    <div className="divide-y divide-white/5">
                      {signals.map(s => (
                        <div key={s.key} className="px-5 py-3 flex items-center justify-between gap-3">
                          <div className="min-w-0">
                            <p className="text-xs font-bold text-on-surface truncate">{s.label}</p>
                            <p className="text-[10px] font-technical text-neutral-500 mt-0.5">
                              {s.lastHit ? `Last: ${new Date(s.lastHit).toLocaleTimeString()}` : 'No recent events'}
                            </p>
                          </div>
                          <div className="flex items-center gap-2 flex-shrink-0">
                            <span className={`font-technical text-sm font-bold ${s.countLast24h > 5 ? 'text-red-400' : s.countLast24h > 0 ? 'text-orange-400' : 'text-neutral-500'}`}>
                              {s.countLast24h}
                            </span>
                            <span className={`material-symbols-outlined text-[16px] ${TREND_CLASS[s.trend]}`}>{TREND_ICON[s.trend]}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                <button onClick={generateBriefing}
                  className="w-full flex items-center justify-center gap-2 px-4 py-3 bg-blue-500/10 border border-blue-500/20 text-blue-400 font-bold rounded-xl hover:bg-blue-500/20 transition-colors text-sm">
                  <span className="material-symbols-outlined text-[16px]">trip_origin</span>
                  Generate Aegis Briefing
                </button>
                <Link href="/aegis?context=threat_correlation"
                  className="w-full flex items-center justify-center gap-2 px-4 py-3 bg-white/5 border border-white/10 text-neutral-400 font-bold rounded-xl hover:bg-white/10 transition-colors text-sm">
                  <span className="material-symbols-outlined text-[16px]">chat</span>
                  Ask Aegis to Investigate
                </Link>
              </div>

              {/* Cluster panel */}
              <div className="col-span-8 space-y-4">
                <div className="bg-[#131313] border border-white/5 rounded-2xl overflow-hidden">
                  <div className="px-6 py-4 border-b border-white/5">
                    <h2 className="font-headline font-bold">Detected Attack Clusters</h2>
                    <p className="text-[10px] font-technical text-neutral-500 mt-0.5">Computed from live ledger — updates on page refresh</p>
                  </div>
                  {clusters.length === 0 ? (
                    <div className="p-12 text-center text-neutral-600 font-technical text-xs">
                      <span className="material-symbols-outlined text-4xl opacity-20 block mb-2">hub</span>
                      No attack clusters detected. The platform has not recorded any blocked events yet.
                    </div>
                  ) : (
                    <div className="divide-y divide-white/5">
                      {clusters.map(c => (
                        <div key={c.key} className="px-6 py-5">
                          <div className="flex items-start justify-between gap-4">
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center gap-3 mb-2">
                                <span className={`px-2 py-0.5 rounded border text-[10px] font-technical font-bold uppercase ${SEVERITY_CLASSES[c.severity]}`}>
                                  {c.severity}
                                </span>
                                <p className="font-bold text-sm text-on-surface">{c.label}</p>
                              </div>
                              <div className="flex flex-wrap gap-4 text-xs font-technical text-neutral-400">
                                <span className="flex items-center gap-1">
                                  <span className="material-symbols-outlined text-[14px]">bar_chart</span>
                                  {c.count} event{c.count !== 1 ? 's' : ''}
                                </span>
                                <span className="flex items-center gap-1">
                                  <span className="material-symbols-outlined text-[14px]">smart_toy</span>
                                  {c.agentCount} agent{c.agentCount !== 1 ? 's' : ''}
                                </span>
                                {c.tenantCount > 0 && (
                                  <span className="flex items-center gap-1">
                                    <span className="material-symbols-outlined text-[14px]">business</span>
                                    {c.tenantCount} tenant{c.tenantCount !== 1 ? 's' : ''}
                                  </span>
                                )}
                                <span className="flex items-center gap-1">
                                  <span className="material-symbols-outlined text-[14px]">schedule</span>
                                  First {new Date(c.firstSeen).toLocaleDateString()}
                                </span>
                                <span className="flex items-center gap-1">
                                  <span className="material-symbols-outlined text-[14px]">update</span>
                                  Last {new Date(c.lastSeen).toLocaleString()}
                                </span>
                              </div>
                              <p className="mt-2 px-2 py-1 bg-white/5 rounded font-technical text-[10px] text-neutral-500 inline-block">{c.key}</p>
                            </div>
                            <div className="flex flex-col gap-2 flex-shrink-0">
                              <Link href={`/pipeline?trace=${c.exampleTrace}`}
                                className="flex items-center gap-1.5 px-3 py-1.5 bg-white/5 border border-white/10 text-neutral-400 rounded-lg text-[11px] font-bold hover:bg-white/10 transition-colors whitespace-nowrap">
                                <span className="material-symbols-outlined text-[13px]">open_in_new</span>Example Trace
                              </Link>
                              <Link href={`/agent-admin/rogue`}
                                className="flex items-center gap-1.5 px-3 py-1.5 bg-white/5 border border-white/10 text-neutral-400 rounded-lg text-[11px] font-bold hover:bg-white/10 transition-colors whitespace-nowrap">
                                <span className="material-symbols-outlined text-[13px]">gpp_bad</span>All Events
                              </Link>
                              <Link href={`/aegis?context=violation:${encodeURIComponent(c.key)}`}
                                className="flex items-center gap-1.5 px-3 py-1.5 bg-blue-500/10 border border-blue-500/20 text-blue-400 rounded-lg text-[11px] font-bold hover:bg-blue-500/20 transition-colors whitespace-nowrap">
                                <span className="material-symbols-outlined text-[13px]">trip_origin</span>Ask Aegis
                              </Link>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {briefing && (
                  <div className="bg-blue-500/5 border border-blue-500/20 rounded-2xl p-5">
                    <div className="flex items-center gap-2 mb-3">
                      <span className="material-symbols-outlined text-blue-400 text-[18px]">trip_origin</span>
                      <p className="font-bold text-blue-300 text-sm">Aegis-0 Threat Briefing</p>
                      <span className="ml-auto text-[10px] font-technical text-neutral-500">Generated from live ledger data</span>
                    </div>
                    <p className="font-technical text-xs text-neutral-400 whitespace-pre-line leading-relaxed">{briefing}</p>
                    <Link href="/aegis?context=threat_briefing"
                      className="mt-3 inline-flex items-center gap-2 text-blue-400 hover:text-blue-300 text-xs font-bold font-technical transition-colors">
                      Continue in Aegis Chat →
                    </Link>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </main>
    </>
  );
}
