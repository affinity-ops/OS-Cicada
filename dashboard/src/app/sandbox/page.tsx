// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Shadow Sandbox — Ghost Mode Monitoring Station
//
// This page provides real-time visual monitoring of agents diverted to the
// Shadow Sandbox via Ghost Mode. Operators can observe intercepted requests,
// inspect anomaly findings, and take action (quarantine / release) directly.
//
// Data flow: Dashboard → Core API (sandboxEvents enrichment) → Shadow Sandbox
// SQLite. Polls every 5 seconds for near-real-time updates.

'use client';
import { operatorFetch } from '@/lib/operatorFetch';
import { useState, useEffect, useMemo } from 'react';
import { Sidebar } from '../../components/Sidebar';
import { TopAppBar } from '../../components/TopAppBar';
import { useToast } from '../../components/ToastContext';

const API = process.env.NEXT_PUBLIC_CORE_API_URL ?? 'http://localhost:8000';

// ── Types ────────────────────────────────────────────────────────────────────

/** A single parsed anomaly finding from the analyzer's 7-rule engine. */
type Finding = {
  rule: string;
  score: number;
  hit: string;
};

/** A single intercepted sandbox event, enriched by the Core API proxy. */
type SandboxEvent = {
  id: number;
  agent_id: string;
  agent_name: string;
  tenant_id: string;
  trace_id: string;
  method: string;
  target_url: string;
  anomaly_score: number;
  findings: string;
  findings_parsed: Finding[];
  sent_to_gossip: boolean;
  recorded_at: string;
  created_at: string;
  body_snapshot: string;
};

/** Summary statistics computed server-side in DashboardController. */
type SandboxSummary = {
  total_events: number;
  unique_agents: number;
  high_risk_count: number;
  quarantine_count: number;
};

/** Hourly activity bucket for the timeline chart. */
type ActivityBucket = {
  hour: string;
  count: number;
  high_risk: number;
};

// ── Helpers ──────────────────────────────────────────────────────────────────

/** Returns a 4-tier severity class based on anomaly score. */
function severityClass(score: number): string {
  if (score >= 0.85) return 'critical';
  if (score >= 0.70) return 'high';
  if (score >= 0.40) return 'medium';
  return 'low';
}

/** Returns Tailwind-compatible colour tokens for the severity tier. */
function severityColors(tier: string): { bg: string; text: string; border: string; glow: string } {
  switch (tier) {
    case 'critical': return { bg: 'bg-red-500/10', text: 'text-red-500', border: 'border-red-500/30', glow: 'shadow-[0_0_20px_rgba(239,68,68,0.3)]' };
    case 'high':     return { bg: 'bg-orange-500/10', text: 'text-orange-500', border: 'border-orange-500/30', glow: 'shadow-[0_0_15px_rgba(249,115,22,0.2)]' };
    case 'medium':   return { bg: 'bg-amber-500/10', text: 'text-amber-400', border: 'border-amber-500/20', glow: '' };
    default:         return { bg: 'bg-green-500/10', text: 'text-green-400', border: 'border-green-500/20', glow: '' };
  }
}

/** Human-readable label for anomaly detection rules. */
function ruleLabel(rule: string): string {
  const labels: Record<string, string> = {
    destructive_sql:          'Destructive SQL',
    sql_injection:            'SQL Injection',
    credential_in_body:       'Credential Leak',
    prompt_injection_in_body: 'Prompt Injection',
    bulk_email_extraction:    'Bulk Email Exfil',
    large_base64_payload:     'Base64 Exfil',
    oversized_body:           'Oversized Body',
    destructive_method:       'HTTP DELETE',
  };
  return labels[rule] ?? rule;
}

/** Formats an ISO timestamp to a concise locale string. */
function formatTime(ts: string): string {
  if (!ts) return '—';
  try {
    const d = new Date(ts);
    if (isNaN(d.getTime())) return '—';
    return d.toLocaleString(undefined, {
      month: 'short', day: 'numeric',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
    });
  } catch {
    return '—';
  }
}

// ── Component ────────────────────────────────────────────────────────────────

export default function SandboxMonitor() {
  const [events, setEvents] = useState<SandboxEvent[]>([]);
  const [summary, setSummary] = useState<SandboxSummary>({ total_events: 0, unique_agents: 0, high_risk_count: 0, quarantine_count: 0 });
  const [timeline, setTimeline] = useState<ActivityBucket[]>([]);
  const [loading, setLoading] = useState(true);
  const [errorMsg, setErrorMsg] = useState('');
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const [selectedAgent, setSelectedAgent] = useState<string | null>(null);
  const [actionInProgress, setActionInProgress] = useState<string | null>(null);
  const { showToast } = useToast();

  // ── Data fetching (polls every 5 seconds) ────────────────────────────────
  const loadData = async () => {
    try {
      const res = await operatorFetch(`${API}/api/v1/sandbox/events`, { cache: 'no-store' });
      if (!res.ok) throw new Error('Fetch failed');
      const data = await res.json();
      if (data.error) {
        setErrorMsg(data.error);
        showToast('Shadow Sandbox offline or unreachable.');
      } else {
        setEvents(data.events || []);
        setSummary(data.summary || { total_events: 0, unique_agents: 0, high_risk_count: 0, quarantine_count: 0 });
        setTimeline(data.activity_timeline || []);
        setErrorMsg('');
      }
    } catch {
      setErrorMsg('Failed to connect to sandbox API.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
    const intv = setInterval(loadData, 5000);
    return () => clearInterval(intv);
  }, []);

  // ── Derived: group events by agent for the agent panel ────────────────────
  const agentGroups = useMemo(() => {
    const groups: Record<string, {
      agent_id: string;
      agent_name: string;
      events: SandboxEvent[];
      maxScore: number;
      lastSeen: string;
      targetApis: Set<string>;
    }> = {};

    for (const evt of events) {
      if (!groups[evt.agent_id]) {
        groups[evt.agent_id] = {
          agent_id: evt.agent_id,
          agent_name: evt.agent_name || `Agent-${evt.agent_id.substring(0, 8).toUpperCase()}`,
          events: [],
          maxScore: 0,
          lastSeen: '',
          targetApis: new Set(),
        };
      }
      const g = groups[evt.agent_id];
      g.events.push(evt);
      if (evt.anomaly_score > g.maxScore) g.maxScore = evt.anomaly_score;
      if (!g.lastSeen || evt.recorded_at > g.lastSeen) g.lastSeen = evt.recorded_at;
      if (evt.target_url) g.targetApis.add(new URL(evt.target_url).hostname);
    }

    // Sort by highest anomaly score descending.
    return Object.values(groups).sort((a, b) => b.maxScore - a.maxScore);
  }, [events]);

  // ── Filtered events (by selected agent, if any) ──────────────────────────
  const filteredEvents = useMemo(() => {
    if (!selectedAgent) return events;
    return events.filter(e => e.agent_id === selectedAgent);
  }, [events, selectedAgent]);

  // ── Ghost Mode action (quarantine / release) ─────────────────────────────
  const handleGhostAction = async (agentId: string, action: 'activate' | 'release') => {
    setActionInProgress(agentId + action);
    try {
      const res = await operatorFetch(`${API}/api/v1/shadow-mode`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ agent_ids: [agentId], action }),
      });
      if (res.ok) {
        showToast(action === 'activate'
          ? 'Agent quarantined — routed to sandbox.'
          : 'Agent released — returning to normal routing.');
        await loadData();
      } else {
        showToast('Action failed. Check gateway connectivity.');
      }
    } catch {
      showToast('Network error. Gateway may be unreachable.');
    } finally {
      setActionInProgress(null);
    }
  };

  // ── Timeline chart: find max count for scaling ───────────────────────────
  const maxTimelineCount = useMemo(() => {
    return Math.max(1, ...timeline.map(t => t.count));
  }, [timeline]);

  // ════════════════════════════════════════════════════════════════════════════
  // RENDER
  // ════════════════════════════════════════════════════════════════════════════

  return (
    <>
      <Sidebar />
      <TopAppBar />

      <main
        className="pt-24 pb-12 px-8 min-h-screen bg-background relative z-10"
        style={{ marginLeft: 'var(--sidebar-width, 18rem)' }}
      >
        {/* ── Header ─────────────────────────────────────────────────── */}
        <section className="mb-8 flex justify-between items-end">
          <div>
            <h1 className="text-4xl font-headline font-black text-on-surface tracking-tighter mb-1 uppercase">
              Shadow Sandbox
            </h1>
            <p className="text-xs font-technical text-purple-400 uppercase tracking-widest bg-purple-500/10 inline-block px-3 py-1 rounded-full border border-purple-500/20">
              Ghost Mode — Live Agent Observation
            </p>
          </div>
          <div className="flex gap-3">
            {selectedAgent && (
              <button
                onClick={() => setSelectedAgent(null)}
                className="px-4 py-2 border border-purple-500/30 bg-purple-500/10 text-purple-400 hover:bg-purple-500/20 transition-colors uppercase font-technical text-xs flex items-center gap-2 rounded"
              >
                <span className="material-symbols-outlined text-sm">close</span> Clear Filter
              </button>
            )}
            <button
              onClick={loadData}
              className="px-4 py-2 border border-white/20 hover:bg-white/10 transition-colors uppercase font-technical text-xs flex items-center gap-2 rounded"
            >
              <span className="material-symbols-outlined text-sm">refresh</span> Refresh
            </button>
          </div>
        </section>

        {/* ── Error banner ───────────────────────────────────────────── */}
        {errorMsg && (
          <div className="mb-6 bg-red-900/20 border border-red-500/50 text-red-200 p-4 rounded-lg text-sm font-technical uppercase flex items-center gap-2">
            <span className="material-symbols-outlined align-middle">error</span>
            {errorMsg}
          </div>
        )}

        {/* ── Summary Stat Cards ─────────────────────────────────────── */}
        <section className="grid grid-cols-4 gap-4 mb-8">
          {[
            { label: 'Total Captures', value: summary.total_events, icon: 'inbox', color: 'text-blue-400', borderColor: 'border-blue-500/20' },
            { label: 'Monitored Agents', value: summary.unique_agents, icon: 'smart_toy', color: 'text-purple-400', borderColor: 'border-purple-500/20' },
            { label: 'High Risk Events', value: summary.high_risk_count, icon: 'warning', color: 'text-orange-500', borderColor: 'border-orange-500/20' },
            { label: 'Auto-Quarantined', value: summary.quarantine_count, icon: 'podcasts', color: 'text-red-500', borderColor: 'border-red-500/20' },
          ].map(card => (
            <div key={card.label} className={`bg-[#111] border ${card.borderColor} rounded-xl p-5 relative overflow-hidden`}>
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-[10px] font-technical text-neutral-500 uppercase tracking-widest mb-1">{card.label}</p>
                  <p className={`text-3xl font-headline font-black ${card.color}`}>{card.value}</p>
                </div>
                <span className={`material-symbols-outlined text-3xl ${card.color} opacity-30`}>{card.icon}</span>
              </div>
              {/* Decorative glow for non-zero high-risk cards */}
              {card.label === 'High Risk Events' && card.value > 0 && (
                <div className="absolute -bottom-4 -right-4 w-24 h-24 bg-orange-500/10 rounded-full blur-2xl pointer-events-none" />
              )}
              {card.label === 'Auto-Quarantined' && card.value > 0 && (
                <div className="absolute -bottom-4 -right-4 w-24 h-24 bg-red-500/10 rounded-full blur-2xl pointer-events-none" />
              )}
            </div>
          ))}
        </section>

        {/* ── Activity Timeline Chart ────────────────────────────────── */}
        {timeline.length > 0 && (
          <section className="mb-8 bg-[#111] border border-white/5 rounded-xl p-6">
            <h2 className="text-xs font-headline font-bold text-white uppercase tracking-widest mb-4 flex items-center gap-2">
              <span className="material-symbols-outlined text-sm text-purple-400">timeline</span>
              Activity Timeline
            </h2>
            <div className="flex items-end gap-1 h-24">
              {timeline.map((bucket, i) => {
                const heightPct = Math.max(4, (bucket.count / maxTimelineCount) * 100);
                const highRiskPct = bucket.count > 0 ? (bucket.high_risk / bucket.count) * 100 : 0;
                const hourLabel = bucket.hour.split(' ')[1] ?? '';
                return (
                  <div key={i} className="flex-1 flex flex-col items-center group relative">
                    {/* Tooltip on hover */}
                    <div className="absolute -top-10 hidden group-hover:flex bg-black/90 border border-white/10 rounded px-2 py-1 text-[9px] font-technical text-neutral-300 whitespace-nowrap z-30">
                      {bucket.count} events · {bucket.high_risk} high risk
                    </div>
                    <div
                      className="w-full rounded-t relative overflow-hidden transition-all"
                      style={{ height: `${heightPct}%` }}
                    >
                      {/* Normal portion */}
                      <div className="absolute bottom-0 left-0 right-0 bg-purple-500/40 rounded-t" style={{ height: '100%' }} />
                      {/* High-risk overlay */}
                      {highRiskPct > 0 && (
                        <div className="absolute bottom-0 left-0 right-0 bg-red-500/60 rounded-t" style={{ height: `${highRiskPct}%` }} />
                      )}
                    </div>
                    {/* Hour label (show every 3rd to avoid crowding) */}
                    {i % 3 === 0 && (
                      <span className="text-[8px] font-technical text-neutral-600 mt-1">{hourLabel}</span>
                    )}
                  </div>
                );
              })}
            </div>
            <div className="flex gap-4 mt-3 text-[9px] font-technical text-neutral-500">
              <span className="flex items-center gap-1"><span className="w-2 h-2 bg-purple-500/40 rounded-sm inline-block" /> Normal</span>
              <span className="flex items-center gap-1"><span className="w-2 h-2 bg-red-500/60 rounded-sm inline-block" /> High Risk (≥0.70)</span>
            </div>
          </section>
        )}

        {/* ── Monitored Agents Panel ─────────────────────────────────── */}
        {agentGroups.length > 0 && (
          <section className="mb-8">
            <h2 className="text-xs font-headline font-bold text-white uppercase tracking-widest mb-4 flex items-center gap-2">
              <span className="material-symbols-outlined text-sm text-purple-400">smart_toy</span>
              Monitored Agents
              <span className="text-neutral-600">({agentGroups.length})</span>
            </h2>
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
              {agentGroups.map(agent => {
                const tier = severityClass(agent.maxScore);
                const colors = severityColors(tier);
                const isSelected = selectedAgent === agent.agent_id;
                const apis = Array.from(agent.targetApis).slice(0, 3);

                return (
                  <div
                    key={agent.agent_id}
                    onClick={() => setSelectedAgent(isSelected ? null : agent.agent_id)}
                    className={`bg-[#131313] rounded-xl p-5 cursor-pointer transition-all border relative overflow-hidden group
                      ${isSelected ? 'border-purple-500/50 ring-1 ring-purple-500/20' : `${colors.border} hover:border-white/20`}
                      ${colors.glow}`}
                  >
                    {/* Severity badge */}
                    <div className={`absolute top-0 right-0 py-1 px-3 border-b border-l rounded-bl-lg text-[10px] font-technical uppercase font-bold tracking-wider ${colors.bg} ${colors.border} ${colors.text}`}>
                      {tier === 'critical' ? 'Auto-Quarantine' : tier === 'high' ? 'High Risk' : tier === 'medium' ? 'Suspicious' : 'Nominal'}
                    </div>

                    {/* Agent identity */}
                    <div className="flex items-center gap-3 mb-3">
                      <div className={`w-10 h-10 border rounded-full flex items-center justify-center ${colors.bg} ${colors.text} ${colors.border}`}>
                        <span className="material-symbols-outlined text-lg">smart_toy</span>
                      </div>
                      <div className="min-w-0 flex-1">
                        <h3 className="text-sm font-headline font-bold text-on-surface truncate">{agent.agent_name}</h3>
                        <p className="text-[10px] text-neutral-500 font-technical truncate">
                          {agent.events.length} requests · Last seen {formatTime(agent.lastSeen)}
                        </p>
                      </div>
                    </div>

                    {/* Target APIs */}
                    <div className="flex flex-wrap gap-1 mb-3">
                      {apis.map(api => (
                        <span key={api} className="text-[9px] font-technical text-neutral-400 bg-white/5 px-2 py-0.5 rounded border border-white/5">
                          {api}
                        </span>
                      ))}
                      {agent.targetApis.size > 3 && (
                        <span className="text-[9px] font-technical text-neutral-600">+{agent.targetApis.size - 3} more</span>
                      )}
                    </div>

                    {/* Anomaly score bar */}
                    <div className="mb-3">
                      <div className="flex justify-between text-[9px] font-technical text-neutral-500 mb-1">
                        <span>Peak Anomaly</span>
                        <span className={colors.text}>{Math.round(agent.maxScore * 100)}%</span>
                      </div>
                      <div className="w-full h-1.5 bg-white/5 rounded-full overflow-hidden">
                        <div
                          className={`h-full rounded-full transition-all duration-500 ${
                            tier === 'critical' ? 'bg-red-500' :
                            tier === 'high' ? 'bg-orange-500' :
                            tier === 'medium' ? 'bg-amber-400' : 'bg-green-500'
                          }`}
                          style={{ width: `${Math.max(2, agent.maxScore * 100)}%` }}
                        />
                      </div>
                    </div>

                    {/* Action buttons */}
                    <div className="grid grid-cols-2 gap-2">
                      <button
                        onClick={(e) => { e.stopPropagation(); handleGhostAction(agent.agent_id, 'activate'); }}
                        disabled={actionInProgress === agent.agent_id + 'activate'}
                        className="py-2 bg-red-500/10 hover:bg-red-500/20 border border-red-500/20 text-red-400 rounded-lg text-[10px] font-technical uppercase font-bold tracking-wider transition-colors disabled:opacity-50 flex items-center justify-center gap-1"
                      >
                        <span className="material-symbols-outlined text-xs">shield</span>
                        Quarantine
                      </button>
                      <button
                        onClick={(e) => { e.stopPropagation(); handleGhostAction(agent.agent_id, 'release'); }}
                        disabled={actionInProgress === agent.agent_id + 'release'}
                        className="py-2 bg-green-500/10 hover:bg-green-500/20 border border-green-500/20 text-green-400 rounded-lg text-[10px] font-technical uppercase font-bold tracking-wider transition-colors disabled:opacity-50 flex items-center justify-center gap-1"
                      >
                        <span className="material-symbols-outlined text-xs">lock_open</span>
                        Release
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          </section>
        )}

        {/* ── Live Event Feed ─────────────────────────────────────────── */}
        <section className="bg-[#111] border border-white/5 rounded-2xl overflow-hidden shadow-2xl relative">
          {/* Decorative background icon */}
          <div className="absolute top-0 right-0 p-8 opacity-5 pointer-events-none">
            <span className="material-symbols-outlined text-9xl text-purple-500">grid_goldenratio</span>
          </div>

          {/* Section header */}
          <div className="bg-[#181818] border-b border-white/5 px-6 py-4 flex items-center gap-4 relative z-10">
            <h3 className="text-xs font-headline font-bold text-white uppercase tracking-widest flex-1 flex items-center gap-2">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-purple-400 opacity-75" />
                <span className="relative inline-flex rounded-full h-2 w-2 bg-purple-500" />
              </span>
              Live Intercepted Traffic
              {selectedAgent && (
                <span className="text-purple-400 ml-2">
                  — {agentGroups.find(a => a.agent_id === selectedAgent)?.agent_name ?? selectedAgent.substring(0, 8)}
                </span>
              )}
            </h3>
            <div className="flex gap-4 font-technical text-xs text-neutral-400 uppercase">
              <span>{filteredEvents.length} Events</span>
            </div>
          </div>

          {/* Event table */}
          <div className="overflow-x-auto relative z-10">
            {loading && events.length === 0 ? (
              <div className="p-12 text-center text-neutral-500 font-technical text-xs tracking-widest uppercase animate-pulse">
                <span className="material-symbols-outlined text-4xl block mb-2 opacity-30">radar</span>
                Intercepting ghost-mode traffic...
              </div>
            ) : filteredEvents.length === 0 && !errorMsg ? (
              <div className="p-12 text-center text-neutral-500 font-technical text-sm flex flex-col items-center gap-2">
                <span className="material-symbols-outlined text-4xl opacity-20">check_circle</span>
                No active captures in the shadow sandbox.
              </div>
            ) : (
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="bg-[#181818]/50 border-b border-white/5 text-[10px] font-technical text-neutral-500 uppercase tracking-wider">
                    <th className="p-4 font-normal w-8" />
                    <th className="p-4 font-normal">Time</th>
                    <th className="p-4 font-normal">Agent</th>
                    <th className="p-4 font-normal">Method / Target</th>
                    <th className="p-4 font-normal">Anomaly</th>
                    <th className="p-4 font-normal">Findings</th>
                    <th className="p-4 font-normal">Gossip</th>
                  </tr>
                </thead>
                <tbody className="text-xs font-technical text-neutral-300">
                  {filteredEvents.map((evt) => {
                    const tier = severityClass(evt.anomaly_score);
                    const colors = severityColors(tier);
                    const isExpanded = expandedId === evt.id;
                    const findings: Finding[] = evt.findings_parsed || [];

                    return (
                      <>
                        {/* Main row */}
                        <tr
                          key={evt.id}
                          onClick={() => setExpandedId(isExpanded ? null : evt.id)}
                          className={`border-b border-white/5 cursor-pointer transition-colors
                            ${isExpanded ? 'bg-white/[0.04]' : 'hover:bg-white/[0.02]'}
                            ${tier === 'critical' ? 'bg-red-500/[0.03]' : ''}`}
                        >
                          {/* Expand chevron */}
                          <td className="p-4 text-neutral-600">
                            <span className={`material-symbols-outlined text-sm transition-transform ${isExpanded ? 'rotate-90' : ''}`}>
                              chevron_right
                            </span>
                          </td>

                          {/* Timestamp */}
                          <td className="p-4 whitespace-nowrap text-neutral-500">
                            {formatTime(evt.recorded_at)}
                          </td>

                          {/* Agent name */}
                          <td className="p-4 text-purple-300 truncate max-w-[140px]" title={evt.agent_id}>
                            {evt.agent_name}
                          </td>

                          {/* Method + Target */}
                          <td className="p-4">
                            <span className={`inline-block px-1.5 mr-2 rounded text-[10px] font-bold border ${
                              evt.method === 'GET'    ? 'border-green-500/20 text-green-400 bg-green-500/10' :
                              evt.method === 'POST'   ? 'border-blue-500/20 text-blue-400 bg-blue-500/10' :
                              evt.method === 'PUT'    ? 'border-amber-500/20 text-amber-400 bg-amber-500/10' :
                              evt.method === 'DELETE' ? 'border-red-500/20 text-red-400 bg-red-500/10' :
                              'border-neutral-500/20 text-neutral-400 bg-neutral-500/10'
                            }`}>{evt.method}</span>
                            <span className="text-neutral-400">{evt.target_url}</span>
                          </td>

                          {/* Anomaly score */}
                          <td className="p-4">
                            <span className={`px-2 py-0.5 rounded border font-bold ${colors.bg} ${colors.text} ${colors.border}`}>
                              {Math.round(evt.anomaly_score * 100)}%
                            </span>
                          </td>

                          {/* Findings count */}
                          <td className="p-4">
                            {findings.length > 0 ? (
                              <span className={`text-[10px] ${colors.text}`}>
                                {findings.length} rule{findings.length !== 1 ? 's' : ''} triggered
                              </span>
                            ) : (
                              <span className="text-neutral-600 text-[10px]">Clean</span>
                            )}
                          </td>

                          {/* Gossip status */}
                          <td className="p-4">
                            {evt.sent_to_gossip ? (
                              <span className="text-red-500 material-symbols-outlined text-[14px]" title="Reported to Gossip Mesh">
                                podcasts
                              </span>
                            ) : (
                              <span className="text-neutral-700">—</span>
                            )}
                          </td>
                        </tr>

                        {/* Expanded detail row */}
                        {isExpanded && (
                          <tr key={`${evt.id}-detail`} className="bg-[#0a0a0a] border-b border-white/5">
                            <td colSpan={7} className="p-6">
                              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                                {/* Left: Findings breakdown */}
                                <div>
                                  <h4 className="text-[10px] font-technical text-neutral-500 uppercase tracking-widest mb-3">
                                    Anomaly Findings
                                  </h4>
                                  {findings.length > 0 ? (
                                    <div className="space-y-2">
                                      {findings.map((f, fi) => {
                                        const fTier = severityClass(f.score);
                                        const fColors = severityColors(fTier);
                                        return (
                                          <div key={fi} className={`flex items-center gap-3 p-3 rounded-lg border ${fColors.border} ${fColors.bg}`}>
                                            <span className={`material-symbols-outlined text-sm ${fColors.text}`}>
                                              {fTier === 'critical' ? 'dangerous' : fTier === 'high' ? 'warning' : 'info'}
                                            </span>
                                            <div className="flex-1 min-w-0">
                                              <p className={`text-xs font-bold ${fColors.text}`}>{ruleLabel(f.rule)}</p>
                                              <p className="text-[10px] text-neutral-500 truncate">{f.hit || 'No detail'}</p>
                                            </div>
                                            <span className={`text-xs font-bold ${fColors.text}`}>
                                              {Math.round(f.score * 100)}%
                                            </span>
                                          </div>
                                        );
                                      })}
                                    </div>
                                  ) : (
                                    <p className="text-neutral-600 text-xs">No anomalies detected in this request.</p>
                                  )}
                                </div>

                                {/* Right: Metadata + body snapshot */}
                                <div>
                                  <h4 className="text-[10px] font-technical text-neutral-500 uppercase tracking-widest mb-3">
                                    Request Metadata
                                  </h4>
                                  <div className="space-y-2 text-xs">
                                    <div className="flex gap-2">
                                      <span className="text-neutral-600 w-20 shrink-0">Trace ID</span>
                                      <span className="font-mono text-cyan-300/70 truncate">{evt.trace_id}</span>
                                    </div>
                                    <div className="flex gap-2">
                                      <span className="text-neutral-600 w-20 shrink-0">Agent ID</span>
                                      <span className="font-mono text-neutral-400 truncate">{evt.agent_id}</span>
                                    </div>
                                    <div className="flex gap-2">
                                      <span className="text-neutral-600 w-20 shrink-0">Tenant</span>
                                      <span className="text-neutral-400">{evt.tenant_id || 'Not set'}</span>
                                    </div>
                                  </div>

                                  <h4 className="text-[10px] font-technical text-neutral-500 uppercase tracking-widest mt-5 mb-3">
                                    Body Snapshot
                                  </h4>
                                  <div className="font-mono text-[10px] bg-black/50 p-3 rounded-lg border border-white/5 whitespace-pre-wrap max-h-32 overflow-y-auto text-cyan-200/70">
                                    {evt.body_snapshot || 'Empty body — no data transmitted in this request.'}
                                  </div>
                                </div>
                              </div>
                            </td>
                          </tr>
                        )}
                      </>
                    );
                  })}
                </tbody>
              </table>
            )}
          </div>
        </section>
      </main>
    </>
  );
}
