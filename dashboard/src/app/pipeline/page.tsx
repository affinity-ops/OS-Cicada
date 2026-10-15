// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

'use client';
import { operatorFetch } from '@/lib/operatorFetch';

import { useState, useEffect, Suspense } from 'react';
import Link from 'next/link';
import { useSearchParams } from 'next/navigation';
import { Sidebar } from '../../components/Sidebar';
import { TopAppBar } from '../../components/TopAppBar';

interface LedgerEntry {
  trace_id: string;
  agent_id: string;
  agent_name: string | null;
  tenant_id: string;
  tenant_name: string;
  action_type: string;
  payload_hash: string;
  target_api: string;
  status: string;
  swarm_confidence_score: number | null;
  semantic_alignment_score: number | null;
  reasoning_trace: string | null;
  policy_violations: string | null;
  reason: string | null;
  evidence: string | null;
  trust_tier: string | null;
  scope_entitlements: string | null;
  human_user_context: string | null;
  created_at: string;
}

const API = process.env.NEXT_PUBLIC_CORE_API_URL ?? 'http://localhost:8000';

function buildStages(entry: LedgerEntry) {
  const blocked  = entry.status === 'blocked';
  const ghost    = entry.status === 'shadow_sandbox';
  const approved = entry.status === 'approved';

  const violations = entry.policy_violations ? (() => { try { return JSON.parse(entry.policy_violations); } catch { return entry.policy_violations; } })() : null;
  const blockReason = Array.isArray(violations) ? violations.join(', ') : (typeof violations === 'string' ? violations : entry.action_type);

  return [
    { id: 1, num: '1',   title: 'Identity Resolution',           desc: 'EVAR Validated',           ms: '—',    state: 'pass' as const },
    { id: 2, num: '2&3', title: 'Scope & Budget',                 desc: 'Scope checked',            ms: '—',    state: 'pass' as const },
    { id: 3, num: '4',   title: 'Data Sensitivity Scan',          desc: 'Payload hashed',           ms: '—',    state: 'pass' as const },
    {
      id: 4, num: '5', title: 'Alignment Shield (Trust Evaluation)',
      desc: blocked ? `Blocked: ${blockReason}` : 'Trust evaluation passed',
      ms: '—',
      state: blocked ? 'block' as const : 'pass' as const,
      subLog: blocked ? [
        { label: 'Action Type:',      val: entry.action_type, err: true  },
        { label: 'Target:',           val: entry.target_api,  err: false },
        { label: 'Decision:',         val: 'BLOCKED',         pulse: false, err: true },
      ] : undefined,
    },
    {
      id: 5, num: '6&7', title: 'Approval Gate & Proxy',
      desc: ghost ? 'Ghost Mode — Sandbox' : blocked ? 'Pending' : 'Proxy Complete',
      ms: '—',
      state: blocked ? 'pending' as const : 'pass' as const,
    },
    {
      id: 6, num: '8-10', title: 'Attestation Ledger',
      desc: blocked ? 'Pending' : 'Ledger entry written',
      ms: '—',
      state: blocked ? 'pending' as const : 'pass' as const,
    },
  ];
}

function buildLogs(entry: LedgerEntry) {
  const t = new Date(entry.created_at).toLocaleTimeString();
  const logs = [
    { time: t, sys: 'Gateway',   msg: `Received request from ${entry.agent_name ?? entry.agent_id}`, isError: false, isPulse: false, mapsToNode: 1 },
    { time: t, sys: 'Sentry',    msg: `EVAR validated — tenant: ${entry.tenant_name}`, isError: false, isPulse: false, mapsToNode: 1 },
    { time: t, sys: 'Swarm',     msg: `Payload hash: ${(entry.payload_hash ?? '').substring(0, 32)}...`, isError: false, isPulse: false, mapsToNode: 3 },
  ];
  if (entry.status === 'blocked') {
    logs.push({ time: t, sys: 'Interceptor', msg: `⚠ Execution Intercepted: ${entry.action_type}`, isError: true, isPulse: false, mapsToNode: 4 });
    logs.push({ time: t, sys: 'Gateway',     msg: `✗ BLOCKED → ${entry.target_api}`, isError: true, isPulse: false, mapsToNode: 4 });
    logs.push({ time: t, sys: 'Kernel',      msg: `> Suspending EVAR identity...`, isError: false, isPulse: true, mapsToNode: 4 });
  } else if (entry.status === 'shadow_sandbox') {
    logs.push({ time: t, sys: 'ShadowSandbox', msg: `Ghost mode active — request diverted to sandbox`, isError: false, isPulse: false, mapsToNode: 5 });
    logs.push({ time: t, sys: 'Kernel',         msg: `✓ Sandbox analysis complete`, isError: false, isPulse: true, mapsToNode: 5 });
  } else {
    logs.push({ time: t, sys: 'ActionProxy', msg: `Proxied request to ${entry.target_api}`, isError: false, isPulse: false, mapsToNode: 5 });
    if (entry.swarm_confidence_score !== null) {
      logs.push({ time: t, sys: 'Swarm', msg: `Confidence score: ${entry.swarm_confidence_score}`, isError: false, isPulse: false, mapsToNode: 5 });
    }
    logs.push({ time: t, sys: 'Ledger', msg: `✓ Trace recorded — ID: ${entry.trace_id}`, isError: false, isPulse: true, mapsToNode: 6 });
  }
  return logs;
}

function PipelineMonitorCore() {
  const searchParams = useSearchParams();
  const [entry, setEntry] = useState<LedgerEntry | null>(null);
  const [traces, setTraces] = useState<LedgerEntry[]>([]);
  const [mode, setMode] = useState<'intercept' | 'nominal'>('nominal');
  const [loading, setLoading] = useState(false);
  const [hoveredStageId, setHoveredStageId] = useState<number | null>(null);

  const loadTrace = (traceId: string) => {
    setLoading(true);
    operatorFetch(`${API}/api/v1/logs/${encodeURIComponent(traceId)}`)
      .then(r => r.json())
      .then(body => { if (body.status === 'success') setEntry(body.data); })
      .catch(() => {})
      .finally(() => setLoading(false));
  };

  const loadTraceList = () => {
    operatorFetch(`${API}/api/v1/logs?per_page=20`)
      .then(r => r.json())
      .then(body => { setTraces(body.data?.data ?? []); })
      .catch(() => {});
  };

  const loadByMode = (m: 'intercept' | 'nominal') => {
    setLoading(true);
    const status = m === 'intercept' ? 'blocked' : 'approved';
    operatorFetch(`${API}/api/v1/logs?status=${status}&per_page=1`)
      .then(r => r.json())
      .then(body => {
        const rows: LedgerEntry[] = body.data?.data ?? [];
        if (rows.length > 0) setEntry(rows[0]);
        else setEntry(null);
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    loadTraceList();
    const interval = setInterval(loadTraceList, 5000);
    const traceParam = searchParams.get('trace');
    if (traceParam) loadTrace(traceParam);
    else loadByMode('nominal');
    return () => clearInterval(interval);
  }, [searchParams]);

  const switchMode = (m: 'intercept' | 'nominal') => {
    setMode(m);
    loadByMode(m);
  };

  const stages = entry ? buildStages(entry) : [];
  const logs   = entry ? buildLogs(entry) : [];
  const trustScore = entry?.swarm_confidence_score !== null && entry?.swarm_confidence_score !== undefined
    ? Math.round(entry.swarm_confidence_score * 100)
    : entry?.status === 'blocked' ? 12 : 98;
  const isBlocked = entry?.status === 'blocked';

  return (
    <>
      <Sidebar />
      <TopAppBar />
      <main className="pt-24 px-8 pb-12 min-h-screen bg-background relative z-10 overflow-hidden transition-all duration-300" style={{ marginLeft: 'var(--sidebar-width, 18rem)', width: 'calc(100% - var(--sidebar-width, 18rem))' }}>
        <div className="absolute inset-0 z-0 pointer-events-none opacity-[0.03]"
             style={{ backgroundImage: 'linear-gradient(rgba(255,255,255,1) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,1) 1px, transparent 1px)', backgroundSize: '40px 40px' }}>
        </div>

        <div className="max-w-[95%] mx-auto space-y-8 relative z-10">

          {/* Header */}
          <section className="flex flex-col xl:flex-row justify-between items-end gap-6 bg-[#131313] p-8 rounded-2xl border border-white/5">
            <div className="space-y-4 w-full">
              <div className="flex items-center gap-3">
                <div className="px-3 py-1 bg-primary/20 text-primary text-[10px] font-black font-headline tracking-widest rounded-full uppercase border border-primary/20 flex items-center">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse mr-2"></span>
                  LIVE TRACE
                </div>
                <div className="flex bg-[#1a1a1a] border border-white/10 rounded-lg overflow-hidden ml-2">
                  <button onClick={() => switchMode('intercept')} className={`px-4 py-1.5 text-[10px] font-bold font-headline uppercase tracking-widest transition-colors ${mode === 'intercept' ? 'bg-error/20 text-error' : 'text-neutral-500 hover:text-white'}`}>Intercept Mode</button>
                  <button onClick={() => switchMode('nominal')}   className={`px-4 py-1.5 text-[10px] font-bold font-headline uppercase tracking-widest transition-colors ${mode === 'nominal'   ? 'bg-emerald-500/20 text-emerald-500' : 'text-neutral-500 hover:text-white'}`}>Nominal Mode</button>
                </div>
              </div>
              <h2 className="text-5xl font-black font-headline tracking-tighter uppercase leading-none">Pipeline <span className="text-primary">Monitor</span></h2>
              <p className="text-on-surface-variant max-w-2xl font-body text-sm leading-relaxed">
                Real-time execution visualization. Trace an individual agent&apos;s EVAR token as it propagates through the cryptographic pipeline.
              </p>
            </div>

            <div className="min-w-[320px] bg-[#1a1a1a] border border-white/10 rounded-xl p-5 flex flex-col gap-4 relative overflow-hidden">
              {loading ? (
                <div className="py-4 text-center text-neutral-500 font-technical text-xs animate-pulse">Loading trace...</div>
              ) : entry ? (
                <>
                  <div className="flex justify-between items-center">
                    <div className="flex items-center gap-3">
                      <div className="w-10 h-10 rounded-lg bg-surface-bright flex items-center justify-center border border-white/5">
                        <span className="material-symbols-outlined text-primary text-xl">smart_toy</span>
                      </div>
                      <div>
                        <h3 className="font-headline font-bold text-on-surface">{entry.agent_name ?? `Agent-${entry.agent_id.substring(0, 8)}`}</h3>
                        <p className="text-[10px] font-technical text-neutral-500">TENANT: {entry.tenant_name}</p>
                      </div>
                    </div>
                    <div className="text-right">
                      <p className={`text-2xl font-black font-headline ${isBlocked ? 'text-error' : 'text-emerald-500'}`}>{trustScore}<span className="text-xs text-neutral-500 font-medium">%</span></p>
                      <p className="text-[9px] font-technical text-neutral-500 uppercase">Confidence</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 bg-white/5 border border-white/10 rounded text-[9px] font-technical text-neutral-400">{entry.action_type.toUpperCase()}</span>
                    {isBlocked
                      ? <span className="px-2 py-0.5 bg-error/10 border border-error/20 rounded text-[9px] font-technical text-error">BLOCKED</span>
                      : <span className="px-2 py-0.5 bg-emerald-500/10 border border-emerald-500/20 rounded text-[9px] font-technical text-emerald-400">APPROVED</span>
                    }
                  </div>
                </>
              ) : (
                <div className="py-4 text-center text-neutral-600 font-technical text-xs">No trace data. Route traffic through the gateway first.</div>
              )}
            </div>
          </section>

          {/* Trace List */}
          <div className="bg-[#131313] rounded-2xl border border-white/5 p-4 overflow-hidden">
            <p className="text-[10px] font-headline font-bold tracking-widest uppercase text-neutral-500 mb-3">All Agent Traces — Live Feed</p>
            <div className="flex gap-2 flex-wrap">
              {traces.length === 0 && <p className="text-neutral-600 font-technical text-xs py-2">No traces yet.</p>}
              {traces.map(t => (
                <button key={t.trace_id} onClick={() => { setEntry(t); }}
                  className={`flex flex-col gap-1 px-3 py-2 rounded-xl border text-left transition-all ${entry?.trace_id === t.trace_id ? 'bg-primary/10 border-primary/40' : 'bg-[#1a1a1a] border-white/5 hover:border-white/20'}`}>
                  <div className="flex items-center gap-2">
                    <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${t.status === 'blocked' ? 'bg-error' : t.status === 'shadow_sandbox' ? 'bg-yellow-500' : 'bg-emerald-500'}`}></span>
                    <span className="font-technical text-[10px] text-neutral-300 font-bold">{t.agent_name ?? `Agent-${t.agent_id.substring(0, 8)}`}</span>
                  </div>
                  <span className={`text-[9px] font-technical font-bold uppercase ${t.status === 'blocked' ? 'text-error' : 'text-emerald-500'}`}>{t.status}</span>
                  <span className="text-[9px] font-technical text-neutral-600">{new Date(t.created_at).toLocaleTimeString()}</span>
                </button>
              ))}
            </div>
          </div>

          <div className="grid grid-cols-1 xl:grid-cols-12 gap-8">

            {/* Stage Flow Visualizer */}
            <div className="col-span-12 xl:col-span-8 bg-[#131313] rounded-2xl border border-white/5 p-8 flex flex-col min-h-[700px]">
              <div className="flex justify-between items-center mb-8 border-b border-white/5 pb-4">
                <h3 className="font-headline font-bold text-xl tracking-tight">Execution Telemetry Map</h3>
                <span className="text-xs font-technical text-neutral-400 bg-white/5 px-3 py-1.5 rounded-lg border border-white/10">
                  Trace ID: <span className="text-primary font-bold">{entry?.trace_id ?? '—'}</span>
                </span>
              </div>

              {!entry && !loading && (
                <div className="flex-1 flex flex-col items-center justify-center text-neutral-600 gap-3">
                  <span className="material-symbols-outlined text-5xl opacity-20">schema</span>
                  <p className="font-technical text-xs">No traces yet. Search by trace ID above or route agent traffic through the gateway.</p>
                </div>
              )}

              <div className="relative flex-1 py-4 flex flex-col justify-between">
                <div className="absolute left-[38px] top-6 bottom-6 w-px bg-white/10"></div>
                <div className="space-y-6 relative z-10">
                  {stages.map(stg => {
                    const isHovered = hoveredStageId === stg.id;
                    const isMuted   = hoveredStageId !== null && !isHovered;

                    if (stg.state === 'pass') return (
                      <div key={stg.id} className={`flex gap-4 items-center transition-all duration-300 ${isMuted ? 'opacity-20 scale-[0.98]' : ''}`}>
                        <div className="w-[78px] flex justify-end items-center gap-4 relative z-10">
                          <span className="text-[10px] font-technical text-neutral-500">{stg.ms}</span>
                          <div className={`w-8 h-8 rounded-full border-2 flex items-center justify-center transition-all ${isHovered ? 'bg-emerald-500 border-emerald-400 shadow-[0_0_20px_rgba(16,185,129,0.5)]' : 'bg-[#1a1a1a] border-emerald-500'}`}>
                            <span className={`material-symbols-outlined text-[14px] ${isHovered ? 'text-black' : 'text-emerald-500'}`}>check</span>
                          </div>
                        </div>
                        <div className={`flex-1 p-4 rounded-xl flex justify-between items-center transition-all ${isHovered ? 'bg-[#262626] border border-white/20' : 'bg-transparent border border-transparent'}`}>
                          <div>
                            <p className="text-[10px] font-headline font-bold text-emerald-500 tracking-widest uppercase mb-0.5">Stage {stg.num}</p>
                            <p className="font-body text-sm font-bold text-on-surface">{stg.title}</p>
                          </div>
                          <span className="font-technical text-[10px] text-neutral-400">{stg.desc}</span>
                        </div>
                      </div>
                    );

                    if (stg.state === 'block') return (
                      <div key={stg.id} className={`flex gap-4 items-stretch relative transition-all duration-300 ${isMuted ? 'opacity-20 scale-[0.98]' : 'scale-[1.02]'}`}>
                        <div className="absolute inset-0 bg-secondary/5 rounded-2xl border border-secondary/10 -z-10 animate-pulse"></div>
                        <div className="w-[78px] flex justify-end items-center gap-4 relative z-10">
                          <span className="text-[10px] font-technical text-secondary font-bold">{stg.ms}</span>
                          <div className="w-8 h-8 rounded-full border-2 font-bold flex items-center justify-center bg-secondary/20 border-secondary text-secondary shadow-[0_0_20px_rgba(249,193,61,0.5)]">
                            <span className="material-symbols-outlined text-[14px] animate-spin">warning</span>
                          </div>
                        </div>
                        <div className="flex-1 bg-gradient-to-r from-[#262626] to-[#1a1a1a] border border-white/5 p-5 rounded-xl shadow-2xl relative overflow-hidden">
                          <div className="flex justify-between items-start mb-4">
                            <div>
                              <p className="text-[10px] font-headline font-bold text-secondary tracking-widest uppercase mb-1">Stage {stg.num}</p>
                              <p className="font-headline text-xl font-bold text-on-surface">{stg.title}</p>
                            </div>
                            <span className="px-3 py-1 bg-secondary/20 text-secondary border border-secondary/30 rounded text-xs font-technical font-bold animate-pulse">BLOCKED</span>
                          </div>
                          {stg.subLog && (
                            <div className="bg-[#111] p-3 rounded-lg border border-white/5 space-y-2 font-technical text-xs">
                              {stg.subLog.map((log, i) => (
                                <div key={i} className="flex justify-between">
                                  <span className="text-neutral-500">{log.label}</span>
                                  <span className={log.err ? 'text-error font-bold' : 'text-neutral-300'}>{log.val}</span>
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                      </div>
                    );

                    return (
                      <div key={stg.id} className={`flex gap-4 items-center transition-all ${isMuted ? 'opacity-10 scale-[0.98]' : 'opacity-40'}`}>
                        <div className="w-[78px] flex justify-end items-center gap-4 relative z-10">
                          <span className="text-[10px] font-technical text-neutral-600">Pending</span>
                          <div className="w-8 h-8 rounded-full bg-[#111] border border-white/10 flex items-center justify-center">
                            <span className="w-2 h-2 rounded-full bg-white/20"></span>
                          </div>
                        </div>
                        <div className="flex-1 p-4 rounded-xl flex justify-between items-center">
                          <div>
                            <p className="text-[10px] font-headline font-bold text-neutral-500 tracking-widest uppercase mb-0.5">Stage {stg.num}</p>
                            <p className="font-body text-sm font-bold text-neutral-400">{stg.title}</p>
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>

            {/* Right Panel */}
            <div className="col-span-12 xl:col-span-4 flex flex-col gap-6">
              <div className="bg-[#1a1a1a] rounded-2xl border border-white/5 p-6 flex flex-col">
                <p className={`text-[10px] font-headline font-bold tracking-widest uppercase mb-4 flex items-center justify-between ${isBlocked ? 'text-orange-500' : 'text-emerald-500'}`}>
                  Action Detail
                  <span className="material-symbols-outlined text-sm">open_in_new</span>
                </p>
                {entry ? (
                  <div className="space-y-4">
                    <div>
                      <p className="text-xs text-neutral-500 mb-1 font-technical">Target Resource</p>
                      <p className="font-technical text-sm font-bold text-neutral-200">{entry.target_api}</p>
                    </div>
                    <div className="flex gap-4">
                      <div className="flex-1">
                        <p className="text-xs text-neutral-500 mb-1 font-technical">Action Type</p>
                        <code className={`text-xs font-technical px-3 py-2 rounded-lg block ${isBlocked ? 'text-error bg-error/10 border border-error/20' : 'text-emerald-400 bg-emerald-500/10 border border-emerald-500/20'}`}>
                          {entry.action_type}
                        </code>
                      </div>
                      <div className="border-l border-white/5 pl-4 flex flex-col gap-3">
                        <div>
                          <p className="text-[10px] text-neutral-500 mb-0.5 font-technical uppercase">Swarm</p>
                          <p className={`font-technical text-sm font-bold tabular-nums ${Number(entry.swarm_confidence_score) < 0.5 ? 'text-red-400' : 'text-emerald-400'}`}>
                            {entry.swarm_confidence_score != null ? `${(Number(entry.swarm_confidence_score) * 100).toFixed(0)}%` : '—'}
                          </p>
                        </div>
                        <div>
                          <p className="text-[10px] text-neutral-500 mb-0.5 font-technical uppercase">Alignment</p>
                          <p className={`font-technical text-sm font-bold tabular-nums ${entry.semantic_alignment_score != null && Number(entry.semantic_alignment_score) < 0.6 ? 'text-amber-400' : 'text-sky-400'}`}>
                            {entry.semantic_alignment_score != null ? `${(Number(entry.semantic_alignment_score) * 100).toFixed(0)}%` : '—'}
                          </p>
                        </div>
                      </div>
                    </div>
                    {entry.reasoning_trace && (
                      <div className="p-3 border border-sky-500/20 bg-sky-500/5 rounded-xl">
                        <p className="text-[10px] uppercase font-bold tracking-widest text-sky-400 mb-1.5 flex items-center gap-1.5">
                          <span className="material-symbols-outlined text-[12px]">psychology</span>
                          Chain-of-Thought
                        </p>
                        <div className="max-h-32 overflow-y-auto custom-scrollbar">
                          <p className="text-[10px] font-technical text-neutral-300 whitespace-pre-wrap leading-relaxed">{entry.reasoning_trace}</p>
                        </div>
                      </div>
                    )}

                    {/* User-Context Attribution (H2.1) */}
                    {entry.human_user_context && (() => {
                      try {
                        const uc = JSON.parse(entry.human_user_context);
                        if (!uc.sub) return null;
                        return (
                          <div className="p-3 border border-indigo-500/20 bg-indigo-500/5 rounded-xl">
                            <p className="text-[10px] uppercase font-bold tracking-widest text-indigo-400 mb-1.5 flex items-center gap-1.5">
                              <span className="material-symbols-outlined text-[12px]">person_pin</span>
                              Acting On Behalf Of
                            </p>
                            <div className="flex items-center gap-3">
                              <div className={`w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0 ${
                                uc.verified ? 'bg-emerald-500/10 border border-emerald-500/20' : 'bg-amber-500/10 border border-amber-500/20'
                              }`}>
                                <span className={`material-symbols-outlined text-[14px] ${
                                  uc.verified ? 'text-emerald-400' : 'text-amber-400'
                                }`}>
                                  {uc.verified ? 'verified_user' : 'person'}
                                </span>
                              </div>
                              <div>
                                <p className="text-xs font-bold text-white">{uc.name ?? uc.email ?? uc.sub}</p>
                                <p className="text-[9px] text-neutral-500">
                                  {uc.email && <>{uc.email} &middot; </>}
                                  {uc.iss && <>IdP: {uc.iss} &middot; </>}
                                  <span className={`font-bold ${uc.verified ? 'text-emerald-400' : 'text-amber-400'}`}>
                                    {uc.verified ? 'JWT Verified' : 'Unverified'}
                                  </span>
                                </p>
                              </div>
                            </div>
                          </div>
                        );
                      } catch { return null; }
                    })()}
                    
                    {/* Explicit Evidence Dump for Human Verification */}
                    {isBlocked && (entry.reason || entry.policy_violations) && (
                      <div className="p-3 mt-4 border border-red-500/20 bg-red-500/5 rounded-xl space-y-3">
                         <p className="text-[10px] uppercase font-bold tracking-widest text-red-500 flex items-center gap-2">
                           <span className="material-symbols-outlined text-[14px]">gavel</span>
                           Block Justification
                         </p>
                         
                         {entry.reason && (
                           <div>
                             <p className="text-[10px] text-neutral-500 font-technical uppercase">Primary Reason</p>
                             <p className="text-xs font-bold text-red-300 mt-0.5">{entry.reason}</p>
                           </div>
                         )}

                         {entry.policy_violations && (
                           <div>
                             <p className="text-[10px] text-neutral-500 font-technical uppercase mb-1">Policy Breaches</p>
                             <ul className="list-disc list-inside space-y-1">
                                {(() => {
                                  try {
                                    const parsed = JSON.parse(entry.policy_violations || '[]');
                                    const items = Array.isArray(parsed) ? parsed : [String(parsed)];
                                    return items.map((v: string, idx: number) => (
                                      <li key={idx} className="text-[10px] font-technical text-red-400">{v}</li>
                                    ));
                                  } catch {
                                    return <li className="text-[10px] font-technical text-red-400">{entry.policy_violations}</li>;
                                  }
                                })()}
                             </ul>
                           </div>
                         )}
                         
                         {entry.evidence && (
                           <div className="pt-2 border-t border-red-500/20 w-full min-w-0">
                             <p className="text-[10px] text-neutral-500 font-technical uppercase mb-1">Diagnostic Evidence</p>
                             <div className="max-h-40 overflow-y-auto overflow-x-hidden bg-black/50 rounded w-full custom-scrollbar">
                               <code className="text-[10px] text-white/50 block p-2 whitespace-pre-wrap break-all w-full">
                                 {entry.evidence}
                               </code>
                             </div>
                           </div>
                         )}
                      </div>
                    )}
                    <div className="pt-4 border-t border-white/5">
                      <Link href={`/registry/${entry.agent_id}`} className="flex items-center justify-center gap-2 w-full bg-primary/10 hover:bg-primary/20 text-primary border border-primary/20 font-bold py-2 rounded-xl text-xs transition-colors group">
                        <span className="material-symbols-outlined text-[16px] group-hover:-translate-x-1 transition-transform">badge</span>
                        View Full Agent Profile
                        <span className="material-symbols-outlined text-[16px] group-hover:translate-x-1 transition-transform">arrow_forward</span>
                      </Link>
                    </div>
                  </div>
                ) : (
                  <p className="text-neutral-600 font-technical text-xs">No trace selected.</p>
                )}
              </div>

              {/* Terminal Logs */}
              <div className="bg-black rounded-2xl border border-white/10 flex-1 flex flex-col overflow-hidden shadow-2xl relative min-h-[400px]">
                <div className="bg-[#1a1a1a] border-b border-white/5 px-4 py-2 flex justify-between items-center">
                  <div className="flex gap-1.5">
                    <span className="w-2.5 h-2.5 rounded-full bg-neutral-700"></span>
                    <span className="w-2.5 h-2.5 rounded-full bg-neutral-700"></span>
                    <span className="w-2.5 h-2.5 rounded-full bg-neutral-700"></span>
                  </div>
                  <span className="text-[10px] font-technical text-neutral-500 uppercase tracking-widest flex items-center gap-2">
                    <span className="material-symbols-outlined text-[12px]">terminal</span>
                    Interactive Consumer Logs
                  </span>
                </div>
                <div className="flex-1 p-4 font-technical text-[10px] overflow-y-auto space-y-1 bg-[#050505]">
                  <p className="text-neutral-500 opacity-50 select-none pb-4">// Hover entries to ping mathematical framework...</p>
                  {logs.map((log, i) => (
                    <p
                      key={i}
                      onMouseEnter={() => setHoveredStageId(log.mapsToNode)}
                      onMouseLeave={() => setHoveredStageId(null)}
                      className={`cursor-pointer px-2 py-1 -mx-2 rounded transition-colors ${hoveredStageId === log.mapsToNode ? 'bg-white/10' : 'hover:bg-white/5'} ${log.isError ? 'text-error font-bold' : log.isPulse ? 'text-primary animate-pulse font-bold' : 'text-neutral-400'}`}
                    >
                      <span className="text-neutral-500 w-16 inline-block">[{log.time}]</span>
                      <span className={`${hoveredStageId === log.mapsToNode ? 'text-white' : 'text-emerald-500'} font-bold`}>{log.sys}:</span> {log.msg}
                    </p>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      </main>
    </>
  );
}

export default function PipelineView() {
  return (
    <Suspense fallback={<div className="min-h-screen bg-black flex items-center justify-center text-primary font-technical animate-pulse">Loading Kafka Pipeline Vectors...</div>}>
      <PipelineMonitorCore />
    </Suspense>
  );
}
