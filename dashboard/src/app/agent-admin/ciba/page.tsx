// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

'use client';
import { operatorFetch } from '@/lib/operatorFetch';

import { useState, useEffect, useCallback, useRef } from 'react';
import { Sidebar } from '../../../components/Sidebar';
import { TopAppBar } from '../../../components/TopAppBar';
import { useToast } from '../../../components/ToastContext';
import Link from 'next/link';

const CORE_API = process.env.NEXT_PUBLIC_CORE_API_URL || 'http://localhost:8000';

interface CibaEvent {
  trace_id: string;
  agent_id: string;
  tenant_id: string;
  agent_name: string | null;
  action_summary: string | null;
  target_url: string | null;
  payload_preview: string | null;
  risk_score: string | null;
  risk_reason: string | null;
  status: string;
  created_at: string;
  expires_at: string;
}

function fmt(ts: string) {
  return new Date(ts).toLocaleString('en-GB', { dateStyle: 'short', timeStyle: 'medium' });
}

function timeLeft(expiresAt: string): string {
  const diff = new Date(expiresAt).getTime() - Date.now();
  if (diff <= 0) return 'EXPIRED';
  const s = Math.floor(diff / 1000);
  const m = Math.floor(s / 60);
  return m > 0 ? `${m}m ${s % 60}s` : `${s}s`;
}

export default function CibaApprovalQueue() {
  const { showToast } = useToast();
  const [pending, setPending] = useState<CibaEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [acting, setActing] = useState<string | null>(null);
  const [sirenMuted, setSirenMuted] = useState(false);
  const [, setTick] = useState(0); // forces re-render for countdown

  // ── Browser Audio Siren ─────────────────────────────────────────
  const audioCtxRef = useRef<AudioContext | null>(null);
  const oscillatorRef = useRef<OscillatorNode | null>(null);
  const gainRef = useRef<GainNode | null>(null);
  const sirenChannelRef = useRef<BroadcastChannel | null>(null);

  // ── Cross-tab siren coordination ────────────────────────────────────
  // When the operator mutes the siren in ANY tab, ALL tabs mute.
  useEffect(() => {
    const channel = new BroadcastChannel('cicada-siren-sync');
    sirenChannelRef.current = channel;
    channel.onmessage = (e) => {
      if (e.data?.type === 'SIREN_MUTED') {
        setSirenMuted(true);
        if (oscillatorRef.current) { try { oscillatorRef.current.stop(); } catch {} oscillatorRef.current = null; }
        if (audioCtxRef.current) { try { audioCtxRef.current.close(); } catch {} audioCtxRef.current = null; }
        gainRef.current = null;
      }
    };
    return () => channel.close();
  }, []);

  const startSiren = useCallback(() => {
    if (sirenMuted) return;
    if (oscillatorRef.current) return; // already playing

    try {
      const ctx = new (window.AudioContext || (window as any).webkitAudioContext)();
      audioCtxRef.current = ctx;

      const oscillator = ctx.createOscillator();
      const gain = ctx.createGain();
      
      oscillator.type = 'sine';
      oscillator.frequency.value = 800;
      gain.gain.value = 0.15;

      // Siren sweep: 600Hz → 1000Hz → 600Hz repeating
      const now = ctx.currentTime;
      for (let i = 0; i < 60; i++) {
        oscillator.frequency.setValueAtTime(600, now + i * 1.0);
        oscillator.frequency.linearRampToValueAtTime(1000, now + i * 1.0 + 0.5);
        oscillator.frequency.linearRampToValueAtTime(600, now + i * 1.0 + 1.0);
      }

      oscillator.connect(gain);
      gain.connect(ctx.destination);
      oscillator.start();

      oscillatorRef.current = oscillator;
      gainRef.current = gain;
    } catch (e) {
      console.warn('Audio siren failed:', e);
    }
  }, [sirenMuted]);

  const stopSiren = useCallback(() => {
    if (oscillatorRef.current) {
      try { oscillatorRef.current.stop(); } catch {}
      oscillatorRef.current = null;
    }
    if (audioCtxRef.current) {
      try { audioCtxRef.current.close(); } catch {}
      audioCtxRef.current = null;
    }
    gainRef.current = null;
  }, []);

  const muteAllTabs = useCallback(() => {
    setSirenMuted(true);
    stopSiren();
    try { sirenChannelRef.current?.postMessage({ type: 'SIREN_MUTED' }); } catch {}
  }, [stopSiren]);

  // Start/stop siren based on pending count
  useEffect(() => {
    if (pending.length > 0 && !sirenMuted) {
      startSiren();
    } else {
      stopSiren();
    }
    return () => stopSiren();
  }, [pending.length, sirenMuted, startSiren, stopSiren]);

  // Countdown timer tick
  useEffect(() => {
    if (pending.length === 0) return;
    const i = setInterval(() => setTick(t => t + 1), 1000);
    return () => clearInterval(i);
  }, [pending.length]);

  const load = useCallback(async () => {
    const json = await operatorFetch(`${CORE_API}/api/v1/admin/ciba/pending`, {
      headers: { Accept: 'application/json' },
    }).then(r => r.json()).catch(() => null);

    if (json?.data) {
      setPending(json.data ?? []);
    }
    setLoading(false);
  }, []);

  useEffect(() => {
    load();
    const i = setInterval(load, 5000);
    return () => clearInterval(i);
  }, [load]);

  // ── Admin Override Decision ─────────────────────────────────────────
  const decide = async (traceId: string, action: 'approve' | 'reject') => {
    setActing(traceId);
    try {
      const res = await operatorFetch(`${CORE_API}/api/v1/admin/ciba/${traceId}/admin-respond`, {
        method: 'POST',
        headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
        body: JSON.stringify({ decision: action })
      });

      const data = await res.json();

      if (res.ok && data.status === 'success') {
        showToast(`✅ CIBA request ${action === 'approve' ? 'approved' : 'rejected'} — ${traceId.substring(0, 12)}`);
        muteAllTabs();
      } else {
        showToast(`❌ Failed: ${data.error || 'Unknown error'}`);
      }
    } catch {
      showToast('Network error resolving CIBA request.');
    }
    await load();
    setActing(null);
  };

  const hasPending = pending.length > 0;

  return (
    <div className="min-h-screen bg-[#070707] text-white flex font-sans">
      <Sidebar />
      <div className="flex-1 flex flex-col h-screen overflow-hidden" style={{ paddingLeft: 'var(--sidebar-width, 18rem)', transition: 'padding-left 300ms' }}>
        <TopAppBar />

        <main className="flex-1 overflow-y-auto p-6 lg:p-10 mt-16 relative">

          {/* ── Red Pulse Overlay when alerts pending ── */}
          {hasPending && (
            <div className="fixed inset-0 pointer-events-none z-50" style={{ paddingLeft: 'var(--sidebar-width, 18rem)' }}>
              <div className="absolute inset-0 animate-pulse-red" />
              <style jsx>{`
                @keyframes pulse-red {
                  0%, 100% { background: rgba(239, 68, 68, 0); }
                  50% { background: rgba(239, 68, 68, 0.06); }
                }
                .animate-pulse-red {
                  animation: pulse-red 2s ease-in-out infinite;
                }
              `}</style>
            </div>
          )}

          {/* Header */}
          <div className="mb-8 mt-4">
            <div className="flex items-center gap-3 mb-2">
              {hasPending && (
                <span className="material-symbols-outlined text-red-500 text-3xl animate-pulse">crisis_alert</span>
              )}
              <h1 className="text-3xl font-headline font-black uppercase tracking-tighter text-white">
                CIBA Global Queue
              </h1>
              {hasPending && (
                <span className="bg-red-500 text-white text-xs font-bold px-2.5 py-1 rounded-full animate-pulse">
                  {pending.length} PENDING
                </span>
              )}
              {hasPending && (
                <button
                  onClick={() => { if (!sirenMuted) { muteAllTabs(); } else { setSirenMuted(false); } }}
                  className={`ml-auto px-3 py-1.5 rounded-lg text-xs font-technical font-bold border transition-all flex items-center gap-1.5 ${
                    sirenMuted
                      ? 'bg-neutral-800 border-neutral-700 text-neutral-400 hover:bg-neutral-700'
                      : 'bg-red-500/10 border-red-500/30 text-red-400 hover:bg-red-500/20 animate-pulse'
                  }`}
                >
                  <span className="material-symbols-outlined text-[16px]">
                    {sirenMuted ? 'volume_off' : 'volume_up'}
                  </span>
                  {sirenMuted ? 'Siren Muted' : 'Siren Active — Click to Mute'}
                </button>
              )}
            </div>
            <p className="text-sm font-technical text-neutral-400 max-w-2xl">
              Global queue for Client Initiated Backchannel Authentication (CIBA) requests. These requests are awaiting out-of-band mobile verification. As a global operator, you can override and resolve these manually if required.
            </p>
          </div>

          {/* ── Pending Queue ── */}
          <section className="mb-10">
            <h2 className="text-xs font-bold uppercase tracking-widest text-orange-400 font-technical mb-4 flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
              Awaiting Mobile Authorization ({pending.length})
            </h2>

            {loading ? (
              <div className="flex items-center gap-3 py-8 text-neutral-500 font-technical text-sm">
                <div className="w-5 h-5 border-2 border-orange-500/20 border-t-orange-500 rounded-full animate-spin" />
                Loading queue…
              </div>
            ) : pending.length === 0 ? (
              <div className="bg-emerald-500/5 border border-emerald-500/20 rounded-2xl p-8 text-center">
                <span className="material-symbols-outlined text-4xl text-emerald-500/40 block mb-2">mobile_friendly</span>
                <p className="text-sm font-technical text-emerald-400">No CIBA requests pending.</p>
                <p className="text-xs font-technical text-neutral-500 mt-1">Queue auto-refreshes every 5 seconds.</p>
              </div>
            ) : (
              <div className="space-y-6">
                {pending.map(ev => {
                  const remaining = timeLeft(ev.expires_at);
                  const isUrgent = remaining !== 'EXPIRED' && parseInt(remaining) < 60;
                  const riskPct = ev.risk_score ? Math.round(parseFloat(ev.risk_score) * 100) : 0;
                  const riskColor = riskPct >= 80 ? 'text-red-500' : riskPct >= 50 ? 'text-amber-400' : 'text-emerald-400';
                  const riskBg = riskPct >= 80 ? 'bg-red-500' : riskPct >= 50 ? 'bg-amber-400' : 'bg-emerald-400';

                  return (
                    <div key={ev.trace_id} className={`rounded-2xl relative overflow-hidden transition-all border ${
                      remaining === 'EXPIRED'
                        ? 'bg-neutral-900/50 border-neutral-700/30 opacity-60'
                        : 'bg-neutral-900/80 border-red-500/40 shadow-[0_0_30px_rgba(239,68,68,0.15)]'
                    }`}>
                      {remaining !== 'EXPIRED' && (
                        <div className="absolute inset-0 bg-red-500/3 pointer-events-none" />
                      )}

                      {/* ── Card Header: Agent Identity + Countdown + Actions ── */}
                      <div className="relative p-6 pb-4 flex flex-col lg:flex-row lg:items-center gap-4 border-b border-white/5">
                        <div className="flex items-center gap-4 flex-1 min-w-0">
                          {/* Countdown Badge */}
                          <div className="text-center shrink-0">
                            <span className={`text-[9px] font-bold uppercase tracking-widest px-2.5 py-1 rounded border font-technical ${
                              remaining === 'EXPIRED'
                                ? 'text-neutral-500 bg-neutral-500/10 border-neutral-500/20'
                                : 'text-red-400 bg-red-500/10 border-red-500/20'
                            }`}>
                              <span className="material-symbols-outlined text-[10px] mr-1 align-middle">
                                {remaining === 'EXPIRED' ? 'timer_off' : 'timer'}
                              </span>
                              {remaining === 'EXPIRED' ? 'EXPIRED' : 'LIVE'}
                            </span>
                            {remaining !== 'EXPIRED' && (
                              <div className={`text-xl font-black font-technical tabular-nums mt-1 ${
                                isUrgent ? 'text-red-500 animate-pulse' : 'text-orange-400'
                              }`}>
                                {remaining}
                              </div>
                            )}
                          </div>

                          {/* Agent Identity */}
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 flex-wrap">
                              <span className="material-symbols-outlined text-orange-500 text-xl">smart_toy</span>
                              <span className="text-lg font-bold text-white font-headline">
                                {ev.agent_name ?? `Agent-${ev.agent_id.substring(0, 8)}`}
                              </span>
                              {ev.risk_score && parseFloat(ev.risk_score) >= 0.8 && (
                                <span className="text-[9px] px-2 py-0.5 rounded border font-technical font-bold text-red-400 bg-red-400/10 border-red-400/20 animate-pulse">
                                  ⚠ CRITICAL RISK
                                </span>
                              )}
                              {ev.risk_score && parseFloat(ev.risk_score) >= 0.5 && parseFloat(ev.risk_score) < 0.8 && (
                                <span className="text-[9px] px-2 py-0.5 rounded border font-technical font-bold text-amber-400 bg-amber-400/10 border-amber-400/20">
                                  ELEVATED RISK
                                </span>
                              )}
                            </div>
                            <p className="text-xs text-neutral-500 font-technical mt-0.5">
                              ID: <code className="text-neutral-400">{ev.agent_id}</code>
                              <span className="text-neutral-700 mx-2">•</span>
                              Tenant: <code className="text-neutral-400">{ev.tenant_id?.substring(0, 8) ?? 'unknown'}</code>
                              <span className="text-neutral-700 mx-2">•</span>
                              {fmt(ev.created_at)}
                            </p>
                          </div>

                          {/* Risk Score Gauge */}
                          {ev.risk_score && (
                            <div className="shrink-0 text-center px-4">
                              <div className={`text-3xl font-black font-technical tabular-nums ${riskColor}`}>
                                {riskPct}<span className="text-xs text-neutral-500 font-medium">%</span>
                              </div>
                              <p className="text-[9px] font-technical text-neutral-500 uppercase tracking-widest">Risk Score</p>
                              <div className="w-20 h-1.5 bg-neutral-800 rounded-full mt-1 overflow-hidden">
                                <div className={`h-full rounded-full transition-all ${riskBg}`} style={{ width: `${riskPct}%` }} />
                              </div>
                            </div>
                          )}
                        </div>

                        {/* Action Buttons */}
                        <div className="flex gap-3 shrink-0">
                          <Link href={`/registry/${ev.agent_id}`} target="_blank"
                            className="px-4 py-2.5 bg-white/5 border border-white/10 text-neutral-400 font-bold rounded-xl text-xs font-technical hover:bg-white/10 transition-all flex items-center gap-1.5">
                            <span className="material-symbols-outlined text-[16px]">open_in_new</span>
                            Biography
                          </Link>
                          <button
                            onClick={() => decide(ev.trace_id, 'reject')}
                            disabled={acting === ev.trace_id}
                            className="px-6 py-2.5 bg-red-500/10 border border-red-500/30 text-red-400 font-bold rounded-xl text-xs font-technical hover:bg-red-500/20 transition-all flex items-center gap-1.5 disabled:opacity-50 disabled:cursor-not-allowed"
                          >
                            <span className="material-symbols-outlined text-[16px]">block</span>
                            Force Reject
                          </button>
                          <button
                            onClick={() => decide(ev.trace_id, 'approve')}
                            disabled={acting === ev.trace_id}
                            className="px-6 py-2.5 bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 font-bold rounded-xl text-xs font-technical hover:bg-emerald-500/20 transition-all flex items-center gap-1.5 disabled:opacity-50 disabled:cursor-not-allowed"
                          >
                            <span className="material-symbols-outlined text-[16px]">check_circle</span>
                            Force Approve
                          </button>
                        </div>
                      </div>

                      {/* ── Card Body: Full Forensic Context ── */}
                      <div className="relative p-6 pt-4 grid grid-cols-1 xl:grid-cols-3 gap-6">
                        {/* Left Column: What Happened */}
                        <div className="xl:col-span-2 space-y-4">
                          {/* Action Summary */}
                          <div>
                            <p className="text-[10px] font-bold uppercase tracking-widest text-neutral-500 mb-1.5 flex items-center gap-1.5">
                              <span className="material-symbols-outlined text-[12px]">description</span>
                              Action Summary
                            </p>
                            <p className="text-sm font-body text-white leading-relaxed bg-white/[0.02] border border-white/5 rounded-xl p-3">
                              {ev.action_summary ?? 'No action summary provided'}
                            </p>
                          </div>

                          {/* Target + Risk Reason */}
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                            {ev.target_url && (
                              <div>
                                <p className="text-[10px] font-bold uppercase tracking-widest text-neutral-500 mb-1.5 flex items-center gap-1.5">
                                  <span className="material-symbols-outlined text-[12px]">link</span>
                                  Target API Endpoint
                                </p>
                                <code className="text-xs font-technical text-orange-400 bg-orange-500/5 border border-orange-500/10 px-3 py-2 rounded-lg block truncate">
                                  {ev.target_url}
                                </code>
                              </div>
                            )}
                            {ev.risk_reason && (
                              <div>
                                <p className="text-[10px] font-bold uppercase tracking-widest text-neutral-500 mb-1.5 flex items-center gap-1.5">
                                  <span className="material-symbols-outlined text-[12px]">warning</span>
                                  Risk Reason
                                </p>
                                <p className="text-xs font-technical text-red-400 bg-red-500/5 border border-red-500/10 px-3 py-2 rounded-lg">
                                  {ev.risk_reason}
                                </p>
                              </div>
                            )}
                          </div>

                          {/* Payload Preview */}
                          {ev.payload_preview && (
                            <div>
                              <p className="text-[10px] font-bold uppercase tracking-widest text-neutral-500 mb-1.5 flex items-center gap-1.5">
                                <span className="material-symbols-outlined text-[12px]">data_object</span>
                                Payload Preview
                              </p>
                              <div className="bg-black border border-white/10 rounded-xl overflow-hidden">
                                <div className="bg-[#1a1a1a] border-b border-white/5 px-3 py-1.5 flex items-center gap-1.5">
                                  <span className="w-2 h-2 rounded-full bg-neutral-700" />
                                  <span className="w-2 h-2 rounded-full bg-neutral-700" />
                                  <span className="w-2 h-2 rounded-full bg-neutral-700" />
                                  <span className="text-[9px] font-technical text-neutral-600 ml-2 uppercase tracking-widest">Intercepted Payload</span>
                                </div>
                                <pre className="p-3 text-[11px] font-technical text-neutral-300 whitespace-pre-wrap break-all max-h-32 overflow-y-auto custom-scrollbar">
                                  {ev.payload_preview}
                                </pre>
                              </div>
                            </div>
                          )}
                        </div>

                        {/* Right Column: Metadata */}
                        <div className="space-y-4">
                          {/* Trace Reference */}
                          <div>
                            <p className="text-[10px] font-bold uppercase tracking-widest text-neutral-500 mb-1.5">Trace Reference</p>
                            <code className="text-[10px] font-technical text-neutral-400 bg-white/[0.03] border border-white/5 px-3 py-2 rounded-lg block break-all">
                              {ev.trace_id}
                            </code>
                          </div>

                          {/* Timeline */}
                          <div>
                            <p className="text-[10px] font-bold uppercase tracking-widest text-neutral-500 mb-1.5">Timeline</p>
                            <div className="space-y-1.5 text-xs font-technical">
                              <div className="flex justify-between">
                                <span className="text-neutral-500">Created</span>
                                <span className="text-neutral-300 tabular-nums">{fmt(ev.created_at)}</span>
                              </div>
                              <div className="flex justify-between">
                                <span className="text-neutral-500">Expires</span>
                                <span className={`tabular-nums ${remaining === 'EXPIRED' ? 'text-neutral-600' : 'text-red-400 font-bold'}`}>
                                  {fmt(ev.expires_at)}
                                </span>
                              </div>
                              <div className="flex justify-between">
                                <span className="text-neutral-500">Status</span>
                                <span className={`font-bold uppercase ${remaining === 'EXPIRED' ? 'text-neutral-600' : 'text-orange-400'}`}>
                                  {remaining === 'EXPIRED' ? 'Expired' : `${remaining} remaining`}
                                </span>
                              </div>
                            </div>
                          </div>

                          {/* CISO Audit Note */}
                          <div className="bg-amber-500/5 border border-amber-500/10 rounded-xl p-3">
                            <p className="text-[9px] font-bold uppercase tracking-widest text-amber-500/70 mb-1 flex items-center gap-1">
                              <span className="material-symbols-outlined text-[11px]">gavel</span>
                              Compliance Note
                            </p>
                            <p className="text-[10px] text-neutral-400 leading-relaxed">
                              This decision will be permanently recorded in the immutable action ledger. Both the decision and the operator identity are logged for audit traceability.
                            </p>
                          </div>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </section>

        </main>
      </div>
    </div>
  );
}
