// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

'use client';
import { operatorFetch } from '@/lib/operatorFetch';

import { useState, useEffect, useCallback } from 'react';
import { Sidebar } from '../../../components/Sidebar';
import { TopAppBar } from '../../../components/TopAppBar';
import { useToast } from '../../../components/ToastContext';
import Link from 'next/link';

const CORE_API = process.env.NEXT_PUBLIC_CORE_API_URL || 'http://localhost:8000';

interface HitlEvent {
  trace_id: string;
  agent_id: string;
  agent_name: string | null;
  company_name: string | null;
  trust_tier: string | null;
  target_api: string;
  action_type: string;
  status: string;
  policy_violations: string | null;
  created_at: string;
  // Saga fields
  decision?: string | null;
  webhook_url?: string | null;
  webhook_response_code?: number | null;
  retry_count?: number | null;
  payload_hash?: string | null;
  payload_size?: number | null;
  http_method?: string | null;
  resolved_at?: string | null;
}

type SagaState = 'suspended' | 'approved' | 'denied' | 'timed_out' | 'delivered' | 'retrying' | 'dead_letter';

const SAGA_BADGES: Record<string, { label: string; color: string; icon: string }> = {
  suspended:   { label: 'SUSPENDED',   color: 'text-amber-400 bg-amber-500/10 border-amber-500/20',       icon: 'hourglass_top' },
  approved:    { label: 'APPROVED',    color: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20', icon: 'check_circle' },
  denied:      { label: 'DENIED',      color: 'text-red-400 bg-red-500/10 border-red-500/20',             icon: 'block' },
  timed_out:   { label: 'TIMED OUT',   color: 'text-neutral-400 bg-neutral-500/10 border-neutral-500/20', icon: 'timer_off' },
  delivered:   { label: 'DELIVERED',   color: 'text-blue-400 bg-blue-500/10 border-blue-500/20',           icon: 'send' },
  retrying:    { label: 'RETRYING',    color: 'text-orange-400 bg-orange-500/10 border-orange-500/20',     icon: 'refresh' },
  dead_letter: { label: 'DEAD LETTER', color: 'text-red-600 bg-red-900/20 border-red-800/30',             icon: 'error' },
};

function mapToSagaState(ev: HitlEvent): SagaState {
  const s = ev.status?.toLowerCase();
  const d = ev.decision?.toLowerCase();
  if (s === 'dead_letter' || d === 'dead_letter') return 'dead_letter';
  if (s === 'retrying' || d === 'retrying') return 'retrying';
  if (s === 'delivered' || d === 'delivered') return 'delivered';
  if (d === 'timed_out' || ev.action_type === 'hitl_timeout') return 'timed_out';
  if (d === 'denied' || ev.action_type === 'hitl_rejected' || s === 'hitl_rejected') return 'denied';
  if (d === 'approved' || ev.action_type === 'hitl_approved' || s === 'hitl_approved') return 'approved';
  return 'suspended';
}

function fmt(ts: string) {
  return new Date(ts).toLocaleString('en-GB', { dateStyle: 'short', timeStyle: 'medium' });
}

export default function HitlApprovalQueue() {
  const { showToast } = useToast();
  const [pending, setPending] = useState<HitlEvent[]>([]);
  const [resolved, setResolved] = useState<HitlEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [acting, setActing] = useState<string | null>(null);
  const [expandedTrace, setExpandedTrace] = useState<string | null>(null);

  const load = useCallback(async () => {
    const json = await operatorFetch(`${CORE_API}/api/v1/admin/hitl/queue`, {
      headers: { Accept: 'application/json' },
    }).then(r => r.json()).catch(() => null);

    if (json?.status === 'success') {
      setPending(json.pending ?? []);
      setResolved(json.resolved ?? []);
    }
    setLoading(false);
  }, []);

  useEffect(() => {
    load();
    const i = setInterval(load, 5000);
    return () => clearInterval(i);
  }, [load]);

  const decide = async (traceId: string, action: 'approve' | 'reject') => {
    setActing(traceId);
    try {
      const res = await operatorFetch(`${CORE_API}/api/v1/admin/hitl/${traceId}/${action}`, {
        method: 'POST',
        headers: { Accept: 'application/json' },
      });

      if (res.status === 409) {
        showToast('Resolution already recorded for this trace.');
      } else if (res.ok) {
        showToast(action === 'approve' ? 'Trace approved. Saga Executor dispatching webhook.' : 'Trace denied. Denial webhook dispatched.');
      } else {
        showToast('Failed to resolve trace.');
      }
    } catch {
      showToast('Network error resolving trace.');
    }
    await load();
    setActing(null);
  };

  return (
    <div className="min-h-screen bg-[#070707] text-white flex font-sans">
      <Sidebar />
      <div className="flex-1 flex flex-col h-screen overflow-hidden" style={{ paddingLeft: 'var(--sidebar-width, 18rem)', transition: 'padding-left 300ms' }}>
        <TopAppBar />

        <main className="flex-1 overflow-y-auto p-6 lg:p-10 mt-16">

          {/* Header */}
          <div className="mb-8 mt-4">
            <div className="flex items-center gap-3 mb-2">
              <h1 className="text-3xl font-headline font-black uppercase tracking-tighter text-white">
                HITL Approval Queue
              </h1>
              {pending.length > 0 && (
                <span className="bg-red-500 text-white text-xs font-bold px-2.5 py-1 rounded-full animate-pulse">
                  {pending.length} PENDING
                </span>
              )}
            </div>
            <p className="text-sm font-technical text-neutral-400 max-w-2xl">
              Suspended Saga queue. Payloads are encrypted at rest with AES-256-GCM. The origin service receives a 202 Accepted immediately — no TCP hold. Unresolved traces auto-deny after the configured timeout.
            </p>
            {/* Lifecycle Legend */}
            <div className="flex flex-wrap gap-2 mt-4">
              {Object.entries(SAGA_BADGES).map(([key, badge]) => (
                <span key={key} className={`text-[9px] font-bold uppercase tracking-widest px-2 py-0.5 rounded border font-technical ${badge.color}`}>
                  <span className="material-symbols-outlined text-[10px] mr-1 align-middle">{badge.icon}</span>
                  {badge.label}
                </span>
              ))}
            </div>
          </div>

          {/* ── Pending Queue ── */}
          <section className="mb-10">
            <h2 className="text-xs font-bold uppercase tracking-widest text-orange-400 font-technical mb-4 flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
              Awaiting Decision ({pending.length})
            </h2>

            {loading ? (
              <div className="flex items-center gap-3 py-8 text-neutral-500 font-technical text-sm">
                <div className="w-5 h-5 border-2 border-orange-500/20 border-t-orange-500 rounded-full animate-spin" />
                Loading queue…
              </div>
            ) : pending.length === 0 ? (
              <div className="bg-emerald-500/5 border border-emerald-500/20 rounded-2xl p-8 text-center">
                <span className="material-symbols-outlined text-4xl text-emerald-500/40 block mb-2">check_circle</span>
                <p className="text-sm font-technical text-emerald-400">No calls pending human approval.</p>
                <p className="text-xs font-technical text-neutral-500 mt-1">Queue auto-refreshes every 5 seconds.</p>
              </div>
            ) : (
              <div className="space-y-4">
                {pending.map(ev => {
                  const sagaState = mapToSagaState(ev);
                  const badge = SAGA_BADGES[sagaState];
                  return (
                    <div key={ev.trace_id} className="bg-neutral-900/80 border border-red-500/30 rounded-2xl p-6 relative overflow-hidden">
                      <div className="absolute inset-0 bg-red-500/3 pointer-events-none" />
                      <div className="relative flex flex-col lg:flex-row lg:items-start gap-6">
                        <div className="flex items-start gap-4 flex-1 min-w-0">
                          {/* Badge */}
                          <div className="text-center shrink-0">
                            <span className={`text-[9px] font-bold uppercase tracking-widest px-2.5 py-1 rounded border font-technical ${badge.color}`}>
                              <span className="material-symbols-outlined text-[10px] mr-1 align-middle">{badge.icon}</span>
                              {badge.label}
                            </span>
                          </div>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 flex-wrap mb-1">
                              <span className="text-xs font-bold text-white font-headline">
                                {ev.agent_name ?? ev.agent_id.substring(0, 8)}
                              </span>
                              {ev.trust_tier && (
                                <span className="text-[9px] px-1.5 py-0.5 rounded border font-technical font-bold text-sky-400 bg-sky-400/10 border-sky-400/20">
                                  {ev.trust_tier}
                                </span>
                              )}
                              <span className="text-[9px] text-neutral-500 font-technical">{ev.company_name}</span>
                            </div>
                            {/* Structural metadata only — payload guardrails */}
                            <p className="text-sm font-technical text-white truncate mb-1">
                              <span className="text-neutral-500">Target: </span>{ev.target_api}
                            </p>
                            {ev.http_method && (
                              <span className="text-[9px] px-1.5 py-0.5 rounded bg-white/5 border border-white/10 font-technical text-neutral-400 mr-2">{ev.http_method}</span>
                            )}
                            {ev.payload_size != null && (
                              <span className="text-[9px] font-technical text-neutral-500">{(ev.payload_size / 1024).toFixed(1)} KB</span>
                            )}
                            <p className="text-xs text-neutral-500 font-technical mt-1">{fmt(ev.created_at)}</p>

                            {ev.policy_violations && (
                              <div className="mt-3 p-3 bg-red-500/5 border border-red-500/20 rounded-xl">
                                <p className="text-[10px] uppercase font-bold text-red-400 mb-1">Risk Reason</p>
                                <p className="text-xs font-technical text-red-300">{ev.policy_violations}</p>
                              </div>
                            )}
                          </div>
                        </div>

                        {/* Actions */}
                        <div className="flex gap-3 shrink-0 self-center">
                          <Link href={`/registry/${ev.agent_id}`} target="_blank"
                            className="px-4 py-2.5 bg-white/5 border border-white/10 text-neutral-400 font-bold rounded-xl text-xs font-technical hover:bg-white/10 transition-all flex items-center gap-1.5">
                            <span className="material-symbols-outlined text-[16px]">open_in_new</span>
                            Biography
                          </Link>
                          <button
                            onClick={() => decide(ev.trace_id, 'reject')}
                            disabled={acting === ev.trace_id}
                            className="px-6 py-2.5 bg-red-500/10 border border-red-500/30 text-red-400 font-bold rounded-xl text-xs font-technical hover:bg-red-500/20 transition-all flex items-center gap-1.5 disabled:opacity-50"
                          >
                            <span className="material-symbols-outlined text-[16px]">block</span>
                            Reject
                          </button>
                          <button
                            onClick={() => decide(ev.trace_id, 'approve')}
                            disabled={acting === ev.trace_id}
                            className="px-6 py-2.5 bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 font-bold rounded-xl text-xs font-technical hover:bg-emerald-500/20 transition-all flex items-center gap-1.5 disabled:opacity-50"
                          >
                            <span className="material-symbols-outlined text-[16px]">check_circle</span>
                            Approve
                          </button>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </section>

          {/* ── Resolved History ── */}
          <section>
            <h2 className="text-xs font-bold uppercase tracking-widest text-neutral-500 font-technical mb-4">
              Recently Resolved ({resolved.length})
            </h2>

            {resolved.length === 0 ? (
              <p className="text-xs text-neutral-600 font-technical italic">No resolved HITL events yet.</p>
            ) : (
              <div className="bg-neutral-900/60 border border-white/5 rounded-2xl overflow-hidden">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-white/5 text-left">
                      {['State', 'Agent', 'Company', 'Target', 'Resolved At', 'Delivery'].map(h => (
                        <th key={h} className="px-4 py-3 text-[10px] font-bold uppercase tracking-widest text-neutral-600">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {resolved.map(ev => {
                      const sagaState = mapToSagaState(ev);
                      const badge = SAGA_BADGES[sagaState];
                      const isExpanded = expandedTrace === ev.trace_id;

                      return (
                        <tr key={ev.trace_id}
                          className="border-b border-white/5 last:border-0 hover:bg-white/[0.02] transition-colors cursor-pointer"
                          onClick={() => setExpandedTrace(isExpanded ? null : ev.trace_id)}
                        >
                          <td className="px-4 py-3">
                            <span className={`text-[9px] font-bold uppercase tracking-widest px-2 py-0.5 rounded border font-technical ${badge.color}`}>
                              <span className="material-symbols-outlined text-[10px] mr-1 align-middle">{badge.icon}</span>
                              {badge.label}
                            </span>
                          </td>
                          <td className="px-4 py-3">
                            <Link href={`/registry/${ev.agent_id}`} className="text-white hover:text-orange-400 transition-colors font-medium text-xs" onClick={e => e.stopPropagation()}>
                              {ev.agent_name ?? ev.agent_id.substring(0, 8)}
                            </Link>
                          </td>
                          <td className="px-4 py-3 text-neutral-400 text-xs font-technical">{ev.company_name ?? '—'}</td>
                          <td className="px-4 py-3 text-neutral-400 text-xs font-technical truncate max-w-[200px]">{ev.target_api}</td>
                          <td className="px-4 py-3 text-neutral-500 text-xs font-technical">{ev.resolved_at ? fmt(ev.resolved_at) : fmt(ev.created_at)}</td>
                          <td className="px-4 py-3">
                            <button className="text-[10px] font-technical text-neutral-500 hover:text-white transition-colors flex items-center gap-1">
                              <span className="material-symbols-outlined text-[14px]">{isExpanded ? 'expand_less' : 'expand_more'}</span>
                              {isExpanded ? 'Hide' : 'Log'}
                            </button>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>

                {/* Expanded Delivery Log */}
                {expandedTrace && (() => {
                  const ev = resolved.find(e => e.trace_id === expandedTrace);
                  if (!ev) return null;
                  const sagaState = mapToSagaState(ev);
                  return (
                    <div className="border-t border-white/10 bg-[#0a0a0a] p-6 space-y-3">
                      <p className="text-[10px] uppercase font-bold tracking-widest text-neutral-500 font-technical flex items-center gap-2">
                        <span className="material-symbols-outlined text-[14px]">receipt_long</span>
                        Delivery Telemetry — {ev.trace_id}
                      </p>
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-xs font-technical">
                        <div>
                          <p className="text-neutral-600 text-[10px] uppercase">Webhook URL</p>
                          <p className="text-neutral-300 truncate">{ev.webhook_url ?? '—'}</p>
                        </div>
                        <div>
                          <p className="text-neutral-600 text-[10px] uppercase">Response Code</p>
                          <p className={ev.webhook_response_code === 200 ? 'text-emerald-400' : 'text-red-400'}>{ev.webhook_response_code ?? '—'}</p>
                        </div>
                        <div>
                          <p className="text-neutral-600 text-[10px] uppercase">Retry Count</p>
                          <p className="text-neutral-300">{ev.retry_count ?? 0}</p>
                        </div>
                        <div>
                          <p className="text-neutral-600 text-[10px] uppercase">Payload Hash</p>
                          <p className="text-neutral-500 truncate text-[10px]">{ev.payload_hash ?? '—'}</p>
                        </div>
                      </div>
                      {sagaState === 'dead_letter' && (
                        <button className="mt-3 px-4 py-2 bg-red-500/10 border border-red-500/30 text-red-400 font-bold rounded-xl text-xs font-technical hover:bg-red-500/20 transition-all flex items-center gap-1.5">
                          <span className="material-symbols-outlined text-[16px]">replay</span>
                          Redispatch
                        </button>
                      )}
                    </div>
                  );
                })()}
              </div>
            )}
          </section>

        </main>
      </div>
    </div>
  );
}
