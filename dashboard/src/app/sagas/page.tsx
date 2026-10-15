// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

'use client';
import { operatorFetch } from '@/lib/operatorFetch';
import { useState, useEffect } from 'react';
import { useToast } from '../../components/ToastContext';
import { Sidebar } from '../../components/Sidebar';
import { TopAppBar } from '../../components/TopAppBar';

interface SagaEntry {
  trace_id: string;
  agent_id: string;
  agent_name: string | null;
  tenant_id: string;
  tenant_name: string;
  action_type: string;
  target_api: string;
  status: string;
  policy_violations: string | null;
  created_at: string;
}

const API = process.env.NEXT_PUBLIC_CORE_API_URL ?? 'http://localhost:8000';

function statusLabel(actionType: string, status: string) {
  if (actionType === 'circuit_breaker_trip') return { label: 'AUTO-STOPPED', cls: 'text-error font-bold' };
  if (actionType === 'hitl_rejected')        return { label: 'REJECTED',      cls: 'text-error font-bold' };
  if (status === 'blocked')                  return { label: 'NEEDS REVIEW',  cls: 'text-error font-bold' };
  return { label: 'REVERSED', cls: 'text-emerald-500' };
}

export default function RollbackHistory() {
  const { showToast } = useToast();
  const [sagas, setSagas] = useState<SagaEntry[]>([]);
  const [loading, setLoading] = useState(true);

  const load = () => {
    setLoading(true);
    operatorFetch(`${API}/api/v1/sagas?per_page=100`)
      .then(r => r.json())
      .then(body => { if (body.status === 'success') setSagas(body.data.data ?? []); })
      .catch(() => showToast('Failed to load rollback history.'))
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, []);

  return (
    <>
      <Sidebar />
      <TopAppBar />
      <main className="pt-24 pb-12 px-10 min-h-screen transition-all duration-300" style={{ marginLeft: 'var(--sidebar-width, 18rem)' }}>
        <section className="mb-10">
          <div className="flex justify-between items-end mb-8">
            <div>
              <h1 className="text-4xl font-black font-headline tracking-tighter text-on-surface mb-2">Rollback History</h1>
              <p className="text-on-surface-variant font-body max-w-xl">A record of every action that was automatically reversed, blocked, or flagged for review by the security system.</p>
            </div>
            <div className="flex gap-3">
              <button
                onClick={load}
                className="px-4 py-2 bg-[#262626] border border-white/5 text-on-surface rounded-lg font-headline font-bold text-xs uppercase tracking-wider hover:bg-white/10 flex items-center gap-2"
              >
                <span className="material-symbols-outlined text-[14px]">refresh</span> Refresh
              </button>
            </div>
          </div>

          <div className="bg-[#131313] border border-white/5 rounded-2xl p-8 flex flex-col h-auto">
            <div className="grid grid-cols-5 font-technical text-on-surface-variant text-xs border-b border-white/5 pb-4 mb-4">
              <span>Reference ID</span>
              <span>Agent</span>
              <span>Destination</span>
              <span>Reason</span>
              <span>Result</span>
            </div>

            {loading && (
              <div className="py-12 flex items-center justify-center text-neutral-500 font-technical text-xs animate-pulse">
                Loading rollback history...
              </div>
            )}

            {!loading && sagas.length === 0 && (
              <div className="py-12 flex items-center justify-center text-neutral-600 font-technical text-xs">
                No rollbacks yet. Reversed and blocked actions appear here automatically.
              </div>
            )}

            {sagas.map((saga, i) => {
              const { label, cls } = statusLabel(saga.action_type, saga.status);
              const needsReview = saga.status === 'blocked' || saga.action_type === 'circuit_breaker_trip';
              const reasonLabel =
                saga.action_type === 'circuit_breaker_trip' ? 'Auto-stopped' :
                saga.action_type === 'hitl_rejected' ? 'Manually rejected' :
                saga.action_type === 'rollback_triggered' ? 'Action reversed' :
                saga.action_type.replace(/_/g, ' ');
              return (
                <div
                  key={saga.trace_id}
                  className={`grid grid-cols-5 font-technical text-on-surface text-sm py-4 hover:bg-white/5 px-2 rounded-lg transition-colors border-t items-center ${i === 0 ? 'border-transparent' : 'border-white/5'}`}
                >
                  <span className="text-orange-500 truncate pr-2">{saga.trace_id}</span>
                  <span className="truncate pr-2 text-neutral-300">{saga.agent_name ?? saga.agent_id}</span>
                  <span className="truncate pr-2">{saga.target_api}</span>
                  <span className="text-neutral-400 truncate pr-2">{reasonLabel}</span>
                  <span className={`${cls} flex items-center gap-2`}>
                    <span className={`w-2 h-2 rounded-full ${needsReview ? 'bg-error animate-pulse' : 'bg-emerald-500'}`}></span>
                    {label}
                  </span>
                </div>
              );
            })}
          </div>
        </section>
      </main>
    </>
  );
}
