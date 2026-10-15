// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

'use client';

import React, { useEffect, useState } from 'react';
import { useSession } from '../layout';

const CORE_API = process.env.NEXT_PUBLIC_CORE_API_URL || 'http://localhost:8000';

export default function ThreatIntelligence() {
  const session = useSession();
  const [records, setRecords]   = useState<any[]>([]);
  const [stats, setStats]       = useState({ blocked: 0, sandboxed: 0, lowConfidence: 0 });
  const [loading, setLoading]   = useState(true);
  const [page, setPage]         = useState(1);
  const [lastPage, setLastPage] = useState(1);

  function load(p = 1) {
    if (!session) return;
    setLoading(true);
    fetch(`${CORE_API}/api/v1/portal/transactions?status=blocked&page=${p}`, {
      headers: { Authorization: `Bearer ${session.token}`, Accept: 'application/json' },
    }).then(r => r.json()).then(({ data }) => {
      setRecords(data.records);
      setLastPage(data.last_page);
      setStats({ blocked: data.total, sandboxed: 0, lowConfidence: 0 });
      setLoading(false);
    });
  }

  useEffect(() => { load(); }, [session]);

  return (
    <div className="p-8 space-y-6">
      <div>
        <h1 className="text-3xl font-black font-headline tracking-tighter">Threat Intelligence</h1>
        <p className="text-on-surface-muted text-sm mt-1">Blocked agents, anomalies, and suspicious patterns detected by your Gateway</p>
      </div>

      <div className="grid grid-cols-3 gap-4">
        {[
          { label: 'Agents Blocked',     value: stats.blocked,        icon: 'block',         accent: 'text-red-400' },
          { label: 'Shadow Sandboxed',   value: stats.sandboxed,      icon: 'science',       accent: 'text-purple-400' },
          { label: 'Low Confidence',     value: stats.lowConfidence,  icon: 'warning',       accent: 'text-yellow-400' },
        ].map(s => (
          <div key={s.label} className="bg-surface-raised border border-[rgba(255,159,74,0.08)] rounded-2xl p-6">
            <span className={`material-symbols-outlined text-2xl ${s.accent}`}>{s.icon}</span>
            <p className="text-3xl font-black font-headline mt-3">{s.value}</p>
            <p className="text-xs font-technical text-on-surface-muted uppercase tracking-widest mt-1">{s.label}</p>
          </div>
        ))}
      </div>

      <div>
        <h2 className="text-lg font-headline font-bold mb-4">Blocked Agent Events</h2>
        {loading ? (
          <div className="flex items-center justify-center py-16">
            <div className="w-8 h-8 border-2 border-primary border-t-transparent rounded-full animate-spin" />
          </div>
        ) : records.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 bg-surface-raised border border-[rgba(255,159,74,0.08)] rounded-2xl">
            <span className="material-symbols-outlined text-green-400 text-5xl mb-3">verified_user</span>
            <p className="text-on-surface-muted text-sm">No blocked agents. Your Gateway is clean.</p>
          </div>
        ) : (
          <>
            <div className="space-y-2">
              {records.map((r: any) => (
                <div key={r.trace_id} className="flex items-center justify-between p-4 bg-surface-raised border border-red-500/10 rounded-xl">
                  <div className="flex items-center gap-4 min-w-0">
                    <span className="material-symbols-outlined text-red-400 text-xl flex-shrink-0">block</span>
                    <div className="min-w-0">
                      <p className="text-sm font-headline font-bold">{r.agent_name ?? 'Unknown Agent'}</p>
                      <p className="text-xs font-technical text-on-surface-muted truncate">{r.target_api}</p>
                      <p className="text-[10px] text-on-surface-muted/50 font-technical">{new Date(r.created_at).toLocaleString()}</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-3 flex-shrink-0">
                    {r.swarm_confidence_score != null && (
                      <div className="text-right">
                        <p className="text-xs font-technical text-red-400">{(r.swarm_confidence_score * 100).toFixed(0)}%</p>
                        <p className="text-[10px] text-on-surface-muted/50 font-technical">confidence</p>
                      </div>
                    )}
                    <span className="text-xs font-technical px-2.5 py-1 rounded-full text-red-400 bg-red-400/10">blocked</span>
                  </div>
                </div>
              ))}
            </div>
            {lastPage > 1 && (
              <div className="flex items-center justify-center gap-3 mt-4">
                <button onClick={() => { setPage(p => p - 1); load(page - 1); }} disabled={page === 1}
                  className="px-4 py-2 rounded-lg text-sm font-technical text-on-surface-muted hover:text-on-surface disabled:opacity-30"
                >← Prev</button>
                <span className="text-xs font-technical text-on-surface-muted">{page} / {lastPage}</span>
                <button onClick={() => { setPage(p => p + 1); load(page + 1); }} disabled={page === lastPage}
                  className="px-4 py-2 rounded-lg text-sm font-technical text-on-surface-muted hover:text-on-surface disabled:opacity-30"
                >Next →</button>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
