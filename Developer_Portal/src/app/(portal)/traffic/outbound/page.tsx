// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

'use client';

import React, { useEffect, useState } from 'react';
import { useSession } from '../../layout';

const CORE_API = process.env.NEXT_PUBLIC_CORE_API_URL || 'http://localhost:8000';

const STATUS_STYLE: Record<string, string> = {
  approved:       'text-green-400 bg-green-400/10',
  blocked:        'text-red-400 bg-red-400/10',
  pending_swarm:  'text-yellow-400 bg-yellow-400/10',
  shadow_sandbox: 'text-purple-400 bg-purple-400/10',
};

export default function OutboundTraffic() {
  const session = useSession();
  const [records, setRecords]   = useState<any[]>([]);
  const [total, setTotal]       = useState(0);
  const [page, setPage]         = useState(1);
  const [lastPage, setLastPage] = useState(1);
  const [loading, setLoading]   = useState(true);
  const [status, setStatus]     = useState('');

  function load(p = 1, s = status) {
    if (!session) return;
    setLoading(true);
    const params = new URLSearchParams({ page: String(p) });
    if (s) params.set('status', s);
    fetch(`${CORE_API}/api/v1/portal/traffic/outbound?${params}`, {
      headers: { Authorization: `Bearer ${session.token}`, Accept: 'application/json' },
    }).then(r => r.json()).then(({ data }) => {
      setRecords(data.records);
      setTotal(data.total);
      setLastPage(data.last_page);
      setLoading(false);
    });
  }

  useEffect(() => { load(); }, [session]);

  return (
    <div className="p-8 space-y-6">
      <div>
        <h1 className="text-3xl font-black font-headline tracking-tighter">Outbound Traffic</h1>
        <p className="text-on-surface-muted text-sm mt-1">Your agents&apos; requests passing through the Sentry Gateway — {total.toLocaleString()} total</p>
      </div>

      <div className="flex gap-2">
        {['', 'approved', 'blocked', 'pending_swarm', 'shadow_sandbox'].map(s => (
          <button key={s} onClick={() => { setStatus(s); setPage(1); load(1, s); }}
            className={`px-4 py-1.5 rounded-full text-xs font-technical transition-colors ${
              status === s ? 'bg-primary text-black' : 'bg-white/5 text-on-surface-muted hover:bg-white/10'
            }`}
          >
            {s === '' ? 'All' : s.replace('_', ' ')}
          </button>
        ))}
      </div>

      {loading ? (
        <div className="flex items-center justify-center py-20">
          <div className="w-8 h-8 border-2 border-primary border-t-transparent rounded-full animate-spin" />
        </div>
      ) : records.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-20 bg-surface-raised border border-[rgba(255,159,74,0.08)] rounded-2xl">
          <span className="material-symbols-outlined text-on-surface-muted text-5xl mb-3">call_made</span>
          <p className="text-on-surface-muted text-sm">No outbound traffic recorded yet.</p>
          <p className="text-xs text-on-surface-muted/60 mt-1">Traffic appears here once your agents start making requests.</p>
        </div>
      ) : (
        <>
          <div className="space-y-2">
            {records.map((r: any) => (
              <div key={r.trace_id} className="flex items-center justify-between p-4 bg-surface-raised border border-[rgba(255,159,74,0.06)] rounded-xl">
                <div className="flex items-center gap-4 min-w-0">
                  <span className="material-symbols-outlined text-primary text-xl flex-shrink-0">call_made</span>
                  <div className="min-w-0">
                    <p className="text-sm font-headline font-bold truncate">{r.agent_name ?? 'Unknown Agent'}</p>
                    <p className="text-xs text-on-surface-muted font-technical truncate">{r.target_api}</p>
                    <p className="text-[10px] text-on-surface-muted/50 font-technical">{new Date(r.created_at).toLocaleString()}</p>
                  </div>
                </div>
                <div className="flex items-center gap-3 flex-shrink-0">
                  {r.swarm_confidence_score != null && (
                    <span className="text-[10px] font-technical text-on-surface-muted">
                      {(r.swarm_confidence_score * 100).toFixed(0)}% confidence
                    </span>
                  )}
                  <span className={`text-xs font-technical px-2.5 py-1 rounded-full ${STATUS_STYLE[r.status] ?? 'text-gray-400 bg-gray-400/10'}`}>
                    {r.status.replace('_', ' ')}
                  </span>
                </div>
              </div>
            ))}
          </div>

          {lastPage > 1 && (
            <div className="flex items-center justify-center gap-3">
              <button onClick={() => { setPage(p => p - 1); load(page - 1); }} disabled={page === 1}
                className="px-4 py-2 rounded-lg text-sm font-technical text-on-surface-muted hover:text-on-surface disabled:opacity-30 transition-colors"
              >← Prev</button>
              <span className="text-xs font-technical text-on-surface-muted">{page} / {lastPage}</span>
              <button onClick={() => { setPage(p => p + 1); load(page + 1); }} disabled={page === lastPage}
                className="px-4 py-2 rounded-lg text-sm font-technical text-on-surface-muted hover:text-on-surface disabled:opacity-30 transition-colors"
              >Next →</button>
            </div>
          )}
        </>
      )}
    </div>
  );
}
