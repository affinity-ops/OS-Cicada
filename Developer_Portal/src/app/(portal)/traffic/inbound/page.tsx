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

export default function InboundTraffic() {
  const session = useSession();
  const [records, setRecords]       = useState<any[]>([]);
  const [total, setTotal]           = useState(0);
  const [hasGateway, setHasGateway] = useState(false);
  const [loading, setLoading]       = useState(true);
  const [page, setPage]             = useState(1);
  const [lastPage, setLastPage]     = useState(1);

  function load(p = 1) {
    if (!session) return;
    setLoading(true);
    fetch(`${CORE_API}/api/v1/portal/traffic/inbound?page=${p}`, {
      headers: { Authorization: `Bearer ${session.token}`, Accept: 'application/json' },
    }).then(r => r.json()).then(({ data }) => {
      setRecords(data.records);
      setTotal(data.total);
      setLastPage(data.last_page);
      setHasGateway(data.has_gateway);
      setLoading(false);
    });
  }

  useEffect(() => { load(); }, [session]);

  return (
    <div className="p-8 space-y-6">
      <div>
        <h1 className="text-3xl font-black font-headline tracking-tighter">Inbound Traffic</h1>
        <p className="text-on-surface-muted text-sm mt-1">External agents that have arrived at your Sentry Gateway installation</p>
      </div>

      {loading ? (
        <div className="flex items-center justify-center py-20">
          <div className="w-8 h-8 border-2 border-primary border-t-transparent rounded-full animate-spin" />
        </div>
      ) : !hasGateway ? (
        <div className="flex flex-col items-center justify-center py-20 bg-surface-raised border border-[rgba(255,159,74,0.08)] rounded-2xl text-center px-8">
          <span className="material-symbols-outlined text-on-surface-muted text-5xl mb-4">shield</span>
          <h2 className="text-lg font-headline font-bold mb-2">No Gateway Installation Detected</h2>
          <p className="text-sm text-on-surface-muted max-w-md">
            Inbound traffic appears here once you install the Cicada Sentry Gateway on your infrastructure.
            The Gateway intercepts external agent requests arriving at your systems and validates them against the Cicada trust network.
          </p>
          <a href="https://docs.cicada.io/gateway" target="_blank" rel="noopener noreferrer"
            className="mt-6 flex items-center gap-2 px-5 py-2.5 border border-primary/30 text-primary rounded-xl font-headline font-bold text-sm hover:bg-primary/5 transition-colors"
          >
            <span className="material-symbols-outlined text-[18px]">open_in_new</span>
            Gateway Installation Guide
          </a>
        </div>
      ) : records.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-20 bg-surface-raised border border-[rgba(255,159,74,0.08)] rounded-2xl">
          <span className="material-symbols-outlined text-on-surface-muted text-5xl mb-3">call_received</span>
          <p className="text-on-surface-muted text-sm">No inbound agents recorded yet.</p>
        </div>
      ) : (
        <>
          <p className="text-xs font-technical text-on-surface-muted">{total.toLocaleString()} inbound validations recorded</p>
          <div className="space-y-2">
            {records.map((r: any) => (
              <div key={r.trace_id} className="flex items-center justify-between p-4 bg-surface-raised border border-[rgba(255,159,74,0.06)] rounded-xl">
                <div className="flex items-center gap-4 min-w-0">
                  <span className="material-symbols-outlined text-primary text-xl flex-shrink-0">call_received</span>
                  <div className="min-w-0">
                    <p className="text-sm font-headline font-bold truncate font-mono">{r.payload_hash?.slice(0, 16)}…</p>
                    <p className="text-xs text-on-surface-muted font-technical truncate">{r.target_api}</p>
                    <p className="text-[10px] text-on-surface-muted/50 font-technical">{new Date(r.created_at).toLocaleString()}</p>
                  </div>
                </div>
                <span className={`text-xs font-technical px-2.5 py-1 rounded-full flex-shrink-0 ${STATUS_STYLE[r.status] ?? 'text-gray-400 bg-gray-400/10'}`}>
                  {r.status.replace('_', ' ')}
                </span>
              </div>
            ))}
          </div>
          {lastPage > 1 && (
            <div className="flex items-center justify-center gap-3">
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
  );
}
