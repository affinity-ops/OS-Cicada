// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

'use client';

import React, { useEffect, useState } from 'react';
import { useSession } from '../layout';

const CORE_API = process.env.NEXT_PUBLIC_CORE_API_URL || 'http://localhost:8000';

const STATUS_STYLE: Record<string, string> = {
  approved:       'text-green-400 bg-green-400/10',
  blocked:        'text-red-400 bg-red-400/10',
  pending_swarm:  'text-yellow-400 bg-yellow-400/10',
  shadow_sandbox: 'text-purple-400 bg-purple-400/10',
};

export default function Transactions() {
  const session = useSession();
  const [records, setRecords]   = useState<any[]>([]);
  const [total, setTotal]       = useState(0);
  const [page, setPage]         = useState(1);
  const [lastPage, setLastPage] = useState(1);
  const [loading, setLoading]   = useState(true);
  const [filters, setFilters]   = useState({ status: '', search: '', date_from: '', date_to: '' });

  function load(p = 1, f = filters) {
    if (!session) return;
    setLoading(true);
    const params = new URLSearchParams({ page: String(p) });
    if (f.status)    params.set('status', f.status);
    if (f.search)    params.set('search', f.search);
    if (f.date_from) params.set('date_from', f.date_from);
    if (f.date_to)   params.set('date_to', f.date_to);
    fetch(`${CORE_API}/api/v1/portal/transactions?${params}`, {
      headers: { Authorization: `Bearer ${session.token}`, Accept: 'application/json' },
    }).then(r => r.json()).then(({ data }) => {
      setRecords(data.records);
      setTotal(data.total);
      setLastPage(data.last_page);
      setLoading(false);
    });
  }

  useEffect(() => { load(); }, [session]);

  function applyFilter(key: string, val: string) {
    const updated = { ...filters, [key]: val };
    setFilters(updated);
    setPage(1);
    load(1, updated);
  }

  return (
    <div className="p-8 space-y-6">
      <div>
        <h1 className="text-3xl font-black font-headline tracking-tighter">Transaction History</h1>
        <p className="text-on-surface-muted text-sm mt-1">Complete action ledger for all agents — {total.toLocaleString()} records</p>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-3">
        <input
          placeholder="Search by target API…"
          value={filters.search}
          onChange={e => applyFilter('search', e.target.value)}
          className="bg-black/40 border border-white/10 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-primary transition-colors w-56"
        />
        <select value={filters.status} onChange={e => applyFilter('status', e.target.value)}
          className="bg-black/40 border border-white/10 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-primary transition-colors"
        >
          <option value="">All statuses</option>
          <option value="approved">Approved</option>
          <option value="blocked">Blocked</option>
          <option value="pending_swarm">Pending Swarm</option>
          <option value="shadow_sandbox">Shadow Sandbox</option>
        </select>
        <input type="date" value={filters.date_from} onChange={e => applyFilter('date_from', e.target.value)}
          className="bg-black/40 border border-white/10 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-primary transition-colors text-on-surface-muted"
        />
        <input type="date" value={filters.date_to} onChange={e => applyFilter('date_to', e.target.value)}
          className="bg-black/40 border border-white/10 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-primary transition-colors text-on-surface-muted"
        />
        {(filters.status || filters.search || filters.date_from || filters.date_to) && (
          <button onClick={() => { setFilters({ status: '', search: '', date_from: '', date_to: '' }); load(1, { status: '', search: '', date_from: '', date_to: '' }); }}
            className="px-3 py-2 text-xs font-technical text-on-surface-muted hover:text-on-surface transition-colors"
          >
            Clear filters
          </button>
        )}
      </div>

      {loading ? (
        <div className="flex items-center justify-center py-20">
          <div className="w-8 h-8 border-2 border-primary border-t-transparent rounded-full animate-spin" />
        </div>
      ) : records.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-20 bg-surface-raised border border-[rgba(255,159,74,0.08)] rounded-2xl">
          <span className="material-symbols-outlined text-on-surface-muted text-5xl mb-3">receipt_long</span>
          <p className="text-on-surface-muted text-sm">No transactions found.</p>
        </div>
      ) : (
        <>
          {/* Table */}
          <div className="bg-surface-raised border border-[rgba(255,159,74,0.08)] rounded-2xl overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[rgba(255,159,74,0.08)]">
                  {['Agent', 'Target API', 'Action', 'Status', 'Confidence', 'Time'].map(h => (
                    <th key={h} className="text-left px-4 py-3 text-[10px] font-technical text-on-surface-muted uppercase tracking-widest">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {records.map((r: any) => (
                  <tr key={r.trace_id} className="border-b border-[rgba(255,255,255,0.03)] hover:bg-white/2 transition-colors">
                    <td className="px-4 py-3 font-headline font-bold text-xs">{r.agent_name ?? '—'}</td>
                    <td className="px-4 py-3 font-technical text-xs text-on-surface-muted truncate max-w-[180px]">{r.target_api}</td>
                    <td className="px-4 py-3 font-technical text-xs text-on-surface-muted">{r.action_type}</td>
                    <td className="px-4 py-3">
                      <span className={`text-[10px] font-technical px-2 py-0.5 rounded-full ${STATUS_STYLE[r.status] ?? 'text-gray-400 bg-gray-400/10'}`}>
                        {r.status.replace('_', ' ')}
                      </span>
                    </td>
                    <td className="px-4 py-3 font-technical text-xs text-on-surface-muted">
                      {r.swarm_confidence_score != null ? `${(r.swarm_confidence_score * 100).toFixed(0)}%` : '—'}
                    </td>
                    <td className="px-4 py-3 font-technical text-[10px] text-on-surface-muted/60">
                      {new Date(r.created_at).toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
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
