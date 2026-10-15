// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

'use client';
import { operatorFetch } from '@/lib/operatorFetch';

import React, { useEffect, useState, useCallback } from 'react';
import Link from 'next/link';
import { Sidebar } from '../../components/Sidebar';
import { TopAppBar } from '../../components/TopAppBar';

const CORE_API = process.env.NEXT_PUBLIC_CORE_API_URL || 'http://localhost:8000';

const PLAN_COLOUR: Record<string, string> = {
  starter:      'text-sky-400 bg-sky-400/10',
  professional: 'text-primary bg-primary/10',
  enterprise:   'text-purple-400 bg-purple-400/10',
};

const STATUS_COLOUR: Record<string, string> = {
  active:    'text-green-400 bg-green-400/10',
  suspended: 'text-red-400 bg-red-400/10',
  pending:   'text-yellow-400 bg-yellow-400/10',
};

export default function CRMCompanies() {
  const [companies, setCompanies]   = useState<any[]>([]);
  const [total, setTotal]           = useState(0);
  const [page, setPage]             = useState(1);
  const [lastPage, setLastPage]     = useState(1);
  const [loading, setLoading]       = useState(true);
  const [search, setSearch]         = useState('');
  const [planFilter, setPlanFilter] = useState('');

  const load = useCallback((p = 1, s = search, plan = planFilter) => {
    setLoading(true);
    const params = new URLSearchParams({ page: String(p) });
    if (s)    params.set('search', s);
    if (plan) params.set('plan', plan);
    operatorFetch(`${CORE_API}/api/v1/crm/companies?${params}`)
      .then(r => r.json())
      .then(({ data }) => {
        setCompanies(data.data);
        setTotal(data.total);
        setLastPage(data.last_page);
        setLoading(false);
      });
  }, [search, planFilter]);

  useEffect(() => { load(); }, []);

  function handleSearch(e: React.FormEvent) {
    e.preventDefault();
    setPage(1);
    load(1, search, planFilter);
  }

  return (
    <>
      <Sidebar />
      <TopAppBar />
      <main className="pt-24 px-8 pb-12 min-h-screen transition-all duration-300" style={{ marginLeft: 'var(--sidebar-width, 18rem)' }}>
        <div className="space-y-6 max-w-[95%] mx-auto">
          <div className="flex items-start justify-between">
        <div>
          <h1 className="text-3xl font-black font-headline tracking-tighter">Company CRM</h1>
          <p className="text-on-surface-muted text-sm mt-1">{total.toLocaleString()} registered companies</p>
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-3">
        <form onSubmit={handleSearch} className="flex gap-2 flex-1 min-w-[220px]">
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search by name or email…"
            className="flex-1 bg-black/40 border border-white/10 rounded-xl px-4 py-2 text-sm focus:outline-none focus:border-primary transition-colors"
          />
          <button type="submit" className="px-4 py-2 bg-primary text-black rounded-xl text-sm font-headline font-bold hover:brightness-110 transition-all">
            Search
          </button>
        </form>
        <div className="flex gap-2">
          {['', 'starter', 'professional', 'enterprise'].map(p => (
            <button key={p} onClick={() => { setPlanFilter(p); setPage(1); load(1, search, p); }}
              className={`px-4 py-2 rounded-xl text-xs font-technical transition-colors ${
                planFilter === p ? 'bg-primary text-black' : 'bg-white/5 text-on-surface-muted hover:bg-white/10'
              }`}
            >
              {p === '' ? 'All plans' : p.charAt(0).toUpperCase() + p.slice(1)}
            </button>
          ))}
        </div>
      </div>

      {loading ? (
        <div className="flex items-center justify-center py-20">
          <div className="w-8 h-8 border-2 border-primary border-t-transparent rounded-full animate-spin" />
        </div>
      ) : companies.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-20 bg-surface-raised border border-[rgba(255,159,74,0.08)] rounded-2xl">
          <span className="material-symbols-outlined text-on-surface-muted text-5xl mb-3">business</span>
          <p className="text-on-surface-muted text-sm">No companies found.</p>
        </div>
      ) : (
        <>
          <div className="bg-surface-raised border border-[rgba(255,159,74,0.08)] rounded-2xl overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-white/5 text-[10px] font-technical uppercase tracking-widest text-on-surface-muted">
                  <th className="text-left px-5 py-3">Company</th>
                  <th className="text-left px-5 py-3">Primary Contact</th>
                  <th className="text-left px-5 py-3">Plan</th>
                  <th className="text-left px-5 py-3">Status</th>
                  <th className="text-right px-5 py-3">Agents</th>
                  <th className="text-left px-5 py-3">Joined</th>
                  <th className="px-5 py-3" />
                </tr>
              </thead>
              <tbody>
                {companies.map((c: any) => (
                  <tr key={c.id} className="border-b border-white/[0.04] hover:bg-white/[0.02] transition-colors">
                    <td className="px-5 py-4">
                      <p className="font-headline font-bold">{c.name}</p>
                      {c.company_email && <p className="text-xs text-on-surface-muted/60 font-technical truncate max-w-[180px]">{c.company_email}</p>}
                    </td>
                    <td className="px-5 py-4">
                      {c.contact_name ? (
                        <>
                          <div className="flex items-center gap-2">
                            {c.contact_avatar && (
                              <img src={c.contact_avatar} alt="" className="w-6 h-6 rounded-full flex-shrink-0" />
                            )}
                            <p className="font-medium">{c.contact_name}</p>
                          </div>
                          <p className="text-xs text-on-surface-muted/60 font-technical">{c.contact_email}</p>
                        </>
                      ) : (
                        <span className="text-on-surface-muted/40 text-xs">—</span>
                      )}
                    </td>
                    <td className="px-5 py-4">
                      <span className={`text-xs font-technical px-2.5 py-1 rounded-full capitalize ${PLAN_COLOUR[c.plan] ?? 'text-gray-400 bg-gray-400/10'}`}>
                        {c.plan}
                      </span>
                    </td>
                    <td className="px-5 py-4">
                      <span className={`text-xs font-technical px-2.5 py-1 rounded-full capitalize ${STATUS_COLOUR[c.status] ?? 'text-gray-400 bg-gray-400/10'}`}>
                        {c.status}
                      </span>
                    </td>
                    <td className="px-5 py-4 text-right">
                      <p className="font-headline font-bold">{c.agent_count}</p>
                      <p className="text-[10px] text-on-surface-muted/50 font-technical">{c.certified_count} certified</p>
                    </td>
                    <td className="px-5 py-4 text-xs text-on-surface-muted font-technical">
                      {new Date(c.created_at).toLocaleDateString()}
                    </td>
                    <td className="px-5 py-4">
                      <Link href={`/crm/${c.id}`}
                        className="px-3 py-1.5 text-xs font-technical border border-white/10 rounded-lg hover:border-primary/30 hover:bg-white/5 transition-colors whitespace-nowrap"
                      >
                        View →
                      </Link>
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
      </main>
    </>
  );
}
