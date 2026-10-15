// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

'use client';
import { operatorFetch } from '@/lib/operatorFetch';
import { useState } from 'react';
import Link from 'next/link';
import { Sidebar } from '../../../components/Sidebar';
import { TopAppBar } from '../../../components/TopAppBar';

const API = process.env.NEXT_PUBLIC_CORE_API_URL ?? 'http://localhost:8000';

export default function AuditExport() {
  const [from, setFrom] = useState(() => {
    const d = new Date(); d.setDate(d.getDate() - 7);
    return d.toISOString().substring(0, 10);
  });
  const [to, setTo] = useState(() => new Date().toISOString().substring(0, 10));
  const [status, setStatus] = useState('all');
  const [exporting, setExporting] = useState(false);
  const [exported, setExported] = useState(false);

  const runExport = (format: 'csv' | 'json' | 'pdf') => {
    setExporting(true);
    const params = new URLSearchParams({ from, to, ...(status !== 'all' && { status }), format });
    operatorFetch(`${API}/api/v1/admin/compliance-report?${params}`)
      .then(r => r.blob())
      .then(blob => {
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `cicada-audit-${from}-to-${to}.${format}`;
        a.click();
        URL.revokeObjectURL(url);
        setExported(true);
        setTimeout(() => setExported(false), 3000);
      })
      .catch(() => {
        if (format === 'pdf') return; // PDF must come from backend
        // Fallback: build client-side CSV from logs endpoint
        operatorFetch(`${API}/api/v1/logs?per_page=1000${status !== 'all' ? `&status=${status}` : ''}`)
          .then(r => r.json())
          .then(body => {
            const rows: Record<string, unknown>[] = body.data?.data ?? [];
            const headers = ['trace_id','agent_id','action_type','status','target_api','swarm_confidence_score','policy_violations','created_at'];
            const csv = [headers.join(','), ...rows.map(r => headers.map(h => JSON.stringify(r[h] ?? '')).join(','))].join('\n');
            const blob2 = new Blob([csv], { type: 'text/csv' });
            const url2 = URL.createObjectURL(blob2);
            const a = document.createElement('a');
            a.href = url2; a.download = `cicada-audit-${from}-to-${to}.csv`; a.click();
            URL.revokeObjectURL(url2);
            setExported(true);
            setTimeout(() => setExported(false), 3000);
          });
      })
      .finally(() => setExporting(false));
  };

  return (
    <>
      <Sidebar />
      <TopAppBar />
      <main className="pt-24 px-8 pb-12 min-h-screen bg-background transition-all duration-300" style={{ marginLeft: 'var(--sidebar-width, 18rem)' }}>
        <div className="max-w-5xl mx-auto space-y-8">

          <div>
            <h1 className="text-5xl font-black font-headline tracking-tighter">Audit <span className="text-orange-500">&amp; Export</span></h1>
            <p className="text-neutral-400 mt-2 max-w-2xl">Generate signed audit reports for any time range. Export for compliance, legal review, or insurance requirements. Every export is timestamped and traceable.</p>
          </div>

          <div className="bg-blue-500/5 border border-blue-500/20 rounded-2xl p-6 flex gap-4">
            <span className="material-symbols-outlined text-blue-400 flex-shrink-0 mt-0.5">info</span>
            <div className="space-y-1">
              <p className="font-bold text-blue-300 text-sm">How to use this screen</p>
              <p className="text-neutral-400 text-sm">Select a date range and filter by event status. Click Export CSV to download a spreadsheet of all matching events — suitable for SOC2 auditors, legal teams, or insurance providers. Ask Aegis to generate a narrative summary report with recommendations.</p>
            </div>
          </div>

          <div className="bg-[#131313] border border-white/5 rounded-2xl p-8 space-y-6">
            <h2 className="font-headline font-bold text-xl">Configure Export</h2>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="space-y-2">
                <label className="text-xs font-technical text-neutral-500 uppercase tracking-wider">From Date</label>
                <input type="date" value={from} onChange={e => setFrom(e.target.value)}
                  className="w-full bg-[#1a1a1a] border border-white/10 rounded-xl px-4 py-3 font-technical text-sm text-on-surface focus:outline-none focus:border-orange-500/50" />
              </div>
              <div className="space-y-2">
                <label className="text-xs font-technical text-neutral-500 uppercase tracking-wider">To Date</label>
                <input type="date" value={to} onChange={e => setTo(e.target.value)}
                  className="w-full bg-[#1a1a1a] border border-white/10 rounded-xl px-4 py-3 font-technical text-sm text-on-surface focus:outline-none focus:border-orange-500/50" />
              </div>
              <div className="space-y-2">
                <label className="text-xs font-technical text-neutral-500 uppercase tracking-wider">Event Status</label>
                <select value={status} onChange={e => setStatus(e.target.value)}
                  className="w-full bg-[#1a1a1a] border border-white/10 rounded-xl px-4 py-3 font-technical text-sm text-on-surface focus:outline-none focus:border-orange-500/50">
                  <option value="all">All Events</option>
                  <option value="blocked">Blocked Only</option>
                  <option value="approved">Approved Only</option>
                  <option value="shadow_sandbox">Shadow Sandbox</option>
                </select>
              </div>
            </div>

            <div className="flex flex-wrap gap-4 pt-2">
              <button onClick={() => runExport('csv')} disabled={exporting}
                className="flex items-center gap-2 px-6 py-3 bg-white/5 hover:bg-white/10 border border-white/10 text-white font-bold rounded-xl transition-colors disabled:opacity-50">
                <span className="material-symbols-outlined text-[18px]">download</span>
                {exporting ? 'Exporting…' : 'Export CSV'}
              </button>
              <button onClick={() => runExport('json')} disabled={exporting}
                className="flex items-center gap-2 px-6 py-3 bg-white/5 hover:bg-white/10 border border-white/10 font-bold rounded-xl transition-colors disabled:opacity-50">
                <span className="material-symbols-outlined text-[18px]">code</span>
                Export JSON
              </button>
              <button onClick={() => runExport('pdf')} disabled={exporting}
                className="flex items-center gap-2 px-6 py-3 bg-orange-500 hover:bg-orange-600 text-black font-bold rounded-xl transition-colors disabled:opacity-50">
                <span className="material-symbols-outlined text-[18px]">picture_as_pdf</span>
                {exporting ? 'Generating PDF…' : 'Generate PDF'}
              </button>
              <button onClick={() => {
                const a = document.createElement('a');
                a.href = `${API}/api/v1/admin/retraining-dataset`;
                a.download = `retraining-dataset.jsonl`;
                a.click();
              }}
                className="flex items-center gap-2 px-6 py-3 bg-purple-500/10 border border-purple-500/20 text-purple-400 hover:bg-purple-500/20 font-bold rounded-xl transition-colors">
                <span className="material-symbols-outlined text-[18px]">model_training</span>
                Export Dataset
              </button>
              <Link href="/aegis" className="flex items-center gap-2 px-6 py-3 bg-blue-500/10 border border-blue-500/20 text-blue-400 font-bold rounded-xl hover:bg-blue-500/20 transition-colors">
                <span className="material-symbols-outlined text-[18px]">trip_origin</span>
                Ask Aegis for Report
              </Link>
            </div>
            {exported && <p className="text-emerald-400 font-technical text-sm animate-pulse">Export downloaded successfully.</p>}
          </div>

          <div className="bg-[#131313] border border-white/5 rounded-2xl p-6">
            <h3 className="font-headline font-bold mb-4">What is included in every export</h3>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              {['Trace ID','Agent ID','Action Type','Block Status','Target API','Risk Score','Policy Violations','Timestamp'].map(f => (
                <div key={f} className="flex items-center gap-2 text-sm text-neutral-400">
                  <span className="material-symbols-outlined text-emerald-500 text-[16px]">check</span>{f}
                </div>
              ))}
            </div>
          </div>
        </div>
      </main>
    </>
  );
}
