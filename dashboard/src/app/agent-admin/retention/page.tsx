// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

'use client';
import { operatorFetch } from '@/lib/operatorFetch';
import { useState, useEffect, useCallback } from 'react';
import Link from 'next/link';
import { Sidebar } from '../../../components/Sidebar';
import { TopAppBar } from '../../../components/TopAppBar';

const API = process.env.NEXT_PUBLIC_CORE_API_URL ?? 'http://localhost:8000';

interface RetentionPolicy {
  id: string;
  label: string;
  description: string;
  retention_days: number;
  auto_delete: boolean;
  archive_before_delete: boolean;
}

export default function RetentionPolicyPage() {
  const [policies, setPolicies] = useState<RetentionPolicy[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);

  const loadPolicies = useCallback(() => {
    setLoading(true);
    operatorFetch(`${API}/api/v1/admin/retention-policies`, { headers: { Accept: 'application/json' } })
      .then(r => r.json())
      .then(body => { if (body.status === 'success') setPolicies(body.data ?? []); })
      .catch((e: any) => { console.error('Failed to load retention policies:', e); })
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => { loadPolicies(); }, [loadPolicies]);

  const updatePolicy = (id: string, field: keyof RetentionPolicy, value: unknown) => {
    setPolicies(p => p.map(x => x.id === id ? { ...x, [field]: value } : x));
  };

  const save = async () => {
    setSaving(true);
    try {
      const res = await operatorFetch(`${API}/api/v1/admin/retention-policies`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({
          policies: policies.map(p => ({
            id: p.id,
            retention_days: p.retention_days,
            auto_delete: p.auto_delete,
            archive_before_delete: p.archive_before_delete,
          })),
        }),
      });
      if (res.ok) {
        setSaved(true);
        setTimeout(() => setSaved(false), 2500);
      }
    } catch (e) {
      console.error('Failed to save retention policies:', e);
    }
    setSaving(false);
  };

  const tierColour = (days: number) => {
    if (days >= 730) return 'text-red-400';
    if (days >= 365) return 'text-orange-400';
    if (days >= 180) return 'text-yellow-400';
    return 'text-emerald-400';
  };

  return (
    <>
      <Sidebar />
      <TopAppBar />
      <main className="pt-24 px-8 pb-12 min-h-screen bg-background transition-all duration-300" style={{ marginLeft: 'var(--sidebar-width, 18rem)' }}>
        <div className="max-w-5xl mx-auto space-y-8">

          <div>
            <h1 className="text-5xl font-black font-headline tracking-tighter">Retention <span className="text-orange-500">Policy</span></h1>
            <p className="text-neutral-400 mt-2 max-w-2xl">Control how long each data category is kept. Longer retention improves auditability; shorter retention reduces storage and privacy exposure. SOC2 and ISO27001 typically require at least 12 months for security events.</p>
          </div>

          <div className="bg-blue-500/5 border border-blue-500/20 rounded-2xl p-6 flex gap-4">
            <span className="material-symbols-outlined text-blue-400 flex-shrink-0 mt-0.5">info</span>
            <div>
              <p className="font-bold text-blue-300 text-sm">How to use this screen</p>
              <p className="text-neutral-400 text-sm mt-1">
                Each row controls one category of platform data. Set the number of days to retain records after they are created. Enable &ldquo;Auto Delete&rdquo; to have Cicada purge records automatically when they expire. Enable &ldquo;Archive First&rdquo; to export a signed archive before deletion — required for any data that may be subject to a legal hold. Click &ldquo;Ask Aegis&rdquo; for compliance guidance tailored to your industry.
              </p>
            </div>
          </div>

          {/* Compliance quick-reference */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {[
              { standard: 'SOC 2 Type II', requirement: 'Minimum 12 months', icon: 'verified_user', colour: 'emerald' },
              { standard: 'ISO 27001',     requirement: 'Minimum 12 months', icon: 'shield',         colour: 'blue'    },
              { standard: 'NIST AI RMF',   requirement: 'Risk-proportionate', icon: 'policy',        colour: 'orange'  },
            ].map(c => (
              <div key={c.standard} className={`bg-${c.colour}-500/5 border border-${c.colour}-500/20 rounded-xl p-4 flex items-start gap-3`}>
                <span className={`material-symbols-outlined text-${c.colour}-400 text-[20px] flex-shrink-0 mt-0.5`}>{c.icon}</span>
                <div>
                  <p className={`font-bold text-${c.colour}-300 text-sm`}>{c.standard}</p>
                  <p className="text-neutral-400 text-xs mt-0.5">{c.requirement}</p>
                </div>
              </div>
            ))}
          </div>

          {/* Policy table */}
          <div className="bg-[#131313] border border-white/5 rounded-2xl overflow-hidden">
            <div className="px-6 py-4 border-b border-white/5 flex justify-between items-center">
              <h2 className="font-headline font-bold">Data Category Policies</h2>
              <Link href="/aegis?context=retention_review" className="flex items-center gap-2 px-3 py-2 bg-blue-500/10 border border-blue-500/20 text-blue-400 rounded-lg text-xs font-bold hover:bg-blue-500/20 transition-colors">
                <span className="material-symbols-outlined text-[14px]">trip_origin</span>Ask Aegis for Compliance Guidance
              </Link>
            </div>

            {loading ? (
              <div className="px-6 py-8 text-center text-neutral-500 font-technical text-xs animate-pulse">Loading retention policies…</div>
            ) : (
              <div className="divide-y divide-white/5">
                {policies.map(p => (
                  <div key={p.id} className="px-6 py-5 grid grid-cols-12 gap-4 items-center">
                    <div className="col-span-4">
                      <p className="font-bold text-sm text-on-surface">{p.label}</p>
                      <p className="text-xs text-neutral-500 mt-0.5">{p.description}</p>
                    </div>
                    <div className="col-span-2">
                      <label className="text-[10px] font-technical text-neutral-500 uppercase tracking-wider block mb-1">Retain (days)</label>
                      <input
                        type="number" min={1} max={3650} value={p.retention_days}
                        onChange={e => updatePolicy(p.id, 'retention_days', Number(e.target.value))}
                        className="w-full bg-[#1a1a1a] border border-white/10 rounded-lg px-3 py-2 font-technical text-sm focus:outline-none focus:border-orange-500/50"
                      />
                      <p className={`text-[10px] font-technical mt-1 font-bold ${tierColour(p.retention_days)}`}>
                        {p.retention_days >= 730 ? '2 yr+' : p.retention_days >= 365 ? '1 yr+' : p.retention_days >= 180 ? '6 mo+' : `${p.retention_days}d`}
                      </p>
                    </div>
                    <div className="col-span-3 flex flex-col gap-3">
                      <label className="flex items-center gap-3 cursor-pointer">
                        <button
                          onClick={() => updatePolicy(p.id, 'auto_delete', !p.auto_delete)}
                          className={`w-10 h-6 rounded-full transition-colors flex-shrink-0 relative ${p.auto_delete ? 'bg-orange-500' : 'bg-white/10'}`}
                        >
                          <span className={`absolute top-1 w-4 h-4 rounded-full bg-white transition-all ${p.auto_delete ? 'left-5' : 'left-1'}`}></span>
                        </button>
                        <span className="text-xs font-technical text-neutral-400">Auto Delete</span>
                      </label>
                      <label className="flex items-center gap-3 cursor-pointer">
                        <button
                          onClick={() => updatePolicy(p.id, 'archive_before_delete', !p.archive_before_delete)}
                          className={`w-10 h-6 rounded-full transition-colors flex-shrink-0 relative ${p.archive_before_delete ? 'bg-emerald-500' : 'bg-white/10'}`}
                        >
                          <span className={`absolute top-1 w-4 h-4 rounded-full bg-white transition-all ${p.archive_before_delete ? 'left-5' : 'left-1'}`}></span>
                        </button>
                        <span className="text-xs font-technical text-neutral-400">Archive First</span>
                      </label>
                    </div>
                    <div className="col-span-3">
                      <div className={`inline-flex items-center gap-1.5 px-2 py-1 rounded text-[10px] font-technical font-bold uppercase ${
                        !p.auto_delete ? 'bg-emerald-500/10 text-emerald-400' :
                        p.archive_before_delete ? 'bg-yellow-500/10 text-yellow-400' :
                        'bg-red-500/10 text-red-400'
                      }`}>
                        <span className="material-symbols-outlined text-[12px]">
                          {!p.auto_delete ? 'lock' : p.archive_before_delete ? 'archive' : 'delete_forever'}
                        </span>
                        {!p.auto_delete ? 'Manual only' : p.archive_before_delete ? 'Archive & delete' : 'Hard delete'}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Legal hold notice */}
          <div className="bg-orange-500/5 border border-orange-500/20 rounded-2xl p-6 flex gap-4">
            <span className="material-symbols-outlined text-orange-400 flex-shrink-0 mt-0.5">gavel</span>
            <div>
              <p className="font-bold text-orange-300 text-sm">Legal Hold</p>
              <p className="text-neutral-400 text-sm mt-1">
                If your organisation is subject to litigation or regulatory investigation, all auto-delete rules are suspended for affected tenants. Contact your legal team before modifying any policy during an active hold. Aegis-0 can flag any retention changes made during a hold period.
              </p>
            </div>
          </div>

          <div className="flex gap-3">
            <button onClick={save} disabled={saving} className="px-6 py-3 bg-orange-500 hover:bg-orange-600 text-black font-bold rounded-xl transition-colors disabled:opacity-50">
              {saving ? 'Saving…' : saved ? '✓ Policy Saved' : 'Save Policy'}
            </button>
            <Link href="/agent-admin/audit" className="flex items-center gap-2 px-6 py-3 bg-white/5 hover:bg-white/10 border border-white/10 font-bold rounded-xl transition-colors">
              <span className="material-symbols-outlined text-[18px]">receipt_long</span>
              View Audit Export
            </Link>
          </div>
        </div>
      </main>
    </>
  );
}
