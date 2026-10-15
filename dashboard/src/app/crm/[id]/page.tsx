// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

'use client';
import { operatorFetch } from '@/lib/operatorFetch';

import React, { useEffect, useState } from 'react';
import Link from 'next/link';
import { useParams } from 'next/navigation';
import { Sidebar } from '../../../components/Sidebar';
import { TopAppBar } from '../../../components/TopAppBar';

const CORE_API = process.env.NEXT_PUBLIC_CORE_API_URL || 'http://localhost:8000';

const TRUST_COLOUR: Record<string, string> = {
  unverified: 'text-gray-400 bg-gray-400/10',
  nominal:    'text-sky-400 bg-sky-400/10',
  elevated:   'text-yellow-400 bg-yellow-400/10',
  critical:   'text-red-400 bg-red-400/10',
};

const AGENT_STATUS_COLOUR: Record<string, string> = {
  certified:                'text-green-400 bg-green-400/10',
  pending_certification:    'text-yellow-400 bg-yellow-400/10',
  recertification_required: 'text-orange-400 bg-orange-400/10',
  terminated:               'text-red-400 bg-red-400/10',
};

function agentStatus(agent: any): string {
  if (agent.revoked_at) return 'terminated';
  if (!agent.certified_at) return 'pending_certification';
  if (agent.recertification_due_at && new Date(agent.recertification_due_at) < new Date()) return 'recertification_required';
  return 'certified';
}

export default function CompanyDetail() {
  const { id } = useParams<{ id: string }>();
  const [data, setData]         = useState<any>(null);
  const [notes, setNotes]       = useState('');
  const [savingNotes, setSavingNotes] = useState(false);
  const [notesSaved, setNotesSaved]   = useState(false);

  useEffect(() => {
    operatorFetch(`${CORE_API}/api/v1/crm/companies/${id}`)
      .then(r => r.json())
      .then(({ data: d }) => {
        setData(d);
        setNotes(d.tenant?.admin_notes ?? '');
      });
  }, [id]);

  async function saveNotes() {
    setSavingNotes(true);
    await operatorFetch(`${CORE_API}/api/v1/crm/companies/${id}/notes`, {
      method:  'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ admin_notes: notes }),
    });
    setSavingNotes(false);
    setNotesSaved(true);
    setTimeout(() => setNotesSaved(false), 3000);
  }

  if (!data) {
    return (
      <>
        <Sidebar />
        <TopAppBar />
        <main className="pt-24 px-8 pb-12 min-h-screen transition-all duration-300" style={{ marginLeft: 'var(--sidebar-width, 18rem)' }}>
          <div className="flex items-center justify-center p-20">
            <div className="w-8 h-8 border-2 border-primary border-t-transparent rounded-full animate-spin" />
          </div>
        </main>
      </>
    );
  }

  const { tenant, contacts, agents, recent_actions } = data;

  return (
    <>
      <Sidebar />
      <TopAppBar />
      <main className="pt-24 px-8 pb-12 min-h-screen transition-all duration-300" style={{ marginLeft: 'var(--sidebar-width, 18rem)' }}>
        <div className="space-y-8 max-w-[95%] mx-auto">
          {/* Breadcrumb */}
      <div className="flex items-center gap-2 text-sm text-on-surface-muted">
        <Link href="/crm" className="hover:text-on-surface transition-colors">Company CRM</Link>
        <span className="material-symbols-outlined text-[16px]">chevron_right</span>
        <span className="text-on-surface">{tenant.name}</span>
      </div>

      {/* Header */}
      <div className="flex items-start justify-between gap-6">
        <div>
          <h1 className="text-3xl font-black font-headline tracking-tighter">{tenant.name}</h1>
          <div className="flex items-center gap-3 mt-2 flex-wrap">
            <span className={`text-xs font-technical px-2.5 py-1 rounded-full capitalize ${
              tenant.status === 'active' ? 'text-green-400 bg-green-400/10' : 'text-red-400 bg-red-400/10'
            }`}>{tenant.status}</span>
            <span className="text-xs font-technical px-2.5 py-1 rounded-full text-primary bg-primary/10 capitalize">{tenant.plan}</span>
            {tenant.plan_started_at && (
              <span className="text-xs font-technical text-on-surface-muted">
                since {new Date(tenant.plan_started_at).toLocaleDateString()}
              </span>
            )}
          </div>
        </div>
        <div className="text-right text-xs font-technical text-on-surface-muted">
          <p>Tenant ID</p>
          <p className="font-mono text-[10px] text-on-surface-muted/60">{tenant.id}</p>
          <p className="mt-1">Joined {new Date(tenant.created_at).toLocaleDateString()}</p>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-6">
        {/* Company info */}
        <div className="bg-surface-raised border border-[rgba(255,159,74,0.08)] rounded-2xl p-6 space-y-3">
          <h2 className="font-headline font-bold flex items-center gap-2">
            <span className="material-symbols-outlined text-primary text-xl">business</span>
            Company Details
          </h2>
          {[
            { label: 'Email',   value: tenant.company_email },
            { label: 'Phone',   value: tenant.company_phone },
            { label: 'Website', value: tenant.company_website },
            { label: 'Address', value: tenant.company_address },
          ].map(({ label, value }) => value ? (
            <div key={label}>
              <p className="text-[10px] font-technical text-on-surface-muted uppercase tracking-widest">{label}</p>
              <p className="text-sm mt-0.5">{value}</p>
            </div>
          ) : null)}
        </div>

        {/* Contacts */}
        <div className="bg-surface-raised border border-[rgba(255,159,74,0.08)] rounded-2xl p-6 space-y-3">
          <h2 className="font-headline font-bold flex items-center gap-2">
            <span className="material-symbols-outlined text-primary text-xl">people</span>
            Contacts
          </h2>
          {contacts.length === 0 ? (
            <p className="text-sm text-on-surface-muted">No contacts yet.</p>
          ) : contacts.map((c: any) => (
            <div key={c.id} className="flex items-center gap-3">
              {c.avatar_url
                ? <img src={c.avatar_url} alt="" className="w-8 h-8 rounded-full flex-shrink-0" />
                : <div className="w-8 h-8 rounded-full bg-primary/10 flex items-center justify-center flex-shrink-0">
                    <span className="material-symbols-outlined text-primary text-sm">person</span>
                  </div>
              }
              <div>
                <p className="text-sm font-medium flex items-center gap-2">
                  {c.name}
                  {c.is_primary && <span className="text-[10px] font-technical text-primary bg-primary/10 px-1.5 py-0.5 rounded">Primary</span>}
                </p>
                <p className="text-xs text-on-surface-muted font-technical">{c.email}{c.role ? ` · ${c.role}` : ''}</p>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Agent Registry */}
      <div className="bg-surface-raised border border-[rgba(255,159,74,0.08)] rounded-2xl overflow-hidden">
        <div className="p-5 border-b border-white/5 flex items-center gap-2">
          <span className="material-symbols-outlined text-primary text-xl">smart_toy</span>
          <h2 className="font-headline font-bold">Registered Agents ({agents.length})</h2>
        </div>
        {agents.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-12">
            <p className="text-on-surface-muted text-sm">No agents registered yet.</p>
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="text-[10px] font-technical uppercase tracking-widest text-on-surface-muted border-b border-white/5">
                <th className="text-left px-5 py-3">Agent</th>
                <th className="text-left px-5 py-3">Type</th>
                <th className="text-left px-5 py-3">Trust Tier</th>
                <th className="text-left px-5 py-3">Status</th>
                <th className="text-left px-5 py-3">Certified</th>
                <th className="text-right px-5 py-3">Profile</th>
              </tr>
            </thead>
            <tbody>
              {agents.map((a: any) => {
                const status = agentStatus(a);
                return (
                  <tr key={a.id} className="border-b border-white/[0.04] hover:bg-white/[0.02] transition-colors">
                    <td className="px-5 py-3">
                      <p className="font-medium">{a.name ?? 'Unnamed Agent'}</p>
                      <p className="text-[10px] font-technical text-on-surface-muted/60">v{a.version}</p>
                    </td>
                    <td className="px-5 py-3 text-xs font-technical text-on-surface-muted capitalize">{a.agent_type ?? '—'}</td>
                    <td className="px-5 py-3">
                      <span className={`text-xs font-technical px-2 py-0.5 rounded-full capitalize ${TRUST_COLOUR[a.trust_tier] ?? ''}`}>
                        {a.trust_tier}
                      </span>
                    </td>
                    <td className="px-5 py-3">
                      <span className={`text-xs font-technical px-2 py-0.5 rounded-full ${AGENT_STATUS_COLOUR[status] ?? ''}`}>
                        {status.replace(/_/g, ' ')}
                      </span>
                    </td>
                    <td className="px-5 py-3 text-xs font-technical text-on-surface-muted">
                      {a.certified_at ? new Date(a.certified_at).toLocaleDateString() : '—'}
                    </td>
                    <td className="px-5 py-3 text-right">
                      <Link href={`/registry/${a.id}`} className="inline-flex items-center gap-1 text-[10px] font-technical font-bold uppercase tracking-widest text-primary hover:text-white transition-colors bg-primary/10 border border-primary/20 hover:bg-primary/20 px-3 py-1.5 rounded-lg">
                        Master Profile
                      </Link>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>

      {/* Recent Activity */}
      {recent_actions.length > 0 && (
        <div className="bg-surface-raised border border-[rgba(255,159,74,0.08)] rounded-2xl overflow-hidden">
          <div className="p-5 border-b border-white/5">
            <h2 className="font-headline font-bold flex items-center gap-2">
              <span className="material-symbols-outlined text-primary text-xl">history</span>
              Recent Activity
            </h2>
          </div>
          <div className="divide-y divide-white/[0.04]">
            {recent_actions.map((a: any) => (
              <div key={a.trace_id} className="flex items-center justify-between px-5 py-3">
                <div>
                  <p className="text-xs font-technical">{a.action_type}</p>
                  <p className="text-[10px] text-on-surface-muted/60 font-technical truncate max-w-xs">{a.target_api}</p>
                </div>
                <div className="text-right">
                  <span className={`text-xs font-technical px-2 py-0.5 rounded-full ${
                    a.status === 'approved' ? 'text-green-400 bg-green-400/10' : 'text-red-400 bg-red-400/10'
                  }`}>{a.status}</span>
                  <p className="text-[10px] text-on-surface-muted/50 font-technical mt-1">{new Date(a.created_at).toLocaleString()}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Admin Notes */}
      <div className="bg-surface-raised border border-[rgba(255,159,74,0.08)] rounded-2xl p-6 space-y-3">
        <h2 className="font-headline font-bold flex items-center gap-2">
          <span className="material-symbols-outlined text-primary text-xl">edit_note</span>
          Admin Notes
        </h2>
        <p className="text-xs text-on-surface-muted">Internal notes — not visible to the company.</p>
        <textarea
          value={notes}
          onChange={e => setNotes(e.target.value)}
          rows={4}
          placeholder="Add internal notes about this company…"
          className="w-full bg-black/40 border border-white/10 rounded-xl p-4 text-sm font-technical focus:outline-none focus:border-primary transition-colors resize-none"
        />
        {notesSaved && <p className="text-xs text-green-400">Notes saved.</p>}
        <button onClick={saveNotes} disabled={savingNotes}
          className="px-5 py-2.5 bg-primary text-black rounded-xl text-sm font-headline font-bold hover:brightness-110 disabled:opacity-50 transition-all"
        >
          {savingNotes ? 'Saving…' : 'Save Notes'}
        </button>
      </div>
        </div>
      </main>
    </>
  );
}
