// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

'use client';

import React, { useEffect, useState } from 'react';
import { useSession } from '../layout';

const CORE_API = process.env.NEXT_PUBLIC_CORE_API_URL || 'http://localhost:8000';

export default function GatewayAccount() {
  const session = useSession();
  const [data, setData]     = useState<any>(null);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved]   = useState(false);
  const [form, setForm]     = useState<Record<string, string>>({});

  useEffect(() => {
    if (!session) return;
    fetch(`${CORE_API}/api/v1/portal/company`, {
      headers: { Authorization: `Bearer ${session.token}`, Accept: 'application/json' },
    }).then(r => r.json()).then(({ data }) => {
      setData(data);
      setForm({
        company_name:    data.tenant?.name ?? '',
        company_email:   data.tenant?.company_email ?? '',
        company_phone:   data.tenant?.company_phone ?? '',
        company_address: data.tenant?.company_address ?? '',
        company_website: data.tenant?.company_website ?? '',
        contact_name:    data.contact?.name ?? '',
        contact_phone:   data.contact?.phone ?? '',
        contact_role:    data.contact?.role ?? '',
      });
    });
  }, [session]);

  async function save(e: React.FormEvent) {
    e.preventDefault();
    setSaving(true);
    const res = await fetch(`${CORE_API}/api/v1/portal/company`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json', Authorization: `Bearer ${session?.token}` },
      body: JSON.stringify(form),
    });
    setSaving(false);
    if (res.ok) { setSaved(true); setTimeout(() => setSaved(false), 3000); }
  }

  if (!data) return <div className="flex items-center justify-center p-20"><div className="w-8 h-8 border-2 border-primary border-t-transparent rounded-full animate-spin" /></div>;

  const f = (key: string, label: string, type = 'text', placeholder = '') => (
    <div>
      <label className="text-[10px] uppercase font-technical text-on-surface-muted tracking-widest block mb-1">{label}</label>
      <input type={type} value={form[key] ?? ''} onChange={e => setForm(v => ({ ...v, [key]: e.target.value }))}
        placeholder={placeholder}
        className="w-full bg-black/40 border border-white/10 rounded-lg p-3 text-sm focus:outline-none focus:border-primary transition-colors"
      />
    </div>
  );

  return (
    <div className="p-8 max-w-2xl space-y-8">
      <div>
        <h1 className="text-3xl font-black font-headline tracking-tighter">Licence & Company</h1>
        <p className="text-on-surface-muted text-sm mt-1">Your Gateway licence details and organisation information</p>
      </div>

      {/* Licence info */}
      <div className="bg-surface-raised border border-primary/20 rounded-2xl p-6 space-y-3">
        <h2 className="font-headline font-bold flex items-center gap-2">
          <span className="material-symbols-outlined text-primary text-xl">verified_user</span>
          Gateway Licence
        </h2>
        <div className="grid grid-cols-2 gap-4 text-sm">
          <div>
            <p className="text-[10px] font-technical text-on-surface-muted uppercase tracking-widest mb-0.5">Plan</p>
            <p className="font-headline font-bold text-primary uppercase">{data.tenant?.plan}</p>
          </div>
          <div>
            <p className="text-[10px] font-technical text-on-surface-muted uppercase tracking-widest mb-0.5">Status</p>
            <p className="font-headline font-bold text-green-400 uppercase">{data.tenant?.status}</p>
          </div>
          <div>
            <p className="text-[10px] font-technical text-on-surface-muted uppercase tracking-widest mb-0.5">Tenant ID</p>
            <p className="font-mono text-xs text-on-surface-muted">{data.tenant?.id}</p>
          </div>
          <div>
            <p className="text-[10px] font-technical text-on-surface-muted uppercase tracking-widest mb-0.5">Active Since</p>
            <p className="font-technical text-sm">{data.tenant?.plan_started_at ? new Date(data.tenant.plan_started_at).toLocaleDateString() : 'N/A'}</p>
          </div>
        </div>
      </div>

      <form onSubmit={save} className="space-y-6">
        <div className="bg-surface-raised border border-[rgba(255,159,74,0.08)] rounded-2xl p-6 space-y-4">
          <h2 className="font-headline font-bold flex items-center gap-2">
            <span className="material-symbols-outlined text-primary text-xl">business</span>
            Company Details
          </h2>
          <div className="grid grid-cols-2 gap-4">
            {f('company_name',  'Company Name',  'text',  'Acme Corp')}
            {f('company_email', 'Company Email', 'email', 'security@acme.com')}
            {f('company_phone', 'Phone',         'tel',   '+44 20 0000 0000')}
            {f('company_website', 'Website',     'url',   'https://acme.com')}
          </div>
          {f('company_address', 'Registered Address', 'text', '123 Business St, London')}
        </div>

        <div className="bg-surface-raised border border-[rgba(255,159,74,0.08)] rounded-2xl p-6 space-y-4">
          <h2 className="font-headline font-bold flex items-center gap-2">
            <span className="material-symbols-outlined text-primary text-xl">person</span>
            Primary Contact
          </h2>
          <div className="grid grid-cols-2 gap-4">
            {f('contact_name',  'Full Name', 'text', 'Jane Smith')}
            {f('contact_phone', 'Phone',     'tel',  '+44 7700 000000')}
          </div>
          {f('contact_role', 'Role / Title', 'text', 'Security Engineer')}
        </div>

        {saved && <p className="text-sm text-green-400 bg-green-500/10 border border-green-500/20 rounded-lg p-3">Changes saved.</p>}

        <button type="submit" disabled={saving}
          className="px-6 py-3 bg-primary text-black rounded-xl font-headline font-bold hover:brightness-110 disabled:opacity-50 transition-all"
        >
          {saving ? 'Saving…' : 'Save Changes'}
        </button>
      </form>
    </div>
  );
}
