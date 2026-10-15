// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

'use client';

import React, { useEffect, useState } from 'react';
import { useSession } from '../../layout';

const CORE_API = process.env.NEXT_PUBLIC_CORE_API_URL || 'http://localhost:8000';

export default function CompanyAccount() {
  const session = useSession();
  const [data, setData]       = useState<any>(null);
  const [saving, setSaving]   = useState(false);
  const [saved, setSaved]     = useState(false);
  const [error, setError]     = useState('');
  const [form, setForm]       = useState<Record<string, string>>({});

  useEffect(() => {
    if (!session) return;
    fetch(`${CORE_API}/api/v1/portal/company`, {
      headers: { Authorization: `Bearer ${session.token}`, Accept: 'application/json' },
    }).then(r => r.json()).then(({ data }) => {
      setData(data);
      setForm({
        company_name:              data.tenant?.name ?? '',
        company_email:             data.tenant?.company_email ?? '',
        company_phone:             data.tenant?.company_phone ?? '',
        company_address:           data.tenant?.company_address ?? '',
        company_website:           data.tenant?.company_website ?? '',
        contact_name:              data.contact?.name ?? '',
        contact_phone:             data.contact?.phone ?? '',
        contact_role:              data.contact?.role ?? '',
        ciba_notification_channel: data.tenant?.ciba_notification_channel ?? 'dashboard',
        ciba_notification_email:   data.tenant?.ciba_notification_email ?? '',
      });
    });
  }, [session]);

  async function save(e: React.FormEvent) {
    e.preventDefault();
    setSaving(true);
    setError('');
    setSaved(false);
    const res = await fetch(`${CORE_API}/api/v1/portal/company`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json', Authorization: `Bearer ${session?.token}` },
      body: JSON.stringify(form),
    });
    setSaving(false);
    if (res.ok) { setSaved(true); setTimeout(() => setSaved(false), 3000); }
    else setError('Failed to save. Please try again.');
  }

  function field(key: string, label: string, type = 'text', placeholder = '') {
    return (
      <div>
        <label className="text-[10px] uppercase font-technical text-on-surface-muted tracking-widest block mb-1">{label}</label>
        <input type={type} value={form[key] ?? ''} onChange={e => setForm(f => ({ ...f, [key]: e.target.value }))}
          placeholder={placeholder}
          className="w-full bg-black/40 border border-white/10 rounded-lg p-3 text-sm focus:outline-none focus:border-primary transition-colors"
        />
      </div>
    );
  }

  if (!data) return (
    <div className="flex items-center justify-center p-20">
      <div className="w-8 h-8 border-2 border-primary border-t-transparent rounded-full animate-spin" />
    </div>
  );

  const providerIcon: Record<string, string> = { github: '⚙ GitHub', google: '✦ Google' };

  return (
    <div className="p-8 max-w-2xl space-y-8">
      <div>
        <h1 className="text-3xl font-black font-headline tracking-tighter">Company & Profile</h1>
        <p className="text-on-surface-muted text-sm mt-1">Your organisation details and contact information</p>
      </div>

      <form onSubmit={save} className="space-y-8">

        {/* Company details */}
        <div className="bg-surface-raised border border-[rgba(255,159,74,0.08)] rounded-2xl p-6 space-y-4">
          <h2 className="font-headline font-bold flex items-center gap-2">
            <span className="material-symbols-outlined text-primary text-xl">business</span>
            Company Details
          </h2>
          <div className="grid grid-cols-2 gap-4">
            {field('company_name',  'Company Name',    'text',  'Acme Corp')}
            {field('company_email', 'Company Email',   'email', 'hello@acme.com')}
            {field('company_phone', 'Company Phone',   'tel',   '+44 20 0000 0000')}
            {field('company_website', 'Website',       'url',   'https://acme.com')}
          </div>
          <div>{field('company_address', 'Registered Address', 'text', '123 Business St, London')}</div>
        </div>

        {/* Contact details */}
        <div className="bg-surface-raised border border-[rgba(255,159,74,0.08)] rounded-2xl p-6 space-y-4">
          <h2 className="font-headline font-bold flex items-center gap-2">
            <span className="material-symbols-outlined text-primary text-xl">person</span>
            Primary Contact
          </h2>
          <div className="grid grid-cols-2 gap-4">
            {field('contact_name',  'Full Name',    'text', 'Jane Smith')}
            {field('contact_phone', 'Phone',        'tel',  '+44 7700 000000')}
          </div>
          {field('contact_role', 'Role / Title', 'text', 'Lead Developer')}
          <div className="pt-2">
            <p className="text-[10px] uppercase font-technical text-on-surface-muted tracking-widest mb-2">Verified Identities</p>
            <div className="flex gap-2">
              {data.identities?.map((id: any) => (
                <div key={id.id} className="flex items-center gap-2 px-3 py-1.5 bg-primary/10 border border-primary/20 rounded-full text-xs font-technical text-primary">
                  <span className="material-symbols-outlined text-[14px]">verified</span>
                  {providerIcon[id.provider] ?? id.provider} — {id.provider_email}
                </div>
              ))}
            </div>
            <p className="text-[10px] text-on-surface-muted/50 mt-2 font-technical">
              Verified identities are set by OAuth and cannot be changed here. All your agent actions are traceable to these accounts.
            </p>
          </div>
        </div>

        {/* CIBA Notification Preferences */}
        <div className="bg-surface-raised border border-[rgba(255,159,74,0.08)] rounded-2xl p-6 space-y-4">
          <h2 className="font-headline font-bold flex items-center gap-2">
            <span className="material-symbols-outlined text-primary text-xl">notifications_active</span>
            CIBA Authorization Alerts
          </h2>
          <p className="text-xs text-on-surface-muted">
            When an AI agent attempts a high-risk action, the Sentry Gateway pauses execution and asks for your approval.
            Configure how you want to be notified. If no response is received before the timeout, the action is <strong className="text-red-400">automatically denied</strong>.
          </p>

          <div>
            <label className="text-[10px] uppercase font-technical text-on-surface-muted tracking-widest block mb-2">Notification Channel</label>
            <div className="grid grid-cols-3 gap-3">
              {[
                { key: 'dashboard',      icon: 'dashboard',        label: 'Dashboard Only',   desc: 'Check manually' },
                { key: 'email',           icon: 'mail',             label: 'Email',             desc: 'Instant alert' },
                { key: 'companion_app',   icon: 'phone_iphone',     label: 'Aegis App',         desc: 'Push + biometric' },
              ].map(ch => (
                <button key={ch.key} type="button"
                  onClick={() => setForm(f => ({ ...f, ciba_notification_channel: ch.key }))}
                  className={`p-4 rounded-xl border text-left transition-all ${
                    form.ciba_notification_channel === ch.key
                      ? 'border-primary bg-primary/10 text-primary'
                      : 'border-white/10 bg-black/40 text-on-surface-muted hover:border-primary/30'
                  }`}
                >
                  <span className="material-symbols-outlined text-xl block mb-1">{ch.icon}</span>
                  <p className="text-sm font-headline font-bold">{ch.label}</p>
                  <p className="text-[10px] font-technical">{ch.desc}</p>
                </button>
              ))}
            </div>
          </div>

          {form.ciba_notification_channel === 'email' && (
            <div className="animate-in fade-in">
              {field('ciba_notification_email', 'CIBA Alert Email', 'email', 'security-alerts@yourcompany.com')}
              <p className="text-[10px] text-on-surface-muted/50 mt-1 font-technical">
                If left blank, alerts will be sent to your Company Email above.
              </p>
            </div>
          )}

          {form.ciba_notification_channel === 'dashboard' && (
            <div className="flex items-start gap-3 p-3 bg-yellow-500/10 border border-yellow-500/20 rounded-lg">
              <span className="material-symbols-outlined text-yellow-400 text-lg mt-0.5">warning</span>
              <p className="text-xs text-yellow-300">
                Dashboard-only mode requires you to actively monitor the Governance panel for pending requests.
                High-risk actions will be <strong>automatically denied</strong> if not responded to within the timeout window (default: 120 seconds).
              </p>
            </div>
          )}

          {form.ciba_notification_channel === 'companion_app' && (
            <div className="space-y-3 animate-in fade-in">
              <div className="flex items-start gap-3 p-3 bg-primary/5 border border-primary/15 rounded-lg">
                <span className="material-symbols-outlined text-primary text-lg mt-0.5">verified_user</span>
                <div>
                  <p className="text-xs text-on-surface font-headline font-bold mb-1">Aegis Companion App</p>
                  <p className="text-[10px] text-on-surface-muted font-technical leading-relaxed">
                    The Aegis app delivers real-time push notifications directly to your device when an agent triggers CIBA authorization.
                    Approve or deny with biometric authentication (fingerprint or face). The decision is cryptographically signed with
                    a hardware-bound PQC hybrid dual-signature (Ed25519 + ML-DSA-65) and sent back to the Gateway within milliseconds.
                  </p>
                </div>
              </div>
              <div className="flex items-start gap-3 p-3 bg-black/30 border border-white/5 rounded-lg">
                <span className="material-symbols-outlined text-on-surface-muted text-lg mt-0.5">qr_code_2</span>
                <div>
                  <p className="text-xs text-on-surface font-headline font-bold mb-1">Device Pairing</p>
                  <ol className="text-[10px] text-on-surface-muted font-technical space-y-1 list-decimal list-inside">
                    <li>Install the Aegis app on your device (iOS / Android / Desktop)</li>
                    <li>Open the app and tap <strong>Pair Device</strong></li>
                    <li>Navigate to the <strong>Aegis</strong> page in this portal to generate a QR pairing code</li>
                    <li>Scan the code with the app — this binds your device to your tenant&apos;s CIBA endpoint</li>
                    <li>Complete biometric enrollment — all future approvals require fingerprint or face verification</li>
                  </ol>
                </div>
              </div>
            </div>
          )}
        </div>

        {error && <p className="text-sm text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg p-3">{error}</p>}
        {saved && <p className="text-sm text-green-400 bg-green-500/10 border border-green-500/20 rounded-lg p-3">Changes saved successfully.</p>}

        <button type="submit" disabled={saving}
          className="px-6 py-3 bg-primary text-black rounded-xl font-headline font-bold hover:brightness-110 disabled:opacity-50 transition-all"
        >
          {saving ? 'Saving…' : 'Save Changes'}
        </button>
      </form>
    </div>
  );
}
