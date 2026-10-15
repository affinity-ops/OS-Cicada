// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

'use client';

import React, { useEffect, useState, useCallback } from 'react';
import { useSession } from '../layout';

const CORE_API = process.env.NEXT_PUBLIC_CORE_API_URL || 'http://localhost:8000';

/**
 * Revocation Webhooks Management (H2.3).
 *
 * Allows developers to configure outbound webhook endpoints that Cicada fires
 * when an agent is quarantined. These endpoints typically point to external
 * IdPs (Okta, Entra, Auth0) or SIEM platforms (Splunk, PagerDuty) that can
 * revoke the agent's sessions across all connected services.
 *
 * Wire format follows the IETF Shared Signals Framework / CAEP standard.
 */

interface Webhook {
  id: string;
  name: string;
  endpoint_url: string;
  event_types: string[];
  auth_method: string;
  auth_secret_masked: string | null;
  enabled: boolean;
  last_success_at: string | null;
  last_failure_reason: string | null;
  consecutive_failures: number;
  created_at: string;
}

const EVENT_TYPES = [
  { value: 'agent_quarantined',     label: 'Agent Quarantined',   icon: 'block' },
  { value: 'circuit_breaker_trip',  label: 'Circuit Breaker Trip', icon: 'flash_off' },
  { value: 'operator_quarantine',   label: 'Operator Quarantine', icon: 'person_off' },
  { value: 'attestation_failed',    label: 'Attestation Failed',  icon: 'gpp_bad' },
  { value: 'canary_triggered',      label: 'Canary Triggered',    icon: 'warning' },
];

export default function RevocationWebhooksPage() {
  const session = useSession();
  const [webhooks, setWebhooks] = useState<Webhook[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [testing, setTesting] = useState<string | null>(null);

  // Form state
  const [formName, setFormName] = useState('');
  const [formUrl, setFormUrl] = useState('');
  const [formAuthMethod, setFormAuthMethod] = useState('bearer_token');
  const [formSecret, setFormSecret] = useState('');
  const [formEvents, setFormEvents] = useState<string[]>(['agent_quarantined']);
  const [creating, setCreating] = useState(false);

  const loadWebhooks = useCallback(async () => {
    if (!session) return;
    try {
      const res = await fetch(`${CORE_API}/api/v1/portal/revocation-webhooks`, {
        headers: { Authorization: `Bearer ${session.token}`, Accept: 'application/json' },
      });
      const json = await res.json();
      if (json.status === 'success') setWebhooks(json.data ?? []);
    } catch (e) {
      console.error('Failed to load webhooks:', e);
    }
    setLoading(false);
  }, [session]);

  useEffect(() => { loadWebhooks(); }, [loadWebhooks]);

  const createWebhook = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!session) return;
    setCreating(true);
    try {
      const res = await fetch(`${CORE_API}/api/v1/portal/revocation-webhooks`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${session.token}`,
          'Content-Type': 'application/json',
          Accept: 'application/json',
        },
        body: JSON.stringify({
          name: formName,
          endpoint_url: formUrl,
          auth_method: formAuthMethod,
          auth_secret: formSecret || undefined,
          event_types: formEvents,
        }),
      });
      if (res.ok) {
        setShowCreate(false);
        setFormName(''); setFormUrl(''); setFormSecret(''); setFormEvents(['agent_quarantined']);
        loadWebhooks();
      }
    } catch (e) {
      console.error('Create failed:', e);
    }
    setCreating(false);
  };

  const deleteWebhook = async (id: string) => {
    if (!session || !confirm('Remove this revocation webhook?')) return;
    await fetch(`${CORE_API}/api/v1/portal/revocation-webhooks/${id}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${session.token}`, Accept: 'application/json' },
    });
    loadWebhooks();
  };

  const testWebhook = async (id: string) => {
    if (!session) return;
    setTesting(id);
    try {
      await fetch(`${CORE_API}/api/v1/portal/revocation-webhooks/${id}/test`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${session.token}`, Accept: 'application/json' },
      });
    } catch (e) {
      console.error('Test failed:', e);
    }
    setTimeout(() => { setTesting(null); loadWebhooks(); }, 2000);
  };

  const toggleEvent = (event: string) => {
    setFormEvents(prev =>
      prev.includes(event) ? prev.filter(e => e !== event) : [...prev, event]
    );
  };

  return (
    <div className="p-8 space-y-6">
      <div className="flex justify-between items-end">
        <div>
          <h1 className="text-3xl font-black font-headline tracking-tighter">Revocation Webhooks</h1>
          <p className="text-on-surface-muted text-sm mt-1 max-w-xl">
            Configure outbound CAEP-compatible endpoints that fire when your agents are quarantined. External IdPs and SIEMs can consume these events to revoke agent sessions across all connected services.
          </p>
        </div>
        <button
          onClick={() => setShowCreate(!showCreate)}
          className="px-5 py-2.5 bg-primary text-on-primary rounded-xl font-headline font-bold text-xs uppercase tracking-wider hover:brightness-110 transition-all shadow-lg shadow-primary/20 flex items-center gap-2"
        >
          <span className="material-symbols-outlined text-[16px]">add</span>
          Add Webhook
        </button>
      </div>

      {/* Create Form */}
      {showCreate && (
        <form onSubmit={createWebhook} className="bg-surface-raised border border-[rgba(255,159,74,0.12)] rounded-2xl p-6 space-y-5">
          <h2 className="text-sm font-headline font-bold uppercase tracking-widest text-primary">New Revocation Webhook</h2>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-[10px] font-technical text-on-surface-muted uppercase tracking-widest mb-1">Name</label>
              <input
                type="text" required value={formName} onChange={e => setFormName(e.target.value)}
                placeholder="e.g. Okta Universal Logout"
                className="w-full px-4 py-2.5 bg-white/5 border border-white/10 rounded-xl text-sm font-technical text-on-surface placeholder-neutral-600 focus:outline-none focus:border-primary/50"
              />
            </div>
            <div>
              <label className="block text-[10px] font-technical text-on-surface-muted uppercase tracking-widest mb-1">Endpoint URL (HTTPS)</label>
              <input
                type="url" required value={formUrl} onChange={e => setFormUrl(e.target.value)}
                placeholder="https://idp.example.com/caep/events"
                className="w-full px-4 py-2.5 bg-white/5 border border-white/10 rounded-xl text-sm font-technical text-on-surface placeholder-neutral-600 focus:outline-none focus:border-primary/50"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-[10px] font-technical text-on-surface-muted uppercase tracking-widest mb-1">Authentication</label>
              <select
                value={formAuthMethod} onChange={e => setFormAuthMethod(e.target.value)}
                className="w-full px-4 py-2.5 bg-white/5 border border-white/10 rounded-xl text-sm font-technical text-on-surface focus:outline-none focus:border-primary/50"
              >
                <option value="bearer_token">Bearer Token</option>
                <option value="hmac_sha256">HMAC-SHA256</option>
                <option value="none">None (not recommended)</option>
              </select>
            </div>
            {formAuthMethod !== 'none' && (
              <div>
                <label className="block text-[10px] font-technical text-on-surface-muted uppercase tracking-widest mb-1">
                  {formAuthMethod === 'bearer_token' ? 'Bearer Token' : 'HMAC Secret Key'}
                </label>
                <input
                  type="password" value={formSecret} onChange={e => setFormSecret(e.target.value)}
                  placeholder="••••••••"
                  className="w-full px-4 py-2.5 bg-white/5 border border-white/10 rounded-xl text-sm font-technical text-on-surface placeholder-neutral-600 focus:outline-none focus:border-primary/50"
                />
              </div>
            )}
          </div>

          <div>
            <label className="block text-[10px] font-technical text-on-surface-muted uppercase tracking-widest mb-2">Subscribe to Events</label>
            <div className="flex flex-wrap gap-2">
              {EVENT_TYPES.map(evt => (
                <button
                  key={evt.value} type="button"
                  onClick={() => toggleEvent(evt.value)}
                  className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-technical transition-all border ${
                    formEvents.includes(evt.value)
                      ? 'bg-primary/10 border-primary/30 text-primary'
                      : 'bg-white/5 border-white/10 text-on-surface-muted hover:border-white/20'
                  }`}
                >
                  <span className="material-symbols-outlined text-[14px]">{evt.icon}</span>
                  {evt.label}
                </button>
              ))}
            </div>
          </div>

          <div className="flex gap-3 pt-2">
            <button
              type="submit" disabled={creating}
              className="px-6 py-2.5 bg-primary text-on-primary rounded-xl font-headline font-bold text-xs uppercase tracking-wider hover:brightness-110 transition-all disabled:opacity-50"
            >
              {creating ? 'Creating…' : 'Create Webhook'}
            </button>
            <button
              type="button" onClick={() => setShowCreate(false)}
              className="px-6 py-2.5 bg-white/5 border border-white/10 text-on-surface-muted rounded-xl font-technical text-xs hover:bg-white/10 transition-colors"
            >
              Cancel
            </button>
          </div>
        </form>
      )}

      {/* Webhook List */}
      {loading ? (
        <div className="flex items-center justify-center py-16">
          <div className="w-8 h-8 border-2 border-primary border-t-transparent rounded-full animate-spin" />
        </div>
      ) : webhooks.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-16 bg-surface-raised border border-[rgba(255,159,74,0.08)] rounded-2xl">
          <span className="material-symbols-outlined text-on-surface-muted text-5xl mb-3">webhook</span>
          <p className="text-on-surface-muted text-sm">No revocation webhooks configured.</p>
          <p className="text-on-surface-muted/60 text-xs mt-1">
            Add an endpoint to receive CAEP events when your agents are quarantined.
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          {webhooks.map(wh => (
            <div key={wh.id} className={`p-5 bg-surface-raised border rounded-xl transition-colors ${
              !wh.enabled ? 'border-red-500/20 opacity-60' : 'border-[rgba(255,159,74,0.08)]'
            }`}>
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-3">
                  <div className={`w-10 h-10 rounded-xl flex items-center justify-center ${
                    wh.enabled ? 'bg-emerald-500/10' : 'bg-red-500/10'
                  }`}>
                    <span className={`material-symbols-outlined text-xl ${
                      wh.enabled ? 'text-emerald-400' : 'text-red-400'
                    }`}>
                      {wh.enabled ? 'webhook' : 'link_off'}
                    </span>
                  </div>
                  <div>
                    <p className="font-headline font-bold">{wh.name}</p>
                    <p className="text-xs text-on-surface-muted font-technical font-mono truncate max-w-md">{wh.endpoint_url}</p>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  {!wh.enabled && (
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-red-500/10 border border-red-500/20 text-red-400">
                      Disabled
                    </span>
                  )}
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${
                    wh.auth_method === 'bearer_token' ? 'text-blue-400 bg-blue-500/10 border-blue-500/20' :
                    wh.auth_method === 'hmac_sha256' ? 'text-purple-400 bg-purple-500/10 border-purple-500/20' :
                    'text-neutral-400 bg-white/5 border-white/10'
                  }`}>
                    {wh.auth_method.replace('_', ' ')}
                  </span>
                </div>
              </div>

              {/* Event subscriptions */}
              <div className="flex flex-wrap gap-1.5 mb-3">
                {(typeof wh.event_types === 'string' ? JSON.parse(wh.event_types) : wh.event_types).map((evt: string) => {
                  const config = EVENT_TYPES.find(e => e.value === evt);
                  return (
                    <span key={evt} className="flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-technical bg-white/5 border border-white/10 text-on-surface-muted">
                      <span className="material-symbols-outlined text-[12px]">{config?.icon ?? 'info'}</span>
                      {config?.label ?? evt}
                    </span>
                  );
                })}
              </div>

              {/* Health status */}
              <div className="flex items-center justify-between text-[10px] font-technical text-on-surface-muted">
                <div className="flex gap-4">
                  {wh.last_success_at && (
                    <span className="text-emerald-400">Last success: {new Date(wh.last_success_at).toLocaleString()}</span>
                  )}
                  {wh.consecutive_failures > 0 && (
                    <span className="text-red-400">{wh.consecutive_failures} consecutive failures</span>
                  )}
                  {wh.last_failure_reason && (
                    <span className="text-red-400/60 truncate max-w-xs" title={wh.last_failure_reason}>
                      {wh.last_failure_reason}
                    </span>
                  )}
                </div>
                <div className="flex gap-2">
                  <button
                    onClick={() => testWebhook(wh.id)}
                    disabled={testing === wh.id}
                    className="px-3 py-1 bg-blue-500/10 border border-blue-500/20 text-blue-400 rounded-lg hover:bg-blue-500/20 transition-colors disabled:opacity-50"
                  >
                    {testing === wh.id ? 'Sending…' : 'Test'}
                  </button>
                  <button
                    onClick={() => deleteWebhook(wh.id)}
                    className="px-3 py-1 bg-red-500/10 border border-red-500/20 text-red-400 rounded-lg hover:bg-red-500/20 transition-colors"
                  >
                    Remove
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
