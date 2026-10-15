// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

'use client';
import { operatorFetch } from '@/lib/operatorFetch';
import { useState, useEffect, useCallback } from 'react';
import Link from 'next/link';
import { Sidebar } from '../../../components/Sidebar';
import { TopAppBar } from '../../../components/TopAppBar';

const API = process.env.NEXT_PUBLIC_CORE_API_URL ?? 'http://localhost:8000';

interface AlertRule { id: string; event_type: string; channel: string; destination: string; enabled: boolean; }

const EVENT_TYPES = [
  { value: 'agent_blocked',            label: 'Agent Blocked' },
  { value: 'memory_contamination',     label: 'Memory Contamination Detected' },
  { value: 'circuit_breaker_trip',     label: 'Circuit Breaker Tripped' },
  { value: 'rogue_agent_detected',     label: 'Rogue Agent Detected' },
  { value: 'pii_in_response',          label: 'PII Found in Response' },
  { value: 'role_violation',           label: 'Role Violation' },
];

export default function AlertRules() {
  const [rules, setRules] = useState<AlertRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [newEvent, setNewEvent]       = useState('agent_blocked');
  const [newChannel, setNewChannel]   = useState('email');
  const [newDest, setNewDest]         = useState('');
  const [saving, setSaving]           = useState(false);

  const loadRules = useCallback(() => {
    setLoading(true);
    operatorFetch(`${API}/api/v1/admin/alert-rules`, { headers: { Accept: 'application/json' } })
      .then(r => r.json())
      .then(body => { if (body.status === 'success') setRules(body.data ?? []); })
      .catch((e: any) => { console.error('Failed to load alert rules:', e); })
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => { loadRules(); }, [loadRules]);

  const addRule = async () => {
    if (!newDest) return;
    setSaving(true);
    try {
      await operatorFetch(`${API}/api/v1/admin/alert-rules`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ event_type: newEvent, channel: newChannel, destination: newDest }),
      });
      setNewDest('');
      loadRules();
    } catch (e) {
      console.error('Failed to create alert rule:', e);
    }
    setSaving(false);
  };

  const toggleRule = async (id: string) => {
    await operatorFetch(`${API}/api/v1/admin/alert-rules/${id}`, {
      method: 'PATCH', headers: { Accept: 'application/json' },
    });
    loadRules();
  };

  const deleteRule = async (id: string) => {
    await operatorFetch(`${API}/api/v1/admin/alert-rules/${id}`, {
      method: 'DELETE', headers: { Accept: 'application/json' },
    });
    loadRules();
  };

  return (
    <>
      <Sidebar />
      <TopAppBar />
      <main className="pt-24 px-8 pb-12 min-h-screen bg-background transition-all duration-300" style={{ marginLeft: 'var(--sidebar-width, 18rem)' }}>
        <div className="max-w-5xl mx-auto space-y-8">
          <div>
            <h1 className="text-5xl font-black font-headline tracking-tighter">Alert <span className="text-orange-500">Rules</span></h1>
            <p className="text-neutral-400 mt-2 max-w-2xl">Configure who gets notified when critical security events fire. Email, webhook, or let Aegis handle it automatically.</p>
          </div>

          <div className="bg-blue-500/5 border border-blue-500/20 rounded-2xl p-6 flex gap-4">
            <span className="material-symbols-outlined text-blue-400 flex-shrink-0 mt-0.5">info</span>
            <div>
              <p className="font-bold text-blue-300 text-sm">How to use this screen</p>
              <p className="text-neutral-400 text-sm mt-1">Add a rule for each event type you want to be notified about. Choose email for human notification or webhook to integrate with Slack, PagerDuty, or your own system. Aegis-0 can also be configured to send alerts automatically — click Ask Aegis to set that up.</p>
            </div>
          </div>

          {/* Existing Rules */}
          <div className="bg-[#131313] border border-white/5 rounded-2xl overflow-hidden">
            <div className="px-6 py-4 border-b border-white/5 flex justify-between items-center">
              <h2 className="font-headline font-bold">Active Rules</h2>
              <Link href="/aegis" className="flex items-center gap-2 px-3 py-2 bg-blue-500/10 border border-blue-500/20 text-blue-400 rounded-lg text-xs font-bold hover:bg-blue-500/20 transition-colors">
                <span className="material-symbols-outlined text-[14px]">trip_origin</span>Ask Aegis to Configure
              </Link>
            </div>
            <div className="divide-y divide-white/5">
              {loading && <div className="px-6 py-8 text-center text-neutral-500 font-technical text-xs animate-pulse">Loading rules…</div>}
              {!loading && rules.map(r => (
                <div key={r.id} className="px-6 py-4 flex items-center gap-4">
                  <button onClick={() => toggleRule(r.id)} className={`w-10 h-6 rounded-full transition-colors flex-shrink-0 relative ${r.enabled ? 'bg-emerald-500' : 'bg-white/10'}`}>
                    <span className={`absolute top-1 w-4 h-4 rounded-full bg-white transition-all ${r.enabled ? 'left-5' : 'left-1'}`}></span>
                  </button>
                  <div className="flex-1 min-w-0">
                    <p className="font-bold text-sm text-on-surface">{EVENT_TYPES.find(e => e.value === r.event_type)?.label ?? r.event_type}</p>
                    <p className="text-xs font-technical text-neutral-500">{r.channel.toUpperCase()} → {r.destination}</p>
                  </div>
                  <button onClick={() => deleteRule(r.id)} className="text-neutral-600 hover:text-red-400 transition-colors">
                    <span className="material-symbols-outlined text-[18px]">delete</span>
                  </button>
                </div>
              ))}
              {!loading && rules.length === 0 && <div className="px-6 py-8 text-center text-neutral-600 font-technical text-xs">No alert rules configured.</div>}
            </div>
          </div>

          {/* Add New Rule */}
          <div className="bg-[#131313] border border-white/5 rounded-2xl p-6 space-y-6">
            <h2 className="font-headline font-bold text-xl">Add New Rule</h2>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="space-y-2">
                <label className="text-xs font-technical text-neutral-500 uppercase tracking-wider">Event Type</label>
                <select value={newEvent} onChange={e => setNewEvent(e.target.value)}
                  className="w-full bg-[#1a1a1a] border border-white/10 rounded-xl px-4 py-3 font-technical text-sm text-on-surface focus:outline-none focus:border-orange-500/50">
                  {EVENT_TYPES.map(e => <option key={e.value} value={e.value}>{e.label}</option>)}
                </select>
              </div>
              <div className="space-y-2">
                <label className="text-xs font-technical text-neutral-500 uppercase tracking-wider">Channel</label>
                <select value={newChannel} onChange={e => setNewChannel(e.target.value)}
                  className="w-full bg-[#1a1a1a] border border-white/10 rounded-xl px-4 py-3 font-technical text-sm text-on-surface focus:outline-none focus:border-orange-500/50">
                  <option value="email">Email</option>
                  <option value="webhook">Webhook</option>
                  <option value="aegis">Aegis-0 (Automated)</option>
                </select>
              </div>
              <div className="space-y-2">
                <label className="text-xs font-technical text-neutral-500 uppercase tracking-wider">Destination</label>
                <input type="text" value={newDest} onChange={e => setNewDest(e.target.value)}
                  placeholder={newChannel === 'email' ? 'admin@company.com' : newChannel === 'webhook' ? 'https://hooks.slack.com/…' : 'Aegis handles automatically'}
                  className="w-full bg-[#1a1a1a] border border-white/10 rounded-xl px-4 py-3 font-technical text-sm text-on-surface focus:outline-none focus:border-orange-500/50 placeholder:text-neutral-700" />
              </div>
            </div>
            <button onClick={addRule} disabled={saving || !newDest} className="px-6 py-3 bg-orange-500 hover:bg-orange-600 text-black font-bold rounded-xl transition-colors disabled:opacity-50">
              {saving ? 'Saving…' : 'Add Rule'}
            </button>
          </div>
        </div>
      </main>
    </>
  );
}
