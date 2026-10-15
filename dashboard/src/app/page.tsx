// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

'use client';
import { operatorFetch } from '@/lib/operatorFetch';

import React, { useState, useEffect, useRef, useCallback } from 'react';
import Link from 'next/link';
import { CommandMatrix } from '../components/CommandMatrix';
import { Sidebar } from '../components/Sidebar';
import { TopAppBar } from '../components/TopAppBar';
import { KPICard } from '../components/KPICard';

interface DashboardSummary {
  total_agents: number;
  total_tenants: number;
  active_tenants: number;
  active_agents_24h: number;
  verified_agents: number;
  quarantined_agents: number;
  approved_today: number;
  blocked_today: number;
  pending_hitl_count: number;
  recent_activity: any[];
  active_threat_alerts?: any[];
  budget_warnings?: { agent_id: string; agent_name: string; budget_usd: number; estimated_cost: number; pct_used: number; calls_mtd: number }[];
}

interface GatewayInstance {
  id: string;
  gateway_id: string;
  company_name: string | null;
  tenant_id: string;
  gateway_version: string;
  region: string | null;
  country: string | null;
  ip_address: string | null;
  agents_registered: number;
  calls_last_window: number;
  calls_blocked_last_window: number;
  tls_enabled: boolean;
  mtls_enabled: boolean;
  canary_tokens_active: number;
  quarantined_agents: number;
  live_status: 'online' | 'degraded' | 'offline' | 'pending';
  last_seen_at: string | null;
  first_registered_at: string;
}

interface GatewayFleetData {
  summary: { total: number; online: number; degraded: number; offline: number };
  gateways: GatewayInstance[];
}

const CORE_API = process.env.NEXT_PUBLIC_CORE_API_URL || 'http://localhost:8000';

export default function GlobalOverview() {
  const [dashboardStats, setDashboardStats] = useState<DashboardSummary | null>(null);
  const [gatewayFleet, setGatewayFleet] = useState<GatewayFleetData | null>(null);
  const [sirenMuted, setSirenMuted] = useState(false);
  // Track which alert is currently being dismissed to show loading state.
  const [dismissingAlert, setDismissingAlert] = useState<string | null>(null);
  const oscillatorRef = useRef<OscillatorNode | null>(null);
  const audioCtxRef = useRef<AudioContext | null>(null);
  const sirenChannelRef = useRef<BroadcastChannel | null>(null);

  // ── Cross-tab siren coordination ────────────────────────────────────
  // When the operator mutes the siren in ANY tab, ALL other tabs mute too.
  // This prevents the "two sirens" problem when Global Overview and CIBA
  // pages are both open.
  useEffect(() => {
    const channel = new BroadcastChannel('cicada-siren-sync');
    sirenChannelRef.current = channel;
    channel.onmessage = (e) => {
      if (e.data?.type === 'SIREN_MUTED') {
        setSirenMuted(true);
        if (oscillatorRef.current) { try { oscillatorRef.current.stop(); } catch {} oscillatorRef.current = null; }
        if (audioCtxRef.current) { try { audioCtxRef.current.close(); } catch {} audioCtxRef.current = null; }
      }
    };
    return () => channel.close();
  }, []);

  const stopSiren = useCallback(() => {
    if (oscillatorRef.current) { try { oscillatorRef.current.stop(); } catch {} oscillatorRef.current = null; }
    if (audioCtxRef.current) { try { audioCtxRef.current.close(); } catch {} audioCtxRef.current = null; }
  }, []);

  const muteAllTabs = useCallback(() => {
    setSirenMuted(true);
    stopSiren();
    // Broadcast to other tabs
    try { sirenChannelRef.current?.postMessage({ type: 'SIREN_MUTED' }); } catch {}
  }, [stopSiren]);

  const startSiren = useCallback(() => {
    if (sirenMuted || oscillatorRef.current) return;
    try {
      const ctx = new (window.AudioContext || (window as any).webkitAudioContext)();
      audioCtxRef.current = ctx;
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = 'sine';
      gain.gain.value = 0.12;
      const now = ctx.currentTime;
      for (let i = 0; i < 60; i++) {
        osc.frequency.setValueAtTime(600, now + i);
        osc.frequency.linearRampToValueAtTime(1000, now + i + 0.5);
        osc.frequency.linearRampToValueAtTime(600, now + i + 1.0);
      }
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.start();
      oscillatorRef.current = osc;
    } catch {}
  }, [sirenMuted]);

  // Siren when pending HITL alerts exist
  useEffect(() => {
    if (dashboardStats && dashboardStats.pending_hitl_count > 0 && !sirenMuted) {
      startSiren();
    } else {
      stopSiren();
    }
    return () => stopSiren();
  }, [dashboardStats?.pending_hitl_count, sirenMuted, startSiren, stopSiren]);

  // ─── Data Loading ─────────────────────────────────────────────────────
  // IMPORTANT: We never clear existing state during refresh. This prevents
  // the "loading glitch" where KPI cards would go blank for several seconds
  // during the 10-second auto-refresh cycle. State is only replaced when
  // new data arrives successfully from the API.
  const loadData = useCallback(() => {
    operatorFetch(`${CORE_API}/api/v1/dashboard/summary`, { headers: { Accept: 'application/json' } })
      .then(r => r.json())
      .then(json => {
        if (json.data) setDashboardStats(json.data);
      })
      .catch((e: any) => { console.error('Failed to load dashboard summary:', e); });

    operatorFetch(`${CORE_API}/api/v1/admin/gateways`, { headers: { Accept: 'application/json' } })
      .then(r => r.json())
      .then(json => {
        if (json.status === 'success') setGatewayFleet(json);
      })
      .catch((e: any) => { console.error('Failed to load gateway fleet:', e); });
  }, []);

  useEffect(() => {
    loadData();
    const i = setInterval(loadData, 10000); // Auto-refresh every 10s
    return () => clearInterval(i);
  }, [loadData]);

  // ─── Dismiss Threat Alert ─────────────────────────────────────────────
  // Calls the backend to transition an operator_alert from 'open' to
  // 'resolved', then refreshes the dashboard data to update the view.
  const dismissAlert = useCallback(async (alertId: string) => {
    setDismissingAlert(alertId);
    try {
      const res = await operatorFetch(`${CORE_API}/api/v1/admin/alerts/${alertId}/dismiss`, {
        method: 'POST',
        headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
      });
      if (res.ok) {
        // Optimistic removal: immediately remove the alert from local state
        // so the card disappears without waiting for the full dashboard refresh.
        setDashboardStats(prev => {
          if (!prev) return prev;
          return {
            ...prev,
            active_threat_alerts: (prev.active_threat_alerts || []).filter(
              (a: any) => a.id !== alertId
            ),
          };
        });
        // Background refresh to sync all other stats (counts, etc.)
        loadData();
      } else {
        const errorBody = await res.text().catch(() => 'Unknown error');
        console.error('Failed to dismiss alert:', errorBody);
        alert(`Failed to dismiss alert: ${res.status} — ${errorBody}`);
      }
    } catch (e: any) {
      console.error('Network error dismissing alert:', e);
      alert(`Network error dismissing alert: ${e.message}`);
    } finally {
      setDismissingAlert(null);
    }
  }, [loadData]);

  return (
    <>
      <Sidebar />
      <TopAppBar />

      <main className="pt-24 pb-4 px-10 min-h-screen transition-all duration-300 relative z-10" style={{ marginLeft: 'var(--sidebar-width, 18rem)' }}>
        <div className="p-4 md:p-8 max-w-[95%] mx-auto space-y-4">
          
          <section className="flex flex-col md:flex-row md:items-end justify-between gap-4">
            <div>
              <h2 className="text-5xl font-black font-headline tracking-tighter text-on-surface leading-none text-white">Global Command Center</h2>
              <p className="text-[#a0a0a0] mt-2 font-technical text-sm pb-4">
                Operational AI Agent Governance Control Plane. Source of Truth: Central PostgreSQL Ledger.
              </p>
            </div>
          </section>

          <section className="grid grid-cols-1 xl:grid-cols-2 gap-6 min-h-[500px]">
            
            <div className="flex flex-col gap-6 h-full relative z-20 overflow-y-auto pr-2" style={{ scrollbarWidth: 'none' }}>
               <div className="grid grid-cols-2 gap-4">
                 <KPICard 
                    title="Total Tenants" 
                    value={dashboardStats ? dashboardStats.total_tenants.toLocaleString() : '—'} 
                    trendText="Registered Companies" 
                    trendIcon="corporate_fare" 
                    colorVariant="secondary" 
                    progressPercentage={0} 
                    href="/crm" 
                 />
                 <KPICard 
                    title="Total Agents" 
                    value={dashboardStats ? dashboardStats.total_agents.toLocaleString() : '—'} 
                    trendText={dashboardStats ? `${dashboardStats.active_agents_24h} active in last 24h` : ''} 
                    trendIcon="smart_toy" 
                    colorVariant="primary" 
                    progressPercentage={dashboardStats && dashboardStats.total_agents > 0 ? (dashboardStats.active_agents_24h / dashboardStats.total_agents) * 100 : 0} 
                    href="/registry" 
                 />
                 <KPICard 
                    title="Today's Execution" 
                    value={dashboardStats ? (dashboardStats.approved_today + dashboardStats.blocked_today).toLocaleString() : '—'} 
                    trendText={dashboardStats ? `${dashboardStats.approved_today} allowed / ${dashboardStats.blocked_today} blocked` : 'Loading...'} 
                    trendIcon="compare_arrows" 
                    colorVariant="tertiary" 
                    progressPercentage={dashboardStats && (dashboardStats.approved_today + dashboardStats.blocked_today) > 0 ? (dashboardStats.blocked_today / (dashboardStats.approved_today + dashboardStats.blocked_today)) * 100 : 0} 
                    href="/pipeline" 
                 />
                 <KPICard 
                    title="Triage & Quarantines" 
                    value={dashboardStats ? dashboardStats.quarantined_agents.toLocaleString() : '—'} 
                    trendText={dashboardStats ? `${dashboardStats.pending_hitl_count} pending HITL approvals` : 'Loading...'} 
                    trendIcon="security" 
                    colorVariant="error" 
                    progressPercentage={dashboardStats && dashboardStats.pending_hitl_count > 0 ? 100 : 0} 
                    href="/agent-admin/ciba" 
                 />
               </div>

               {/* Real-Time Threat Alerts */}
               {dashboardStats?.active_threat_alerts && dashboardStats.active_threat_alerts.length > 0 && (
                 <div className="bg-[#1a0505] rounded-2xl border border-red-500/50 relative overflow-hidden p-6 shadow-[0_0_30px_rgba(239,68,68,0.2)] animate-pulse-border">
                    <div className="flex items-center gap-2 mb-4">
                      <span className="material-symbols-outlined text-red-500 animate-pulse">crisis_alert</span>
                      <h2 className="text-xl font-black font-headline tracking-tighter uppercase text-red-500 drop-shadow-lg">
                         Active Threat Alerts
                      </h2>
                      <button
                        onClick={() => { if (!sirenMuted) { muteAllTabs(); } else { setSirenMuted(false); } }}
                        className={`ml-2 px-2 py-1 rounded text-[10px] font-technical font-bold border transition-all flex items-center gap-1 ${
                          sirenMuted
                            ? 'bg-neutral-800 border-neutral-700 text-neutral-400'
                            : 'bg-red-500/20 border-red-500/30 text-red-400 animate-pulse'
                        }`}
                      >
                        <span className="material-symbols-outlined text-[12px]">{sirenMuted ? 'volume_off' : 'volume_up'}</span>
                        {sirenMuted ? 'Muted' : 'Siren'}
                      </button>
                      <span className="ml-auto text-[10px] font-technical text-red-400 bg-red-500/20 px-2 py-1 rounded border border-red-500/30 uppercase tracking-widest flex items-center gap-1">
                         <span className="w-1.5 h-1.5 rounded-full bg-red-500 animate-ping"></span> Real-Time
                      </span>
                    </div>
                   
                   <div className="flex flex-col gap-3">
                      {dashboardStats.active_threat_alerts.map((alert: any) => (
                         <div key={alert.id} className="p-3 bg-red-500/10 border border-red-500/30 rounded-xl">
                            <div className="flex items-center justify-between mb-1">
                               <span className="text-white font-technical text-sm font-bold">{alert.agent_name || 'Unknown Agent'}</span>
                               <div className="flex items-center gap-2">
                                 <span className="text-[10px] font-bold uppercase tracking-widest text-red-400 border border-red-500/50 bg-red-500/20 px-2 py-0.5 rounded">
                                   {alert.severity} • {alert.event_type.replace('_', ' ')}
                                 </span>
                                 {/* Dismiss button — resolves the alert via the backend API */}
                                 <button
                                   onClick={() => dismissAlert(alert.id)}
                                   disabled={dismissingAlert === alert.id}
                                   className="px-2 py-0.5 text-[10px] font-bold font-technical uppercase tracking-wider border rounded transition-all flex items-center gap-1 bg-white/5 border-white/10 text-neutral-400 hover:bg-white/10 hover:text-white disabled:opacity-50 disabled:cursor-not-allowed"
                                   title="Mark this alert as resolved"
                                 >
                                   <span className="material-symbols-outlined text-[12px]">{dismissingAlert === alert.id ? 'hourglass_empty' : 'check_circle'}</span>
                                   {dismissingAlert === alert.id ? 'Dismissing…' : 'Dismiss'}
                                 </button>
                               </div>
                            </div>
                            <p className="text-xs text-red-200 mt-1 font-technical">{alert.summary}</p>
                            <div className="mt-2 text-[10px] font-technical text-red-500/70 uppercase">
                               {new Date(alert.created_at).toLocaleString()}
                            </div>
                         </div>
                      ))}
                   </div>

                   {/* Link to the full CIBA queue for approve/reject actions */}
                   <div className="mt-4 pt-3 border-t border-red-500/20 flex items-center justify-between">
                     {dashboardStats.pending_hitl_count > 0 && (
                       <span className="text-xs font-technical text-red-400 animate-pulse">
                         ⚠ {dashboardStats.pending_hitl_count} CIBA hold{dashboardStats.pending_hitl_count > 1 ? 's' : ''} awaiting approval
                       </span>
                     )}
                     <Link href="/agent-admin/ciba" className="ml-auto px-4 py-2 bg-red-500/20 border border-red-500/40 text-red-300 font-bold rounded-xl text-xs font-technical hover:bg-red-500/30 transition-all flex items-center gap-1.5">
                       <span className="material-symbols-outlined text-[14px]">gavel</span>
                       Review CIBA Queue
                     </Link>
                   </div>
                 </div>
               )}

               {/* ── Recent Activity Feed ── */}
               {/* This card mirrors the Activity Ledger page (/logs) — showing */}
               {/* all recent actions (approved, blocked, shadow) not just blocks. */}
               {/* Naming standardised: "Activity Ledger" is the operator-facing */}
               {/* name; the database table remains 'action_ledger'. */}
               <div className="bg-[#101010] rounded-2xl border border-white/10 relative overflow-hidden p-6 flex-1 flex flex-col shadow-2xl mt-4">
                 <div className="flex items-center justify-between mb-4">
                   <h2 className="text-xl font-black font-headline tracking-tighter uppercase text-white drop-shadow-lg flex items-center gap-2">
                      <span className="material-symbols-outlined text-orange-500">history</span>
                      Recent Activity
                   </h2>
                   <Link href="/logs" className="text-[10px] font-technical font-bold uppercase tracking-widest text-orange-400 hover:text-orange-300 transition-colors flex items-center gap-1">
                     <span className="material-symbols-outlined text-[14px]">open_in_new</span>
                     Full Activity Ledger
                   </Link>
                 </div>
                 
                 <div className="flex flex-col gap-3 overflow-y-auto">
                    {!dashboardStats ? (
                       <p className="text-neutral-500 font-technical text-sm text-center mt-10">Loading activity ledger...</p>
                    ) : dashboardStats.recent_activity && dashboardStats.recent_activity.length > 0 ? (
                       dashboardStats.recent_activity.map((entry: any, idx: number) => {
                          // Colour-code each entry by status.
                          // 'resolved' = a dealt-with threat from operator_alerts.
                          // 'threat' = would only appear if an open alert leaked in (shouldn't happen).
                          const statusConfig: Record<string, { label: string; color: string }> = {
                            blocked:         { label: 'Blocked',  color: 'text-red-400 border-red-500/20 bg-red-500/10' },
                            approved:        { label: 'Approved', color: 'text-emerald-400 border-emerald-500/20 bg-emerald-500/10' },
                            shadow_allowed:  { label: 'Shadow',   color: 'text-amber-400 border-amber-500/20 bg-amber-500/10' },
                            shadow_sandbox:  { label: 'Monitored',color: 'text-orange-400 border-orange-500/20 bg-orange-500/10' },
                            resolved:        { label: 'Resolved', color: 'text-sky-400 border-sky-500/20 bg-sky-500/10' },
                            threat:          { label: 'Threat',   color: 'text-red-400 border-red-500/20 bg-red-500/10' },
                          };
                          const cfg = statusConfig[entry.status] || { label: entry.status, color: 'text-neutral-400 border-white/10 bg-white/5' };
                          // Alert entries (source='alert') show summary instead of target_api.
                          const detail = entry.source === 'alert'
                            ? (entry.summary || entry.action_type?.replace(/_/g, ' ') || 'Threat event')
                            : `via ${entry.target_api || 'Unknown API'}`;
                          return (
                            <div key={idx} className={`p-3 rounded-xl flex items-start justify-between gap-4 ${entry.source === 'alert' ? 'bg-sky-500/5 border border-sky-500/10' : 'bg-white/5 border border-white/5'}`}>
                               <div className="flex-1 min-w-0 leading-relaxed">
                                  <div className="flex items-center gap-2 flex-wrap">
                                    <span className={`text-[10px] font-bold uppercase tracking-widest px-2 py-0.5 rounded border whitespace-nowrap ${cfg.color}`}>{cfg.label}</span>
                                    <span className="text-white font-technical text-sm font-bold">{entry.agent_name || 'System'}</span>
                                    {entry.severity && (
                                      <span className="text-[9px] font-bold uppercase tracking-widest text-red-400/60">{entry.severity}</span>
                                    )}
                                  </div>
                                  <p className="text-neutral-500 font-technical text-xs mt-1 truncate">{detail}</p>
                               </div>
                               <div className="text-right shrink-0 pt-0.5">
                                  <p className="text-[10px] font-technical text-[#888] uppercase leading-normal">{new Date(entry.created_at).toLocaleString()}</p>
                                  <p className="text-[10px] font-technical font-bold text-orange-400 mt-1 leading-normal">{entry.action_type?.replace(/_/g, ' ')}</p>
                               </div>
                            </div>
                          );
                       })
                    ) : (
                       <p className="text-neutral-500 font-technical text-sm text-center mt-10">No recent activity detected. Ledger is clean.</p>
                    )}
                 </div>
               </div>
            </div>

             {/* Budget Alerts */}
             {dashboardStats?.budget_warnings && dashboardStats.budget_warnings.length > 0 && (
               <div className="bg-[#101010] rounded-2xl border border-amber-500/20 relative overflow-hidden p-6 shadow-2xl">
                 <div className="flex items-center gap-2 mb-4">
                   <span className="material-symbols-outlined text-amber-400">account_balance_wallet</span>
                   <h2 className="text-lg font-black font-headline tracking-tighter uppercase text-amber-400">Budget Alerts</h2>
                   <span className="ml-auto text-[10px] font-technical text-neutral-500 uppercase tracking-widest">Month-to-Date</span>
                 </div>
                 <div className="flex flex-col gap-3">
                   {dashboardStats.budget_warnings.map(w => (
                     <div key={w.agent_id} className="p-3 bg-amber-500/5 border border-amber-500/10 rounded-xl">
                       <div className="flex items-center justify-between mb-2">
                         <span className="text-white font-technical text-sm font-bold">{w.agent_name}</span>
                         <span className={`text-[10px] font-bold uppercase tracking-widest px-2 py-0.5 rounded border ${
                           w.pct_used >= 100 ? 'text-red-400 bg-red-500/10 border-red-500/20' : 'text-amber-400 bg-amber-500/10 border-amber-500/20'
                         }`}>
                           {w.pct_used >= 100 ? 'OVER BUDGET' : 'WARNING'}
                         </span>
                       </div>
                       <div className="flex items-center gap-3">
                         <div className="flex-1 h-2 rounded-full bg-white/10 overflow-hidden">
                           <div className={`h-full rounded-full transition-all ${w.pct_used >= 100 ? 'bg-red-500' : 'bg-amber-500'}`}
                             style={{ width: `${Math.min(w.pct_used, 100)}%` }} />
                         </div>
                         <span className="text-xs font-technical text-neutral-400 whitespace-nowrap">
                           ${w.estimated_cost.toFixed(2)} / ${w.budget_usd.toFixed(2)} ({w.pct_used}%)
                         </span>
                       </div>
                       <p className="text-[10px] font-technical text-neutral-500 mt-1">{w.calls_mtd.toLocaleString()} calls this month</p>
                     </div>
                   ))}
                 </div>
               </div>
             )}

            {/* RIGHT PANE: Real Globe using ONLY returned Gateway API Installs */}
            <div className="bg-[#060608] rounded-2xl overflow-hidden border border-white/10 relative group shadow-[inset_0_0_80px_rgba(0,0,0,0.9)] z-10 min-h-[500px]">
              
              <div className="p-6 absolute top-0 left-0 right-0 z-40 pointer-events-none">
                <div>
                  <h4 className="text-xl font-black font-technical tracking-tighter flex items-center gap-2 text-white drop-shadow-lg">
                    <span className="material-symbols-outlined text-[20px] text-orange-500">satellite_alt</span>
                    Active Gateway Fleet
                  </h4>
                  <p className="text-neutral-400 text-xs mt-1 max-w-[250px] font-technical drop-shadow-md">
                    {gatewayFleet ? `Mapping ${gatewayFleet.gateways.length} persistent gateway installations.` : `Loading fleet telemetry...`}
                  </p>
                </div>
              </div>
              
              <div className="w-full h-full min-h-[500px] relative">
                <CommandMatrix gateways={gatewayFleet?.gateways || []} />
              </div>
            </div>
          </section>

          {/* ── Gateway Fleet Table Extract ── */}
          <section className="mt-6 border-t border-white/10 pt-6">
            <div className="flex items-center justify-between mb-4">
               <h2 className="text-2xl font-black font-headline tracking-tighter text-white flex items-center gap-3">
                  <span className="material-symbols-outlined text-orange-500">router</span>
                  Heartbeat Status
               </h2>
               {gatewayFleet && (
                 <div className="flex gap-3">
                   {[
                     { label: 'Online', count: gatewayFleet.summary.online, color: 'text-green-400 bg-green-500/10 border-green-500/20' },
                     { label: 'Degraded', count: gatewayFleet.summary.degraded, color: 'text-orange-400 bg-orange-500/10 border-orange-500/20' },
                     { label: 'Offline', count: gatewayFleet.summary.offline, color: 'text-red-400 bg-red-500/10 border-red-500/20' },
                   ].map(s => (
                     <div key={s.label} className={`px-3 py-1.5 rounded-lg border text-xs font-bold font-technical ${s.color}`}>
                       {s.count} {s.label}
                     </div>
                   ))}
                 </div>
               )}
            </div>

            <div className="bg-[#121212] rounded-xl border border-white/10 overflow-hidden">
               {gatewayFleet && gatewayFleet.gateways.length > 0 ? (
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-white/5 bg-white/[0.02]">
                        {['Status', 'Company', 'Location', 'IP', 'Version', 'Agents', 'Load (Window)', 'TLS', 'mTLS', 'Canary Tokens', 'Last Seen'].map(col => (
                           <th key={col} className="px-4 py-3 text-[10px] font-bold uppercase tracking-widest text-[#888] text-left">{col}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                       {gatewayFleet.gateways.map(gw => (
                         <tr key={gw.id} className="border-b border-white/5 hover:bg-white/[0.03]">
                            <td className="px-4 py-3">
                              <span className={`text-xs font-bold uppercase ${gw.live_status === 'online' ? 'text-emerald-400' : gw.live_status === 'degraded' ? 'text-orange-400' : 'text-red-400'}`}>{gw.live_status}</span>
                            </td>
                            <td className="px-4 py-3 text-sm text-white">{gw.company_name || '—'}</td>
                            <td className="px-4 py-3 text-xs text-neutral-400">{gw.country || '—'}</td>
                            <td className="px-4 py-3 text-xs text-neutral-500 font-technical">{gw.ip_address || '—'}</td>
                            <td className="px-4 py-3 text-xs text-neutral-400">v{gw.gateway_version}</td>
                            <td className="px-4 py-3 text-sm font-technical text-white">{gw.agents_registered}</td>
                            <td className="px-4 py-3 text-sm font-technical text-white">{gw.calls_last_window}</td>
                            <td className="px-4 py-3 text-xs font-technical">
                              <span className={gw.tls_enabled ? 'text-emerald-400' : 'text-neutral-600'}>{gw.tls_enabled ? '✓' : '✗'}</span>
                            </td>
                            <td className="px-4 py-3 text-xs font-technical">
                              <span className={gw.mtls_enabled ? 'text-emerald-400' : 'text-neutral-600'}>{gw.mtls_enabled ? '✓' : '✗'}</span>
                            </td>
                            <td className="px-4 py-3 text-sm font-technical text-white">{gw.canary_tokens_active}</td>
                            <td className="px-4 py-3 text-xs font-technical text-neutral-500">{new Date(gw.last_seen_at || Date.now()).toLocaleString()}</td>
                         </tr>
                       ))}
                    </tbody>
                  </table>
               ) : (
                  <div className="p-8 text-center text-[#666] text-sm font-technical">No gateway instances identified in schema.</div>
               )}
            </div>
          </section>

        </div>
      </main>
    </>
  );
}
