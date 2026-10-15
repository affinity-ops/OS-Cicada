// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

'use client';
import { operatorFetch } from '@/lib/operatorFetch';
import { useState, useEffect } from 'react';
import { useToast } from '../../components/ToastContext';
import { Sidebar } from '../../components/Sidebar';
import { TopAppBar } from '../../components/TopAppBar';
import { Tooltip } from '../../components/Tooltip';

interface ComputeAction {
  trace_id: string;
  action_type: string;
  target_api: string;
  status: string;
  swarm_confidence_score: number | null;
  created_at: string;
  agent_name: string;
}

interface ComputeMetrics {
  active_instances: number;
  threat_velocity: number;
  active_threads: number;
  system_load: number;
  verification_hops: number;
  recent_actions: ComputeAction[];
}

const API = process.env.NEXT_PUBLIC_CORE_API_URL ?? 'http://localhost:8000';

function activityLine(action: ComputeAction) {
  const time = new Date(action.created_at).toLocaleTimeString();
  if (action.status === 'blocked') {
    return { time, sys: 'Security', msg: `Blocked: ${action.action_type.replace(/_/g, ' ')} → ${action.target_api}`, cls: 'text-error font-bold' };
  }
  if (action.status === 'shadow_sandbox') {
    return { time, sys: 'Monitor', msg: `Watching: ${action.agent_name}`, cls: 'text-orange-400' };
  }
  if (action.swarm_confidence_score !== null) {
    return { time, sys: 'Verified', msg: `Approved: ${action.agent_name} (score: ${action.swarm_confidence_score})`, cls: 'text-emerald-500' };
  }
  return { time, sys: 'Gateway', msg: `${action.action_type.replace(/_/g, ' ')}: ${action.agent_name}`, cls: 'text-neutral-400' };
}

export default function SecurityMonitor() {
  const [sensitivity, setSensitivity] = useState(84);
  const [strictness, setStrictness] = useState(42);
  const [isSaving, setIsSaving] = useState(false);
  const [metrics, setMetrics] = useState<ComputeMetrics | null>(null);
  const { showToast } = useToast();

  useEffect(() => {
    const load = () => {
      operatorFetch(`${API}/api/v1/compute/metrics`)
        .then(r => r.json())
        .then(body => { if (body.status === 'success') setMetrics(body.data); })
        .catch(() => {});
    };
    load();
    const interval = setInterval(load, 10_000);
    return () => clearInterval(interval);
  }, []);

  const handleSaveSettings = () => {
    setIsSaving(true);
    // NOTE: /api/v1/compute/settings endpoint not yet implemented.
    // Settings are stored in local component state only until the backend
    // endpoint is created (see CICADA_PRODUCTION_ROADMAP Phase 2).
    showToast('Settings saved locally. Backend persistence endpoint pending.');
    setIsSaving(false);
  };

  const threads      = metrics?.active_threads ?? 0;
  const load         = metrics?.system_load ?? 0;
  const hops         = metrics?.verification_hops ?? 0;
  const instances    = metrics?.active_instances ?? 0;
  const velocity     = metrics?.threat_velocity ?? 0;
  const recentActions = metrics?.recent_actions ?? [];

  return (
    <>
      <Sidebar />
      <TopAppBar />
      <main className="pt-24 px-8 pb-12 min-h-screen transition-all duration-300" style={{ marginLeft: 'var(--sidebar-width, 18rem)' }}>
        <div className="max-w-[95%] mx-auto space-y-8">

          <section className="flex flex-col md:flex-row justify-between items-end gap-6">
            <div className="space-y-2">
              <h2 className="text-5xl font-black font-headline tracking-tighter uppercase leading-none">Security <span className="text-primary">Monitor</span></h2>
              <p className="text-on-surface-variant max-w-lg font-body leading-relaxed">
                Live feed of all agent activity going through the security system. Blocked requests and threats are highlighted automatically.
              </p>
            </div>
            <div className="flex items-center gap-4 bg-[#131313] p-4 rounded-2xl border border-white/5">
              <div className="text-right">
                <p className="text-[10px] font-technical text-neutral-500 uppercase tracking-widest">Active Agents</p>
                <p className="text-2xl font-bold font-headline">{instances.toLocaleString()}</p>
              </div>
              <div className="h-10 w-px bg-white/10"></div>
              <div className="text-right">
                <p className="text-[10px] font-technical text-neutral-500 uppercase tracking-widest">Threats / sec</p>
                <p className="text-2xl font-bold font-headline text-error">{velocity}/s</p>
              </div>
            </div>
          </section>

          <div className="grid grid-cols-12 gap-6">

            {/* Live Activity Feed */}
            <div className="col-span-12 lg:col-span-8 bg-[#1a1a1a] rounded-2xl overflow-hidden border border-white/5 flex flex-col h-[500px]">
              <div className="bg-[#262626]/50 px-6 py-3 flex items-center justify-between border-b border-white/5">
                <div className="flex items-center gap-2">
                  <div className="flex gap-1.5">
                    <div className="w-2.5 h-2.5 rounded-full bg-error/40"></div>
                    <div className="w-2.5 h-2.5 rounded-full bg-secondary/40"></div>
                    <div className="w-2.5 h-2.5 rounded-full bg-primary/40"></div>
                  </div>
                  <span className="ml-4 text-[11px] font-technical text-neutral-400 uppercase tracking-widest">Live Activity Feed</span>
                </div>
                <span className="text-[10px] font-technical text-primary animate-pulse">● LIVE</span>
              </div>
              <div className="flex-1 p-6 font-technical text-xs overflow-y-auto bg-[#000000]/40">
                {recentActions.length === 0 ? (
                  <p className="text-neutral-600 animate-pulse">[Waiting for agent activity...]</p>
                ) : (
                  <div className="space-y-1.5">
                    {recentActions.map(action => {
                      const line = activityLine(action);
                      return (
                        <p key={action.trace_id} className={line.cls}>
                          <span className="text-neutral-600">[{line.time}]</span>{' '}
                          <span className="text-emerald-600 font-bold">{line.sys}:</span>{' '}
                          {line.msg}
                        </p>
                      );
                    })}
                  </div>
                )}
              </div>
            </div>

            {/* Security Settings */}
            <div className="col-span-12 lg:col-span-4 space-y-6">
              <div className="bg-[#1a1a1a] p-6 rounded-2xl border border-white/5 space-y-8">
                <div className="flex justify-between items-start">
                  <h3 className="font-headline font-bold text-lg uppercase tracking-tight">Security Settings</h3>
                  <span className="material-symbols-outlined text-primary">tune</span>
                </div>
                <div className="space-y-10">
                  <div className="space-y-4">
                    <Tooltip warning={sensitivity > 80} content={sensitivity > 80 ? "CRITICAL: High sensitivity actively blocks edge-case legitimate API calls to protect the platform. False-positives are virtually guaranteed." : "Balanced threshold processing native telemetry with baseline tolerances."}>
                      <div className="flex justify-between items-end cursor-help w-full">
                        <label className="text-[10px] flex items-center gap-1 font-technical text-neutral-500 uppercase tracking-widest">
                          Threat Sensitivity <span className="material-symbols-outlined text-[12px] text-neutral-600">info</span>
                        </label>
                        <span className="text-xl font-bold font-headline text-primary">{sensitivity}<span className="text-xs text-neutral-600">%</span></span>
                      </div>
                    </Tooltip>
                    <input className="w-full h-1 bg-[#262626] rounded-full appearance-none outline-none" style={{ accentColor: '#ff9f4a' }} type="range" min="0" max="100" value={sensitivity} onChange={e => setSensitivity(Number(e.target.value))} />
                    <div className="flex justify-between text-[9px] font-technical text-neutral-700"><span>LOW</span><span>HIGH</span></div>
                    {sensitivity > 80 && <p className="text-[10px] text-error font-technical animate-pulse mt-1">Extreme Quarantine Mode Active</p>}
                  </div>
                  <div className="space-y-4">
                    <Tooltip warning={strictness < 20} content={strictness < 20 ? "WARNING: Relaxed strictness permits agents to bypass structural boundaries. Extreme threat of hallucination or data exposure." : "Normal enforcement of Open Policy Agent (OPA) parameters."}>
                      <div className="flex justify-between items-end cursor-help w-full">
                        <label className="text-[10px] flex items-center gap-1 font-technical text-neutral-500 uppercase tracking-widest">
                          Policy Strictness <span className="material-symbols-outlined text-[12px] text-neutral-600">info</span>
                        </label>
                        <span className="text-xl font-bold font-headline text-secondary">{strictness}<span className="text-xs text-neutral-600">%</span></span>
                      </div>
                    </Tooltip>
                    <input className="w-full h-1 bg-[#262626] rounded-full appearance-none outline-none" style={{ accentColor: '#f9c13d' }} type="range" min="0" max="100" value={strictness} onChange={e => setStrictness(Number(e.target.value))} />
                    <div className="flex justify-between text-[9px] font-technical text-neutral-700"><span>RELAXED</span><span>STRICT</span></div>
                    {strictness < 20 && <p className="text-[10px] text-error flex items-center gap-1 font-technical animate-pulse mt-1"><span className="material-symbols-outlined text-[10px]">warning</span> Architecture Sandbox Compromised</p>}
                  </div>
                </div>
                <button onClick={handleSaveSettings} disabled={isSaving} className={`w-full py-4 rounded-xl border transition-all flex items-center justify-center gap-2 group font-headline font-bold ${isSaving ? 'bg-primary/20 text-primary border-primary/50' : 'bg-white/5 hover:bg-white/10 text-on-surface border-white/10'}`}>
                  {isSaving ? 'Saving...' : 'Save Settings'}
                  {!isSaving && <span className="material-symbols-outlined text-sm group-hover:translate-x-1 transition-transform">arrow_forward</span>}
                </button>
              </div>
            </div>
          </div>

          <section className="grid grid-cols-1 md:grid-cols-5 gap-6">
            <div className="bg-[#131313] p-6 rounded-2xl border border-white/5 space-y-4">
              <p className="text-[10px] font-technical text-neutral-500 uppercase tracking-widest">Checks Run (1h)</p>
              <div className="h-1 bg-[#262626] rounded-full overflow-hidden"><div className="h-full bg-primary" style={{ width: `${Math.min(threads / 100, 1) * 100}%` }}></div></div>
              <p className="text-2xl font-black font-headline tracking-tighter">{threads.toLocaleString()}</p>
            </div>
            <div className="bg-[#131313] p-6 rounded-2xl border border-white/5 space-y-4">
              <p className="text-[10px] font-technical text-neutral-500 uppercase tracking-widest">System Load</p>
              <div className="h-1 bg-[#262626] rounded-full overflow-hidden"><div className="h-full bg-secondary" style={{ width: `${load}%` }}></div></div>
              <p className="text-2xl font-black font-headline tracking-tighter text-secondary">{load}%</p>
            </div>
            <div className="bg-[#131313] p-6 rounded-2xl border border-white/5 space-y-4">
              <p className="text-[10px] font-technical text-neutral-500 uppercase tracking-widest">Verifications (1h)</p>
              <div className="h-1 bg-[#262626] rounded-full overflow-hidden"><div className="h-full bg-orange-400" style={{ width: `${Math.min(hops / 50, 1) * 100}%` }}></div></div>
              <p className="text-2xl font-black font-headline tracking-tighter">{hops.toLocaleString()}</p>
            </div>
            <div className="bg-[#131313] p-6 rounded-2xl border border-white/5 space-y-4">
              <p className="text-[10px] font-technical text-neutral-500 uppercase tracking-widest">Status</p>
              <div className="h-1 bg-[#262626] rounded-full overflow-hidden"><div className="h-full bg-emerald-500 w-full"></div></div>
              <p className="text-2xl font-black font-headline tracking-tighter text-emerald-500">LIVE</p>
            </div>
            <div className="bg-[#131313] p-6 rounded-2xl border border-amber-500/20 space-y-4">
              <p className="text-[10px] font-technical text-amber-400 uppercase tracking-widest flex items-center gap-1.5">
                <span className="material-symbols-outlined text-[12px]">visibility</span>
                Shadow Flags (24h)
              </p>
              <div className="h-1 bg-[#262626] rounded-full overflow-hidden"><div className="h-full bg-amber-500" style={{ width: '30%' }}></div></div>
              <p className="text-2xl font-black font-headline tracking-tighter text-amber-400">—</p>
              <p className="text-[9px] font-technical text-neutral-600">Observe-only violations</p>
            </div>
          </section>

        </div>
      </main>
    </>
  );
}
