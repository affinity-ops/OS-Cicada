// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

'use client';
import { operatorFetch } from '@/lib/operatorFetch';
import { useState, useEffect } from 'react';
import { useToast } from '../../components/ToastContext';
import { Sidebar } from '../../components/Sidebar';
import { TopAppBar } from '../../components/TopAppBar';

interface GhostAgent {
  agent_id: string;
  agent_name: string;
  tenant_id: string;
  tenant_name: string;
  target_api: string;
  intercept_count: number;
  last_seen: string;
  block_count: number;
}

interface DiscoveryData {
  ghost_agents: GhostAgent[];
  sandbox_anomalies: unknown[];
  total_ghost: number;
}

const API = process.env.NEXT_PUBLIC_CORE_API_URL ?? 'http://localhost:8000';

export default function UnmanagedAgents() {
  const { showToast } = useToast();
  const [data, setData] = useState<DiscoveryData | null>(null);
  const [loading, setLoading] = useState(true);
  const [actionInProgress, setActionInProgress] = useState<string | null>(null);

  useEffect(() => {
    operatorFetch(`${API}/api/v1/discovery`)
      .then(r => r.json())
      .then(body => { if (body.status === 'success') setData(body.data); })
      .catch(() => showToast('Failed to load unmanaged agent data.'))
      .finally(() => setLoading(false));
  }, []);

  const applyAction = (agentId: string, agentName: string, action: 'monitor' | 'block' | 'rollback') => {
    setActionInProgress(agentId + action);
    const endpoint = action === 'block' ? 'revoke' : action === 'rollback' ? 'rollback' : 'monitor';
    operatorFetch(`${API}/api/v1/agents/${agentId}/${endpoint}`, { method: 'POST' })
      .then(r => r.ok ? r.json() : Promise.reject())
      .then(() => {
        const msg =
          action === 'block'    ? `${agentName} has been blocked.` :
          action === 'rollback' ? `Rollback triggered for ${agentName}.` :
                                  `${agentName} is now being monitored.`;
        showToast(msg);
      })
      .catch(() => {
        showToast(`Action recorded for ${agentName}. Connect gateway to enforce.`);
      })
      .finally(() => setActionInProgress(null));
  };

  const ghosts = data?.ghost_agents ?? [];
  const totalGhost = data?.total_ghost ?? 0;

  return (
    <>
      <Sidebar />
      <TopAppBar />
      <main className="pt-24 pb-12 px-10 min-h-screen bg-background transition-all duration-300 relative overflow-hidden" style={{ marginLeft: 'var(--sidebar-width, 18rem)' }}>

        <div className="absolute top-[-10%] right-[-5%] w-[800px] h-[800px] border-[1px] border-orange-500/5 rounded-full pointer-events-none flex items-center justify-center animate-pulse">
          <div className="w-[600px] h-[600px] border-[1px] border-orange-500/10 rounded-full flex items-center justify-center">
            <div className="w-[400px] h-[400px] border-[1px] border-orange-500/20 rounded-full flex items-center justify-center">
              <div className="w-[200px] h-[200px] border-[1px] border-orange-500/30 rounded-full"></div>
            </div>
          </div>
        </div>

        <div className="max-w-[95%] mx-auto relative z-10">
          <div className="mb-10 flex justify-between items-end">
            <div>
              <h1 className="text-5xl font-black font-headline tracking-tighter text-on-surface mb-2">
                Unmanaged <span className="text-orange-500">Agents</span>
              </h1>
              <p className="text-on-surface-variant text-lg max-w-2xl">
                Agents detected operating outside your approved security gateway. Review each one and decide whether to monitor, block, or reverse their actions.
              </p>
            </div>
            <div className="flex gap-4">
              <div className="flex items-center gap-3 px-5 py-3 bg-[#131313] border border-white/10 rounded-lg">
                <span className="relative flex h-3 w-3">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-orange-400 opacity-75"></span>
                  <span className="relative inline-flex rounded-full h-3 w-3 bg-orange-500"></span>
                </span>
                <span className="text-xs uppercase font-technical text-orange-500 tracking-wider font-bold">
                  {totalGhost} Unmanaged agent{totalGhost !== 1 ? 's' : ''} detected
                </span>
              </div>
            </div>
          </div>

          {/* Risk Map */}
          <div className="bg-[#131313] border border-white/5 rounded-2xl p-8 mb-8 relative overflow-hidden shadow-2xl">
            <h2 className="text-xl font-headline font-black text-on-surface mb-8 flex items-center gap-2">
              <span className="material-symbols-outlined text-orange-500">radar</span> Risk Map
            </h2>
            <div className="h-[400px] w-full bg-[#0a0a0a] rounded-xl border border-white/5 relative flex items-center justify-center">
              <div className="absolute top-[40%] left-[50%] transform -translate-x-1/2 -translate-y-1/2 flex flex-col items-center group z-20">
                <div className="w-20 h-20 bg-blue-500/10 border-2 border-blue-500 text-blue-500 rounded-full flex items-center justify-center shadow-[0_0_40px_rgba(59,130,246,0.3)]">
                  <span className="material-symbols-outlined text-3xl">database</span>
                </div>
                <p className="text-xs font-technical mt-3 text-neutral-400 font-bold tracking-wider">Your Platform</p>
              </div>

              {ghosts.length === 0 ? (
                <div className="flex flex-col items-center text-neutral-700 gap-2">
                  <span className="material-symbols-outlined text-4xl opacity-30">radar</span>
                  <p className="font-technical text-xs">No unmanaged agents detected in the last 24 hours.</p>
                </div>
              ) : (
                ghosts.slice(0, 3).map((ghost, i) => {
                  const positions = [
                    { top: '20%', left: '20%' },
                    { top: '65%', left: '30%' },
                    { top: '25%', left: '70%' },
                  ];
                  const pos = positions[i] ?? positions[0];
                  const isHigh = ghost.block_count > 0;
                  const color = isHigh ? 'red' : 'orange';
                  return (
                    <div key={ghost.agent_id} className="absolute flex flex-col items-center group z-20" style={pos}>
                      <div className={`w-16 h-16 bg-${color}-500/10 border-2 border-${color}-500 text-${color}-500 rounded-full flex items-center justify-center shadow-[0_0_30px_rgba(239,68,68,0.2)]`}>
                        <span className="material-symbols-outlined text-2xl">smart_toy</span>
                      </div>
                      <p className={`text-[10px] uppercase font-technical mt-2 text-${color}-400 font-bold bg-${color}-500/10 px-2 py-0.5 rounded border border-${color}-500/20`}>
                        {ghost.agent_name}
                      </p>
                    </div>
                  );
                })
              )}

              <div className="absolute bottom-4 left-4 bg-black/60 backdrop-blur-md border border-white/10 p-4 rounded-lg text-xs font-technical text-neutral-400 space-y-2">
                <p className="flex items-center gap-2"><span className="w-2 h-2 rounded-full bg-red-500 inline-block"></span> High risk (blocked attempts recorded)</p>
                <p className="flex items-center gap-2"><span className="w-2 h-2 rounded-full bg-orange-500 inline-block"></span> Under monitoring</p>
              </div>
            </div>
          </div>

          <h2 className="text-xl font-headline font-black text-on-surface mb-6 mt-12 flex items-center gap-2">
            <span className="material-symbols-outlined text-neutral-400">gavel</span> Take Action
          </h2>

          {loading && (
            <div className="py-12 flex items-center justify-center text-neutral-500 font-technical text-xs animate-pulse">
              Scanning for unmanaged agents...
            </div>
          )}

          {!loading && ghosts.length === 0 && (
            <div className="py-12 flex flex-col items-center text-neutral-600 gap-2">
              <span className="material-symbols-outlined text-4xl opacity-20">check_circle</span>
              <p className="font-technical text-xs">No unmanaged agents detected in the last 24 hours. All clear.</p>
            </div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {ghosts.map(ghost => {
              const isHigh = ghost.block_count > 0;
              const lastSeen = ghost.last_seen ? `${Math.round((Date.now() - new Date(ghost.last_seen).getTime()) / 60000)}m ago` : 'N/A';
              return (
                <div
                  key={ghost.agent_id}
                  className={`bg-[#131313] rounded-2xl p-6 relative overflow-hidden transition-all hover:bg-[#1a1a1a] border ${isHigh ? 'border-red-500/30' : 'border-orange-500/30'}`}
                >
                  <div className={`absolute top-0 right-0 py-1 px-3 border-b border-l rounded-bl-lg text-[10px] font-technical uppercase font-bold tracking-wider ${isHigh ? 'bg-red-500/10 border-red-500/30 text-red-500' : 'bg-orange-500/10 border-orange-500/30 text-orange-500'}`}>
                    {isHigh ? 'High Risk' : 'Being Monitored'}
                  </div>

                  <div className="flex items-center gap-3 mb-4">
                    <div className={`w-12 h-12 border rounded-full flex items-center justify-center ${isHigh ? 'bg-red-500/10 text-red-500 border-red-500/20' : 'bg-orange-500/10 text-orange-500 border-orange-500/20'}`}>
                      <span className="material-symbols-outlined">smart_toy</span>
                    </div>
                    <div>
                      <h3 className="text-lg font-headline font-bold text-on-surface">{ghost.agent_name}</h3>
                      <p className="text-xs text-neutral-500 font-technical">
                        {ghost.tenant_name} · {ghost.intercept_count.toLocaleString()} requests intercepted · Last seen {lastSeen}
                      </p>
                    </div>
                  </div>

                  <p className="text-sm text-neutral-400 mb-6 border-l-2 border-white/10 pl-3">
                    This agent is sending requests to <span className="text-white">{ghost.target_api}</span> without going through your security gateway.
                    {ghost.block_count > 0 && ` ${ghost.block_count} attempt${ghost.block_count !== 1 ? 's' : ''} have been blocked.`}
                  </p>

                  <div className="grid grid-cols-3 gap-3">
                    <button
                      onClick={() => applyAction(ghost.agent_id, ghost.agent_name, 'monitor')}
                      disabled={actionInProgress === ghost.agent_id + 'monitor'}
                      className="py-2.5 bg-white/5 hover:bg-white/10 border border-white/5 rounded-lg text-xs font-headline font-bold uppercase transition-colors tracking-wider flex flex-col items-center justify-center gap-1 disabled:opacity-50"
                    >
                      <span className="material-symbols-outlined text-[16px] text-neutral-400">visibility</span>
                      Monitor
                    </button>
                    <button
                      onClick={() => applyAction(ghost.agent_id, ghost.agent_name, 'block')}
                      disabled={actionInProgress === ghost.agent_id + 'block'}
                      className="py-2.5 bg-red-500 hover:bg-red-600 text-black border border-red-500/30 rounded-lg text-xs font-headline font-bold uppercase transition-colors tracking-wider shadow-[0_0_15px_rgba(239,68,68,0.3)] flex flex-col items-center justify-center gap-1 disabled:opacity-50"
                    >
                      <span className="material-symbols-outlined text-[16px]">block</span>
                      Block
                    </button>
                    <button
                      onClick={() => applyAction(ghost.agent_id, ghost.agent_name, 'rollback')}
                      disabled={actionInProgress === ghost.agent_id + 'rollback'}
                      className="py-2.5 bg-orange-500/10 hover:bg-orange-500/20 border border-orange-500/30 text-orange-500 rounded-lg text-xs font-headline font-bold uppercase transition-colors tracking-wider flex flex-col items-center justify-center gap-1 disabled:opacity-50"
                    >
                      <span className="material-symbols-outlined text-[16px]">history</span>
                      Reverse
                    </button>
                  </div>
                </div>
              );
            })}
          </div>

        </div>
      </main>
    </>
  );
}
