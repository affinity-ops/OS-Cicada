// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import { useToast } from './ToastContext';

export type CreatorAgent = {
  id: string;
  name: string;
  evarToken: string;
  firstSeen: string;
  lastSeen: string;
  status: 'Active' | 'Suspended' | 'Revoked' | 'Expired';
  revocationReason?: string;
  trustScore: number;
  certificationLevel: string;
  declaredScopes: string[];
  approvedScopes: string[];
  deniedScopes: string[];
  spendLimits: string;
  rollback: string;
  totalActions: number;
  allowedActions: number;
  blockedActions: number;
  anomalies: string[];
  sandboxStatus: string;
  falsePositiveRate: string;
};

export type CreatorAccount = {
  id: string;
  name: string;
  email: string;
  ownerName: string;
  globalTrustScore: number;
  agents: CreatorAgent[];
};

interface PanelProps {
  isOpen: boolean;
  onClose: () => void;
  creator: CreatorAccount | null;
  initialAgentId?: string | null;
}

export const CreatorDetailPanel: React.FC<PanelProps> = ({ isOpen, onClose, creator, initialAgentId }) => {
  const [activeTab, setActiveTab] = useState<'overview' | 'scopes' | 'physics' | 'ledger'>('overview');
  const [selectedAgentId, setSelectedAgentId] = useState<string | null>(initialAgentId || creator?.agents[0]?.id || null);
  const { showToast } = useToast();

  // Sync state if initialAgentId or creator changes
  React.useEffect(() => {
    if (creator) {
      setSelectedAgentId(initialAgentId || creator.agents[0]?.id || null);
    }
  }, [creator, initialAgentId]);

  if (!isOpen || !creator) return null;

  // Sync state if creator changes
  const activeAgent = creator.agents.find(a => a.id === selectedAgentId) || creator.agents[0];

  return (
    <>
      {/* Backdrop overlay */}
      <div 
        className={`fixed inset-0 bg-black/60 backdrop-blur-sm z-50 transition-opacity duration-300 ${isOpen ? 'opacity-100' : 'opacity-0 pointer-events-none'}`} 
        onClick={onClose}
      ></div>

      {/* Sliding CRM Panel */}
      <div className={`fixed top-0 right-0 h-full w-[65rem] bg-[#0a0a0a] border-l border-white/5 shadow-[-20px_0_100px_rgba(0,0,0,0.8)] z-[60] flex flex-col transform transition-transform duration-500 ease-in-out ${isOpen ? 'translate-x-0' : 'translate-x-full'}`}>
        
        {/* Header: The Master Account Record */}
        <header className="px-10 py-8 border-b border-white/5 bg-[#131313] flex-shrink-0 relative overflow-hidden">
          <div className="absolute top-0 right-0 w-64 h-64 bg-orange-500/5 blur-3xl rounded-full translate-x-1/2 -translate-y-1/2 pointer-events-none"></div>
          
          <button onClick={onClose} className="absolute top-6 right-8 w-10 h-10 bg-black rounded-full border border-white/10 flex items-center justify-center text-neutral-400 hover:text-white hover:bg-neutral-900 transition-colors z-10">
            <span className="material-symbols-outlined">close</span>
          </button>

          <div className="flex items-start gap-6">
            <div className="w-20 h-20 rounded-2xl bg-gradient-to-br from-neutral-800 to-neutral-950 border border-white/10 flex items-center justify-center shadow-2xl relative z-10">
               <span className="material-symbols-outlined text-4xl text-orange-500">domain</span>
            </div>
            <div className="relative z-10">
              <div className="flex items-center gap-3 mb-1">
                <span className="px-2.5 py-1 bg-orange-500/10 border border-orange-500/20 rounded text-[10px] uppercase tracking-widest font-bold text-orange-500 font-headline">Verified Builder Org</span>
                <span className="font-technical text-xs tracking-widest text-neutral-500">ORG-{creator.id}</span>
              </div>
              <h2 className="text-4xl font-black font-headline tracking-tighter text-on-surface">{creator.name}</h2>
              <div className="flex gap-6 mt-3 font-body text-sm text-neutral-400">
                <p className="flex items-center gap-2"><span className="material-symbols-outlined text-[16px]">mail</span> {creator.email}</p>
                <p className="flex items-center gap-2"><span className="material-symbols-outlined text-[16px]">shield_person</span> {creator.ownerName} (Gov Lead)</p>
                <div className="flex items-center gap-2 px-3 py-0.5 bg-secondary/10 border border-secondary/20 rounded-full">
                  <span className="w-2 h-2 rounded-full bg-secondary"></span>
                  <span className="text-secondary font-bold text-[10px] uppercase tracking-wider">Account Trust: {creator.globalTrustScore}%</span>
                </div>
              </div>
            </div>
          </div>
        </header>

        {/* Content Body: Two Columns */}
        <div className="flex-1 flex overflow-hidden">
          
          {/* Left Column: Subsets (Agents) */}
          <div className="w-80 border-r border-white/5 bg-[#0f0f0f] flex flex-col">
            <div className="px-6 py-4 border-b border-white/5 flex justify-between items-center bg-[#131313]">
              <h3 className="font-headline font-bold text-xs uppercase tracking-widest text-neutral-400">Deployed Agents ({creator.agents.length})</h3>
              <button onClick={() => showToast("Initializing EVAR Generation Sandbox...")} className="w-6 h-6 rounded bg-orange-500/10 text-orange-500 flex items-center justify-center hover:bg-orange-500 hover:text-black transition-colors"><span className="material-symbols-outlined text-[14px]">add</span></button>
            </div>
            
            <div className="overflow-y-auto flex-1 p-4 space-y-3">
              {creator.agents.map(agent => (
                <button 
                  key={agent.id}
                  onClick={() => setSelectedAgentId(agent.id)}
                  className={`w-full text-left px-5 py-4 rounded-xl border transition-all ${activeAgent?.id === agent.id ? 'bg-[#1a1a1a] border-orange-500/50 shadow-[inset_4px_0_0_#ff8a00]' : 'bg-[#131313] border-white/5 hover:border-white/20'}`}
                >
                  <div className="flex justify-between items-start mb-2">
                    <p className={`font-headline font-bold truncate ${activeAgent?.id === agent.id ? 'text-orange-400' : 'text-on-surface'}`}>{agent.name}</p>
                    <div className={`w-2 h-2 rounded-full mt-1.5 flex-shrink-0 ${agent.status === 'Active' ? 'bg-emerald-500' : 'bg-error'}`}></div>
                  </div>
                  <div className="flex justify-between items-end">
                    <p className="font-technical text-[10px] text-neutral-500 truncate">{agent.id}</p>
                    <p className="font-technical text-xs font-bold text-neutral-300">{agent.trustScore}% <span className="text-[9px] text-neutral-600">TRST</span></p>
                  </div>
                </button>
              ))}
            </div>
          </div>

          {/* Right Column: Subset Details (The 7 CRM Buckets) */}
          <div className="flex-1 flex flex-col bg-black">
            {activeAgent ? (
              <>
                {/* Detail Header & Tabs */}
                <div className="px-8 pt-8 border-b border-white/5 bg-[#111111]">
                  <div className="flex justify-between items-start mb-6">
                    <div>
                      <div className="flex items-center gap-3 mb-2">
                        <h2 className="text-2xl font-black font-headline text-on-surface uppercase">{activeAgent.name}</h2>
                        {activeAgent.status === 'Active' ? (
                          <span className="px-2 py-1 bg-emerald-500/10 text-emerald-500 border border-emerald-500/30 rounded text-[10px] font-bold uppercase tracking-widest animate-pulse">Live</span>
                        ) : (
                          <span className="px-2 py-1 bg-error/10 text-error border border-error/30 rounded text-[10px] font-bold uppercase tracking-widest">Revoked</span>
                        )}
                      </div>
                      <p className="font-technical text-xs text-orange-500/80 mb-1">EVAR: {activeAgent.evarToken}</p>
                      <p className="font-technical text-[10px] text-neutral-500">First Seen: {activeAgent.firstSeen} &mdash; Last Active: {activeAgent.lastSeen}</p>
                    </div>
                    
                    <div className="flex gap-2">
                      <Link href={`/logs?trace=${activeAgent.id}`} className="px-4 py-2 flex items-center bg-[#262626] border border-white/10 hover:border-white/30 rounded-lg text-xs font-headline font-bold uppercase text-white transition-all">Audit Logs</Link>
                      <button onClick={() => showToast("GLOBAL PURGE EXECUTED: All EVAR connections for this agent instantly severed via SSE.")} className="px-4 py-2 bg-error/10 border border-error/30 hover:bg-error/20 rounded-lg text-xs font-headline font-bold uppercase text-error transition-all">Kill Switch</button>
                    </div>
                  </div>

                  <div className="flex gap-6 font-headline font-bold text-xs uppercase tracking-widest">
                    <button onClick={() => setActiveTab('overview')} className={`pb-4 border-b-2 transition-all ${activeTab === 'overview' ? 'border-orange-500 text-orange-500' : 'border-transparent text-neutral-500 hover:text-neutral-300'}`}>Identity &amp; Govt</button>
                    <button onClick={() => setActiveTab('scopes')} className={`pb-4 border-b-2 transition-all ${activeTab === 'scopes' ? 'border-orange-500 text-orange-500' : 'border-transparent text-neutral-500 hover:text-neutral-300'}`}>Scopes &amp; Limits</button>
                    <button onClick={() => setActiveTab('physics')} className={`pb-4 border-b-2 transition-all ${activeTab === 'physics' ? 'border-orange-500 text-orange-500' : 'border-transparent text-neutral-500 hover:text-neutral-300'}`}>Physics &amp; Shadow QA</button>
                    <button onClick={() => setActiveTab('ledger')} className={`pb-4 border-b-2 transition-all ${activeTab === 'ledger' ? 'border-orange-500 text-orange-500' : 'border-transparent text-neutral-500 hover:text-neutral-300'}`}>Activity Ledger</button>
                  </div>
                </div>

                {/* Tab Containers */}
                <div className="p-8 overflow-y-auto flex-1">
                  
                  {activeTab === 'overview' && (
                    <div className="space-y-8 animate-in fade-in slide-in-from-bottom-2">
                      <div className="grid grid-cols-2 gap-6">
                        <div className="bg-[#131313] p-5 rounded-2xl border border-white/5">
                          <p className="text-[10px] text-neutral-500 font-bold uppercase tracking-widest mb-1">Tier Classification</p>
                          <p className="text-lg font-bold text-on-surface">{activeAgent.certificationLevel}</p>
                        </div>
                        <div className="bg-[#131313] p-5 rounded-2xl border border-white/5">
                          <p className="text-[10px] text-neutral-500 font-bold uppercase tracking-widest mb-1">Revocation Status</p>
                          <p className={`text-lg font-bold ${activeAgent.status === 'Active' ? 'text-emerald-500' : 'text-error'}`}>{activeAgent.status}</p>
                          {activeAgent.revocationReason && <p className="text-xs text-neutral-400 mt-2 font-technical bg-black p-2 rounded border border-white/5">{activeAgent.revocationReason}</p>}
                        </div>
                      </div>
                    </div>
                  )}

                  {activeTab === 'scopes' && (
                    <div className="space-y-8 animate-in fade-in slide-in-from-bottom-2">
                      <div className="grid grid-cols-2 gap-8">
                        <div>
                          <div className="flex items-center gap-2 mb-4">
                            <span className="material-symbols-outlined text-emerald-500">check_circle</span>
                            <h3 className="font-headline font-bold text-on-surface">Approved Scopes</h3>
                          </div>
                          <div className="space-y-2">
                            {activeAgent.approvedScopes.map(s => <div key={s} className="px-3 py-2 bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 font-technical text-xs rounded">{s}</div>)}
                          </div>
                        </div>
                        <div>
                          <div className="flex items-center gap-2 mb-4">
                            <span className="material-symbols-outlined text-error">block</span>
                            <h3 className="font-headline font-bold text-on-surface">Denied Scopes</h3>
                          </div>
                          <div className="space-y-2">
                            {activeAgent.deniedScopes.map(s => <div key={s} className="px-3 py-2 bg-error/10 border border-error/20 text-error font-technical text-xs rounded">{s}</div>)}
                          </div>
                        </div>
                      </div>
                      <div className="bg-[#131313] p-5 rounded-2xl border border-white/5">
                         <h3 className="font-headline font-bold text-sm mb-4 border-b border-white/5 pb-2">Financial &amp; Recovery Limits</h3>
                         <div className="grid grid-cols-2 gap-4">
                           <div>
                             <p className="text-[10px] text-neutral-500 font-bold uppercase tracking-widest mb-1">Spend Limits (Rego Policy)</p>
                             <p className="font-technical text-orange-400 bg-orange-500/10 px-2 py-1 rounded inline-block">{activeAgent.spendLimits}</p>
                           </div>
                           <div>
                             <p className="text-[10px] text-neutral-500 font-bold uppercase tracking-widest mb-1">Rollback Contract Endpoint</p>
                             <p className="font-technical text-secondary bg-secondary/10 px-2 py-1 rounded inline-block">{activeAgent.rollback}</p>
                           </div>
                         </div>
                      </div>
                    </div>
                  )}

                  {activeTab === 'physics' && (
                    <div className="space-y-8 animate-in fade-in slide-in-from-bottom-2">
                      <div className="flex gap-6">
                        <div className="flex-1 bg-[#131313] p-6 rounded-2xl border border-white/5 flex flex-col justify-center items-center">
                          <div className="w-32 h-32 rounded-full border-[8px] border-[#262626] flex items-center justify-center relative">
                            <svg className="absolute inset-0 w-full h-full -rotate-90">
                              <circle cx="50%" cy="50%" r="46%" fill="transparent" stroke="#ff8a00" strokeWidth="8" strokeDasharray="300" strokeDashoffset={300 - (300 * activeAgent.trustScore / 100)} className="transition-all duration-1000 ease-out"></circle>
                            </svg>
                            <span className="text-3xl font-black font-technical text-on-surface mt-1">{activeAgent.trustScore}</span>
                          </div>
                          <p className="mt-4 font-headline uppercase font-bold text-xs tracking-widest text-neutral-400">Mesh Trust Score</p>
                        </div>
                        <div className="flex-1 bg-[#131313] p-6 rounded-2xl border border-white/5 border-l-4 border-l-secondary flex flex-col justify-center">
                           <h3 className="font-headline font-bold text-sm mb-4">Shadow QA Results</h3>
                           <p className="text-[10px] text-neutral-500 font-bold uppercase tracking-widest mb-1">Current State</p>
                           <p className="text-secondary font-bold mb-4">{activeAgent.sandboxStatus}</p>
                           <p className="text-[10px] text-neutral-500 font-bold uppercase tracking-widest mb-1">False Positive Offset</p>
                           <p className="text-on-surface font-technical text-lg">{activeAgent.falsePositiveRate}</p>
                        </div>
                      </div>
                    </div>
                  )}

                  {activeTab === 'ledger' && (
                    <div className="space-y-6 animate-in fade-in slide-in-from-bottom-2">
                       <div className="grid grid-cols-3 gap-4">
                         <div className="bg-[#131313] p-4 rounded-xl border border-white/5 text-center">
                           <p className="text-3xl font-black font-technical text-on-surface tracking-tighter">{activeAgent.totalActions.toLocaleString()}</p>
                           <p className="text-[10px] text-neutral-500 font-bold uppercase tracking-widest mt-1">Total Intercepts</p>
                         </div>
                         <div className="bg-emerald-500/5 p-4 rounded-xl border border-emerald-500/20 text-center">
                           <p className="text-3xl font-black font-technical text-emerald-500 tracking-tighter">{activeAgent.allowedActions.toLocaleString()}</p>
                           <p className="text-[10px] text-emerald-500/70 font-bold uppercase tracking-widest mt-1">Proxied Access</p>
                         </div>
                         <div className="bg-error/5 p-4 rounded-xl border border-error/20 text-center">
                           <p className="text-3xl font-black font-technical text-error tracking-tighter">{activeAgent.blockedActions.toLocaleString()}</p>
                           <p className="text-[10px] text-error/70 font-bold uppercase tracking-widest mt-1">Sentry Denials</p>
                         </div>
                       </div>
                       
                       <div className="bg-[#131313] p-6 rounded-2xl border border-white/5">
                         <h3 className="font-headline font-bold text-sm mb-4 flex items-center gap-2"><span className="material-symbols-outlined text-orange-500 text-[18px]">warning</span> Anomaly Alerts</h3>
                         <ul className="space-y-3">
                           {activeAgent.anomalies.map((a, i) => (
                             <li key={i} className="px-4 py-3 bg-black rounded border border-white/5 flex gap-3 text-sm font-technical text-neutral-300">
                               <span className="text-orange-500">&gt;_</span> {a}
                             </li>
                           ))}
                         </ul>
                       </div>
                    </div>
                  )}
                  
                </div>
              </>
            ) : (
              <div className="flex-1 flex flex-col items-center justify-center text-neutral-600">
                <span className="material-symbols-outlined text-6xl mb-4 opacity-20">hub</span>
                <p className="font-headline font-bold uppercase tracking-widest">No Active Subset Selected</p>
              </div>
            )}
          </div>

        </div>
      </div>
    </>
  );
};
