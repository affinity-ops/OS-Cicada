// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

'use client';

import { useState, useEffect } from 'react';

interface HeartbeatPayload {
  gateway_id: string;
  tenant_id?: string;
  gateway_version: string;
  uptime_seconds: number;
  agents_registered: number;
  calls_last_window: number;
  calls_blocked_last_window: number;
  tls_enabled: boolean;
  mtls_enabled: boolean;
  canary_tokens_active: number;
  quarantined_agents: number;
  redis_healthy: boolean;
  postgres_healthy: boolean;
  region?: string;
  metadata?: Record<string, string>;
  timestamp: string;
}

export default function MasterAdminDashboard() {
  const [heartbeats, setHeartbeats] = useState<HeartbeatPayload[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');

  useEffect(() => {
    const fetchHeartbeats = async () => {
      try {
        const response = await fetch('/api/internal/license/list');
        const data = await response.json();
        setHeartbeats(data || []);
      } catch (error) {
        console.error('Failed to fetch heartbeats:', error);
        setHeartbeats([]);
      } finally {
        setLoading(false);
      }
    };

    fetchHeartbeats();
    const interval = setInterval(fetchHeartbeats, 5000);
    return () => clearInterval(interval);
  }, []);

  const filteredHeartbeats = heartbeats.filter(hb => 
    (hb.tenant_id && hb.tenant_id.toLowerCase().includes(searchTerm.toLowerCase())) ||
    hb.gateway_id.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="p-10 font-body">
      <div className="flex justify-between items-end mb-10">
        <div>
          <h1 className="text-3xl font-black font-headline text-white tracking-tight mb-2">Active Telemetry</h1>
          <p className="text-on-surface-muted max-w-2xl">
            Live heartbeat data from customer gateways. This data is fully anonymised and strictly limited to metadata. No agent payloads or API keys are ever transmitted.
          </p>
        </div>
        <div className="flex items-center gap-3 bg-primary/10 text-primary border border-primary/20 px-4 py-2 rounded-xl text-sm font-bold font-technical shadow-[0_0_15px_rgba(255,159,74,0.1)]">
          <span className="relative flex h-3 w-3">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-primary/70 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-3 w-3 bg-primary shadow-[0_0_8px_rgba(255,159,74,1)]"></span>
          </span>
          Receiving Telemetry (Port 3005)
        </div>
      </div>

      <div className="bg-surface/80 backdrop-blur-xl border border-border rounded-2xl overflow-hidden shadow-2xl">
        <div className="p-6 border-b border-border flex justify-between items-center bg-surface-raised/50">
          <div className="flex items-center gap-4">
            <h2 className="text-lg font-bold font-headline text-white flex items-center gap-2">
              <span className="material-symbols-outlined text-primary drop-shadow-[0_0_8px_rgba(255,159,74,0.5)]">router</span>
              Gateway Fleet Overview
            </h2>
            <span className="px-3 py-1 bg-white/5 border border-white/10 rounded-full text-xs text-on-surface-muted font-technical">
              {filteredHeartbeats.length} Active Node{filteredHeartbeats.length !== 1 && 's'}
            </span>
          </div>
          
          <div className="relative">
            <span className="material-symbols-outlined absolute left-3 top-1/2 -translate-y-1/2 text-on-surface-muted text-sm">search</span>
            <input 
              type="text" 
              placeholder="Filter by Tenant ID or License..." 
              className="bg-black/50 border border-white/10 rounded-xl pl-9 pr-4 py-2 text-sm text-white focus:outline-none focus:border-primary w-80 transition-all font-body focus:bg-black focus:shadow-[0_0_10px_rgba(255,159,74,0.1)]"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
            />
          </div>
        </div>
        
        {loading ? (
          <div className="p-20 flex flex-col items-center justify-center text-on-surface-muted">
            <span className="material-symbols-outlined animate-spin text-4xl mb-4 text-primary">autorenew</span>
            <p className="font-body">Fetching latest telemetry...</p>
          </div>
        ) : (
          <table className="w-full text-left text-sm whitespace-nowrap">
            <thead className="bg-background/80 text-on-surface-muted border-b border-border backdrop-blur-md">
              <tr>
                <th className="px-6 py-4 font-semibold">Tenant ID</th>
                <th className="px-6 py-4 font-semibold">License Tier</th>
                <th className="px-6 py-4 font-semibold">Gateway ID</th>
                <th className="px-6 py-4 font-semibold">Version</th>
                <th className="px-6 py-4 font-semibold">Agents</th>
                <th className="px-6 py-4 font-semibold">Last Heartbeat</th>
                <th className="px-6 py-4 font-semibold text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {filteredHeartbeats.length === 0 ? (
                <tr>
                  <td colSpan={7} className="p-12 text-center text-on-surface-muted">
                    <span className="material-symbols-outlined text-4xl mb-3 block opacity-30 text-primary drop-shadow-[0_0_8px_rgba(255,159,74,0.3)]">satellite_alt</span>
                    <span className="font-body">No active gateways streaming telemetry. Start the fleet to view data.</span>
                  </td>
                </tr>
              ) : (
                filteredHeartbeats.map((hb, i) => {
                  const isRecent = (new Date().getTime() - new Date(hb.timestamp).getTime()) < 300000; // 5 mins
                  return (
                    <tr key={i} className="hover:bg-white/5 transition-colors group">
                      <td className="px-6 py-4">
                        <div className="font-bold text-white flex items-center gap-2">
                          <span className="material-symbols-outlined text-on-surface-muted text-sm group-hover:text-primary transition-colors">domain</span>
                          <span className="font-technical">{hb.tenant_id || 'UNKNOWN'}</span>
                        </div>
                      </td>
                      <td className="px-6 py-4">
                        <span className="px-2 py-1 bg-black border border-border rounded text-xs font-technical text-on-surface-muted group-hover:border-primary/30 transition-colors">
                          {hb.metadata?.license_tier || 'N/A'}
                        </span>
                      </td>
                      <td className="px-6 py-4 text-on-surface-muted font-technical text-xs">{hb.gateway_id}</td>
                      <td className="px-6 py-4">
                        <span className="px-2 py-1 bg-primary/10 text-primary rounded-full text-xs font-bold border border-primary/20 font-technical shadow-sm">
                          v{hb.gateway_version}
                        </span>
                      </td>
                      <td className="px-6 py-4 text-gray-300 font-technical">{hb.agents_registered || 0} deployed</td>
                      <td className="px-6 py-4 font-technical">
                        <span className={`flex items-center gap-2 ${isRecent ? 'text-green-400 drop-shadow-[0_0_5px_rgba(74,222,128,0.5)]' : 'text-on-surface-muted'}`}>
                          <span className={`w-2 h-2 rounded-full ${isRecent ? 'bg-green-500 shadow-[0_0_5px_rgba(74,222,128,1)]' : 'bg-gray-600'}`}></span>
                          {new Date(hb.timestamp).toLocaleTimeString()}
                        </span>
                      </td>
                      <td className="px-6 py-4 text-right">
                        <button className="text-on-surface-muted hover:text-primary transition-colors opacity-0 group-hover:opacity-100 drop-shadow-[0_0_5px_rgba(255,159,74,0.3)]">
                          <span className="material-symbols-outlined text-lg">more_vert</span>
                        </button>
                      </td>
                    </tr>
                  )
                })
              )}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
