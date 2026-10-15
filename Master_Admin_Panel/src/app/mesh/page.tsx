// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

'use client';

import { useState, useEffect } from 'react';

interface MeshNode {
  node_id: string;
  tenant_id: string;
  endpoint: string;
  ed25519_pub: string;
  ml_dsa65_pub?: string;
  license_tier: string;
  version: string;
  region?: string;
  registered_at: string;
  last_seen_at: string;
  mesh_enabled: boolean;
}

interface MeshHealth {
  status: string;
  registered_nodes: number;
  intel_buffer: number;
}

export default function MeshTopologyPage() {
  const [nodes, setNodes] = useState<MeshNode[]>([]);
  const [health, setHealth] = useState<MeshHealth | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchMeshData = async () => {
      try {
        const [peersRes, healthRes] = await Promise.all([
          fetch('/api/v1/mesh/peers'),
          fetch('/api/v1/mesh/health'),
        ]);
        
        if (peersRes.ok) {
          const peersData = await peersRes.json();
          setNodes(peersData.peers || []);
        }
        if (healthRes.ok) {
          const healthData = await healthRes.json();
          setHealth(healthData);
        }
      } catch (error) {
        console.error('Failed to fetch mesh data:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchMeshData();
    const interval = setInterval(fetchMeshData, 10000);
    return () => clearInterval(interval);
  }, []);

  const isNodeActive = (lastSeen: string) => {
    const diff = Date.now() - new Date(lastSeen).getTime();
    return diff < 300000; // 5 minutes
  };

  return (
    <div className="p-10 font-body">
      <div className="flex justify-between items-end mb-10">
        <div>
          <h1 className="text-3xl font-black font-headline text-white tracking-tight mb-2">Mesh Topology</h1>
          <p className="text-on-surface-muted max-w-2xl">
            Live view of the P2P gossip mesh. All data shown is anonymous metadata — no customer operational data is disclosed.
          </p>
        </div>
        {health && (
          <div className="flex items-center gap-6">
            <div className="text-center">
              <div className="text-2xl font-black font-headline text-primary">{health.registered_nodes}</div>
              <div className="text-[10px] text-on-surface-muted font-technical uppercase tracking-widest">Nodes</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-black font-headline text-green-400">{health.intel_buffer}</div>
              <div className="text-[10px] text-on-surface-muted font-technical uppercase tracking-widest">Signals</div>
            </div>
            <div className={`flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-bold font-technical border ${
              health.status === 'healthy' 
                ? 'bg-green-500/10 text-green-400 border-green-500/20 shadow-[0_0_15px_rgba(74,222,128,0.1)]' 
                : 'bg-red-500/10 text-red-400 border-red-500/20'
            }`}>
              <span className="relative flex h-3 w-3">
                <span className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${health.status === 'healthy' ? 'bg-green-500/70' : 'bg-red-500/70'}`}></span>
                <span className={`relative inline-flex rounded-full h-3 w-3 ${health.status === 'healthy' ? 'bg-green-500 shadow-[0_0_8px_rgba(74,222,128,1)]' : 'bg-red-500'}`}></span>
              </span>
              {health.status === 'healthy' ? 'Mesh Healthy' : 'Mesh Degraded'}
            </div>
          </div>
        )}
      </div>

      {/* Data Sovereignty Notice */}
      <div className="flex items-center gap-3 bg-blue-500/5 border border-blue-500/20 rounded-xl px-5 py-3 mb-8">
        <span className="material-symbols-outlined text-blue-400">verified_user</span>
        <div className="text-sm text-blue-300/80">
          <strong>Data Sovereignty:</strong> This view shows anonymous metadata only — node IDs, uptime, and health status. 
          No customer agent data, payloads, or operational state is transmitted or displayed.
        </div>
      </div>

      {/* Node Grid */}
      <div className="bg-surface/80 backdrop-blur-xl border border-border rounded-2xl overflow-hidden shadow-2xl">
        <div className="p-6 border-b border-border bg-surface-raised/50">
          <h2 className="text-lg font-bold font-headline text-white flex items-center gap-2">
            <span className="material-symbols-outlined text-primary drop-shadow-[0_0_8px_rgba(255,159,74,0.5)]">hub</span>
            Registered Mesh Nodes
          </h2>
        </div>

        {loading ? (
          <div className="p-20 flex flex-col items-center justify-center text-on-surface-muted">
            <span className="material-symbols-outlined animate-spin text-4xl mb-4 text-primary">autorenew</span>
            <p className="font-body">Querying mesh directory...</p>
          </div>
        ) : nodes.length === 0 ? (
          <div className="p-20 flex flex-col items-center justify-center text-on-surface-muted">
            <span className="material-symbols-outlined text-4xl mb-3 opacity-30 text-primary">satellite_alt</span>
            <p className="font-body">No nodes registered in the mesh. Gateways will appear here once they enroll.</p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 p-6">
            {nodes.map((node) => {
              const active = isNodeActive(node.last_seen_at);
              const hasPQC = !!node.ml_dsa65_pub;
              return (
                <div key={node.node_id} className="bg-background/50 border border-white/5 rounded-xl p-5 hover:border-primary/30 transition-all group">
                  <div className="flex items-center justify-between mb-4">
                    <div className="flex items-center gap-2">
                      <span className={`w-2.5 h-2.5 rounded-full ${active ? 'bg-green-500 shadow-[0_0_5px_rgba(74,222,128,1)]' : 'bg-gray-600'}`}></span>
                      <span className="text-sm font-bold text-white font-technical">{node.node_id}</span>
                    </div>
                    <span className="px-2 py-0.5 bg-primary/10 text-primary rounded-full text-[10px] font-bold border border-primary/20 font-technical">
                      v{node.version || '?'}
                    </span>
                  </div>
                  
                  <div className="space-y-2 text-xs text-on-surface-muted font-technical">
                    <div className="flex justify-between">
                      <span>Tenant</span>
                      <span className="text-white/70">{node.tenant_id}</span>
                    </div>
                    <div className="flex justify-between">
                      <span>Region</span>
                      <span className="text-white/70">{node.region || 'Unset'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span>Tier</span>
                      <span className="text-white/70">{node.license_tier || 'Unknown'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span>Auth</span>
                      <span className={hasPQC ? 'text-green-400' : 'text-yellow-400'}>
                        {hasPQC ? 'Ed25519 + ML-DSA-65' : 'Ed25519 only'}
                      </span>
                    </div>
                  </div>

                  <div className="mt-4 pt-3 border-t border-white/5 flex justify-between items-center text-[10px] font-technical text-on-surface-muted">
                    <span>Last seen: {new Date(node.last_seen_at).toLocaleTimeString()}</span>
                    <span className={active ? 'text-green-400' : 'text-red-400'}>{active ? 'ACTIVE' : 'STALE'}</span>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
