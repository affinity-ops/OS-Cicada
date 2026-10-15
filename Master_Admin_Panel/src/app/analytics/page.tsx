// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

'use client';

import { useState, useEffect } from 'react';

interface HeartbeatPayload {
  gateway_id: string;
  agents_registered: number;
  calls_last_window: number;
  calls_blocked_last_window: number;
}

export default function UsageAnalyticsPage() {
  const [totalAgents, setTotalAgents] = useState(0);
  const [totalIntercepts, setTotalIntercepts] = useState(0);
  const [blockRate, setBlockRate] = useState("0.0");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchAnalytics = async () => {
      try {
        const response = await fetch('/api/internal/license/list');
        const heartbeats: HeartbeatPayload[] = await response.json();
        
        let agents = 0;
        let calls = 0;
        let blocked = 0;

        heartbeats.forEach(hb => {
          agents += (hb.agents_registered || 0);
          calls += (hb.calls_last_window || 0);
          blocked += (hb.calls_blocked_last_window || 0);
        });

        setTotalAgents(agents);
        setTotalIntercepts(blocked);
        
        const rate = calls > 0 ? (blocked / calls) * 100 : 0;
        setBlockRate(rate.toFixed(1));
      } catch (error) {
        console.error('Failed to fetch analytics:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchAnalytics();
    const interval = setInterval(fetchAnalytics, 5000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="p-10 font-body">
      <div className="flex justify-between items-end mb-10">
        <div>
          <h1 className="text-3xl font-black font-headline text-white tracking-tight mb-2">Usage Analytics</h1>
          <p className="text-on-surface-muted max-w-2xl">
            Aggregated, anonymised telemetry across the global gateway fleet. Used for capacity planning and health monitoring.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-3 gap-6 mb-8">
        <div className="bg-surface/80 backdrop-blur-xl border border-border rounded-2xl p-6 shadow-xl">
          <div className="text-primary/70 text-xs font-technical uppercase tracking-widest mb-2">Total Managed Agents</div>
          <div className="text-4xl font-black text-white font-headline">
            {loading ? "..." : totalAgents.toLocaleString()}
          </div>
          <div className="text-sm text-green-400 mt-2 flex items-center gap-1">
            <span className="material-symbols-outlined text-[16px]">sensors</span>
            Live from Active Gateways
          </div>
        </div>
        <div className="bg-surface/80 backdrop-blur-xl border border-border rounded-2xl p-6 shadow-xl">
          <div className="text-primary/70 text-xs font-technical uppercase tracking-widest mb-2">Global Swarm Intercepts</div>
          <div className="text-4xl font-black text-white font-headline">
            {loading ? "..." : totalIntercepts.toLocaleString()}
          </div>
          <div className="text-sm text-on-surface-muted mt-2">Actions blocked by Verification Swarm</div>
        </div>
        <div className="bg-surface/80 backdrop-blur-xl border border-border rounded-2xl p-6 shadow-xl">
          <div className="text-primary/70 text-xs font-technical uppercase tracking-widest mb-2">Platform Block Rate</div>
          <div className="text-4xl font-black text-white font-headline">
            {loading ? "..." : `${blockRate}%`}
          </div>
          <div className="text-sm text-primary mt-2">Average across all active tenants</div>
        </div>
      </div>

      <div className="bg-surface/80 backdrop-blur-xl border border-border rounded-2xl p-8 shadow-2xl min-h-[400px] flex flex-col items-center justify-center text-on-surface-muted">
        <span className="material-symbols-outlined text-6xl mb-4 opacity-20">monitoring</span>
        <h3 className="text-lg font-bold text-white mb-2 font-headline">Detailed Time-Series Charts</h3>
        <p className="max-w-md text-center text-sm">
          A high-performance charting library (e.g., Recharts) will be integrated here to visualise gateway version fragmentation and geographic adoption over time.
        </p>
      </div>
    </div>
  );
}
