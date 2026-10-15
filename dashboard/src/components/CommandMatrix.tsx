// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

'use client';

import React, { useEffect, useState, useRef, useMemo, useCallback } from 'react';
import dynamic from 'next/dynamic';

const Globe = dynamic(() => import('react-globe.gl'), { 
  ssr: false,
  loading: () => (
    <div className="absolute inset-0 bg-black flex items-center justify-center font-technical text-white/50 text-[10px] tracking-[0.3em] uppercase animate-pulse">
      Initializing Sentry Mesh Topology...
    </div>
  )
});

// ── Extended Geo-Coding ─────────────────────────────────────────────────────
// Covers 30+ countries to handle any tenant geography.
// Coordinates are capital/major-city level — sufficient for a command overview.
const GEO_MAP: Record<string, { lat: number; lng: number; city: string }> = {
  // North America
  'US':              { lat: 39.83,  lng: -98.58,  city: 'Central US' },
  'USA':             { lat: 39.83,  lng: -98.58,  city: 'Central US' },
  'United States':   { lat: 39.83,  lng: -98.58,  city: 'Central US' },
  'CA':              { lat: 45.42,  lng: -75.70,  city: 'Ottawa' },
  'Canada':          { lat: 45.42,  lng: -75.70,  city: 'Ottawa' },

  // Europe
  'UK':              { lat: 51.51,  lng: -0.13,   city: 'London' },
  'United Kingdom':  { lat: 51.51,  lng: -0.13,   city: 'London' },
  'GB':              { lat: 51.51,  lng: -0.13,   city: 'London' },
  'DE':              { lat: 50.11,  lng: 8.68,    city: 'Frankfurt' },
  'Germany':         { lat: 50.11,  lng: 8.68,    city: 'Frankfurt' },
  'FR':              { lat: 48.86,  lng: 2.35,    city: 'Paris' },
  'France':          { lat: 48.86,  lng: 2.35,    city: 'Paris' },
  'IE':              { lat: 53.35,  lng: -6.26,   city: 'Dublin' },
  'Ireland':         { lat: 53.35,  lng: -6.26,   city: 'Dublin' },
  'CH':              { lat: 47.37,  lng: 8.54,    city: 'Zürich' },
  'Switzerland':     { lat: 47.37,  lng: 8.54,    city: 'Zürich' },
  'NL':              { lat: 52.37,  lng: 4.90,    city: 'Amsterdam' },
  'Netherlands':     { lat: 52.37,  lng: 4.90,    city: 'Amsterdam' },
  'SE':              { lat: 59.33,  lng: 18.07,   city: 'Stockholm' },
  'Sweden':          { lat: 59.33,  lng: 18.07,   city: 'Stockholm' },
  'ES':              { lat: 40.42,  lng: -3.70,   city: 'Madrid' },
  'Spain':           { lat: 40.42,  lng: -3.70,   city: 'Madrid' },
  'IT':              { lat: 41.90,  lng: 12.50,   city: 'Rome' },
  'Italy':           { lat: 41.90,  lng: 12.50,   city: 'Rome' },
  'NO':              { lat: 59.91,  lng: 10.75,   city: 'Oslo' },
  'Norway':          { lat: 59.91,  lng: 10.75,   city: 'Oslo' },

  // Asia-Pacific
  'JP':              { lat: 35.68,  lng: 139.65,  city: 'Tokyo' },
  'Japan':           { lat: 35.68,  lng: 139.65,  city: 'Tokyo' },
  'AU':              { lat: -33.87, lng: 151.21,  city: 'Sydney' },
  'Australia':       { lat: -33.87, lng: 151.21,  city: 'Sydney' },
  'SG':              { lat: 1.35,   lng: 103.82,  city: 'Singapore' },
  'Singapore':       { lat: 1.35,   lng: 103.82,  city: 'Singapore' },
  'IN':              { lat: 28.61,  lng: 77.21,   city: 'New Delhi' },
  'India':           { lat: 28.61,  lng: 77.21,   city: 'New Delhi' },
  'KR':              { lat: 37.57,  lng: 126.98,  city: 'Seoul' },
  'South Korea':     { lat: 37.57,  lng: 126.98,  city: 'Seoul' },

  // Middle East
  'AE':              { lat: 25.20,  lng: 55.27,   city: 'Dubai' },
  'UAE':             { lat: 25.20,  lng: 55.27,   city: 'Dubai' },
  'IL':              { lat: 32.07,  lng: 34.78,   city: 'Tel Aviv' },
  'Israel':          { lat: 32.07,  lng: 34.78,   city: 'Tel Aviv' },

  // South America
  'BR':              { lat: -23.55, lng: -46.63,  city: 'São Paulo' },
  'Brazil':          { lat: -23.55, lng: -46.63,  city: 'São Paulo' },
};

// AWS/GCP region prefixes → approximate country
const REGION_COUNTRY_MAP: Record<string, string> = {
  'us-east':    'US', 'us-west':    'US', 'us-gov':     'US',
  'eu-west-1':  'IE', 'eu-west-2':  'UK', 'eu-west-3':  'FR',
  'eu-central': 'DE', 'eu-north':   'SE', 'eu-south':   'IT',
  'ap-northeast-1': 'JP', 'ap-northeast-2': 'KR',
  'ap-southeast-1': 'SG', 'ap-southeast-2': 'AU',
  'ap-south':   'IN',
  'ca-central': 'CA',
  'sa-east':    'BR',
  'me-south':   'AE',
  'ch-zrh':     'CH',
};

function resolveCoords(gw: any): { lat: number; lng: number; city: string } | null {
  // Try direct country lookup first
  if (gw.country && GEO_MAP[gw.country]) {
    return GEO_MAP[gw.country];
  }
  // Try region→country mapping
  if (gw.region) {
    for (const [prefix, country] of Object.entries(REGION_COUNTRY_MAP)) {
      if (gw.region.startsWith(prefix)) {
        return GEO_MAP[country] || null;
      }
    }
  }
  return null;
}

// ── Status colours ──────────────────────────────────────────────────────────
function statusColor(status: string): string {
  if (status === 'online')   return '#00e572';
  if (status === 'degraded') return '#ff9f4a';
  return '#ff2a2a';
}

function statusGlow(status: string): string {
  if (status === 'online')   return 'rgba(0, 229, 114, 0.4)';
  if (status === 'degraded') return 'rgba(255, 159, 74, 0.4)';
  return 'rgba(255, 42, 42, 0.4)';
}

// ── Component ───────────────────────────────────────────────────────────────
export const CommandMatrix = ({ gateways = [] }: { gateways?: any[] }) => {
  const globeEl = useRef<any>(null);
  const [dimensions, setDimensions] = useState({ width: 1200, height: 800 });
  const [activeNode, setActiveNode] = useState<any | null>(null);

  useEffect(() => {
    const container = document.getElementById('globe-container');
    if (!container) return;

    let initialTimer: NodeJS.Timeout;
    
    // Initial measurement
    const updateDimensions = () => {
       if (container.offsetWidth && container.offsetHeight) {
           setDimensions({ width: container.offsetWidth, height: container.offsetHeight });
       }
    };
    updateDimensions();
    
    // Setup ResizeObserver for reliable dimension tracking
    const resizeObserver = new ResizeObserver(() => {
        updateDimensions();
    });
    
    resizeObserver.observe(container);
    
    // Also try checking again an instant later after layout paints
    initialTimer = setTimeout(updateDimensions, 100);

    // Configure controls once the dynamically imported globe is ready
    const timer = setInterval(() => {
      if (globeEl.current && globeEl.current.controls) {
        const controls = globeEl.current.controls();
        if (controls) {
          controls.autoRotate = true;
          controls.autoRotateSpeed = 0.4;
          controls.enableZoom = true;
          controls.minDistance = 200;
          controls.maxDistance = 600;
          globeEl.current.pointOfView({ altitude: 2.0 });
          clearInterval(timer);
        }
      }
    }, 200);

    return () => {
      resizeObserver.disconnect();
      clearInterval(timer);
      clearTimeout(initialTimer);
    };
  }, []);

  // ── Build node data from gateway array ──────────────────────────────────
  const nodes = useMemo(() => {
    return gateways.map(gw => {
      const coords = resolveCoords(gw);
      if (!coords) return null;

      // Jitter nodes slightly so multiple gateways in the same country don't stack
      const jitter = () => (Math.random() - 0.5) * 2;

      return {
        id: gw.id,
        gatewayId: gw.gateway_id,
        tenantId: gw.tenant_id,
        name: gw.company_name || 'Autonomous Sentry',
        status: gw.live_status,
        agents: gw.agents_registered,
        calls: gw.calls_last_window,
        blocked: gw.calls_blocked_last_window,
        country: gw.country || 'Unknown',
        city: coords.city,
        region: gw.region || '—',
        ip: gw.ip_address || '—',
        version: gw.gateway_version || '—',
        tls: gw.tls_enabled,
        mtls: gw.mtls_enabled,
        canary: gw.canary_tokens_active || 0,
        quarantined: gw.quarantined_agents || 0,
        lastSeen: gw.last_seen_at,
        firstSeen: gw.first_registered_at,
        lat: coords.lat + jitter(),
        lng: coords.lng + jitter(),
        color: statusColor(gw.live_status),
        size: Math.max(0.6, Math.min(2.0, (gw.agents_registered || 1) / 8)),
      };
    }).filter(Boolean) as any[];
  }, [gateways]);

  // ── Build mesh arcs between gateways owned by the same tenant ──────────
  const arcs = useMemo(() => {
    if (nodes.length < 2) return [];
    
    const result: any[] = [];
    
    // Group by company name to create mesh connections
    const byCompany: Record<string, any[]> = {};
    for (const n of nodes) {
      if (!byCompany[n.name]) byCompany[n.name] = [];
      byCompany[n.name].push(n);
    }

    // Intra-company arcs (same tenant, different regions) — bright
    for (const companyNodes of Object.values(byCompany)) {
      for (let i = 0; i < companyNodes.length; i++) {
        for (let j = i + 1; j < companyNodes.length; j++) {
          result.push({
            startLat: companyNodes[i].lat,
            startLng: companyNodes[i].lng,
            endLat: companyNodes[j].lat,
            endLng: companyNodes[j].lng,
            color: ['rgba(255, 138, 0, 0.6)', 'rgba(255, 138, 0, 0.05)'],
            stroke: 0.5,
            dashLength: 0.6,
            dashGap: 0.3,
            dashAnimateTime: 3000,
          });
        }
      }
    }

    // Cross-tenant gossip mesh arcs — faint, showing the federated network
    const onlineNodes = nodes.filter(n => n.status === 'online');
    for (let i = 0; i < onlineNodes.length; i++) {
      // Connect each node to its 2 nearest neighbours
      const sorted = [...onlineNodes]
        .filter((_, j) => j !== i)
        .sort((a, b) => {
          const distA = Math.hypot(a.lat - onlineNodes[i].lat, a.lng - onlineNodes[i].lng);
          const distB = Math.hypot(b.lat - onlineNodes[i].lat, b.lng - onlineNodes[i].lng);
          return distA - distB;
        })
        .slice(0, 2);

      for (const neighbour of sorted) {
        // Avoid duplicate arcs
        const exists = result.some(r =>
          (r.startLat === onlineNodes[i].lat && r.endLat === neighbour.lat) ||
          (r.startLat === neighbour.lat && r.endLat === onlineNodes[i].lat)
        );
        if (!exists) {
          result.push({
            startLat: onlineNodes[i].lat,
            startLng: onlineNodes[i].lng,
            endLat: neighbour.lat,
            endLng: neighbour.lng,
            color: ['rgba(255, 255, 255, 0.07)', 'rgba(255, 255, 255, 0.02)'],
            stroke: 0.2,
            dashLength: 0.4,
            dashGap: 0.6,
            dashAnimateTime: 6000,
          });
        }
      }
    }

    return result;
  }, [nodes]);

  // ── Zoom to node on click ─────────────────────────────────────────────── 
  const handleNodeClick = useCallback((node: any) => {
    setActiveNode(node);
    if (globeEl.current) {
      globeEl.current.pointOfView({ lat: node.lat, lng: node.lng, altitude: 1.2 }, 1000);
    }
  }, []);

  return (
    <div id="globe-container" className="absolute inset-0 z-0 flex items-center justify-center">
      <Globe
        ref={globeEl}
        width={dimensions.width || 800}
        height={dimensions.height || 500}
        globeImageUrl="https://unpkg.com/three-globe/example/img/earth-topology.png"
        backgroundColor="rgba(0,0,0,0)"
        
        showAtmosphere={true}
        atmosphereColor="#ff8a00"
        atmosphereAltitude={0.12}

        /* ── Mesh Arcs ── */
        arcsData={arcs}
        arcStartLat={(d: any) => d.startLat}
        arcStartLng={(d: any) => d.startLng}
        arcEndLat={(d: any) => d.endLat}
        arcEndLng={(d: any) => d.endLng}
        arcColor={(d: any) => d.color}
        arcStroke={(d: any) => d.stroke}
        arcDashLength={(d: any) => d.dashLength}
        arcDashGap={(d: any) => d.dashGap}
        arcDashAnimateTime={(d: any) => d.dashAnimateTime}
        
        /* ── Gateway Nodes ── */
        htmlElementsData={nodes}
        htmlElement={(d: any) => {
          const el = document.createElement('div');
          const size = 10 + d.size * 6;
          const innerSize = 3 + d.size * 2;
          
          el.innerHTML = `
            <div style="cursor: pointer; position: relative;">
               <div style="
                  width: ${size}px; height: ${size}px; border-radius: 50%; 
                  background: ${d.color}; 
                  display: flex; align-items: center; justify-content: center; 
                  transform: translate(-50%, -50%); 
                  box-shadow: 0 0 ${size}px ${statusGlow(d.status)}, 0 0 ${size * 2}px ${statusGlow(d.status)};
                  animation: pulse-glow 2s ease-in-out infinite;
               ">
                  <div style="width: ${innerSize}px; height: ${innerSize}px; border-radius: 50%; background: white;"></div>
               </div>
               
               <div style="position: absolute; top: -14px; left: ${size / 2 + 6}px; white-space: nowrap; pointer-events: none;">
                  <div style="
                     font-family: 'JetBrains Mono', monospace; font-size: 8px; font-weight: bold; 
                     background: rgba(0,0,0,0.85); color: white; 
                     padding: 2px 8px; 
                     border: 1px solid rgba(255,255,255,0.08); border-radius: 4px; 
                     border-left: 2px solid ${d.color}; 
                     text-transform: uppercase; letter-spacing: 0.05em;
                     backdrop-filter: blur(4px);
                  ">
                     ${d.name}
                     <span style="color: ${d.color}; margin-left: 6px; font-size: 7px;">● ${d.agents} agents</span>
                  </div>
               </div>
            </div>
          `;
          
          el.onclick = () => handleNodeClick(d);
          return el;
        }}
      />

      {/* ── Node Detail Panel ── */}
      {activeNode && (
        <div className="absolute top-6 left-6 bg-[#0a0a0a]/95 backdrop-blur-2xl border border-white/10 p-0 rounded-2xl shadow-2xl z-[100] pointer-events-auto w-[340px] overflow-hidden">
           
           {/* Header with status bar */}
           <div className="px-6 pt-5 pb-4 border-b border-white/5" style={{ borderTop: `3px solid ${activeNode.color}` }}>
              <div className="flex justify-between items-start">
                 <div>
                    <h4 className="text-white font-headline font-black text-lg tracking-tight leading-tight">
                       <a href={`/crm/${activeNode.tenantId}`} className="hover:text-orange-400 hover:underline transition-colors flex items-center gap-1.5 group">
                          {activeNode.name}
                          <span className="material-symbols-outlined text-[14px] opacity-0 group-hover:opacity-100 transition-opacity">open_in_new</span>
                       </a>
                    </h4>
                    <p className="text-[10px] font-technical uppercase tracking-widest flex items-center mt-1.5 gap-1.5" style={{ color: activeNode.color }}>
                       <span className="w-2 h-2 rounded-full animate-pulse" style={{ backgroundColor: activeNode.color }}></span> 
                       {activeNode.status} — {activeNode.city}
                    </p>
                 </div>
                 <button onClick={() => { setActiveNode(null); if (globeEl.current) globeEl.current.pointOfView({ altitude: 2.0 }, 800); }} 
                    className="text-white/40 hover:text-white material-symbols-outlined text-[16px] bg-white/5 hover:bg-white/10 p-1.5 rounded-lg transition-colors">close</button>
              </div>
           </div>

           {/* Gateway Identity */}
           <div className="px-6 py-4 space-y-3 font-technical text-xs border-b border-white/5">
              <div className="flex justify-between items-center">
                 <span className="text-neutral-500 uppercase tracking-widest text-[9px]">Gateway ID</span>
                 <span className="text-neutral-300 font-mono text-[10px] bg-white/5 px-2 py-0.5 rounded">{activeNode.gatewayId}</span>
              </div>
              <div className="flex justify-between items-center">
                 <span className="text-neutral-500 uppercase tracking-widest text-[9px]">Region</span>
                 <span className="text-neutral-400">{activeNode.region}</span>
              </div>
              <div className="flex justify-between items-center">
                 <span className="text-neutral-500 uppercase tracking-widest text-[9px]">IP Address</span>
                 <span className="text-neutral-400 font-mono">{activeNode.ip}</span>
              </div>
              <div className="flex justify-between items-center">
                 <span className="text-neutral-500 uppercase tracking-widest text-[9px]">Sentry Version</span>
                 <span className="text-neutral-400">v{activeNode.version}</span>
              </div>
           </div>

           {/* Live Metrics */}
           <div className="px-6 py-4 grid grid-cols-3 gap-3 border-b border-white/5">
              <div className="text-center">
                 <p className="text-white font-bold text-lg font-technical">{activeNode.agents}</p>
                 <p className="text-neutral-500 text-[9px] uppercase tracking-widest">Agents</p>
              </div>
              <div className="text-center">
                 <p className="text-white font-bold text-lg font-technical">{(activeNode.calls || 0).toLocaleString()}</p>
                 <p className="text-neutral-500 text-[9px] uppercase tracking-widest">Calls</p>
              </div>
              <div className="text-center">
                 <p className="text-red-400 font-bold text-lg font-technical">{activeNode.blocked || 0}</p>
                 <p className="text-neutral-500 text-[9px] uppercase tracking-widest">Blocked</p>
              </div>
           </div>

           {/* Security Posture */}
           <div className="px-6 py-4 space-y-2.5 font-technical text-xs">
              <div className="flex justify-between items-center">
                 <span className="text-neutral-500 uppercase tracking-widest text-[9px]">TLS</span>
                 <span className={activeNode.tls ? 'text-emerald-400 font-bold' : 'text-red-400 font-bold'}>{activeNode.tls ? '✓ Enabled' : '✗ Disabled'}</span>
              </div>
              <div className="flex justify-between items-center">
                 <span className="text-neutral-500 uppercase tracking-widest text-[9px]">mTLS</span>
                 <span className={activeNode.mtls ? 'text-emerald-400 font-bold' : 'text-neutral-600 font-bold'}>{activeNode.mtls ? '✓ Enabled' : '— Not Configured'}</span>
              </div>
              <div className="flex justify-between items-center">
                 <span className="text-neutral-500 uppercase tracking-widest text-[9px]">Canary Tokens</span>
                 <span className="text-orange-400 font-bold">{activeNode.canary} active</span>
              </div>
              {activeNode.quarantined > 0 && (
                 <div className="flex justify-between items-center">
                    <span className="text-neutral-500 uppercase tracking-widest text-[9px]">Quarantined</span>
                    <span className="text-red-400 font-bold bg-red-500/10 px-2 py-0.5 rounded">{activeNode.quarantined} agents</span>
                 </div>
              )}
              <div className="flex justify-between items-center">
                 <span className="text-neutral-500 uppercase tracking-widest text-[9px]">Last Heartbeat</span>
                 <span className="text-neutral-400 text-[10px]">{activeNode.lastSeen ? new Date(activeNode.lastSeen).toLocaleString() : '—'}</span>
              </div>
           </div>
        </div>
      )}

      {/* Pulse animation keyframes (injected once) */}
      <style jsx global>{`
        @keyframes pulse-glow {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.6; }
        }
      `}</style>
    </div>
  );
};
