// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

'use client';

import React, { useEffect, useState, useRef, useCallback } from 'react';
import { useSession } from '../layout';
import * as d3 from 'd3';
import { sankey as d3Sankey, sankeyLinkHorizontal, SankeyNode, SankeyLink } from 'd3-sankey';

// ─── Constants ────────────────────────────────────────────────────────────────
const CORE_API = process.env.NEXT_PUBLIC_CORE_API_URL || 'http://localhost:8000';

// Decision status badge styles — matches the pattern used across all portal pages
const STATUS_STYLE: Record<string, string> = {
  approved:       'text-green-400 bg-green-400/10',
  blocked:        'text-red-400 bg-red-400/10',
  pending_swarm:  'text-yellow-400 bg-yellow-400/10',
  shadow_sandbox: 'text-purple-400 bg-purple-400/10',
};

// Node column colours matching the spec
const NODE_COLOURS: Record<string, string> = {
  tenant:  '#f59e0b', // gold/amber
  agent:   '#22c55e', // green default — overridden by certification status
  model:   '#8b5cf6', // purple
  target:  '#14b8a6', // teal
};

// Agent certification status → node colour
const CERT_COLOURS: Record<string, string> = {
  certified:                '#22c55e', // green
  pending_certification:    '#f59e0b', // amber
  recertification_required: '#f59e0b', // amber
  suspended:                '#6b7280', // grey
  terminated:               '#6b7280', // grey
};

// ─── Types ────────────────────────────────────────────────────────────────────
interface FlowRow {
  agent_id: string;
  agent_name: string;
  model: string | null;
  target_api: string;
  total: number;
  approved: number;
  blocked: number;
  pending: number;
  shadow: number;
}

interface AgentInfo {
  id: string;
  name: string;
  status: string;
}

interface Transaction {
  trace_id: string;
  agent_name: string;
  target_api: string;
  status: string;
  created_at: string;
}

interface SankeyNodeExtra {
  name: string;
  column: number;
  colour: string;
  nodeType: string;
}

interface SankeyLinkExtra {
  colour: string;
  total: number;
}

type SNode = SankeyNode<SankeyNodeExtra, SankeyLinkExtra>;
type SLink = SankeyLink<SankeyNodeExtra, SankeyLinkExtra>;

// ─── Link colour logic ───────────────────────────────────────────────────────
// block_ratio > 0.3 → Red (high threat)
// block_ratio > 0.1 → Amber (elevated risk)
// block_ratio === 0 && shadow > 0 → Blue (shadow mode)
// Default → Green (clean)
function linkColour(blocked: number, shadow: number, total: number): string {
  if (total === 0) return 'rgba(34,197,94,0.35)';
  const ratio = blocked / total;
  if (ratio > 0.3) return 'rgba(239,68,68,0.55)';
  if (ratio > 0.1) return 'rgba(245,158,11,0.50)';
  if (blocked === 0 && shadow > 0) return 'rgba(59,130,246,0.45)';
  return 'rgba(34,197,94,0.35)';
}

// ─── Date helpers ─────────────────────────────────────────────────────────────
function formatDate(d: Date): string {
  return d.toISOString().split('T')[0];
}

function daysAgo(n: number): string {
  const d = new Date();
  d.setDate(d.getDate() - n);
  return formatDate(d);
}

// ─── Sankey data builder ──────────────────────────────────────────────────────
// Transforms flow-data API rows into d3-sankey nodes and links.
// Four columns: 0=Tenant, 1=Agent, 2=Model, 3=Target API
// When model is null, the link skips column 2 entirely.
function buildSankeyData(
  flows: FlowRow[],
  tenantName: string,
  agentCertStatus: Record<string, string>
) {
  const nodeMap = new Map<string, number>();
  const nodes: SankeyNodeExtra[] = [];
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const links: any[] = [];

  // Helper: get or create a node, returns its index
  function getNode(key: string, name: string, column: number, nodeType: string, colour?: string): number {
    if (nodeMap.has(key)) return nodeMap.get(key)!;
    const idx = nodes.length;
    nodeMap.set(key, idx);
    nodes.push({ name, column, nodeType, colour: colour || NODE_COLOURS[nodeType] || '#6b7280' });
    return idx;
  }

  // Always create the tenant node at column 0
  const tenantIdx = getNode('tenant:0', tenantName, 0, 'tenant', NODE_COLOURS.tenant);

  // Aggregate links by (source, target) pair to avoid duplicates
  const linkAgg = new Map<string, { source: number; target: number; total: number; blocked: number; shadow: number }>();

  function addLink(source: number, target: number, row: FlowRow) {
    const key = `${source}→${target}`;
    const existing = linkAgg.get(key);
    if (existing) {
      existing.total += row.total;
      existing.blocked += row.blocked;
      existing.shadow += row.shadow;
    } else {
      linkAgg.set(key, { source, target, total: row.total, blocked: row.blocked, shadow: row.shadow });
    }
  }

  for (const row of flows) {
    // Agent node — colour by certification status
    const agentColour = CERT_COLOURS[agentCertStatus[row.agent_id] || ''] || NODE_COLOURS.agent;
    const agentIdx = getNode(`agent:${row.agent_id}`, row.agent_name || 'Unknown', 1, 'agent', agentColour);

    // Tenant → Agent link
    addLink(tenantIdx, agentIdx, row);

    if (row.model) {
      // Model node at column 2
      const modelIdx = getNode(`model:${row.model}`, row.model, 2, 'model', NODE_COLOURS.model);
      // Target API node at column 3
      const targetIdx = getNode(`target:${row.target_api}`, row.target_api, 3, 'target', NODE_COLOURS.target);
      addLink(agentIdx, modelIdx, row);
      addLink(modelIdx, targetIdx, row);
    } else {
      // NULL model — skip column 2, link agent directly to target at column 3
      const targetIdx = getNode(`target:${row.target_api}`, row.target_api, 3, 'target', NODE_COLOURS.target);
      addLink(agentIdx, targetIdx, row);
    }
  }

  // Convert aggregated links into d3-sankey compatible format
  for (const l of linkAgg.values()) {
    links.push({
      source: l.source,
      target: l.target,
      value: l.total,
      colour: linkColour(l.blocked, l.shadow, l.total),
      total: l.total,
    } as any);
  }

  return { nodes, links };
}

// ═══════════════════════════════════════════════════════════════════════════════
// Main Page Component
// ═══════════════════════════════════════════════════════════════════════════════
export default function AgentFlowPage() {
  const session = useSession();
  const svgRef = useRef<SVGSVGElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  // ─── State ──────────────────────────────────────────────────────────────
  const [flows, setFlows] = useState<FlowRow[]>([]);
  const [agents, setAgents] = useState<AgentInfo[]>([]);
  const [recentTx, setRecentTx] = useState<Transaction[]>([]);
  const [loading, setLoading] = useState(true);

  // Filters
  const [dateFrom, setDateFrom] = useState(daysAgo(7));
  const [dateTo, setDateTo] = useState(formatDate(new Date()));
  const [agentFilter, setAgentFilter] = useState('');
  const [decisionFilter, setDecisionFilter] = useState<string[]>([]);

  // ─── Authenticated fetch helper ─────────────────────────────────────────
  const apiFetch = useCallback(async (path: string) => {
    if (!session) return null;
    const res = await fetch(`${CORE_API}${path}`, {
      headers: { Authorization: `Bearer ${session.token}`, Accept: 'application/json' },
    });
    if (!res.ok) return null;
    const json = await res.json();
    return json.data;
  }, [session]);

  // ─── Data loading ───────────────────────────────────────────────────────
  const loadData = useCallback(async () => {
    if (!session) return;
    setLoading(true);

    const params = new URLSearchParams({ date_from: dateFrom, date_to: dateTo });
    if (agentFilter) params.set('agent_id', agentFilter);

    // Parallel fetch: flow data + agents list + recent transactions
    const [flowData, agentData, txData] = await Promise.all([
      apiFetch(`/api/v1/portal/flow-data?${params}`),
      apiFetch('/api/v1/portal/agents'),
      apiFetch('/api/v1/portal/transactions?per_page=10'),
    ]);

    if (flowData?.flows) setFlows(flowData.flows);
    if (agentData?.agents) setAgents(agentData.agents);
    if (txData?.records) setRecentTx(txData.records.slice(0, 10));

    setLoading(false);
  }, [session, dateFrom, dateTo, agentFilter, apiFetch]);

  useEffect(() => { loadData(); }, [loadData]);

  // ─── Compute summary stats ──────────────────────────────────────────────
  const totalCalls = flows.reduce((s, f) => s + f.total, 0);
  const totalBlocked = flows.reduce((s, f) => s + f.blocked, 0);
  const uniqueAgents = new Set(flows.map(f => f.agent_id)).size;
  const uniqueTargets = new Set(flows.map(f => f.target_api)).size;

  // Top 5 blocked agents
  const blockedByAgent = new Map<string, { name: string; blocked: number }>();
  for (const f of flows) {
    const existing = blockedByAgent.get(f.agent_id);
    if (existing) { existing.blocked += f.blocked; }
    else { blockedByAgent.set(f.agent_id, { name: f.agent_name, blocked: f.blocked }); }
  }
  const topBlocked = [...blockedByAgent.values()]
    .filter(a => a.blocked > 0)
    .sort((a, b) => b.blocked - a.blocked)
    .slice(0, 5);

  // Agent certification status map for node colouring
  const agentCertStatus: Record<string, string> = {};
  for (const a of agents) { agentCertStatus[a.id] = a.status; }

  // ─── D3 Sankey rendering ────────────────────────────────────────────────
  const drawSankey = useCallback(() => {
    if (!svgRef.current || !containerRef.current || flows.length === 0) return;

    const width = containerRef.current.clientWidth;
    const height = Math.max(400, Math.min(700, flows.length * 25 + 100));
    const margin = { top: 20, right: 20, bottom: 20, left: 20 };

    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();
    svg.attr('width', width).attr('height', height);

    const tenantName = session?.tenant.name || 'Tenant';
    const data = buildSankeyData(flows, tenantName, agentCertStatus);

    if (data.nodes.length === 0) return;

    // Configure the Sankey layout
    const sankeyLayout = d3Sankey<SankeyNodeExtra, SankeyLinkExtra>()
      .nodeWidth(18)
      .nodePadding(14)
      .nodeSort(null)
      .extent([[margin.left, margin.top], [width - margin.right, height - margin.bottom]]);

    const { nodes, links } = sankeyLayout({
      nodes: data.nodes.map(d => ({ ...d })),
      links: data.links.map(d => ({ ...d })),
    });

    const g = svg.append('g');

    // ── Draw links ──
    g.append('g')
      .attr('fill', 'none')
      .selectAll('path')
      .data(links)
      .join('path')
      .attr('d', sankeyLinkHorizontal())
      .attr('stroke', (d: any) => d.colour || 'rgba(34,197,94,0.35)')
      .attr('stroke-width', (d: any) => Math.max(2, d.width || 1))
      .attr('stroke-opacity', 0.7)
      .append('title')
      .text((d: any) => {
        const src = (d.source as SNode).name;
        const tgt = (d.target as SNode).name;
        return `${src} → ${tgt}\n${d.total?.toLocaleString() || d.value?.toLocaleString()} calls`;
      });

    // ── Draw nodes ──
    const nodeGroup = g.append('g')
      .selectAll('g')
      .data(nodes)
      .join('g');

    nodeGroup.append('rect')
      .attr('x', (d: any) => d.x0)
      .attr('y', (d: any) => d.y0)
      .attr('width', (d: any) => d.x1 - d.x0)
      .attr('height', (d: any) => Math.max(4, d.y1 - d.y0))
      .attr('fill', (d: any) => d.colour || '#6b7280')
      .attr('rx', 3)
      .attr('opacity', 0.9);

    // ── Node labels ──
    nodeGroup.append('text')
      .attr('x', (d: any) => d.x0 < width / 2 ? d.x1 + 8 : d.x0 - 8)
      .attr('y', (d: any) => (d.y0 + d.y1) / 2)
      .attr('dy', '0.35em')
      .attr('text-anchor', (d: any) => d.x0 < width / 2 ? 'start' : 'end')
      .attr('fill', '#ffffff')
      .attr('font-size', '11px')
      .attr('font-family', "'JetBrains Mono', monospace")
      .text((d: any) => {
        const name = d.name || '';
        return name.length > 35 ? name.slice(0, 32) + '…' : name;
      });

    // ── Column headers ──
    const colLabels = ['TENANT', 'AGENT', 'MODEL', 'TARGET API'];
    const colPositions = [margin.left, width * 0.28, width * 0.55, width - margin.right - 60];
    colLabels.forEach((label, i) => {
      svg.append('text')
        .attr('x', colPositions[i])
        .attr('y', 12)
        .attr('fill', 'rgba(255,255,255,0.3)')
        .attr('font-size', '9px')
        .attr('font-family', "'JetBrains Mono', monospace")
        .attr('letter-spacing', '0.1em')
        .text(label);
    });
  }, [flows, session, agentCertStatus]);

  // Redraw on data change
  useEffect(() => { drawSankey(); }, [drawSankey]);

  // Responsive redraw via ResizeObserver
  useEffect(() => {
    if (!containerRef.current) return;
    const observer = new ResizeObserver(() => { drawSankey(); });
    observer.observe(containerRef.current);
    return () => observer.disconnect();
  }, [drawSankey]);

  // ─── Filter handler ────────────────────────────────────────────────────
  function applyFilters() { loadData(); }

  // ─── Filtered recent transactions ───────────────────────────────────────
  const filteredTx = decisionFilter.length > 0
    ? recentTx.filter(tx => decisionFilter.includes(tx.status))
    : recentTx;

  // ═══════════════════════════════════════════════════════════════════════════
  // Render
  // ═══════════════════════════════════════════════════════════════════════════
  return (
    <div className="p-8 space-y-6">

      {/* ── Page header ──────────────────────────────────────────────────── */}
      <div>
        <h1 className="text-3xl font-black font-headline tracking-tighter">Agent Flow</h1>
        <p className="text-on-surface-muted text-sm mt-1">
          Visualise agent → model → target API traffic with decision outcome analysis
        </p>
      </div>

      {/* ── Filters bar ──────────────────────────────────────────────────── */}
      <div className="flex flex-wrap items-end gap-4 bg-surface-raised border border-[rgba(255,159,74,0.08)] rounded-2xl p-4">
        <div>
          <label className="block text-[10px] font-technical text-on-surface-muted uppercase tracking-widest mb-1">From</label>
          <input type="date" value={dateFrom} onChange={e => setDateFrom(e.target.value)}
            className="bg-[#1a1a1a] border border-white/10 rounded-lg px-3 py-1.5 text-sm font-technical text-on-surface focus:border-primary outline-none" />
        </div>
        <div>
          <label className="block text-[10px] font-technical text-on-surface-muted uppercase tracking-widest mb-1">To</label>
          <input type="date" value={dateTo} onChange={e => setDateTo(e.target.value)}
            className="bg-[#1a1a1a] border border-white/10 rounded-lg px-3 py-1.5 text-sm font-technical text-on-surface focus:border-primary outline-none" />
        </div>
        <div>
          <label className="block text-[10px] font-technical text-on-surface-muted uppercase tracking-widest mb-1">Agent</label>
          <select value={agentFilter} onChange={e => setAgentFilter(e.target.value)}
            className="bg-[#1a1a1a] border border-white/10 rounded-lg px-3 py-1.5 text-sm font-technical text-on-surface focus:border-primary outline-none min-w-[160px]">
            <option value="">All Agents</option>
            {agents.map(a => <option key={a.id} value={a.id}>{a.name}</option>)}
          </select>
        </div>
        <div>
          <label className="block text-[10px] font-technical text-on-surface-muted uppercase tracking-widest mb-1">Decision</label>
          <div className="flex gap-1.5">
            {['approved', 'blocked', 'pending_swarm', 'shadow_sandbox'].map(s => {
              const active = decisionFilter.includes(s);
              return (
                <button key={s} onClick={() => setDecisionFilter(prev =>
                  active ? prev.filter(x => x !== s) : [...prev, s]
                )}
                  className={`px-2.5 py-1 rounded-full text-[10px] font-technical transition-colors ${
                    active ? STATUS_STYLE[s] : 'bg-white/5 text-on-surface-muted hover:bg-white/10'
                  }`}
                >{s.replace('_', ' ')}</button>
              );
            })}
          </div>
        </div>
        <button onClick={applyFilters}
          className="px-5 py-1.5 rounded-lg text-sm font-headline font-bold btn-gradient text-black hover:opacity-90 transition-opacity">
          Apply
        </button>
      </div>

      {/* ── Main content: Sankey + Right Panel ────────────────────────── */}
      <div className="flex gap-6">

        {/* ── Sankey diagram (70%) ──────────────────────────────────── */}
        <div className="flex-[7] min-w-0">
          <div ref={containerRef}
            className="bg-surface-raised border border-[rgba(255,159,74,0.08)] rounded-2xl p-4 overflow-hidden">
            {loading ? (
              <div className="flex items-center justify-center py-32">
                <div className="w-10 h-10 border-2 border-primary border-t-transparent rounded-full animate-spin" />
              </div>
            ) : flows.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-32">
                <span className="material-symbols-outlined text-on-surface-muted text-5xl mb-3">account_tree</span>
                <p className="text-on-surface-muted text-sm">No agent traffic recorded in this time range.</p>
                <p className="text-xs text-on-surface-muted/60 mt-1">Adjust your date range or wait for agent activity.</p>
              </div>
            ) : (
              <svg ref={svgRef} className="w-full" />
            )}
          </div>

          {/* ── Legend ─────────────────────────────────────────────── */}
          <div className="flex flex-wrap gap-5 mt-3 px-1">
            {[
              { colour: 'bg-green-500', label: 'Clean traffic' },
              { colour: 'bg-amber-500', label: 'Elevated risk (>10% blocked)' },
              { colour: 'bg-red-500',   label: 'High threat (>30% blocked)' },
              { colour: 'bg-blue-500',  label: 'Shadow mode' },
            ].map(l => (
              <div key={l.label} className="flex items-center gap-2">
                <div className={`w-3 h-1.5 rounded-full ${l.colour}`} />
                <span className="text-[10px] font-technical text-on-surface-muted">{l.label}</span>
              </div>
            ))}
          </div>
        </div>

        {/* ── Right panel (30%) — mirrors CrowdStrike layout ───── */}
        <div className="flex-[3] space-y-4 min-w-[260px]">

          {/* Summary stats */}
          <div className="bg-surface-raised border border-[rgba(255,159,74,0.08)] rounded-2xl p-5 space-y-4">
            <h3 className="text-[10px] font-technical text-on-surface-muted uppercase tracking-widest">Summary</h3>
            <div className="grid grid-cols-2 gap-3">
              {[
                { label: 'Total Calls',  value: totalCalls,   icon: 'swap_horiz',  accent: 'text-primary' },
                { label: 'Blocked',      value: totalBlocked, icon: 'block',        accent: 'text-red-400' },
                { label: 'Agents',       value: uniqueAgents, icon: 'smart_toy',    accent: 'text-green-400' },
                { label: 'Target APIs',  value: uniqueTargets,icon: 'api',          accent: 'text-teal-400' },
              ].map(s => (
                <div key={s.label} className="bg-[#1a1a1a] rounded-xl p-3">
                  <span className={`material-symbols-outlined text-lg ${s.accent}`}>{s.icon}</span>
                  <p className="text-xl font-black font-headline mt-1">{s.value.toLocaleString()}</p>
                  <p className="text-[9px] font-technical text-on-surface-muted uppercase tracking-widest">{s.label}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Top blocked agents */}
          <div className="bg-surface-raised border border-[rgba(255,159,74,0.08)] rounded-2xl p-5">
            <h3 className="text-[10px] font-technical text-on-surface-muted uppercase tracking-widest mb-3">Top Blocked Agents</h3>
            {topBlocked.length === 0 ? (
              <p className="text-xs text-on-surface-muted/60 py-4 text-center">No blocked agents in range</p>
            ) : (
              <div className="space-y-2">
                {topBlocked.map((a, i) => (
                  <div key={i} className="flex items-center justify-between py-1.5">
                    <div className="flex items-center gap-2 min-w-0">
                      <span className="material-symbols-outlined text-red-400 text-sm">warning</span>
                      <span className="text-xs font-headline truncate">{a.name}</span>
                    </div>
                    <span className="text-xs font-technical text-red-400 bg-red-400/10 px-2 py-0.5 rounded-full flex-shrink-0">
                      {a.blocked}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Recent decisions feed */}
          <div className="bg-surface-raised border border-[rgba(255,159,74,0.08)] rounded-2xl p-5">
            <h3 className="text-[10px] font-technical text-on-surface-muted uppercase tracking-widest mb-3">Recent Decisions</h3>
            {filteredTx.length === 0 ? (
              <p className="text-xs text-on-surface-muted/60 py-4 text-center">No recent activity</p>
            ) : (
              <div className="space-y-2 max-h-[320px] overflow-y-auto">
                {filteredTx.map(tx => (
                  <div key={tx.trace_id} className="border-b border-white/5 pb-2 last:border-0">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-headline font-bold truncate mr-2">{tx.agent_name ?? 'Unknown'}</span>
                      <span className={`text-[10px] font-technical px-2 py-0.5 rounded-full flex-shrink-0 ${
                        STATUS_STYLE[tx.status] ?? 'text-gray-400 bg-gray-400/10'
                      }`}>
                        {tx.status?.replace('_', ' ')}
                      </span>
                    </div>
                    <p className="text-[10px] font-technical text-on-surface-muted truncate">{tx.target_api}</p>
                    <p className="text-[9px] font-technical text-on-surface-muted/50">
                      {tx.created_at ? new Date(tx.created_at).toLocaleString() : ''}
                    </p>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
