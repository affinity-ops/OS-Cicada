// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * /ztna-posture — ZTNA Trust Posture Dashboard
 *
 * Real-time single-pane-of-glass view of the fleet's Zero-Trust compliance
 * across the four ZTNA pillars: Continuous Authentication, Fine-Grained
 * Authorization, Fabric Enforcement, and Cryptographic Containment.
 *
 * Data sources (all read-only, no mutations):
 *   - GET /api/v1/dashboard/summary  → aggregate fleet metrics
 *   - GET /api/v1/admin/gateways     → gateway fleet telemetry
 *   - GET /api/v1/nodes              → per-agent trust/posture data
 *   - GET /api/v1/security/policies  → policy count + health
 *
 * Design notes:
 *   - Matches existing dashboard design system (dark theme, orange primary)
 *   - Auto-refreshes every 10s (consistent with Global Overview)
 *   - SVG radial gauge for the aggregate posture score
 *   - CSS animations for timeline entries + pillar card hover states
 *   - No dangerouslySetInnerHTML, no user inputs, no external deps
 */

'use client';

import { operatorFetch } from '@/lib/operatorFetch';
import React, { useState, useEffect, useCallback, useMemo } from 'react';
import Link from 'next/link';
import { Sidebar } from '../../components/Sidebar';
import { TopAppBar } from '../../components/TopAppBar';

/* -------------------------------------------------------------------------- */
/*  Core API base URL                                                         */
/* -------------------------------------------------------------------------- */
const API = process.env.NEXT_PUBLIC_CORE_API_URL ?? 'http://localhost:8000';

/* -------------------------------------------------------------------------- */
/*  TypeScript interfaces for API responses                                   */
/* -------------------------------------------------------------------------- */

/** Subset of /api/v1/dashboard/summary we consume */
interface DashboardSummary {
  total_agents: number;
  verified_agents: number;
  quarantined_agents: number;
  approved_today: number;
  blocked_today: number;
  pending_hitl_count: number;
  recent_activity: ActivityEntry[];
}

/** A single recent_activity entry from the dashboard summary */
interface ActivityEntry {
  agent_name: string;
  status: string;
  action_type: string;
  target_api: string;
  created_at: string;
  source?: string;
  summary?: string;
  severity?: string;
}

/** Gateway fleet summary from /api/v1/admin/gateways */
interface GatewayFleet {
  summary: { total: number; online: number; degraded: number; offline: number };
  gateways: {
    canary_tokens_active: number;
    quarantined_agents: number;
    live_status: string;
  }[];
}

/** Agent record from /api/v1/nodes (nested under tenants) */
interface ApiAgent {
  id: string;
  name: string | null;
  status: string;
  trust_score: number;
  trust_tier: string;
  total_actions: number;
  blocked_actions: number;
}

/** Tenant record from /api/v1/nodes */
interface ApiTenant {
  id: string;
  name: string;
  agents: ApiAgent[];
}

/** Security policy from /api/v1/security/policies */
interface SecurityPolicy {
  slug: string;
  name: string;
  status: string;
  exceptions: string;
}

/* -------------------------------------------------------------------------- */
/*  Flattened agent with tenant info for the posture ledger                    */
/* -------------------------------------------------------------------------- */
interface PostureAgent {
  id: string;
  name: string;
  tenantName: string;
  trustScore: number;
  trustTier: string;
  status: string;
  totalActions: number;
  blockedActions: number;
  /** Per-pillar compliance flags */
  authOk: boolean;
  authzOk: boolean;
  fabricOk: boolean;
  containOk: boolean;
}

/* -------------------------------------------------------------------------- */
/*  Pillar filter options for the agent table                                 */
/* -------------------------------------------------------------------------- */
type PillarFilter = 'all' | 'auth' | 'authz' | 'fabric' | 'contain';

/* -------------------------------------------------------------------------- */
/*  Event timeline colour classification                                     */
/*  Aligned with the dashboard's existing statusConfig pattern                */
/*  (see Global Overview page.tsx lines 330-337)                              */
/* -------------------------------------------------------------------------- */

/**
 * Maps a recent_activity entry to a ZTNA pillar colour class.
 * The classification heuristic uses action_type and status to infer
 * which pillar the event originated from.
 */
function classifyEvent(entry: ActivityEntry): {
  pillar: string;
  color: string;
  dotColor: string;
  bgColor: string;
  icon: string;
} {
  const action = (entry.action_type ?? '').toLowerCase();
  const status = (entry.status ?? '').toLowerCase();

  // Red: Quarantine events (highest priority — check first)
  if (
    action.includes('quarantine') ||
    action.includes('canary') ||
    action.includes('circuit_breaker') ||
    status === 'threat'
  ) {
    return {
      pillar: 'Quarantine',
      color: 'text-red-400',
      dotColor: 'bg-red-500',
      bgColor: 'bg-red-500/5 border-red-500/10',
      icon: 'lock',
    };
  }

  // Orange: Fabric intercepts (shadow modes)
  if (status === 'shadow_sandbox' || status === 'shadow_allowed') {
    return {
      pillar: 'Fabric Intercept',
      color: 'text-orange-400',
      dotColor: 'bg-orange-500',
      bgColor: 'bg-orange-500/5 border-orange-500/10',
      icon: 'shield',
    };
  }

  // Blue: Auth failures (token / identity related blocks)
  if (
    action.includes('auth') ||
    action.includes('token') ||
    action.includes('identity')
  ) {
    return {
      pillar: 'Auth Failure',
      color: 'text-blue-400',
      dotColor: 'bg-blue-500',
      bgColor: 'bg-blue-500/5 border-blue-500/10',
      icon: 'verified_user',
    };
  }

  // Amber: Policy blocks (everything else that's blocked)
  if (status === 'blocked') {
    return {
      pillar: 'Policy Block',
      color: 'text-amber-400',
      dotColor: 'bg-amber-500',
      bgColor: 'bg-amber-500/5 border-amber-500/10',
      icon: 'policy',
    };
  }

  // Default: Approved/normal activity
  return {
    pillar: 'Approved',
    color: 'text-emerald-400',
    dotColor: 'bg-emerald-500',
    bgColor: 'bg-emerald-500/5 border-emerald-500/10',
    icon: 'check_circle',
  };
}

/* -------------------------------------------------------------------------- */
/*  SVG Radial Gauge Component                                                */
/*  Renders an animated circular progress gauge using stroke-dasharray.       */
/* -------------------------------------------------------------------------- */

function PostureGauge({ score, loading }: { score: number; loading: boolean }) {
  // SVG circle geometry
  const radius = 88;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;

  // Colour tiers matching the whitepaper specification (Section 3.5.1)
  const tierColor =
    score > 85
      ? 'stroke-emerald-500'
      : score >= 60
        ? 'stroke-amber-500'
        : 'stroke-red-500';

  const tierTextColor =
    score > 85
      ? 'text-emerald-400'
      : score >= 60
        ? 'text-amber-400'
        : 'text-red-400';

  const tierLabel =
    score > 85 ? 'NOMINAL' : score >= 60 ? 'DEGRADED' : 'CRITICAL';

  return (
    <div className="relative flex items-center justify-center w-56 h-56">
      {/* Background ring */}
      <svg className="absolute inset-0 w-full h-full -rotate-90" viewBox="0 0 200 200">
        <circle
          cx="100" cy="100" r={radius}
          fill="none"
          stroke="rgba(255,255,255,0.05)"
          strokeWidth="10"
        />
        {/* Animated progress arc */}
        <circle
          cx="100" cy="100" r={radius}
          fill="none"
          className={`${tierColor} transition-all duration-1000 ease-out`}
          strokeWidth="10"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={loading ? circumference : offset}
          style={{
            filter: `drop-shadow(0 0 8px ${score > 85 ? 'rgba(16,185,129,0.4)' : score >= 60 ? 'rgba(245,158,11,0.4)' : 'rgba(239,68,68,0.4)'})`,
          }}
        />
      </svg>
      {/* Centre text */}
      <div className="relative z-10 text-center">
        <p className={`text-5xl font-black font-headline tracking-tighter ${tierTextColor} transition-colors duration-500`}>
          {loading ? '—' : `${score}%`}
        </p>
        <p className="text-[10px] font-technical text-neutral-500 uppercase tracking-[0.2em] mt-1">
          ZTNA Compliant
        </p>
        <p className={`text-[10px] font-technical font-bold uppercase tracking-widest mt-2 px-2 py-0.5 rounded border ${
          score > 85
            ? 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20'
            : score >= 60
              ? 'text-amber-400 bg-amber-500/10 border-amber-500/20'
              : 'text-red-400 bg-red-500/10 border-red-500/20'
        }`}>
          {loading ? '...' : tierLabel}
        </p>
      </div>
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/*  Pillar Metric Card                                                        */
/*  Reusable card for each of the four ZTNA pillars.                          */
/* -------------------------------------------------------------------------- */

interface PillarCardProps {
  icon: string;
  title: string;
  subtitle: string;
  metric: string;
  detail: string;
  /** Optional secondary detail line */
  detail2?: string;
  /** Pillar health as 0-100 percentage */
  pillarPct?: number;
  /** Issue/remediation text shown when pillar is degraded */
  issues?: string[];
  accentColor: string;
  borderColor: string;
  bgColor: string;
  loading: boolean;
}

function PillarCard({
  icon, title, subtitle, metric, detail, detail2,
  pillarPct, issues,
  accentColor, borderColor, bgColor, loading,
}: PillarCardProps) {
  // Determine if this pillar has degraded health
  const isDegraded = pillarPct !== undefined && pillarPct < 100;
  const barColor = pillarPct !== undefined
    ? pillarPct > 85 ? 'bg-emerald-500' : pillarPct >= 60 ? 'bg-amber-500' : 'bg-red-500'
    : '';

  return (
    <div className={`group relative bg-[#131313] rounded-2xl p-6 border ${isDegraded ? 'border-red-500/20' : borderColor} transition-all duration-300 hover:scale-[1.02] hover:shadow-xl overflow-hidden`}>
      {/* Animated top accent bar */}
      <div className={`absolute top-0 left-0 right-0 h-[2px] ${bgColor} opacity-40 group-hover:opacity-100 transition-opacity duration-500`} />
      {/* Subtle corner glow on hover */}
      <div className={`absolute -top-8 -right-8 w-24 h-24 ${bgColor} rounded-full blur-3xl opacity-0 group-hover:opacity-30 transition-opacity duration-500`} />

      <div className="relative z-10">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <div className={`w-10 h-10 rounded-xl flex items-center justify-center ${bgColor} border ${borderColor}`}>
              <span className={`material-symbols-outlined text-xl ${accentColor}`}>{icon}</span>
            </div>
            <div>
              <h4 className="font-headline font-bold text-sm text-white">{title}</h4>
              <p className="text-[10px] font-technical text-neutral-500 uppercase tracking-widest">{subtitle}</p>
            </div>
          </div>
          {/* Pillar health badge */}
          {pillarPct !== undefined && !loading && (
            <span className={`text-[10px] font-technical font-bold px-2 py-0.5 rounded border ${
              pillarPct > 85
                ? 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20'
                : pillarPct >= 60
                  ? 'text-amber-400 bg-amber-500/10 border-amber-500/20'
                  : 'text-red-400 bg-red-500/10 border-red-500/20'
            }`}>
              {pillarPct}%
            </span>
          )}
        </div>
        <p className={`text-3xl font-black font-headline tracking-tighter ${accentColor} mb-1`}>
          {loading ? '—' : metric}
        </p>
        <p className="text-xs font-technical text-neutral-500">{loading ? 'Loading...' : detail}</p>
        {detail2 && !loading && (
          <p className="text-[10px] font-technical text-neutral-600 mt-1">{detail2}</p>
        )}

        {/* Pillar health bar */}
        {pillarPct !== undefined && !loading && (
          <div className="mt-3">
            <div className="h-1 w-full bg-white/5 rounded-full overflow-hidden">
              <div
                className={`h-full rounded-full ${barColor} transition-all duration-1000 ease-out`}
                style={{ width: `${pillarPct}%` }}
              />
            </div>
          </div>
        )}

        {/* Issue/remediation text — only shown when degraded */}
        {issues && issues.length > 0 && !loading && (
          <div className="mt-3 space-y-1 border-t border-white/5 pt-3">
            {issues.map((issue, i) => (
              <p key={i} className="text-[10px] font-technical text-red-400/80 flex items-start gap-1.5">
                <span className="material-symbols-outlined text-[10px] mt-0.5 flex-shrink-0">warning</span>
                {issue}
              </p>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/*  Main Page Component                                                       */
/* -------------------------------------------------------------------------- */

export default function ZtnaPosturePage() {
  /* ── State ─────────────────────────────────────────────────────────── */
  const [dashboard, setDashboard] = useState<DashboardSummary | null>(null);
  const [fleet, setFleet] = useState<GatewayFleet | null>(null);
  const [tenants, setTenants] = useState<ApiTenant[]>([]);
  const [policies, setPolicies] = useState<SecurityPolicy[]>([]);
  const [loading, setLoading] = useState(true);
  const [pillarFilter, setPillarFilter] = useState<PillarFilter>('all');

  /* ── Data Loading ──────────────────────────────────────────────────── */
  // Fetches all four API endpoints in parallel.
  // Matches the Global Overview pattern: never clear existing state during
  // refresh to prevent "loading glitch" on the 10s auto-refresh cycle.
  const loadData = useCallback(() => {
    const promises = [
      operatorFetch(`${API}/api/v1/dashboard/summary`)
        .then(r => r.json())
        .then(json => { if (json.data) setDashboard(json.data); })
        .catch((e: unknown) => console.error('ZTNA: Failed to load dashboard summary:', e)),

      operatorFetch(`${API}/api/v1/admin/gateways`)
        .then(r => r.json())
        .then(json => { if (json.status === 'success') setFleet(json); })
        .catch((e: unknown) => console.error('ZTNA: Failed to load gateway fleet:', e)),

      operatorFetch(`${API}/api/v1/nodes`)
        .then(r => r.json())
        .then(json => { if (json.status === 'success') setTenants(json.data); })
        .catch((e: unknown) => console.error('ZTNA: Failed to load nodes:', e)),

      operatorFetch(`${API}/api/v1/security/policies`)
        .then(r => r.json())
        .then(json => { if (json.status === 'success') setPolicies(json.data); })
        .catch((e: unknown) => console.error('ZTNA: Failed to load policies:', e)),
    ];

    return Promise.allSettled(promises);
  }, []);

  useEffect(() => {
    loadData().finally(() => setLoading(false));
    const interval = setInterval(loadData, 10_000);
    return () => clearInterval(interval);
  }, [loadData]);

  /* ── Computed: Flatten agents with posture compliance ───────────── */
  const postureAgents: PostureAgent[] = useMemo(() => {
    return tenants.flatMap(t =>
      t.agents.map((a): PostureAgent => {
        const blockRate = a.total_actions > 0
          ? (a.blocked_actions / a.total_actions) * 100
          : 0;
        return {
          id: a.id,
          name: a.name ?? `Agent-${a.id.substring(0, 8).toUpperCase()}`,
          tenantName: t.name,
          trustScore: a.trust_score,
          trustTier: a.trust_tier,
          status: a.status,
          totalActions: a.total_actions,
          blockedActions: a.blocked_actions,
          // Pillar compliance logic:
          // Auth ✓:    Has a verified trust tier AND is currently active
          authOk: a.trust_tier !== 'unverified' && a.status === 'Active',
          // Authz ✓:   No blocks or block rate under 5% (within micro-perimeter)
          authzOk: a.blocked_actions === 0 || blockRate < 5,
          // Fabric ✓:  Has been processed through the gateway (has action history)
          fabricOk: a.total_actions > 0,
          // Contain ✓: Not currently quarantined/revoked
          containOk: a.status !== 'Revoked',
        };
      })
    );
  }, [tenants]);

  /* ── Computed: Filtered agents for the posture ledger ───────────── */
  const filteredAgents = useMemo(() => {
    if (pillarFilter === 'all') return postureAgents;
    return postureAgents.filter(a => {
      switch (pillarFilter) {
        case 'auth':    return !a.authOk;
        case 'authz':   return !a.authzOk;
        case 'fabric':  return !a.fabricOk;
        case 'contain': return !a.containOk;
        default:        return true;
      }
    });
  }, [postureAgents, pillarFilter]);

  /* ── Computed: Aggregate ZTNA Posture Score ─────────────────────── */
  // Weighted average across the four pillars:
  //   Auth (30%) + Authz (30%) + Fabric (20%) + Contain (20%)
  const postureScore = useMemo(() => {
    if (postureAgents.length === 0) return 0;
    const total = postureAgents.length;
    const authPct = (postureAgents.filter(a => a.authOk).length / total) * 100;
    const authzPct = (postureAgents.filter(a => a.authzOk).length / total) * 100;
    const fabricPct = (postureAgents.filter(a => a.fabricOk).length / total) * 100;
    const containPct = (postureAgents.filter(a => a.containOk).length / total) * 100;
    return Math.round(authPct * 0.3 + authzPct * 0.3 + fabricPct * 0.2 + containPct * 0.2);
  }, [postureAgents]);

  /* ── Computed: Pillar-specific metrics ──────────────────────────── */
  const totalAgents = dashboard?.total_agents ?? 0;
  const verifiedAgents = dashboard?.verified_agents ?? 0;
  const unverifiedAgents = totalAgents - verifiedAgents;
  const authPct = totalAgents > 0 ? Math.round((verifiedAgents / totalAgents) * 100) : 0;

  const policyCount = policies.length;
  const exceptionCount = policies.reduce((sum, p) => {
    try { return sum + JSON.parse(p.exceptions ?? '[]').length; } catch { return sum; }
  }, 0);
  const healthyPolicies = policies.filter(p => p.status === 'healthy').length;

  const totalIntercepts = (dashboard?.approved_today ?? 0) + (dashboard?.blocked_today ?? 0);
  const blockRate = totalIntercepts > 0
    ? ((dashboard?.blocked_today ?? 0) / totalIntercepts * 100).toFixed(1)
    : '0.0';

  const totalCanaryTokens = fleet?.gateways.reduce((sum, g) => sum + g.canary_tokens_active, 0) ?? 0;
  const meshNodesOnline = fleet?.summary.online ?? 0;
  const quarantinedFleet = dashboard?.quarantined_agents ?? 0;

  /* ── Pillar failure counts for filter badges ────────────────────── */
  const failingAuth = postureAgents.filter(a => !a.authOk).length;
  const failingAuthz = postureAgents.filter(a => !a.authzOk).length;
  const failingFabric = postureAgents.filter(a => !a.fabricOk).length;
  const failingContain = postureAgents.filter(a => !a.containOk).length;

  /* ── Per-pillar health percentages ──────────────────────────────── */
  const authPillarPct = postureAgents.length > 0
    ? Math.round((postureAgents.filter(a => a.authOk).length / postureAgents.length) * 100) : 100;
  const authzPillarPct = postureAgents.length > 0
    ? Math.round((postureAgents.filter(a => a.authzOk).length / postureAgents.length) * 100) : 100;
  const fabricPillarPct = postureAgents.length > 0
    ? Math.round((postureAgents.filter(a => a.fabricOk).length / postureAgents.length) * 100) : 100;
  const containPillarPct = postureAgents.length > 0
    ? Math.round((postureAgents.filter(a => a.containOk).length / postureAgents.length) * 100) : 100;

  /* ── Actionable issue arrays for each pillar ────────────────────── */
  // Only populated when the pillar is below 100% — gives operators
  // specific remediation steps, not just a number.
  const authIssues: string[] = [];
  if (failingAuth > 0) {
    const unverifiedCount = postureAgents.filter(a => a.trustTier === 'unverified').length;
    const inactiveCount = postureAgents.filter(a => a.status !== 'Active' && a.trustTier !== 'unverified').length;
    if (unverifiedCount > 0) authIssues.push(`${unverifiedCount} agent${unverifiedCount > 1 ? 's' : ''} have no verified Ed25519 identity — certify via Developer Portal or decommission`);
    if (inactiveCount > 0) authIssues.push(`${inactiveCount} verified agent${inactiveCount > 1 ? 's' : ''} are inactive — check status or remove stale entries`);
  }

  const authzIssues: string[] = [];
  if (failingAuthz > 0) {
    authzIssues.push(`${failingAuthz} agent${failingAuthz > 1 ? 's' : ''} have a block rate ≥5% — review denied scopes and policy exceptions`);
  }
  if (exceptionCount > 0) {
    authzIssues.push(`${exceptionCount} policy exception${exceptionCount > 1 ? 's' : ''} active — review and reduce attack surface`);
  }

  const fabricIssues: string[] = [];
  if (failingFabric > 0) {
    fabricIssues.push(`${failingFabric} agent${failingFabric > 1 ? 's' : ''} have never routed through the Sentry Gateway — verify SDK integration or decommission`);
  }

  const containIssues: string[] = [];
  if (failingContain > 0) {
    containIssues.push(`${failingContain} agent${failingContain > 1 ? 's' : ''} are quarantined/revoked — investigate and remediate or remove from fleet`);
  }

  /* ── Render ────────────────────────────────────────────────────── */
  return (
    <>
      <Sidebar />
      <TopAppBar />

      {/* Inline CSS for timeline entry animation */}
      <style>{`
        @keyframes ztna-slide-in {
          from { opacity: 0; transform: translateX(-12px); }
          to   { opacity: 1; transform: translateX(0); }
        }
        .ztna-timeline-entry {
          animation: ztna-slide-in 0.3s ease-out both;
        }
        .ztna-timeline-entry:nth-child(1) { animation-delay: 0ms; }
        .ztna-timeline-entry:nth-child(2) { animation-delay: 50ms; }
        .ztna-timeline-entry:nth-child(3) { animation-delay: 100ms; }
        .ztna-timeline-entry:nth-child(4) { animation-delay: 150ms; }
        .ztna-timeline-entry:nth-child(5) { animation-delay: 200ms; }
        .ztna-timeline-entry:nth-child(6) { animation-delay: 250ms; }
        .ztna-timeline-entry:nth-child(7) { animation-delay: 300ms; }
        .ztna-timeline-entry:nth-child(8) { animation-delay: 350ms; }
        @keyframes ztna-dot-pulse {
          0%, 100% { transform: scale(1); opacity: 1; }
          50%      { transform: scale(1.6); opacity: 0.5; }
        }
        .ztna-dot-pulse {
          animation: ztna-dot-pulse 2s ease-in-out infinite;
        }
      `}</style>

      <main
        className="pt-24 pb-16 px-10 min-h-screen transition-all duration-300 relative z-10"
        style={{ marginLeft: 'var(--sidebar-width, 18rem)' }}
      >
        <div className="max-w-[95%] mx-auto space-y-8">

          {/* ── Page Header ───────────────────────────────────────── */}
          <section className="flex flex-col md:flex-row justify-between items-start md:items-end gap-4">
            <div>
              <div className="flex items-center gap-3 mb-2">
                <div className="px-3 py-1 bg-cyan-500/10 border border-cyan-500/20 rounded-full flex items-center gap-2">
                  <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 ztna-dot-pulse" />
                  <span className="text-[10px] font-technical font-bold text-cyan-400 uppercase tracking-widest">Live</span>
                </div>
              </div>
              <h1 className="text-5xl font-black font-headline tracking-tighter text-white uppercase leading-none">
                ZTNA Trust <span className="text-primary">Posture</span>
              </h1>
              <p className="text-neutral-500 mt-2 font-technical text-sm max-w-xl">
                Real-time fleet compliance across the four pillars of Zero-Trust Network Architecture for AI Agents.
              </p>
            </div>
            {/* Quick stats */}
            <div className="flex items-center gap-4 bg-[#131313] p-4 rounded-2xl border border-white/5">
              <div className="text-right">
                <p className="text-[10px] font-technical text-neutral-500 uppercase tracking-widest">Fleet Size</p>
                <p className="text-2xl font-bold font-headline">{totalAgents || '—'}</p>
              </div>
              <div className="h-10 w-px bg-white/10" />
              <div className="text-right">
                <p className="text-[10px] font-technical text-neutral-500 uppercase tracking-widest">Quarantined</p>
                <p className={`text-2xl font-bold font-headline ${quarantinedFleet > 0 ? 'text-red-400' : 'text-neutral-500'}`}>
                  {quarantinedFleet}
                </p>
              </div>
              <div className="h-10 w-px bg-white/10" />
              <div className="text-right">
                <p className="text-[10px] font-technical text-neutral-500 uppercase tracking-widest">Mesh Nodes</p>
                <p className="text-2xl font-bold font-headline text-emerald-400">{meshNodesOnline}</p>
              </div>
            </div>
          </section>

          {/* ── Hero Section: Gauge + Pillar Cards ────────────────── */}
          <section className="grid grid-cols-12 gap-6">

            {/* Posture Gauge — left column */}
            <div className="col-span-12 lg:col-span-3 flex justify-center lg:justify-start">
              <div className="bg-[#0a0a0a] rounded-3xl border border-white/5 p-8 flex flex-col items-center justify-center shadow-2xl w-full">
                <PostureGauge score={postureScore} loading={loading} />
                <div className="mt-6 grid grid-cols-2 gap-4 w-full">
                  <div className="text-center">
                    <p className="text-xl font-black font-headline text-white">{failingAuth + failingAuthz + failingFabric + failingContain}</p>
                    <p className="text-[9px] font-technical text-neutral-600 uppercase tracking-widest">Anomalies</p>
                  </div>
                  <div className="text-center">
                    <p className="text-xl font-black font-headline text-white">{dashboard?.pending_hitl_count ?? 0}</p>
                    <p className="text-[9px] font-technical text-neutral-600 uppercase tracking-widest">Pending HITL</p>
                  </div>
                </div>
              </div>
            </div>

            {/* Four Pillar Cards — right columns */}
            <div className="col-span-12 lg:col-span-9 grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* Pillar 1: Continuous Authentication */}
              <PillarCard
                icon="verified_user"
                title="Continuous Authentication"
                subtitle="Non-Human Identity"
                metric={`${authPct}%`}
                detail={`${verifiedAgents} verified / ${totalAgents} total Ed25519 tokens`}
                detail2={unverifiedAgents > 0 ? `${unverifiedAgents} unverified identities` : undefined}
                pillarPct={authPillarPct}
                issues={authIssues}
                accentColor="text-blue-400"
                borderColor="border-blue-500/10"
                bgColor="bg-blue-500/10"
                loading={loading}
              />
              {/* Pillar 2: Fine-Grained Authorization */}
              <PillarCard
                icon="policy"
                title="Fine-Grained Authorization"
                subtitle="Micro-Perimeter"
                metric={`${policyCount}`}
                detail={`Active Wasm policies · ${healthyPolicies} healthy`}
                detail2={exceptionCount > 0 ? `${exceptionCount} active exceptions` : undefined}
                pillarPct={authzPillarPct}
                issues={authzIssues}
                accentColor="text-amber-400"
                borderColor="border-amber-500/10"
                bgColor="bg-amber-500/10"
                loading={loading}
              />
              {/* Pillar 3: Fabric Enforcement */}
              <PillarCard
                icon="shield"
                title="Fabric Enforcement"
                subtitle="Data Plane"
                metric={totalIntercepts.toLocaleString()}
                detail={`Intercepts today · ${blockRate}% block rate`}
                detail2={`${dashboard?.approved_today ?? 0} approved / ${dashboard?.blocked_today ?? 0} blocked`}
                pillarPct={fabricPillarPct}
                issues={fabricIssues}
                accentColor="text-orange-400"
                borderColor="border-orange-500/10"
                bgColor="bg-orange-500/10"
                loading={loading}
              />
              {/* Pillar 4: Cryptographic Containment */}
              <PillarCard
                icon="lock"
                title="Cryptographic Containment"
                subtitle="Gossip Mesh"
                metric={`${quarantinedFleet}`}
                detail={`Quarantined agents · ${totalCanaryTokens} canary tokens armed`}
                detail2={`${meshNodesOnline} mesh nodes online`}
                pillarPct={containPillarPct}
                issues={containIssues}
                accentColor="text-red-400"
                borderColor="border-red-500/10"
                bgColor="bg-red-500/10"
                loading={loading}
              />
            </div>
          </section>

          {/* ── Posture Issues & Remediation Panel ─────────────────── */}
          {/* Only renders when there are active issues — clean fleets see nothing */}
          {!loading && (authIssues.length > 0 || authzIssues.length > 0 || fabricIssues.length > 0 || containIssues.length > 0) && (
            <section className="bg-[#0a0a0a] rounded-2xl border border-red-500/10 overflow-hidden shadow-2xl">
              <div className="px-6 py-4 border-b border-red-500/10 flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="w-8 h-8 rounded-lg bg-red-500/10 border border-red-500/20 flex items-center justify-center">
                    <span className="material-symbols-outlined text-red-400 text-lg">troubleshoot</span>
                  </div>
                  <div>
                    <h3 className="font-headline font-bold text-sm text-white uppercase tracking-tight">Posture Issues & Remediation</h3>
                    <p className="text-[10px] font-technical text-neutral-500">Actionable items to improve your ZTNA compliance score</p>
                  </div>
                </div>
                <span className="text-[10px] font-technical font-bold text-red-400 bg-red-500/10 border border-red-500/20 px-2 py-0.5 rounded">
                  {authIssues.length + authzIssues.length + fabricIssues.length + containIssues.length} issue{(authIssues.length + authzIssues.length + fabricIssues.length + containIssues.length) !== 1 ? 's' : ''}
                </span>
              </div>
              <div className="p-6 grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* Auth issues */}
                {authIssues.length > 0 && (
                  <div className="p-4 bg-blue-500/5 border border-blue-500/10 rounded-xl space-y-2">
                    <div className="flex items-center gap-2">
                      <span className="material-symbols-outlined text-blue-400 text-[16px]">verified_user</span>
                      <h4 className="font-headline font-bold text-xs text-blue-400 uppercase">Authentication</h4>
                      <span className="text-[9px] font-technical text-red-400 bg-red-500/10 px-1.5 py-0.5 rounded">{authPillarPct}%</span>
                    </div>
                    {authIssues.map((issue, i) => (
                      <p key={i} className="text-[11px] font-technical text-neutral-400 pl-6">{issue}</p>
                    ))}
                  </div>
                )}
                {/* Authz issues */}
                {authzIssues.length > 0 && (
                  <div className="p-4 bg-amber-500/5 border border-amber-500/10 rounded-xl space-y-2">
                    <div className="flex items-center gap-2">
                      <span className="material-symbols-outlined text-amber-400 text-[16px]">policy</span>
                      <h4 className="font-headline font-bold text-xs text-amber-400 uppercase">Authorization</h4>
                      <span className="text-[9px] font-technical text-red-400 bg-red-500/10 px-1.5 py-0.5 rounded">{authzPillarPct}%</span>
                    </div>
                    {authzIssues.map((issue, i) => (
                      <p key={i} className="text-[11px] font-technical text-neutral-400 pl-6">{issue}</p>
                    ))}
                  </div>
                )}
                {/* Fabric issues */}
                {fabricIssues.length > 0 && (
                  <div className="p-4 bg-orange-500/5 border border-orange-500/10 rounded-xl space-y-2">
                    <div className="flex items-center gap-2">
                      <span className="material-symbols-outlined text-orange-400 text-[16px]">shield</span>
                      <h4 className="font-headline font-bold text-xs text-orange-400 uppercase">Fabric Enforcement</h4>
                      <span className="text-[9px] font-technical text-red-400 bg-red-500/10 px-1.5 py-0.5 rounded">{fabricPillarPct}%</span>
                    </div>
                    {fabricIssues.map((issue, i) => (
                      <p key={i} className="text-[11px] font-technical text-neutral-400 pl-6">{issue}</p>
                    ))}
                  </div>
                )}
                {/* Containment issues */}
                {containIssues.length > 0 && (
                  <div className="p-4 bg-red-500/5 border border-red-500/10 rounded-xl space-y-2">
                    <div className="flex items-center gap-2">
                      <span className="material-symbols-outlined text-red-400 text-[16px]">lock</span>
                      <h4 className="font-headline font-bold text-xs text-red-400 uppercase">Containment</h4>
                      <span className="text-[9px] font-technical text-red-400 bg-red-500/10 px-1.5 py-0.5 rounded">{containPillarPct}%</span>
                    </div>
                    {containIssues.map((issue, i) => (
                      <p key={i} className="text-[11px] font-technical text-neutral-400 pl-6">{issue}</p>
                    ))}
                  </div>
                )}
              </div>
            </section>
          )}

          {/* ── Per-Agent Posture Ledger ───────────────────────────── */}
          <section className="bg-[#0a0a0a] rounded-2xl border border-white/5 overflow-hidden shadow-2xl">
            {/* Ledger header + pillar filter tabs */}
            <div className="px-6 py-4 border-b border-white/5 flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                <span className="material-symbols-outlined text-primary">table_chart</span>
                <h3 className="font-headline font-bold text-lg text-white uppercase tracking-tight">
                  Per-Agent Runtime Posture Ledger
                </h3>
                <span className="text-[10px] font-technical text-neutral-500 px-2 py-0.5 bg-white/5 border border-white/10 rounded">
                  {filteredAgents.length} agent{filteredAgents.length !== 1 ? 's' : ''}
                </span>
              </div>
              {/* Pillar filter buttons */}
              <div className="flex p-1 bg-[#131313] border border-white/5 rounded-xl gap-0.5 flex-wrap">
                {([
                  { key: 'all' as PillarFilter, label: 'All Agents', count: postureAgents.length },
                  { key: 'auth' as PillarFilter, label: 'Failing Auth', count: failingAuth },
                  { key: 'authz' as PillarFilter, label: 'Failing Authz', count: failingAuthz },
                  { key: 'fabric' as PillarFilter, label: 'Failing Fabric', count: failingFabric },
                  { key: 'contain' as PillarFilter, label: 'Failing Contain', count: failingContain },
                ]).map(f => (
                  <button
                    key={f.key}
                    onClick={() => setPillarFilter(f.key)}
                    className={`px-3 py-1.5 rounded-lg font-technical text-[11px] font-bold uppercase tracking-wide transition-colors flex items-center gap-1.5 ${
                      pillarFilter === f.key
                        ? 'bg-orange-500/20 text-orange-400'
                        : 'text-neutral-500 hover:text-neutral-300'
                    }`}
                  >
                    {f.label}
                    {f.key !== 'all' && f.count > 0 && (
                      <span className={`w-4 h-4 rounded-full text-[9px] font-bold flex items-center justify-center ${
                        pillarFilter === f.key ? 'bg-orange-500/30 text-orange-300' : 'bg-white/5 text-neutral-600'
                      }`}>
                        {f.count}
                      </span>
                    )}
                  </button>
                ))}
              </div>
            </div>

            {/* Agent table */}
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-white/5 bg-white/[0.02]">
                    <th className="px-4 py-3 text-left text-[10px] font-technical uppercase tracking-wider text-neutral-500">Company</th>
                    <th className="px-4 py-3 text-left text-[10px] font-technical uppercase tracking-wider text-neutral-500">Agent</th>
                    <th className="px-4 py-3 text-left text-[10px] font-technical uppercase tracking-wider text-neutral-500">Trust</th>
                    <th className="px-4 py-3 text-center text-[10px] font-technical uppercase tracking-wider text-blue-400">Auth</th>
                    <th className="px-4 py-3 text-center text-[10px] font-technical uppercase tracking-wider text-amber-400">Authz</th>
                    <th className="px-4 py-3 text-center text-[10px] font-technical uppercase tracking-wider text-orange-400">Fabric</th>
                    <th className="px-4 py-3 text-center text-[10px] font-technical uppercase tracking-wider text-red-400">Contain</th>
                    <th className="px-4 py-3 text-center text-[10px] font-technical uppercase tracking-wider text-neutral-500">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5">
                  {loading ? (
                    <tr><td colSpan={8} className="px-4 py-12 text-center text-neutral-600 font-technical text-xs animate-pulse">Loading posture data...</td></tr>
                  ) : filteredAgents.length === 0 ? (
                    <tr><td colSpan={8} className="px-4 py-12 text-center text-neutral-600 font-technical text-xs">
                      {pillarFilter === 'all' ? 'No agents registered.' : 'No agents failing this pillar. ✓'}
                    </td></tr>
                  ) : (
                    filteredAgents.slice(0, 50).map(agent => (
                      <tr key={agent.id} className="hover:bg-white/[0.03] transition-colors">
                        <td className="px-4 py-3">
                          <p className="font-headline font-bold text-xs text-white">{agent.tenantName}</p>
                        </td>
                        <td className="px-4 py-3">
                          <p className="font-bold text-xs text-white">{agent.name}</p>
                          <p className="font-technical text-[10px] text-neutral-600 mt-0.5">{agent.id.substring(0, 18)}…</p>
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            <div className="w-10 h-1.5 bg-white/5 rounded-full overflow-hidden">
                              <div
                                className={`h-full rounded-full ${
                                  agent.trustTier === 'nominal' ? 'bg-emerald-500'
                                  : agent.trustTier === 'critical' ? 'bg-red-500'
                                  : 'bg-orange-500'
                                }`}
                                style={{ width: `${agent.trustScore}%` }}
                              />
                            </div>
                            <span className="font-technical text-xs text-neutral-300">{agent.trustScore}%</span>
                          </div>
                        </td>
                        {/* Pillar compliance badges — ✓ or ✗ with colour coding */}
                        {([
                          { ok: agent.authOk, okColor: 'text-blue-400 bg-blue-500/10', failColor: 'text-red-400 bg-red-500/10' },
                          { ok: agent.authzOk, okColor: 'text-amber-400 bg-amber-500/10', failColor: 'text-red-400 bg-red-500/10' },
                          { ok: agent.fabricOk, okColor: 'text-orange-400 bg-orange-500/10', failColor: 'text-red-400 bg-red-500/10' },
                          { ok: agent.containOk, okColor: 'text-emerald-400 bg-emerald-500/10', failColor: 'text-red-400 bg-red-500/10' },
                        ]).map((pillar, i) => (
                          <td key={i} className="px-4 py-3 text-center">
                            <span className={`inline-flex items-center justify-center w-7 h-7 rounded-lg text-xs font-bold font-technical ${
                              pillar.ok ? pillar.okColor : pillar.failColor
                            }`}>
                              {pillar.ok ? '✓' : '✗'}
                            </span>
                          </td>
                        ))}
                        <td className="px-4 py-3 text-center">
                          <Link
                            href={`/nodes?agent=${agent.id}`}
                            className="px-3 py-1 bg-white/5 hover:bg-white/10 border border-white/10 rounded-lg font-technical text-[10px] text-neutral-400 hover:text-white transition-colors"
                          >
                            View
                          </Link>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
              {/* Overflow indicator */}
              {filteredAgents.length > 50 && (
                <div className="px-4 py-3 border-t border-white/5 text-center">
                  <p className="text-[10px] font-technical text-neutral-500">
                    Showing 50 of {filteredAgents.length} agents ·{' '}
                    <Link href="/nodes" className="text-orange-400 hover:text-orange-300 transition-colors">
                      View full registry →
                    </Link>
                  </p>
                </div>
              )}
            </div>
          </section>

          {/* ── Real-Time Event Timeline ──────────────────────────── */}
          <section className="bg-[#0a0a0a] rounded-2xl border border-white/5 overflow-hidden shadow-2xl">
            <div className="px-6 py-4 border-b border-white/5 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <span className="material-symbols-outlined text-primary">timeline</span>
                <h3 className="font-headline font-bold text-lg text-white uppercase tracking-tight">
                  ZTNA Event Timeline
                </h3>
              </div>
              <div className="flex items-center gap-2">
                <span className="w-1.5 h-1.5 rounded-full bg-primary animate-ping" />
                <span className="text-[10px] font-technical text-primary uppercase tracking-widest">Real-Time</span>
              </div>
            </div>

            <div className="p-6 space-y-2 max-h-[400px] overflow-y-auto" style={{ scrollbarWidth: 'none' }}>
              {loading ? (
                <p className="text-neutral-600 font-technical text-xs animate-pulse text-center py-8">
                  Loading event timeline...
                </p>
              ) : dashboard?.recent_activity && dashboard.recent_activity.length > 0 ? (
                dashboard.recent_activity.map((entry, idx) => {
                  const classified = classifyEvent(entry);
                  const time = new Date(entry.created_at).toLocaleTimeString();
                  const detail = entry.source === 'alert'
                    ? (entry.summary ?? entry.action_type?.replace(/_/g, ' ') ?? 'Threat event')
                    : `${entry.action_type?.replace(/_/g, ' ')} → ${entry.target_api ?? 'Unknown'}`;
                  return (
                    <div
                      key={idx}
                      className={`ztna-timeline-entry flex items-start gap-4 p-3 rounded-xl border transition-all hover:bg-white/[0.02] ${classified.bgColor}`}
                    >
                      {/* Animated pillar dot */}
                      <div className="flex flex-col items-center gap-1 pt-1">
                        <span className={`w-2.5 h-2.5 rounded-full ${classified.dotColor} ztna-dot-pulse`} />
                        <div className="w-px h-6 bg-white/5" />
                      </div>
                      {/* Event icon */}
                      <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${classified.bgColor} border ${classified.color.replace('text-', 'border-').replace('400', '500/20')} flex-shrink-0 mt-0.5`}>
                        <span className={`material-symbols-outlined text-[16px] ${classified.color}`}>{classified.icon}</span>
                      </div>
                      {/* Event details */}
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className={`text-[10px] font-bold uppercase tracking-widest px-2 py-0.5 rounded border ${classified.bgColor} ${classified.color}`}>
                            {classified.pillar}
                          </span>
                          <span className="text-white font-technical text-sm font-bold">
                            {entry.agent_name ?? 'System'}
                          </span>
                        </div>
                        <p className="text-neutral-500 font-technical text-xs mt-1 truncate">{detail}</p>
                      </div>
                      {/* Timestamp */}
                      <div className="text-right shrink-0">
                        <p className="text-[10px] font-technical text-neutral-600">{time}</p>
                      </div>
                    </div>
                  );
                })
              ) : (
                <p className="text-neutral-600 font-technical text-xs text-center py-8">
                  No recent activity. Event timeline is clean.
                </p>
              )}
            </div>
          </section>

        </div>
      </main>
    </>
  );
}
