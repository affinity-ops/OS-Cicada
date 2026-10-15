// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { useEffect, useState, useCallback } from 'react';
import Link from 'next/link';

const CORE_API = process.env.NEXT_PUBLIC_CORE_API_URL || 'http://localhost:8000';

/* ───── Types ───── */
interface BiographyData {
  identity: {
    agent: Record<string, any>;
    tools: { tool_id: string; tool_name: string; tool_description: string }[];
    resource_policies: { resource_pattern: string; allowed_methods: string }[];
  };
  certification: {
    cert_event: Record<string, any> | null;
    swarm_history: number[];
    swarm_mean: number | null;
  };
  baseline: {
    calls_24h: number;
    calls_7d: number;
    alignment_scores: Record<string, number>;
    target_distribution: { target_api: string; call_count: number }[];
  };
  lifecycle: {
    events: any[];
    total_events: number;
    has_more: boolean;
  };
  execution: any[];
  hitl: any[];
  canary: any[];
  user_attribution: {
    user_subject: string;
    user_email: string | null;
    user_name: string | null;
    issuer: string | null;
    verified: boolean;
    action_count: number;
    first_seen: string;
    last_seen: string;
  }[];
}

/* ───── Helpers ───── */
function StatusBadge({ status }: { status: string }) {
  const cls =
    status === 'blocked' ? 'text-red-400 bg-red-500/10 border-red-500/20' :
    status === 'approved' ? 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20' :
    status === 'shadow_sandbox' ? 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20' :
    'text-neutral-400 bg-white/5 border-white/10';
  return <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${cls}`}>{status}</span>;
}

function Section({ title, icon, children }: { title: string; icon: string; children: React.ReactNode }) {
  return (
    <section className="bg-[#121212] border border-white/10 rounded-xl p-6 shadow-xl">
      <h2 className="text-lg font-bold text-orange-400 uppercase tracking-widest mb-4 flex items-center gap-2">
        <span className="material-symbols-outlined text-[20px]">{icon}</span>
        {title}
      </h2>
      {children}
    </section>
  );
}

function Field({ label, value }: { label: string; value: React.ReactNode }) {
  const isEmpty = value === null || value === undefined || value === '' || value === '—';
  return (
    <div>
      <span className="text-neutral-500 block text-xs uppercase mb-1">{label}</span>
      {isEmpty ? (
        <span className="inline-flex items-center gap-1.5 px-2 py-1 rounded-lg bg-amber-500/10 border border-amber-500/20 text-amber-400 text-[10px] font-bold uppercase tracking-wider cursor-default" title={`${label} has not been configured for this agent`}>
          <span className="material-symbols-outlined text-[12px]">warning</span>
          Config Required
        </span>
      ) : (
        <span className="text-white text-sm">{value}</span>
      )}
    </div>
  );
}

/* ───── Main Component ───── */
export function AgentProfilePage({ agentId }: { agentId: string }) {
  const [data, setData] = useState<BiographyData | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [timelineEvents, setTimelineEvents] = useState<any[]>([]);
  const [timelineCursor, setTimelineCursor] = useState<string | null>(null);
  const [hasMoreTimeline, setHasMoreTimeline] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);
  const [actionInProgress, setActionInProgress] = useState<string | null>(null);

  /* ── Load Biography ── */
  const fetchBiography = useCallback(async () => {
    try {
      const res = await fetch(`${CORE_API}/api/v1/agents/${agentId}/biography`, {
        headers: { Accept: 'application/json' },
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const json = await res.json();
      if (json.status !== 'success') throw new Error('API returned error');
      setData(json.data);
      setTimelineEvents(json.data.lifecycle.events);
      setHasMoreTimeline(json.data.lifecycle.has_more);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setIsLoading(false);
    }
  }, [agentId]);

  useEffect(() => { fetchBiography(); }, [fetchBiography]);

  /* ── Load More Timeline ── */
  const loadMoreTimeline = async () => {
    if (!hasMoreTimeline || loadingMore) return;
    const lastEvent = timelineEvents[timelineEvents.length - 1];
    if (!lastEvent) return;
    setLoadingMore(true);
    try {
      const res = await fetch(`${CORE_API}/api/v1/agents/${agentId}/timeline?cursor=${encodeURIComponent(lastEvent.created_at)}&limit=50`, {
        headers: { Accept: 'application/json' },
      });
      const json = await res.json();
      if (json.status === 'success') {
        setTimelineEvents(prev => [...prev, ...json.events]);
        setHasMoreTimeline(json.has_more);
      }
    } catch (e) {
      console.error('Timeline pagination failed:', e);
    }
    setLoadingMore(false);
  };

  /* ── Agent Controls ── */
  const quarantineAgent = async () => {
    setActionInProgress('quarantine');
    try {
      await fetch(`${CORE_API}/api/v1/admin/agents/${agentId}/universal-revoke`, {
        method: 'POST', headers: { Accept: 'application/json' },
      });
      fetchBiography(); // refresh
    } catch (e) {
      console.error('Agent universal revoke failed:', e);
    }
    setActionInProgress(null);
  };

  /* ── Loading / Error States ── */
  if (isLoading && !data) return <div className="text-white p-10 font-technical animate-pulse">Loading agent biography…</div>;
  if (error) return (
    <div className="p-10 max-w-xl mx-auto">
      <div className="bg-neutral-900 border border-red-500/30 rounded-2xl p-8 text-center">
        <span className="material-symbols-outlined text-5xl text-red-500/50 block mb-4">search_off</span>
        <h2 className="text-xl font-headline font-black text-white mb-2">Agent Not Found</h2>
        <p className="text-sm text-neutral-400 mb-4">
          No biography exists for agent <code className="bg-white/5 px-2 py-0.5 rounded text-xs text-orange-400">{agentId}</code>.
        </p>
        <p className="text-xs text-neutral-500 mb-6">
          This can happen when viewing a CIBA test alert — test holds use a synthetic agent ID that doesn&apos;t exist in the registry.
        </p>
        <Link href="/registry" className="inline-flex items-center gap-2 px-6 py-2.5 bg-orange-500/10 border border-orange-500/30 text-orange-400 rounded-xl text-xs font-bold hover:bg-orange-500/20 transition-all">
          <span className="material-symbols-outlined text-[16px]">arrow_back</span>
          Back to Agent Registry
        </Link>
      </div>
    </div>
  );
  if (!data) return null;

  const agent = data.identity.agent;
  const isRevoked = !!agent.revoked_at;
  const lifecycleState = isRevoked ? 'REVOKED' : agent.certified_at ? 'ACTIVE' : 'REGISTERED';

  return (
    <div className="p-6 space-y-8 text-neutral-300 font-technical">

      {/* ── Header ── */}
      <div className="flex justify-between items-center border-b border-white/10 pb-4">
        <div>
          <h1 className="text-3xl font-black text-white">{agent.name ?? `Agent-${agentId.substring(0,8)}`}</h1>
          <div className="flex items-center gap-3 mt-2">
            <span className={`px-3 py-1 rounded-lg text-xs font-bold uppercase tracking-wider border ${
              lifecycleState === 'REVOKED' ? 'text-red-400 bg-red-500/10 border-red-500/20' :
              lifecycleState === 'ACTIVE' ? 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20' :
              'text-yellow-400 bg-yellow-500/10 border-yellow-500/20'
            }`}>{lifecycleState}</span>
            <span className="text-xs text-neutral-500">{agent.tenant_name}</span>
            <span className="text-xs text-neutral-600">•</span>
            <span className="text-xs text-neutral-500">Trust: <strong className="text-orange-400">{agent.trust_tier}</strong></span>
            <span className="text-xs text-neutral-600">•</span>
            {/* Governance Score Ring */}
            {(() => {
              let gs = 0;
              if (agent.owner_name) gs += 10;
              if (agent.declared_purpose) gs += 10;
              if (agent.criticality_level) gs += 10;
              if (agent.data_classification) gs += 10;
              if (agent.expected_velocity) gs += 10;
              if (agent.monthly_budget_usd) gs += 10;
              try { const f = JSON.parse(agent.regulatory_frameworks ?? '[]'); if (Array.isArray(f) && f.length > 0) gs += 10; } catch (e) { console.warn('Failed to parse regulatory_frameworks:', e); }
              const isHigh = ['high', 'critical'].includes(agent.criticality_level);
              if (isHigh && agent.hitl_enabled) gs += 20; else if (!isHigh) gs += 20;
              // Drift check — award 0 until real drift detection is wired from ledger data.
              // A conservative default: agents only earn this score when actual alignment
              // data confirms they are within threshold over the last 24h.
              // gs += 0;
              const gsColor = gs >= 80 ? 'text-emerald-400' : gs >= 50 ? 'text-orange-400' : 'text-red-400';
              const gsBg = gs >= 80 ? 'border-emerald-500/30' : gs >= 50 ? 'border-orange-500/30' : 'border-red-500/30';
              return (
                <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg border bg-white/5 ${gsBg}`}>
                  <span className="text-[10px] text-neutral-500 uppercase tracking-widest">Gov</span>
                  <span className={`text-sm font-black ${gsColor}`}>{gs}</span>
                  <svg width="18" height="18" viewBox="0 0 36 36" className="-ml-0.5">
                    <path d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                      fill="none" stroke="rgba(255,255,255,0.1)" strokeWidth="3" />
                    <path d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                      fill="none"
                      stroke={gs >= 80 ? '#34d399' : gs >= 50 ? '#fb923c' : '#f87171'}
                      strokeWidth="3"
                      strokeDasharray={`${gs}, 100`}
                      strokeLinecap="round" />
                  </svg>
                </span>
              );
            })()}
          </div>
        </div>
        <div className="flex gap-3">
          <button
            onClick={quarantineAgent}
            disabled={actionInProgress === 'quarantine' || isRevoked}
            className="bg-red-600/20 text-red-400 border border-red-500/30 px-6 py-2 rounded-lg font-bold uppercase tracking-wider text-xs hover:bg-red-600/30 transition-colors disabled:opacity-40"
            title="Quarantines agent internally and fires outbound CAEP revocation events to configured external IdPs"
          >
            {actionInProgress === 'quarantine' ? 'Quarantining…' : '⚡ Universal Revoke'}
          </button>
        </div>
      </div>

      {/* ── Section 1: Identity & Birth ── */}
      <Section title="Identity & Birth" icon="badge">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm mb-6">
          <Field label="Agent ID" value={<span className="truncate block text-xs font-mono">{agent.id}</span>} />
          <Field label="Tenant" value={agent.tenant_name} />
          <Field label="Type" value={agent.agent_type} />
          <Field label="Role" value={agent.role} />
          <Field label="Version" value={agent.version} />
          <Field label="Purpose" value={agent.declared_purpose} />
          <Field label="HITL Enabled" value={agent.hitl_enabled ? 'Yes ✓' : 'No'} />
          <Field label="EVAR Hash" value={<span className="truncate block text-xs font-mono">{agent.pub_key_hash?.substring(0, 40)}…</span>} />
          <Field label="Owner" value={`${agent.owner_name ?? '—'} (${agent.owner_email ?? '—'})`} />
          <Field label="Business Unit" value={agent.business_unit} />
          <Field label="Data Classification" value={agent.data_classification} />
          <Field label="Criticality" value={
            <span className={`font-bold uppercase text-xs tracking-wider px-2 py-0.5 rounded border ${
              agent.criticality_level === 'critical' ? 'text-red-400 bg-red-500/10 border-red-500/20' :
              agent.criticality_level === 'high' ? 'text-orange-400 bg-orange-500/10 border-orange-500/20' :
              'text-neutral-400 bg-white/5 border-white/10'
            }`}>{agent.criticality_level ?? 'Unclassified'}</span>
          } />
        </div>
      </Section>

      {/* ── Section 1b: Operational Guardrails ── */}
      <Section title="Operational Guardrails" icon="shield">
        {/* Velocity Leash */}
        <div className="mb-6">
          <p className="text-neutral-500 text-[10px] uppercase tracking-widest font-bold mb-3">Agent Limits — "The Leash"</p>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* Velocity Gauge */}
            <div className="bg-white/[0.03] border border-white/10 rounded-xl p-4">
              <p className="text-neutral-500 text-[10px] uppercase tracking-wider mb-2">Max Velocity</p>
              {agent.expected_velocity ? (
                <>
                  <div className="flex items-end gap-2 mb-2">
                    <span className="text-2xl font-black text-white">{agent.expected_velocity}</span>
                    <span className="text-xs text-neutral-500 pb-1">calls/hr limit</span>
                  </div>
                  {(() => {
                    const hourlyRate = data.baseline.calls_24h > 0 ? Math.round(data.baseline.calls_24h / 24) : 0;
                    const pct = Math.min((hourlyRate / agent.expected_velocity) * 100, 100);
                    const isOver = hourlyRate > agent.expected_velocity;
                    return (
                      <>
                        <div className="w-full h-3 bg-white/5 rounded-full overflow-hidden mb-1">
                          <div className={`h-full rounded-full transition-all ${isOver ? 'bg-red-500' : pct > 75 ? 'bg-orange-500' : 'bg-emerald-500'}`} style={{ width: `${pct}%` }} />
                        </div>
                        <p className={`text-[10px] font-bold ${isOver ? 'text-red-400' : 'text-neutral-500'}`}>
                          Current: {hourlyRate}/hr ({isOver ? '⚠ EXCEEDING LIMIT' : `${pct.toFixed(0)}% of limit`})
                        </p>
                      </>
                    );
                  })()}
                </>
              ) : (
                <p className="text-neutral-600 text-xs">No velocity limit configured</p>
              )}
            </div>

            {/* Monthly Budget */}
            <div className="bg-white/[0.03] border border-white/10 rounded-xl p-4">
              <p className="text-neutral-500 text-[10px] uppercase tracking-wider mb-2">Monthly Budget Cap</p>
              {agent.monthly_budget_usd ? (
                <>
                  <span className="text-2xl font-black text-white">${Number(agent.monthly_budget_usd).toLocaleString(undefined, { minimumFractionDigits: 2 })}</span>
                  <span className="text-xs text-neutral-500 ml-1">/month</span>
                  {agent.cost_center && (
                    <p className="text-[10px] text-neutral-500 mt-1">Cost Centre: <span className="text-neutral-300 font-bold">{agent.cost_center}</span></p>
                  )}
                </>
              ) : (
                <p className="text-neutral-600 text-xs">No budget cap set</p>
              )}
            </div>

            {/* Regulatory Frameworks */}
            <div className="bg-white/[0.03] border border-white/10 rounded-xl p-4">
              <p className="text-neutral-500 text-[10px] uppercase tracking-wider mb-2">Regulatory Frameworks</p>
              {(() => {
                const frameworks = agent.regulatory_frameworks
                  ? (typeof agent.regulatory_frameworks === 'string' ? JSON.parse(agent.regulatory_frameworks) : agent.regulatory_frameworks)
                  : [];
                return frameworks.length > 0 ? (
                  <div className="flex gap-2 flex-wrap">
                    {frameworks.map((f: string) => (
                      <span key={f} className={`px-2 py-1 rounded text-[10px] font-bold uppercase border ${
                        f === 'GDPR' ? 'text-blue-400 bg-blue-500/10 border-blue-500/20' :
                        f === 'HIPAA' ? 'text-red-400 bg-red-500/10 border-red-500/20' :
                        f === 'SOC2' ? 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20' :
                        'text-neutral-400 bg-white/5 border-white/10'
                      }`}>{f}</span>
                    ))}
                  </div>
                ) : (
                  <p className="text-neutral-600 text-xs">No frameworks declared</p>
                );
              })()}
            </div>
          </div>
        </div>

        {/* Custom Guardrails */}
        {agent.custom_guardrails && (() => {
          const guardrails = typeof agent.custom_guardrails === 'string' ? JSON.parse(agent.custom_guardrails) : agent.custom_guardrails;
          if (!guardrails || (Array.isArray(guardrails) && guardrails.length === 0)) return null;
          const items = Array.isArray(guardrails) ? guardrails : [guardrails];
          return (
            <div className="mb-6">
              <p className="text-neutral-500 text-[10px] uppercase tracking-widest font-bold mb-3">Custom Guardrails</p>
              <div className="space-y-2">
                {items.map((g: any, i: number) => (
                  <div key={i} className="flex items-start gap-3 bg-orange-500/5 border border-orange-500/20 rounded-lg p-3">
                    <span className="material-symbols-outlined text-orange-400 text-[16px] flex-shrink-0 mt-0.5">rule</span>
                    <p className="text-xs text-orange-200">{typeof g === 'string' ? g : JSON.stringify(g)}</p>
                  </div>
                ))}
              </div>
            </div>
          );
        })()}

        {/* Registration Purpose & Impact */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
          {agent.registration_purpose_statement && (
            <div className="bg-white/[0.03] border border-white/10 rounded-xl p-4">
              <p className="text-neutral-500 text-[10px] uppercase tracking-wider mb-2">Registration Purpose Statement</p>
              <p className="text-xs text-neutral-300 leading-relaxed">{agent.registration_purpose_statement}</p>
            </div>
          )}
          {agent.potential_impact && (
            <div className="bg-white/[0.03] border border-white/10 rounded-xl p-4">
              <p className="text-neutral-500 text-[10px] uppercase tracking-wider mb-2">Impact Assessment</p>
              <pre className="text-xs text-neutral-300 leading-relaxed whitespace-pre-wrap">{typeof agent.potential_impact === 'string' ? agent.potential_impact : JSON.stringify(agent.potential_impact, null, 2)}</pre>
            </div>
          )}
        </div>

        {/* HITL Webhook */}
        {agent.hitl_enabled && agent.hitl_webhook_url && (
          <div className="bg-sky-500/5 border border-sky-500/20 rounded-lg p-3 flex items-center gap-3">
            <span className="material-symbols-outlined text-sky-400 text-[16px]">webhook</span>
            <div>
              <p className="text-[10px] text-sky-400 uppercase font-bold tracking-wider">HITL Webhook Endpoint</p>
              <p className="text-xs text-neutral-300 font-mono truncate">{agent.hitl_webhook_url}</p>
            </div>
          </div>
        )}
      </Section>

      {/* ── Section 1c: Tool Access Manifest ── */}
      <Section title="Tool Access Manifest" icon="build">
        {data.identity.tools.length > 0 ? (
          <>
            <p className="text-neutral-500 text-[10px] uppercase tracking-widest font-bold mb-3">Authorised Capabilities ({data.identity.tools.length})</p>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mb-6">
              {data.identity.tools.map(t => (
                <div key={t.tool_id} className="flex items-start gap-3 bg-emerald-500/5 border border-emerald-500/20 rounded-xl p-4">
                  <span className="material-symbols-outlined text-emerald-400 text-[18px] flex-shrink-0 mt-0.5">check_circle</span>
                  <div className="min-w-0">
                    <p className="text-sm font-bold text-emerald-300">{t.tool_name}</p>
                    <p className="text-[10px] text-neutral-500 font-mono truncate">{t.tool_id}</p>
                    {t.tool_description && <p className="text-xs text-neutral-400 mt-1">{t.tool_description}</p>}
                  </div>
                </div>
              ))}
            </div>
          </>
        ) : (
          <div className="bg-yellow-500/5 border border-yellow-500/20 rounded-xl p-4 flex items-center gap-3">
            <span className="material-symbols-outlined text-yellow-400 text-[18px]">warning</span>
            <p className="text-xs text-yellow-300">No declared tools. This agent has not registered any capabilities — it may be operating with implicit access only.</p>
          </div>
        )}

        {/* Resource Policies — Permission boundaries */}
        <p className="text-neutral-500 text-[10px] uppercase tracking-widest font-bold mb-3 mt-6">Resource Policies — Fine-Grained Access (FGA)</p>
        {data.identity.resource_policies.length > 0 ? (
          <div className="space-y-2">
            {data.identity.resource_policies.map((p, i) => {
              const methods: string[] = typeof p.allowed_methods === 'string' ? JSON.parse(p.allowed_methods) : (Array.isArray(p.allowed_methods) ? p.allowed_methods : []);
              return (
                <div key={i} className="flex items-center gap-3 bg-white/[0.02] border border-white/5 rounded-lg p-3">
                  <span className="material-symbols-outlined text-blue-400 text-[16px] flex-shrink-0">lock_open</span>
                  <div className="flex gap-1.5 flex-shrink-0">
                    {methods.map(m => (
                      <span key={m} className={`px-2 py-0.5 rounded text-[9px] font-black uppercase tracking-wider ${
                        m === 'GET' ? 'text-emerald-400 bg-emerald-500/10' :
                        m === 'POST' ? 'text-blue-400 bg-blue-500/10' :
                        m === 'PUT' || m === 'PATCH' ? 'text-orange-400 bg-orange-500/10' :
                        m === 'DELETE' ? 'text-red-400 bg-red-500/10' :
                        'text-neutral-400 bg-white/5'
                      }`}>{m}</span>
                    ))}
                  </div>
                  <span className="text-xs text-neutral-300 truncate font-mono">{p.resource_pattern}</span>
                </div>
              );
            })}
          </div>
        ) : (
          <div className="bg-red-500/5 border border-red-500/20 rounded-xl p-4 flex items-center gap-3">
            <span className="material-symbols-outlined text-red-400 text-[18px]">block</span>
            <p className="text-xs text-red-300">No resource policies configured. This agent is subject to scope-level enforcement only — no fine-grained URL-pattern restrictions are active.</p>
          </div>
        )}
      </Section>

      {/* ── Section 2: Certification ── */}
      <Section title="Certification" icon="verified">
        {data.certification.cert_event ? (
          <div className="space-y-4 text-sm">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <Field label="Certified At" value={agent.certified_at ? new Date(agent.certified_at).toLocaleDateString() : 'Pending'} />
              <Field label="Trust Tier" value={<span className="text-emerald-400 font-bold">{agent.trust_tier}</span>} />
              <Field label="Swarm Score (at cert)" value={data.certification.cert_event.swarm_confidence_score != null ? `${(data.certification.cert_event.swarm_confidence_score * 100).toFixed(0)}%` : '—'} />
              <Field label="Recertification Due" value={agent.recertification_due_at ? new Date(agent.recertification_due_at).toLocaleDateString() : '—'} />
            </div>
            {data.certification.cert_event.policy_violations && (
              <div className="p-3 bg-red-500/5 border border-red-500/20 rounded-xl">
                <p className="text-[10px] uppercase font-bold text-red-500 tracking-widest mb-1">Anomalies at Certification</p>
                <p className="text-xs text-red-300">{data.certification.cert_event.policy_violations}</p>
              </div>
            )}
          </div>
        ) : (
          <p className="text-neutral-500 text-sm">No certification event recorded. This agent may not have been through swarm certification yet.</p>
        )}
        {data.certification.swarm_history.length > 0 && (
          <div className="mt-4">
            <p className="text-neutral-500 text-xs uppercase mb-2">Swarm Confidence Trend (last 20 calls)</p>
            <div className="flex items-end gap-1 h-16">
              {data.certification.swarm_history.map((score, i) => (
                <div key={i} className="flex-1 rounded-t" style={{
                  height: `${Math.max(score * 100, 4)}%`,
                  backgroundColor: score < 0.5 ? 'rgb(248, 113, 113)' : score < 0.8 ? 'rgb(251, 191, 36)' : 'rgb(52, 211, 153)',
                }} />
              ))}
            </div>
            <p className="text-[10px] text-neutral-500 mt-1">Mean: <strong className="text-white">{data.certification.swarm_mean != null ? `${(data.certification.swarm_mean * 100).toFixed(1)}%` : '—'}</strong></p>
          </div>
        )}
      </Section>

      {/* ── Section 3: Behavioural Baseline ── */}
      <Section title="Behavioural Baseline" icon="insights">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm mb-6">
          <Field label="Calls (24h)" value={<span className="text-xl font-bold">{data.baseline.calls_24h.toLocaleString()}</span>} />
          <Field label="Calls (7d)" value={<span className="text-xl font-bold">{data.baseline.calls_7d.toLocaleString()}</span>} />
          <Field label="Daily Average" value={<span className="text-xl font-bold">{data.baseline.calls_7d > 0 ? Math.round(data.baseline.calls_7d / 7).toLocaleString() : '0'}</span>} />
          <Field label="Velocity Ratio" value={
            <span className={`text-xl font-bold ${data.baseline.calls_7d > 0 && (data.baseline.calls_24h / (data.baseline.calls_7d / 7)) > 2 ? 'text-red-400' : 'text-emerald-400'}`}>
              {data.baseline.calls_7d > 0 ? `${(data.baseline.calls_24h / (data.baseline.calls_7d / 7)).toFixed(1)}x` : '—'}
            </span>
          } />
        </div>
        {data.baseline.target_distribution.length > 0 && (
          <div className="mt-4">
            <p className="text-neutral-500 text-xs uppercase mb-3">Target API Distribution (Top 10)</p>
            <div className="space-y-2">
              {data.baseline.target_distribution.map((t, i) => {
                const maxCount = data.baseline.target_distribution[0].call_count;
                return (
                  <div key={i} className="flex items-center gap-3">
                    <span className="text-xs text-neutral-400 w-48 truncate">{t.target_api}</span>
                    <div className="flex-1 h-4 bg-white/5 rounded-full overflow-hidden">
                      <div className="h-full bg-orange-500/40 rounded-full" style={{ width: `${(t.call_count / maxCount) * 100}%` }} />
                    </div>
                    <span className="text-xs font-bold text-white w-12 text-right">{t.call_count}</span>
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </Section>

      {/* ── Section 4: Lifecycle Timeline ── */}
      <Section title="Lifecycle Timeline" icon="timeline">
        <p className="text-xs text-neutral-500 mb-4">{data.lifecycle.total_events.toLocaleString()} total events recorded</p>
        <div className="space-y-2 max-h-[400px] overflow-y-auto pr-2" style={{ scrollbarWidth: 'thin' }}>
          {timelineEvents.map((evt, i) => (
            <div key={`${evt.trace_id}-${i}`} className="flex items-center gap-3 p-2 bg-white/[0.02] rounded-lg hover:bg-white/5 transition-colors">
              <div className={`w-2 h-2 rounded-full flex-shrink-0 ${
                evt.status === 'blocked' ? 'bg-red-500' :
                evt.status === 'approved' ? 'bg-emerald-500' :
                'bg-yellow-500'
              }`} />
              <span className="text-[10px] text-neutral-500 w-32 flex-shrink-0">{new Date(evt.created_at).toLocaleString()}</span>
              <span className="text-xs font-bold text-neutral-300 w-40 flex-shrink-0">{evt.action_type}</span>
              <StatusBadge status={evt.status} />
              <span className="text-xs text-neutral-500 truncate flex-1">{evt.target_api}</span>
              {evt.reasoning_trace && (
                <span className="material-symbols-outlined text-[14px] text-sky-400" title="Has reasoning trace">psychology</span>
              )}
            </div>
          ))}
        </div>
        {hasMoreTimeline && (
          <button onClick={loadMoreTimeline} disabled={loadingMore}
            className="mt-4 w-full bg-white/5 border border-white/10 text-white px-6 py-2 rounded-xl uppercase text-xs tracking-widest font-bold hover:bg-white/10 transition-colors disabled:opacity-50">
            {loadingMore ? 'Loading…' : 'Load More History'}
          </button>
        )}
      </Section>

      {/* ── Section 5: Execution Deep-Dive ── */}
      <Section title="Execution Deep-Dive" icon="query_stats">
        <p className="text-xs text-neutral-500 mb-4">Last 100 calls with full admission check results</p>
        <div className="overflow-x-auto">
          <table className="min-w-full text-left text-xs">
            <thead className="bg-[#1a1a1a] border-b border-white/10 text-neutral-500 uppercase tracking-widest">
              <tr>
                <th className="py-3 px-3">Time</th>
                <th className="py-3 px-3">Action</th>
                <th className="py-3 px-3">Target</th>
                <th className="py-3 px-3">Status</th>
                <th className="py-3 px-3">Swarm</th>
                <th className="py-3 px-3">Alignment</th>
                <th className="py-3 px-3">Chain-of-Thought</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {data.execution.map((call: any, i: number) => (
                <tr key={`exec-${call.trace_id}-${i}`} className="hover:bg-white/[0.02]">
                  <td className="py-2 px-3 whitespace-nowrap">{new Date(call.created_at).toLocaleString()}</td>
                  <td className="py-2 px-3">{call.action_type}</td>
                  <td className="py-2 px-3 truncate max-w-[200px]">{call.target_api}</td>
                  <td className="py-2 px-3"><StatusBadge status={call.status} /></td>
                  <td className={`py-2 px-3 font-bold ${call.swarm_confidence_score != null && call.swarm_confidence_score < 0.5 ? 'text-red-400' : 'text-emerald-400'}`}>
                    {call.swarm_confidence_score != null ? `${(call.swarm_confidence_score * 100).toFixed(0)}%` : '—'}
                  </td>
                  <td className={`py-2 px-3 font-bold ${call.semantic_alignment_score != null && call.semantic_alignment_score < 0.6 ? 'text-amber-400' : 'text-sky-400'}`}>
                    {call.semantic_alignment_score != null ? `${(call.semantic_alignment_score * 100).toFixed(0)}%` : '—'}
                  </td>
                  <td className="py-2 px-3">
                    {call.reasoning_trace ? (
                      <span className="text-sky-400 text-[10px] cursor-help" title={call.reasoning_trace}>
                        <span className="material-symbols-outlined text-[12px]">psychology</span> View
                      </span>
                    ) : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Section>

      {/* ── Section 6: HITL History ── */}
      <Section title="HITL History" icon="pending_actions">
        {data.hitl.length > 0 ? (
          <div className="space-y-3">
            {data.hitl.map((evt: any, i: number) => (
              <div key={`hitl-${evt.trace_id}-${i}`} className={`p-4 rounded-xl border ${
                evt.action_type === 'hitl_approved' ? 'bg-emerald-500/5 border-emerald-500/20' :
                evt.action_type === 'hitl_rejected' ? 'bg-red-500/5 border-red-500/20' :
                evt.action_type === 'hitl_timeout' ? 'bg-yellow-500/5 border-yellow-500/20' :
                'bg-blue-500/5 border-blue-500/20 animate-pulse'
              }`}>
                <div className="flex justify-between items-center">
                  <div className="flex items-center gap-3">
                    <span className={`material-symbols-outlined text-[18px] ${
                      evt.action_type === 'hitl_approved' ? 'text-emerald-400' :
                      evt.action_type === 'hitl_rejected' ? 'text-red-400' :
                      evt.action_type === 'hitl_timeout' ? 'text-yellow-400' :
                      'text-blue-400'
                    }`}>
                      {evt.action_type === 'hitl_approved' ? 'check_circle' :
                       evt.action_type === 'hitl_rejected' ? 'cancel' :
                       evt.action_type === 'hitl_timeout' ? 'schedule' : 'hourglass_top'}
                    </span>
                    <div>
                      <p className="text-sm font-bold text-white">{evt.action_type.replace('hitl_', '').toUpperCase()}</p>
                      <p className="text-[10px] text-neutral-500">{evt.target_api}</p>
                    </div>
                  </div>
                  <span className="text-xs text-neutral-500">{new Date(evt.created_at).toLocaleString()}</span>
                </div>
                {evt.policy_violations && (
                  <p className="mt-2 text-xs text-neutral-400">Reason: {evt.policy_violations}</p>
                )}
              </div>
            ))}
          </div>
        ) : (
          <p className="text-neutral-500 text-sm">No HITL events recorded for this agent.</p>
        )}
      </Section>

      {/* ── Section 7: Canary Token Status ── */}
      <Section title="Canary Token Status" icon="vpn_key">
        {data.canary.length > 0 ? (
          <div className="space-y-2">
            {data.canary.map((evt: any, i: number) => (
              <div key={`canary-${evt.trace_id}-${i}`} className={`flex items-center gap-3 p-3 rounded-lg border ${
                evt.action_type === 'canary_triggered' ? 'bg-red-500/5 border-red-500/20' :
                evt.action_type === 'canary_issued' ? 'bg-emerald-500/5 border-emerald-500/20' :
                'bg-neutral-500/5 border-neutral-500/20'
              }`}>
                <span className={`material-symbols-outlined text-[18px] ${
                  evt.action_type === 'canary_triggered' ? 'text-red-400' :
                  evt.action_type === 'canary_issued' ? 'text-emerald-400' : 'text-neutral-400'
                }`}>
                  {evt.action_type === 'canary_triggered' ? 'warning' : evt.action_type === 'canary_issued' ? 'key' : 'key_off'}
                </span>
                <div className="flex-1">
                  <p className="text-sm font-bold text-white">{evt.action_type.replace('canary_', '').toUpperCase()}</p>
                  <p className="text-[10px] text-neutral-500">{new Date(evt.created_at).toLocaleString()}</p>
                </div>
                <StatusBadge status={evt.status} />
              </div>
            ))}
          </div>
        ) : (
          <p className="text-neutral-500 text-sm">No canary tokens have been issued, triggered, or revoked for this agent.</p>
        )}
      </Section>

      {/* ── Section 8: User-Context Attribution (H2.1) ── */}
      <Section title="User-Context Attribution" icon="person_pin">
        {data.user_attribution && data.user_attribution.length > 0 ? (
          <>
            <p className="text-xs text-neutral-500 mb-4">
              End-users on whose behalf this agent has acted. Answers &ldquo;Agent X performed this action on behalf of Customer Y.&rdquo;
            </p>
            <div className="space-y-2">
              {data.user_attribution.map((ua, i) => (
                <div key={`ua-${i}`} className="flex items-center justify-between p-4 bg-white/[0.02] border border-white/5 rounded-xl hover:border-indigo-500/20 transition-colors">
                  <div className="flex items-center gap-3">
                    <div className={`w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0 ${
                      ua.verified ? 'bg-emerald-500/10 border border-emerald-500/20' : 'bg-amber-500/10 border border-amber-500/20'
                    }`}>
                      <span className={`material-symbols-outlined text-[18px] ${
                        ua.verified ? 'text-emerald-400' : 'text-amber-400'
                      }`}>
                        {ua.verified ? 'verified_user' : 'person'}
                      </span>
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <p className="text-sm font-bold text-white">
                          {ua.user_name ?? ua.user_email ?? ua.user_subject}
                        </p>
                        <span className={`px-2 py-0.5 rounded text-[9px] font-bold uppercase border ${
                          ua.verified
                            ? 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20'
                            : 'text-amber-400 bg-amber-500/10 border-amber-500/20'
                        }`}>
                          {ua.verified ? 'JWT Verified' : 'Unverified'}
                        </span>
                      </div>
                      <p className="text-[10px] text-neutral-500">
                        {ua.user_email && ua.user_email !== ua.user_subject && <>{ua.user_email} · </>}
                        {ua.issuer && <>IdP: {ua.issuer} · </>}
                        Sub: <span className="font-mono">{ua.user_subject}</span>
                      </p>
                    </div>
                  </div>
                  <div className="text-right">
                    <p className="text-lg font-black text-white">{ua.action_count.toLocaleString()}</p>
                    <p className="text-[10px] text-neutral-500">actions</p>
                    <p className="text-[9px] text-neutral-600 mt-1">
                      {new Date(ua.first_seen).toLocaleDateString()} – {new Date(ua.last_seen).toLocaleDateString()}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          </>
        ) : (
          <div className="bg-white/[0.02] border border-white/5 rounded-xl p-6 text-center">
            <span className="material-symbols-outlined text-3xl text-neutral-700 mb-2 block">person_off</span>
            <p className="text-neutral-500 text-sm">No user-context attribution data recorded.</p>
            <p className="text-[10px] text-neutral-600 mt-1">
              Agent SDKs can provide the <code className="bg-white/5 px-1 rounded">X-Cicada-User-Context</code> header to enable &ldquo;on behalf of&rdquo; attribution.
            </p>
          </div>
        )}
      </Section>

    </div>
  );
}
