// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

'use client';

import React, { useEffect, useState } from 'react';
import Link from 'next/link';
import { useParams } from 'next/navigation';
import { useSession } from '../../layout';

const CORE_API = process.env.NEXT_PUBLIC_CORE_API_URL || 'http://localhost:8000';

interface AgentDetail {
  id: string;
  name: string;
  description: string;
  version: string;
  agent_type: string;
  role: string;
  status?: string;
  approval_status?: string;
  trust_tier?: string;
  criticality_level?: string;
  data_classification?: string;
  owner_name: string | null;
  owner_email: string | null;
  business_unit: string | null;
  cost_center: string | null;
  declared_purpose: string | null;
  registration_purpose_statement: string | null;
  expected_velocity: number | null;
  monthly_budget_usd: number | null;
  scopes: string[];
  tools: { tool_id: string; tool_name: string; tool_description: string }[];
  regulatory_frameworks: string[];
  hitl_enabled: boolean;
  hitl_webhook_url: string | null;
  hitl_timeout_hours: number | null;
  observe_only_mode: boolean;
  failure_scope: string | null;
  swarm_verdict: string | null;
  swarm_confidence_score: number | null;
  swarm_reasons: string[];
  evar_preview: string | null;
  certified_at: string | null;
  recertification_due_at: string | null;
  revoked_at: string | null;
  created_at: string;
  target_model: string | null;
}

// Governance fields that are mandatory — must all be present for certification
const MANDATORY_FIELDS: { key: keyof AgentDetail; label: string; reason: string }[] = [
  { key: 'declared_purpose',    label: 'Declared Purpose',    reason: 'Swarm cannot verify intent alignment' },
  { key: 'owner_name',          label: 'Owner Name',          reason: 'No accountable human contact' },
  { key: 'owner_email',         label: 'Owner Email',         reason: 'Owner cannot be notified' },
  { key: 'business_unit',       label: 'Business Unit',       reason: 'No organisational accountability' },
  { key: 'expected_velocity',   label: 'Expected Velocity',   reason: 'Gateway has no rate limit to enforce' },
  { key: 'monthly_budget_usd',  label: 'Monthly Budget',      reason: 'Financial exposure is unbound' },
];

function isMandatoryMissing(agent: AgentDetail, key: keyof AgentDetail): boolean {
  const val = agent[key];
  if (val === null || val === undefined) return true;
  if (typeof val === 'string' && val.trim() === '') return true;
  if (typeof val === 'number' && val <= 0) return true;
  return false;
}

const TIER_COLOURS: Record<string, string> = {
  nominal:    'text-green-400 bg-green-400/10 border-green-400/20',
  elevated:   'text-orange-400 bg-orange-400/10 border-orange-400/20',
  critical:   'text-red-400 bg-red-400/10 border-red-400/20',
  unverified: 'text-zinc-400 bg-zinc-400/10 border-zinc-400/20',
};

const VERDICT_COLOURS: Record<string, string> = {
  ALLOW: 'text-green-400 bg-green-400/10 border-green-400/20',
  BLOCK: 'text-red-400 bg-red-400/10 border-red-400/20',
};

function Field({ label, value, mono = false, missing = false }: {
  label: string; value: string | null | undefined; mono?: boolean; missing?: boolean;
}) {
  return (
    <div>
      <p className="text-[10px] uppercase font-technical text-on-surface-muted tracking-widest mb-1">{label}</p>
      {value ? (
        <p className={`text-sm ${mono ? 'font-mono text-primary/80' : ''}`}>{value}</p>
      ) : (
        <p className={`text-sm ${missing ? 'text-red-400 font-technical' : 'text-on-surface-muted/40 italic'}`}>
          {missing ? '⚠ Not declared' : 'Not set'}
        </p>
      )}
    </div>
  );
}

export default function AgentBiography() {
  const session   = useSession();
  const params    = useParams();
  const agentId   = params?.id as string;

  const [agent, setAgent]     = useState<AgentDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState('');

  useEffect(() => {
    if (!session || !agentId) return;
    fetch(`${CORE_API}/api/v1/portal/agents/${agentId}`, {
      headers: { Authorization: `Bearer ${session.token}`, Accept: 'application/json' },
    })
      .then(r => r.json())
      .then(({ data }) => {
        const a = data.agent;
        // DB returns JSON-encoded arrays as strings — parse them
        const parse = (v: unknown) => {
          if (Array.isArray(v)) return v;
          if (typeof v === 'string') { try { return JSON.parse(v); } catch { return []; } }
          return [];
        };
        setAgent({
          ...a,
          status: a.approval_status ?? a.status ?? 'unknown',
          trust_tier: a.trust_tier ?? 'unverified',
          scopes:               parse(a.scope_entitlements ?? a.scopes),
          tools:                parse(a.tools),
          regulatory_frameworks: parse(a.regulatory_frameworks),
          swarm_reasons:        parse(a.swarm_reasons),
          failure_scope:        typeof a.failure_scope === 'string' && a.failure_scope.startsWith('[')
                                  ? parse(a.failure_scope)[0] : a.failure_scope,
        });
        setLoading(false);
      })
      .catch(() => { setError('Failed to load agent details.'); setLoading(false); });
  }, [session, agentId]);

  if (loading) return (
    <div className="flex items-center justify-center py-32">
      <div className="w-8 h-8 border-2 border-primary border-t-transparent rounded-full animate-spin" />
    </div>
  );

  if (error || !agent) return (
    <div className="p-8 text-center text-on-surface-muted">{error || 'Agent not found.'}</div>
  );

  const missingMandatory = MANDATORY_FIELDS.filter(f => isMandatoryMissing(agent, f.key));
  const hasScope         = agent.scopes?.length > 0;
  const governanceScore  = Math.round(
    ((MANDATORY_FIELDS.length - missingMandatory.length) / MANDATORY_FIELDS.length) * 100
  );
  const tier  = TIER_COLOURS[agent.trust_tier ?? '']   ?? TIER_COLOURS.unverified;
  const vdict = VERDICT_COLOURS[agent.swarm_verdict ?? ''] ?? VERDICT_COLOURS.BLOCK;

  const handleLifecycleAction = async (action: string) => {
    if (!session || !agent) return;
    if (!confirm(`Are you sure you want to ${action} this agent?`)) return;
    try {
      const res = await fetch(`${CORE_API}/api/v1/portal/agents/${agent.id}/${action}`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${session.token}`, Accept: 'application/json' },
      });
      if (res.ok) {
        alert(`Agent successfully ${action}d.`);
        window.location.reload();
      } else {
        const err = await res.json();
        alert(`Failed to ${action}: ${err.error || 'Unknown error'}`);
      }
    } catch (e) {
      alert('Network error');
    }
  };

  return (
    <div className="p-8 max-w-4xl mx-auto space-y-8">

      {/* Back */}
      <Link href="/agents" className="inline-flex items-center gap-1.5 text-sm text-on-surface-muted hover:text-primary transition-colors font-technical">
        <span className="material-symbols-outlined text-[16px]">arrow_back</span>
        Back to registry
      </Link>

      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-3xl font-black font-headline tracking-tighter">{agent.name}</h1>
          <p className="text-xs text-on-surface-muted font-technical mt-1">{agent.id}</p>
        </div>
        <div className="flex flex-col items-end gap-2 flex-shrink-0">
          <div className="flex items-center gap-2">
            <span className={`text-xs font-technical px-3 py-1.5 rounded-full border ${tier}`}>
              {agent.trust_tier?.toUpperCase() || 'UNVERIFIED'}
            </span>
            {agent.swarm_verdict && (
              <span className={`text-xs font-technical px-3 py-1.5 rounded-full border ${vdict}`}>
                {agent.swarm_verdict}
              </span>
            )}
            <span className={`text-xs font-technical px-3 py-1.5 rounded-full border border-white/20 text-on-surface-muted`}>
              STATUS: {agent.status?.toUpperCase() || 'UNKNOWN'}
            </span>
          </div>

          <div className="flex items-center gap-2 mt-2">
            {(agent.status === 'pending_review' || agent.status === 'escalation_required') && (
              <button onClick={() => handleLifecycleAction('certify')} className="text-[11px] font-technical uppercase tracking-wider px-3 py-1.5 bg-green-500/10 text-green-400 hover:bg-green-500/20 border border-green-500/20 rounded transition">Certify</button>
            )}
            {agent.status === 'certified' && (
              <button onClick={() => handleLifecycleAction('suspend')} className="text-[11px] font-technical uppercase tracking-wider px-3 py-1.5 bg-orange-500/10 text-orange-400 hover:bg-orange-500/20 border border-orange-500/20 rounded transition">Suspend</button>
            )}
            {agent.status === 'suspended' && (
              <button onClick={() => handleLifecycleAction('recertify')} className="text-[11px] font-technical uppercase tracking-wider px-3 py-1.5 bg-green-500/10 text-green-400 hover:bg-green-500/20 border border-green-500/20 rounded transition">Re-Certify</button>
            )}
            {agent.status !== 'terminated' && (
              <button onClick={() => handleLifecycleAction('terminate')} className="text-[11px] font-technical uppercase tracking-wider px-3 py-1.5 bg-red-500/10 text-red-400 hover:bg-red-500/20 border border-red-500/20 rounded transition">Terminate</button>
            )}
          </div>
        </div>
      </div>

      {/* Governance Completeness Warning */}
      {(missingMandatory.length > 0 || !hasScope) && (
        <div className="bg-red-500/5 border border-red-500/20 rounded-xl p-5 space-y-3">
          <div className="flex items-center gap-2">
            <span className="material-symbols-outlined text-red-400 text-xl">warning</span>
            <p className="font-headline font-bold text-red-400">Governance Completeness Failure</p>
            <span className="ml-auto text-xs font-technical text-red-400/70">{governanceScore}% complete</span>
          </div>
          <p className="text-sm text-on-surface-muted">
            This agent is missing mandatory governance fields. It cannot be certified by the Verification Swarm until all fields are declared.
          </p>
          <ul className="space-y-1.5">
            {missingMandatory.map(f => (
              <li key={f.key} className="flex items-center gap-2 text-sm">
                <span className="material-symbols-outlined text-red-400 text-[14px]">close</span>
                <span className="text-red-300 font-technical">{f.label}</span>
                <span className="text-on-surface-muted/60">— {f.reason}</span>
              </li>
            ))}
            {!hasScope && (
              <li className="flex items-center gap-2 text-sm">
                <span className="material-symbols-outlined text-red-400 text-[14px]">close</span>
                <span className="text-red-300 font-technical">Scopes</span>
                <span className="text-on-surface-muted/60">— no permission boundary declared. Gateway cannot enforce any policy.</span>
              </li>
            )}
          </ul>
          <Link href={`/agents/${agent.id}/edit`} className="inline-flex items-center gap-1.5 text-sm text-primary font-technical hover:underline mt-1">
            <span className="material-symbols-outlined text-[14px]">edit</span>
            Update registration details
          </Link>
        </div>
      )}

      {/* Identity & Birth */}
      <section className="bg-surface-raised border border-[rgba(255,159,74,0.10)] rounded-xl p-6 space-y-5">
        <h2 className="text-xs uppercase font-technical text-primary tracking-widest">Identity &amp; Birth</h2>
        <div className="grid grid-cols-2 gap-5">
          <Field label="Agent Name"       value={agent.name} />
          <Field label="Version"          value={agent.version} />
          <Field label="Agent Type"       value={agent.agent_type} />
          <Field label="Role"             value={agent.role} />
          <Field label="Criticality"      value={agent.criticality_level?.toUpperCase()} />
          <Field label="Data Classification" value={agent.data_classification?.toUpperCase()} />
          <Field label="Target Model"     value={agent.target_model} />
          <Field label="Registered"       value={agent.created_at ? new Date(agent.created_at).toLocaleString() : null} />
          <Field label="Certified"        value={agent.certified_at ? new Date(agent.certified_at).toLocaleString() : null} />
          <Field label="Recertification Due" value={agent.recertification_due_at ? new Date(agent.recertification_due_at).toLocaleString() : null} />
        </div>
        <div>
          <p className="text-[10px] uppercase font-technical text-on-surface-muted tracking-widest mb-1">Description</p>
          <p className="text-sm">{agent.description || <span className="italic text-on-surface-muted/40">Not set</span>}</p>
        </div>
        <div>
          <p className="text-[10px] uppercase font-technical text-on-surface-muted tracking-widest mb-1">EVAR Token Preview</p>
          <p className="text-xs font-mono text-primary/70 break-all">{agent.evar_preview ?? 'Not issued'}</p>
        </div>
      </section>

      {/* Governance Profile */}
      <section className="bg-surface-raised border border-[rgba(255,159,74,0.10)] rounded-xl p-6 space-y-5">
        <h2 className="text-xs uppercase font-technical text-primary tracking-widest">Governance Profile</h2>
        <div className="grid grid-cols-2 gap-5">
          <Field label="Owner Name"  value={agent.owner_name}  missing={!agent.owner_name} />
          <Field label="Owner Email" value={agent.owner_email} missing={!agent.owner_email} />
          <Field label="Business Unit" value={agent.business_unit} missing={!agent.business_unit} />
          <Field label="Cost Center"   value={agent.cost_center} />
          <Field label="Max Velocity (calls/hr)" value={agent.expected_velocity != null ? String(agent.expected_velocity) : null} missing={!agent.expected_velocity} />
          <Field label="Monthly Budget Cap (USD)" value={agent.monthly_budget_usd != null ? `$${Number(agent.monthly_budget_usd).toFixed(2)}` : null} missing={!agent.monthly_budget_usd} />
        </div>
        <Field label="Declared Purpose" value={agent.declared_purpose} missing={!agent.declared_purpose} />
        <Field label="Registration Purpose Statement" value={agent.registration_purpose_statement} />

        {/* Regulatory Frameworks */}
        <div>
          <p className="text-[10px] uppercase font-technical text-on-surface-muted tracking-widest mb-2">Regulatory Frameworks</p>
          {agent.regulatory_frameworks?.length > 0 ? (
            <div className="flex flex-wrap gap-2">
              {agent.regulatory_frameworks.map(f => (
                <span key={f} className="text-xs font-technical px-2.5 py-1 rounded-full bg-primary/10 text-primary border border-primary/20">{f}</span>
              ))}
            </div>
          ) : (
            <p className="text-sm italic text-on-surface-muted/40">None declared</p>
          )}
        </div>
      </section>

      {/* Scope Declaration */}
      <section className="bg-surface-raised border border-[rgba(255,159,74,0.10)] rounded-xl p-6 space-y-4">
        <h2 className="text-xs uppercase font-technical text-primary tracking-widest">Scope Declaration</h2>
        {!hasScope ? (
          <div className="flex items-center gap-2 text-red-400">
            <span className="material-symbols-outlined text-[16px]">warning</span>
            <p className="text-sm font-technical">No scopes declared — this agent has no permission boundary. The Gateway cannot enforce any policy.</p>
          </div>
        ) : (
          <div className="flex flex-wrap gap-2">
            {agent.scopes.map(s => (
              <span key={s} className="text-xs font-technical px-2.5 py-1 rounded-full bg-white/5 border border-white/10 text-on-surface-muted">{s}</span>
            ))}
          </div>
        )}
      </section>

      {/* Tools */}
      {agent.tools?.length > 0 && (
        <section className="bg-surface-raised border border-[rgba(255,159,74,0.10)] rounded-xl p-6 space-y-3">
          <h2 className="text-xs uppercase font-technical text-primary tracking-widest">Declared Tools</h2>
          <div className="space-y-2">
            {agent.tools.map(t => (
              <div key={t.tool_id} className="flex items-start gap-3 p-3 bg-black/20 rounded-lg">
                <span className="material-symbols-outlined text-primary/60 text-[16px] mt-0.5">build</span>
                <div>
                  <p className="text-sm font-technical font-bold">{t.tool_name}</p>
                  <p className="text-xs text-on-surface-muted">{t.tool_description || 'No description'}</p>
                </div>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* Security Settings */}
      <section className="bg-surface-raised border border-[rgba(255,159,74,0.10)] rounded-xl p-6 space-y-5">
        <h2 className="text-xs uppercase font-technical text-primary tracking-widest">Security &amp; Failure Settings</h2>
        <div className="grid grid-cols-2 gap-5">
          <div>
            <p className="text-[10px] uppercase font-technical text-on-surface-muted tracking-widest mb-1">HITL Enabled</p>
            <span className={`text-xs font-technical px-2.5 py-1 rounded-full ${agent.hitl_enabled ? 'bg-green-400/10 text-green-400' : 'bg-white/5 text-on-surface-muted'}`}>
              {agent.hitl_enabled ? 'Yes' : 'No'}
            </span>
          </div>
          <div>
            <p className="text-[10px] uppercase font-technical text-on-surface-muted tracking-widest mb-1">Shadow / Observe-Only Mode</p>
            <span className={`text-xs font-technical px-2.5 py-1 rounded-full ${agent.observe_only_mode ? 'bg-amber-400/10 text-amber-400' : 'bg-white/5 text-on-surface-muted'}`}>
              {agent.observe_only_mode ? 'Enabled' : 'Disabled'}
            </span>
          </div>
          <Field label="HITL Timeout (hours)" value={agent.hitl_timeout_hours != null ? String(agent.hitl_timeout_hours) : null} />
          <Field label="Failure Behaviour"    value={agent.failure_scope} />
          <Field label="HITL Webhook"         value={agent.hitl_webhook_url} mono />
        </div>
      </section>

      {/* Swarm Verdict */}
      <section className="bg-surface-raised border border-[rgba(255,159,74,0.10)] rounded-xl p-6 space-y-4">
        <h2 className="text-xs uppercase font-technical text-primary tracking-widest">Verification Swarm Verdict</h2>
        {!agent.swarm_verdict ? (
          <p className="text-sm text-on-surface-muted italic">No swarm verification has run for this agent yet.</p>
        ) : (
          <>
            <div className="flex items-center gap-4">
              <span className={`text-sm font-technical font-bold px-4 py-2 rounded-lg border ${vdict}`}>
                {agent.swarm_verdict}
              </span>
              {agent.swarm_confidence_score != null && (
                <div>
                  <p className="text-[10px] uppercase font-technical text-on-surface-muted tracking-widest">Confidence Score</p>
                  <p className="text-xl font-black font-headline">{Math.round(agent.swarm_confidence_score * 100)}<span className="text-sm text-on-surface-muted font-normal"> / 100</span></p>
                </div>
              )}
            </div>
            {agent.swarm_reasons?.length > 0 && (
              <div>
                <p className="text-[10px] uppercase font-technical text-on-surface-muted tracking-widest mb-2">Swarm Reasons</p>
                <ul className="space-y-1.5">
                  {agent.swarm_reasons.map((r, i) => (
                    <li key={i} className="text-sm text-on-surface-muted flex items-start gap-2">
                      <span className="material-symbols-outlined text-[13px] mt-0.5 text-primary/40">fiber_manual_record</span>
                      {r}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </>
        )}
      </section>

    </div>
  );
}
