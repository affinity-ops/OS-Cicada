// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

'use client';

import React, { useState, useRef, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import { useSession } from '../../layout';
import { mapYAMLToWizardForm } from '../../../../lib/agent-mapping';

const CORE_API = process.env.NEXT_PUBLIC_CORE_API_URL || 'http://localhost:8000';

const STEPS = [
  { n: 1, label: 'Identity',    icon: 'badge' },
  { n: 2, label: 'Governance',  icon: 'account_balance' },
  { n: 3, label: 'Architecture',icon: 'account_tree' },
  { n: 4, label: 'Scope',       icon: 'security' },
  { n: 5, label: 'Tools',       icon: 'build' },
  { n: 6, label: 'Failure',     icon: 'warning' },
  { n: 7, label: 'Security',    icon: 'shield' },
  { n: 8, label: 'API Key',     icon: 'key' },
];

const ROLE_OPTIONS = [
  { value: 'autonomous',    label: 'Autonomous',    desc: 'Operates without an orchestrator. Held to the highest Swarm confidence standard (≥0.80).' },
  { value: 'orchestrator',  label: 'Orchestrator',  desc: 'Can spawn and direct sub-agents. Requires proxy:write scope minimum.' },
  { value: 'sub_agent',     label: 'Sub-agent',     desc: 'Only acts when invoked by a specific orchestrator you bind it to.' },
  { value: 'peer',          label: 'Peer',          desc: 'Communicates laterally with other certified agents. Cannot spawn sub-agents.' },
  { value: 'tool_executor', label: 'Tool Executor', desc: 'Passive — only executes tools when called by another agent. Cannot initiate calls independently.' },
];

const AGENT_TYPES = [
  { value: 'reactive',   label: 'Reactive',   desc: 'Responds to direct requests on demand.' },
  { value: 'heartbeat',  label: 'Heartbeat',  desc: 'Runs on a regular interval, polling or monitoring.' },
  { value: 'scheduled',  label: 'Scheduled',  desc: 'Triggered at specific times or by a cron.' },
  { value: 'autonomous', label: 'Autonomous', desc: 'Self-directed — sets its own sub-tasks and goals.' },
];

const SCOPE_OPTIONS = [
  { value: 'proxy:chat',     label: 'Chat Completion',    desc: 'Send messages to LLM endpoints' },
  { value: 'proxy:read',     label: 'Read Data',          desc: 'Read from external APIs or databases' },
  { value: 'proxy:write',    label: 'Write Data',         desc: 'Write or update external records' },
  { value: 'proxy:transact', label: 'Transact',           desc: 'Execute financial or state-changing operations' },
  { value: 'proxy:notify',   label: 'Send Notifications', desc: 'Email, webhook, or push alerts' },
  { value: 'proxy:search',   label: 'Web Search',         desc: 'Query public search or retrieval endpoints' },
];

const FAILURE_OPTIONS = [
  { value: 'silent_exit',      label: 'Silent Exit',        desc: 'Stop immediately. Take no further action.' },
  { value: 'retry_once',       label: 'Retry Once',         desc: 'Attempt the same request one more time then stop.' },
  { value: 'notify_owner',     label: 'Notify Owner',       desc: 'Fire a webhook to the registered owner endpoint.' },
  { value: 'queue_for_review', label: 'Queue for Review',   desc: 'Place the job in a dead-letter queue for manual review.' },
];

const CRITICALITY_OPTIONS = [
  { value: 'low',      label: 'Low',      desc: 'Non-essential. Failure has minimal impact on operations.', colour: 'text-emerald-400 border-emerald-500/30 bg-emerald-500/5' },
  { value: 'medium',   label: 'Medium',   desc: 'Standard business process. Failure is disruptive but recoverable.', colour: 'text-blue-400 border-blue-500/30 bg-blue-500/5' },
  { value: 'high',     label: 'High',     desc: 'Core workflow. Failure causes significant operational or financial impact.', colour: 'text-orange-400 border-orange-500/30 bg-orange-500/5' },
  { value: 'critical', label: 'Critical', desc: 'Mission-critical. Any failure has immediate regulatory, financial, or safety consequences.', colour: 'text-red-400 border-red-500/30 bg-red-500/5' },
];

const CLASSIFICATION_OPTIONS = [
  { value: 'public',       label: 'Public',       desc: 'Data that is freely available or intended for public consumption.' },
  { value: 'internal',     label: 'Internal',     desc: 'Internal business data not intended for public disclosure.' },
  { value: 'confidential', label: 'Confidential', desc: 'Sensitive business data requiring restricted access.' },
  { value: 'restricted',   label: 'Restricted',   desc: 'Highly sensitive data — PII, financial records, regulated data.' },
];

const REGULATORY_OPTIONS = [
  'GDPR', 'HIPAA', 'SOC 2', 'ISO 27001', 'PCI DSS', 'EU AI Act', 'CCPA', 'FCA', 'DORA',
];

type Tool = { tool_id: string; tool_name: string; tool_description: string };

export default function RegisterAgent() {
  const session = useSession();
  const router  = useRouter();
  const [step, setStep]           = useState(1);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError]         = useState('');
  const [successData, setSuccessData] = useState<{agent_id: string, evar_token: string} | null>(null);
  const [yamlImported, setYamlImported] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // ── YAML Import handler ─────────────────────────────────────────────────
  const handleYAMLImport = useCallback(async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    try {
      const text = await file.text();

      // Dynamic import js-yaml (lightweight YAML parser)
      // Falls back to basic key: value parsing if js-yaml isn't available
      let parsed: Record<string, unknown>;
      try {
        const jsyaml = await import('js-yaml');
        parsed = jsyaml.load(text) as Record<string, unknown>;
      } catch {
        // Fallback: try JSON parse (in case user uploaded JSON)
        try {
          parsed = JSON.parse(text);
        } catch {
          setError('Could not parse file. Please upload a valid cicada.yaml or JSON file.');
          return;
        }
      }

      if (!parsed || typeof parsed !== 'object') {
        setError('Invalid YAML structure. Expected a cicada.yaml policy file.');
        return;
      }

      // Map YAML to wizard form state using the shared utility
      const mapped = mapYAMLToWizardForm(parsed as Record<string, any>);

      // Merge into form — preserve any fields the user already filled
      setForm(f => ({
        ...f,
        ...Object.fromEntries(
          Object.entries(mapped).filter(([, v]) => {
            // Only overwrite if the mapped value is non-empty
            if (Array.isArray(v)) return v.length > 0;
            if (typeof v === 'boolean') return true;
            return v !== '' && v !== undefined && v !== null;
          })
        ),
      }));

      setYamlImported(true);
      setError('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to import YAML file.');
    }

    // Reset file input so the same file can be re-imported
    if (fileInputRef.current) fileInputRef.current.value = '';
  }, []);

  const [form, setForm] = useState({
    // Step 1 — Identity
    agent_name:  '',
    description: '',
    version:     '1.0.0',

    // Step 2 — Governance
    owner_name:                    '',
    owner_email:                   '',
    business_unit:                 '',
    data_residency_region:         '',
    declared_purpose:              '',
    criticality_level:             'medium',
    data_classification:           'internal',
    expected_velocity:             '',
    monthly_budget_usd:            '',
    cost_center:                   '',
    regulatory_frameworks:         [] as string[],
    registration_purpose_statement:'',

    // Step 3 — Architecture
    agent_type:      '',
    role:            'autonomous',
    orchestrator_id: '',

    // Step 4 — Scope
    scopes: [] as string[],

    // Step 5 — Tools
    tools: [] as Tool[],

    // Step 6 — Failure
    failure_scope: '',

    // Step 7 — Security
    hitl_enabled:      false,
    hitl_webhook_url:  '',
    hitl_timeout_hours: '24',
    shadow_mode:       false,

    // Step 8 — API Key
    api_provider: 'openai',
    api_key:      '',
    target_model: 'gpt-4o',
  });

  // ── Tool helpers ─────────────────────────────────────────────────────────────
  function addTool() {
    setForm(f => ({ ...f, tools: [...f.tools, { tool_id: '', tool_name: '', tool_description: '' }] }));
  }
  function updateTool(i: number, field: keyof Tool, val: string) {
    setForm(f => {
      const tools = [...f.tools];
      tools[i] = { ...tools[i], [field]: val };
      return { ...f, tools };
    });
  }
  function removeTool(i: number) {
    setForm(f => ({ ...f, tools: f.tools.filter((_, idx) => idx !== i) }));
  }

  function toggleScope(val: string) {
    setForm(f => ({ ...f, scopes: f.scopes.includes(val) ? f.scopes.filter(s => s !== val) : [...f.scopes, val] }));
  }
  function toggleFramework(val: string) {
    setForm(f => ({ ...f, regulatory_frameworks: f.regulatory_frameworks.includes(val) ? f.regulatory_frameworks.filter(r => r !== val) : [...f.regulatory_frameworks, val] }));
  }

  // ── Submit ───────────────────────────────────────────────────────────────────
  async function submit() {
    setSubmitting(true);
    setError('');
    try {
      const res = await fetch(`${CORE_API}/api/v1/portal/provision/agent`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json', Authorization: `Bearer ${session?.token}` },
        body: JSON.stringify({
          agent_name:    form.agent_name,
          description:   form.description,
          version:       form.version,

          owner_name:                     form.owner_name     || undefined,
          owner_email:                    form.owner_email    || undefined,
          business_unit:                  form.business_unit  || undefined,
          data_residency_region:          form.data_residency_region || undefined,
          declared_purpose:               form.declared_purpose || undefined,
          criticality_level:              form.criticality_level,
          data_classification:            form.data_classification,
          expected_velocity:              form.expected_velocity     ? parseInt(form.expected_velocity)      : undefined,
          monthly_budget_usd:             form.monthly_budget_usd    ? parseFloat(form.monthly_budget_usd)   : undefined,
          cost_center:                    form.cost_center    || undefined,
          regulatory_frameworks:          form.regulatory_frameworks.length ? form.regulatory_frameworks : undefined,
          registration_purpose_statement: form.registration_purpose_statement || undefined,

          agent_type:      form.agent_type   || undefined,
          role:            form.role,
          orchestrator_id: form.orchestrator_id || undefined,

          scopes:       form.scopes,
          tools:        form.tools.filter(t => t.tool_name.trim()).map(t => ({
            tool_id:          t.tool_id.trim()          || t.tool_name.toLowerCase().replace(/\s+/g, '_'),
            tool_name:        t.tool_name.trim(),
            tool_description: t.tool_description.trim() || undefined,
          })),

          failure_scope:      form.failure_scope,
          hitl_enabled:       form.hitl_enabled,
          hitl_webhook_url:   form.hitl_enabled ? form.hitl_webhook_url : undefined,
          hitl_timeout_hours: form.hitl_enabled ? parseInt(form.hitl_timeout_hours) || 24 : undefined,
          observe_only_mode:  form.shadow_mode,

          api_provider: form.api_provider,
          api_key:      form.api_key,
          target_model: form.target_model,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        if (data.reasons && data.reasons.length > 0) {
          setError(`Swarm Blocked:\n${data.reasons.join('\n')}`);
        } else {
          throw new Error(data.message ?? 'Registration failed');
        }
        setSubmitting(false);
        return;
      }
      setSuccessData({
        agent_id: data.data.agent_id,
        evar_token: data.data.evar
      });
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Something went wrong');
      setSubmitting(false);
    }
  }

  // ── Validation ────────────────────────────────────────────────────────────────
  const canNext = () => {
    if (step === 1) return form.agent_name.trim().length > 0;
    if (step === 2) return (
      form.owner_name.trim().length > 0 &&
      form.declared_purpose.trim().length > 0 &&
      form.expected_velocity.trim().length > 0 && parseInt(form.expected_velocity) > 0 &&
      form.monthly_budget_usd.trim().length > 0 && parseFloat(form.monthly_budget_usd) > 0
    );
    if (step === 3) return form.agent_type !== '' && form.role !== '';
    if (step === 4) return form.scopes.length > 0;
    if (step === 5) return true; // tools optional
    if (step === 6) return form.failure_scope !== '';
    if (step === 7) return !form.hitl_enabled || form.hitl_webhook_url.trim().length > 0;
    if (step === 8) return form.api_key.trim().length > 0;
    return true;
  };

  if (successData) {
    return (
      <div className="p-8 max-w-2xl mx-auto text-center mt-12 space-y-6">
        <div className="w-20 h-20 bg-emerald-500/20 border border-emerald-500/30 rounded-full flex items-center justify-center mx-auto mb-6">
          <span className="material-symbols-outlined text-4xl text-emerald-400">check_circle</span>
        </div>
        <h1 className="text-3xl font-black font-headline tracking-tighter">Registration Complete</h1>
        <p className="text-on-surface-muted">Your agent has been provisioned successfully.</p>
        
        <div className="bg-surface-raised border border-emerald-500/30 rounded-xl p-8 space-y-4 text-left relative mt-8">
          <p className="font-headline font-bold text-amber-400 flex items-center gap-2">
            <span className="material-symbols-outlined">warning</span>
            SAVE YOUR EVAR TOKEN NOW
          </p>
          <p className="text-sm text-on-surface-muted">
            This is the cryptographic identity credential for your agent. Like an AWS Secret Key, it will <strong>never be shown again</strong>. Copy it now and store it securely.
          </p>
          <div className="bg-black/60 border border-white/10 rounded-lg p-4 mt-4 font-mono text-sm text-primary break-all select-all">
            {successData.evar_token}
          </div>
        </div>

        <button onClick={() => router.push('/agents')} className="mt-8 px-6 py-3 bg-primary text-black font-headline font-bold rounded-xl hover:bg-primary/90 transition-colors">
          Return to Registry
        </button>
      </div>
    );
  }

  return (
    <div className="p-8 max-w-2xl mx-auto">
      <div className="mb-8">
        <h1 className="text-3xl font-black font-headline tracking-tighter">Register an Agent</h1>
        <p className="text-on-surface-muted text-sm mt-1">Walk through each step to provision your agent and receive its EVAR token.</p>
      </div>

      {/* Step indicator */}
      <div className="flex items-center gap-1 mb-8 overflow-x-auto pb-2">
        {STEPS.map((s, i) => (
          <React.Fragment key={s.n}>
            <div className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-full text-xs font-technical transition-colors whitespace-nowrap flex-shrink-0 ${
              step === s.n ? 'bg-primary text-black' :
              step > s.n  ? 'bg-primary/20 text-primary' :
              'bg-white/5 text-on-surface-muted'
            }`}>
              <span className="material-symbols-outlined text-[13px]">{step > s.n ? 'check_circle' : s.icon}</span>
              <span className="hidden sm:block">{s.label}</span>
            </div>
            {i < STEPS.length - 1 && <div className={`w-3 h-px flex-shrink-0 ${step > s.n ? 'bg-primary/40' : 'bg-white/10'}`} />}
          </React.Fragment>
        ))}
      </div>

      <div className="bg-surface-raised border border-[rgba(255,159,74,0.12)] rounded-2xl p-8 space-y-6">

        {/* ── Step 1 — Identity ─────────────────────────────────────────────── */}
        {step === 1 && (
          <>
            <div>
              <h2 className="text-xl font-headline font-bold mb-1">Name your agent</h2>
              <p className="text-sm text-on-surface-muted">Give your agent a clear name and description. This appears in your registry and in Cicada's audit logs.</p>
            </div>

            {/* ── Import YAML panel ───────────────────────────────────── */}
            <div className="p-4 border border-dashed border-white/20 rounded-xl bg-white/[0.02]">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-headline font-bold">Import from cicada.yaml</p>
                  <p className="text-xs text-on-surface-muted mt-0.5">Pre-populate all steps from a scaffolded YAML file. You can review and edit every field before submitting.</p>
                </div>
                <button
                  onClick={() => fileInputRef.current?.click()}
                  className="flex items-center gap-2 px-4 py-2 bg-primary/10 border border-primary/30 text-primary rounded-lg text-sm font-headline font-bold hover:bg-primary/20 transition-colors flex-shrink-0"
                >
                  <span className="material-symbols-outlined text-[16px]">upload_file</span>
                  Import YAML
                </button>
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".yaml,.yml,.json"
                  onChange={handleYAMLImport}
                  className="hidden"
                />
              </div>
              {yamlImported && (
                <div className="mt-3 p-3 bg-emerald-500/10 border border-emerald-500/20 rounded-lg flex items-center gap-2">
                  <span className="material-symbols-outlined text-emerald-400 text-[16px]">check_circle</span>
                  <p className="text-xs text-emerald-400 font-technical">YAML imported — all steps pre-populated. Review each step before registering. API key must be entered manually at Step 8.</p>
                </div>
              )}
            </div>

            <div className="space-y-4">
              <div>
                <label className="text-[10px] uppercase font-technical text-on-surface-muted tracking-widest block mb-1">Agent Name *</label>
                <input value={form.agent_name} onChange={e => setForm(f => ({ ...f, agent_name: e.target.value }))}
                  placeholder="e.g. Acme Invoice Processor"
                  className="w-full bg-black/40 border border-white/10 rounded-lg p-3 text-sm focus:outline-none focus:border-primary transition-colors"
                />
              </div>
              <div>
                <label className="text-[10px] uppercase font-technical text-on-surface-muted tracking-widest block mb-1">Description</label>
                <textarea value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
                  placeholder="What does this agent do? What problem does it solve?"
                  rows={3}
                  className="w-full bg-black/40 border border-white/10 rounded-lg p-3 text-sm focus:outline-none focus:border-primary transition-colors resize-none"
                />
              </div>
              <div>
                <label className="text-[10px] uppercase font-technical text-on-surface-muted tracking-widest block mb-1">Version</label>
                <input value={form.version} onChange={e => setForm(f => ({ ...f, version: e.target.value }))}
                  placeholder="1.0.0"
                  className="w-full bg-black/40 border border-white/10 rounded-lg p-3 text-sm focus:outline-none focus:border-primary transition-colors"
                />
              </div>
            </div>
          </>
        )}

        {/* ── Step 2 — Governance ───────────────────────────────────────────── */}
        {step === 2 && (
          <>
            <div>
              <h2 className="text-xl font-headline font-bold mb-1">Governance profile</h2>
              <p className="text-sm text-on-surface-muted">Declare ownership, business context, and compliance requirements. This forms the legal evidence trail for this agent's registration.</p>
            </div>

            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-[10px] uppercase font-technical text-on-surface-muted tracking-widest block mb-1">Owner Name *</label>
                  <input value={form.owner_name} onChange={e => setForm(f => ({ ...f, owner_name: e.target.value }))}
                    placeholder="Jane Smith"
                    className="w-full bg-black/40 border border-white/10 rounded-lg p-3 text-sm focus:outline-none focus:border-primary transition-colors"
                  />
                </div>
                <div>
                  <label className="text-[10px] uppercase font-technical text-on-surface-muted tracking-widest block mb-1">Owner Email</label>
                  <input type="email" value={form.owner_email} onChange={e => setForm(f => ({ ...f, owner_email: e.target.value }))}
                    placeholder="jane@company.com"
                    className="w-full bg-black/40 border border-white/10 rounded-lg p-3 text-sm focus:outline-none focus:border-primary transition-colors"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-[10px] uppercase font-technical text-on-surface-muted tracking-widest block mb-1">Business Unit</label>
                  <input value={form.business_unit} onChange={e => setForm(f => ({ ...f, business_unit: e.target.value }))}
                    placeholder="e.g. Finance, Engineering, Ops"
                    className="w-full bg-black/40 border border-white/10 rounded-lg p-3 text-sm focus:outline-none focus:border-primary transition-colors"
                  />
                </div>
                <div>
                  <label className="text-[10px] uppercase font-technical text-on-surface-muted tracking-widest block mb-1">Cost Center</label>
                  <input value={form.cost_center} onChange={e => setForm(f => ({ ...f, cost_center: e.target.value }))}
                    placeholder="e.g. CC-1042"
                    className="w-full bg-black/40 border border-white/10 rounded-lg p-3 text-sm focus:outline-none focus:border-primary transition-colors"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-[10px] uppercase font-technical text-on-surface-muted tracking-widest block mb-1">Data Residency Region</label>
                  <select value={form.data_residency_region} onChange={e => setForm(f => ({ ...f, data_residency_region: e.target.value }))}
                    className="w-full bg-black/40 border border-white/10 rounded-lg p-3 text-sm text-white focus:outline-none focus:border-primary transition-colors appearance-none"
                  >
                    <option value="">Global (No pinning)</option>
                    <option value="us">United States (US)</option>
                    <option value="eu">European Union (EU)</option>
                    <option value="uk">United Kingdom (UK)</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="text-[10px] uppercase font-technical text-on-surface-muted tracking-widest block mb-1">Declared Purpose *</label>
                <textarea value={form.declared_purpose} onChange={e => setForm(f => ({ ...f, declared_purpose: e.target.value }))}
                  placeholder="What is the specific business purpose of this agent? What decisions can it make autonomously?"
                  rows={2}
                  className="w-full bg-black/40 border border-white/10 rounded-lg p-3 text-sm focus:outline-none focus:border-primary transition-colors resize-none"
                />
              </div>

              <div>
                <label className="text-[10px] uppercase font-technical text-on-surface-muted tracking-widest block mb-1">Registration Purpose Statement</label>
                <textarea value={form.registration_purpose_statement} onChange={e => setForm(f => ({ ...f, registration_purpose_statement: e.target.value }))}
                  placeholder="Formal statement of why this agent is being deployed. This is stored as legal evidence."
                  rows={2}
                  className="w-full bg-black/40 border border-white/10 rounded-lg p-3 text-sm focus:outline-none focus:border-primary transition-colors resize-none"
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-[10px] uppercase font-technical text-on-surface-muted tracking-widest block mb-1">Expected Call Volume — Max Calls/Hour *</label>
                  <input type="number" min="1" value={form.expected_velocity} onChange={e => setForm(f => ({ ...f, expected_velocity: e.target.value }))}
                    placeholder="e.g. 100"
                    className="w-full bg-black/40 border border-white/10 rounded-lg p-3 text-sm focus:outline-none focus:border-primary transition-colors"
                  />
                  <p className="text-[10px] text-amber-400/80 mt-1">Required — the Sentry Gateway enforces this as the agent's rate limit. The Swarm will flag agents with no velocity declaration.</p>
                </div>
                <div>
                  <label className="text-[10px] uppercase font-technical text-on-surface-muted tracking-widest block mb-1">Monthly Budget Cap (USD) *</label>
                  <input type="number" min="0.01" step="0.01" value={form.monthly_budget_usd} onChange={e => setForm(f => ({ ...f, monthly_budget_usd: e.target.value }))}
                    placeholder="e.g. 500.00"
                    className="w-full bg-black/40 border border-white/10 rounded-lg p-3 text-sm focus:outline-none focus:border-primary transition-colors"
                  />
                  <p className="text-[10px] text-amber-400/80 mt-1">Required — establishes financial accountability for this agent.</p>
                </div>
              </div>

              {/* Criticality */}
              <div>
                <label className="text-[10px] uppercase font-technical text-on-surface-muted tracking-widest block mb-2">Criticality Level</label>
                <div className="grid grid-cols-2 gap-2">
                  {CRITICALITY_OPTIONS.map(c => (
                    <button key={c.value} onClick={() => setForm(f => ({ ...f, criticality_level: c.value }))}
                      className={`flex items-start gap-3 p-3 rounded-xl border text-left transition-colors ${form.criticality_level === c.value ? c.colour + ' border-opacity-60' : 'border-white/10 hover:border-white/20'}`}
                    >
                      <div className={`w-3 h-3 rounded-full border-2 mt-0.5 flex-shrink-0 ${form.criticality_level === c.value ? 'border-current bg-current' : 'border-white/30'}`} />
                      <div>
                        <p className="font-headline font-bold text-xs">{c.label}</p>
                        <p className="text-[10px] text-on-surface-muted mt-0.5">{c.desc}</p>
                      </div>
                    </button>
                  ))}
                </div>
              </div>

              {/* Data Classification */}
              <div>
                <label className="text-[10px] uppercase font-technical text-on-surface-muted tracking-widest block mb-2">Data Classification</label>
                <div className="grid grid-cols-2 gap-2">
                  {CLASSIFICATION_OPTIONS.map(c => (
                    <button key={c.value} onClick={() => setForm(f => ({ ...f, data_classification: c.value }))}
                      className={`flex items-start gap-3 p-3 rounded-xl border text-left transition-colors ${form.data_classification === c.value ? 'border-primary bg-primary/5' : 'border-white/10 hover:border-white/20'}`}
                    >
                      <div className={`w-3 h-3 rounded border-2 mt-0.5 flex-shrink-0 ${form.data_classification === c.value ? 'border-primary bg-primary' : 'border-white/30'}`} />
                      <div>
                        <p className="font-headline font-bold text-xs">{c.label}</p>
                        <p className="text-[10px] text-on-surface-muted mt-0.5">{c.desc}</p>
                      </div>
                    </button>
                  ))}
                </div>
              </div>

              {/* Regulatory frameworks */}
              <div>
                <label className="text-[10px] uppercase font-technical text-on-surface-muted tracking-widest block mb-2">Regulatory Frameworks</label>
                <div className="flex flex-wrap gap-2">
                  {REGULATORY_OPTIONS.map(r => (
                    <button key={r} onClick={() => toggleFramework(r)}
                      className={`px-3 py-1.5 rounded-lg border text-xs font-technical font-bold transition-colors ${form.regulatory_frameworks.includes(r) ? 'border-primary bg-primary/10 text-primary' : 'border-white/10 text-on-surface-muted hover:border-white/20'}`}
                    >
                      {r}
                    </button>
                  ))}
                </div>
                <p className="text-[10px] text-on-surface-muted/60 mt-1">Select all frameworks this agent's operations fall under.</p>
              </div>
            </div>
          </>
        )}

        {/* ── Step 3 — Architecture ─────────────────────────────────────────── */}
        {step === 3 && (
          <>
            <div>
              <h2 className="text-xl font-headline font-bold mb-1">Agent architecture</h2>
              <p className="text-sm text-on-surface-muted">How does your agent operate and what role does it play in multi-agent workflows?</p>
            </div>
            <div className="space-y-3">
              <p className="text-[10px] uppercase font-technical text-on-surface-muted tracking-widest">Operation Type</p>
              {AGENT_TYPES.map(t => (
                <button key={t.value} onClick={() => setForm(f => ({ ...f, agent_type: t.value }))}
                  className={`w-full flex items-start gap-4 p-4 rounded-xl border text-left transition-colors ${form.agent_type === t.value ? 'border-primary bg-primary/5' : 'border-white/10 hover:border-white/20'}`}
                >
                  <div className={`w-4 h-4 rounded-full border-2 mt-0.5 flex-shrink-0 ${form.agent_type === t.value ? 'border-primary bg-primary' : 'border-white/30'}`} />
                  <div>
                    <p className="font-headline font-bold text-sm">{t.label}</p>
                    <p className="text-xs text-on-surface-muted mt-0.5">{t.desc}</p>
                  </div>
                </button>
              ))}
            </div>
            <div className="space-y-3 pt-2 border-t border-white/5">
              <p className="text-[10px] uppercase font-technical text-on-surface-muted tracking-widest pt-2">Orchestration Role</p>
              {ROLE_OPTIONS.map(r => (
                <button key={r.value} onClick={() => setForm(f => ({ ...f, role: r.value }))}
                  className={`w-full flex items-start gap-4 p-4 rounded-xl border text-left transition-colors ${form.role === r.value ? 'border-primary bg-primary/5' : 'border-white/10 hover:border-white/20'}`}
                >
                  <div className={`w-4 h-4 rounded-full border-2 mt-0.5 flex-shrink-0 ${form.role === r.value ? 'border-primary bg-primary' : 'border-white/30'}`} />
                  <div>
                    <p className="font-headline font-bold text-sm">{r.label}</p>
                    <p className="text-xs text-on-surface-muted mt-0.5">{r.desc}</p>
                  </div>
                </button>
              ))}
              {form.role === 'sub_agent' && (
                <div>
                  <label className="text-[10px] uppercase font-technical text-on-surface-muted tracking-widest block mb-1">Orchestrator Agent ID *</label>
                  <input value={form.orchestrator_id} onChange={e => setForm(f => ({ ...f, orchestrator_id: e.target.value }))}
                    placeholder="UUID of the orchestrator agent this sub-agent is bound to"
                    className="w-full bg-black/40 border border-white/10 rounded-lg p-3 text-sm font-technical focus:outline-none focus:border-primary transition-colors"
                  />
                </div>
              )}
            </div>
          </>
        )}

        {/* ── Step 4 — Scope ────────────────────────────────────────────────── */}
        {step === 4 && (
          <>
            <div>
              <h2 className="text-xl font-headline font-bold mb-1">Declare scope entitlements</h2>
              <p className="text-sm text-on-surface-muted">Select every action your agent is permitted to perform. The Sentry Gateway enforces these boundaries on every request. Only declare what your agent genuinely needs.</p>
            </div>
            <div className="space-y-3">
              {SCOPE_OPTIONS.map(s => (
                <button key={s.value} onClick={() => toggleScope(s.value)}
                  className={`w-full flex items-start gap-4 p-4 rounded-xl border text-left transition-colors ${form.scopes.includes(s.value) ? 'border-primary bg-primary/5' : 'border-white/10 hover:border-white/20'}`}
                >
                  <div className={`w-4 h-4 rounded border-2 mt-0.5 flex-shrink-0 flex items-center justify-center ${form.scopes.includes(s.value) ? 'border-primary bg-primary' : 'border-white/30'}`}>
                    {form.scopes.includes(s.value) && <span className="material-symbols-outlined text-black text-[12px]">check</span>}
                  </div>
                  <div>
                    <p className="font-headline font-bold text-sm">{s.label}</p>
                    <p className="text-xs text-on-surface-muted mt-0.5">{s.desc}</p>
                  </div>
                </button>
              ))}
            </div>
          </>
        )}

        {/* ── Step 5 — Tools ────────────────────────────────────────────────── */}
        {step === 5 && (
          <>
            <div>
              <h2 className="text-xl font-headline font-bold mb-1">Declare tools</h2>
              <p className="text-sm text-on-surface-muted">List every tool your agent is permitted to call. The Sentry Gateway flags any undeclared tool call as a policy violation. This step is optional but strongly recommended.</p>
            </div>

            {form.tools.length === 0 ? (
              <div className="p-6 border border-dashed border-white/10 rounded-xl text-center">
                <span className="material-symbols-outlined text-3xl text-on-surface-muted/30 block mb-2">build</span>
                <p className="text-sm text-on-surface-muted">No tools declared yet.</p>
                <p className="text-xs text-on-surface-muted/60 mt-1">Undeclared tool calls will be flagged as V10 violations by Aegis-0.</p>
              </div>
            ) : (
              <div className="space-y-3">
                {form.tools.map((tool, i) => (
                  <div key={i} className="p-4 bg-black/30 border border-white/10 rounded-xl space-y-3">
                    <div className="flex items-center justify-between">
                      <p className="text-xs font-technical text-on-surface-muted">Tool {i + 1}</p>
                      <button onClick={() => removeTool(i)} className="text-neutral-600 hover:text-red-400 transition-colors">
                        <span className="material-symbols-outlined text-[16px]">delete</span>
                      </button>
                    </div>
                    <div className="grid grid-cols-2 gap-3">
                      <div>
                        <label className="text-[10px] uppercase font-technical text-on-surface-muted tracking-widest block mb-1">Tool Name *</label>
                        <input value={tool.tool_name} onChange={e => updateTool(i, 'tool_name', e.target.value)}
                          placeholder="e.g. send_email"
                          className="w-full bg-black/40 border border-white/10 rounded-lg p-2.5 text-sm font-technical focus:outline-none focus:border-primary transition-colors"
                        />
                      </div>
                      <div>
                        <label className="text-[10px] uppercase font-technical text-on-surface-muted tracking-widest block mb-1">Tool ID</label>
                        <input value={tool.tool_id} onChange={e => updateTool(i, 'tool_id', e.target.value)}
                          placeholder="Auto-generated if blank"
                          className="w-full bg-black/40 border border-white/10 rounded-lg p-2.5 text-sm font-technical focus:outline-none focus:border-primary transition-colors"
                        />
                      </div>
                    </div>
                    <div>
                      <label className="text-[10px] uppercase font-technical text-on-surface-muted tracking-widest block mb-1">Description</label>
                      <input value={tool.tool_description} onChange={e => updateTool(i, 'tool_description', e.target.value)}
                        placeholder="What does this tool do?"
                        className="w-full bg-black/40 border border-white/10 rounded-lg p-2.5 text-sm focus:outline-none focus:border-primary transition-colors"
                      />
                    </div>
                  </div>
                ))}
              </div>
            )}

            <button onClick={addTool}
              className="w-full flex items-center justify-center gap-2 px-4 py-3 border border-dashed border-white/20 rounded-xl text-sm text-on-surface-muted hover:border-primary hover:text-primary transition-colors"
            >
              <span className="material-symbols-outlined text-[16px]">add</span>
              Add Tool
            </button>
          </>
        )}

        {/* ── Step 6 — Failure ─────────────────────────────────────────────── */}
        {step === 6 && (
          <>
            <div>
              <h2 className="text-xl font-headline font-bold mb-1">Declare failure behaviour</h2>
              <p className="text-sm text-on-surface-muted">What is your agent permitted to do when it is blocked or rejected? This is a mandatory declaration.</p>
              <div className="mt-3 p-3 bg-yellow-500/10 border border-yellow-500/20 rounded-lg">
                <p className="text-xs text-yellow-400 font-technical">The Verification Swarm will specifically red-team your failure paths. Be accurate — declaring a wider failure scope than needed reduces your agent's trust tier.</p>
              </div>
            </div>
            <div className="space-y-3">
              {FAILURE_OPTIONS.map(f => (
                <button key={f.value} onClick={() => setForm(fm => ({ ...fm, failure_scope: f.value }))}
                  className={`w-full flex items-start gap-4 p-4 rounded-xl border text-left transition-colors ${form.failure_scope === f.value ? 'border-primary bg-primary/5' : 'border-white/10 hover:border-white/20'}`}
                >
                  <div className={`w-4 h-4 rounded-full border-2 mt-0.5 flex-shrink-0 ${form.failure_scope === f.value ? 'border-primary bg-primary' : 'border-white/30'}`} />
                  <div>
                    <p className="font-headline font-bold text-sm">{f.label}</p>
                    <p className="text-xs text-on-surface-muted mt-0.5">{f.desc}</p>
                  </div>
                </button>
              ))}
            </div>
          </>
        )}

        {/* ── Step 7 — Security ─────────────────────────────────────────────── */}
        {step === 7 && (
          <>
            <div>
              <h2 className="text-xl font-headline font-bold mb-1">Security options</h2>
              <p className="text-sm text-on-surface-muted">Configure optional security controls for this agent.</p>
            </div>

            {/* Shadow Mode */}
            <div className="p-5 rounded-xl border border-white/10 space-y-4">
              <div className="flex items-start justify-between gap-4">
                <div>
                  <p className="font-headline font-bold text-sm">Shadow Mode</p>
                  <p className="text-xs text-on-surface-muted mt-1">Log violations without blocking traffic. The Gateway will evaluate all policies and record results to the audit ledger, but allow the call to proceed. Use this to establish behavioral baselines before enabling strict enforcement.</p>
                </div>
                <button onClick={() => setForm(f => ({ ...f, shadow_mode: !f.shadow_mode }))}
                  className={`relative w-12 h-6 rounded-full flex-shrink-0 transition-colors ${form.shadow_mode ? 'bg-amber-500' : 'bg-white/20'}`}
                >
                  <div className={`absolute top-1 w-4 h-4 rounded-full bg-white transition-transform ${form.shadow_mode ? 'translate-x-7' : 'translate-x-1'}`} />
                </button>
              </div>
              {form.shadow_mode && (
                <div className="p-3 bg-amber-500/10 border border-amber-500/20 rounded-lg">
                  <p className="text-xs text-amber-400 font-technical">Shadow Mode active — policy violations will be logged but traffic will NOT be blocked. Velocity limits and circuit breakers remain enforced regardless.</p>
                </div>
              )}
            </div>

            {/* Human-in-the-Loop */}
            <div className="p-5 rounded-xl border border-white/10 space-y-4">
              <div className="flex items-start justify-between gap-4">
                <div>
                  <p className="font-headline font-bold text-sm">Human-in-the-Loop approval</p>
                  <p className="text-xs text-on-surface-muted mt-1">When enabled, the Sentry Gateway intercepts any <span className="font-technical text-primary">proxy:write</span> or <span className="font-technical text-primary">proxy:transact</span> call, encrypts the payload, and immediately returns a <span className="font-technical text-primary">202 Accepted</span>. The trace is held in a Suspended Saga queue while a human reviews it asynchronously.</p>
                </div>
                <button onClick={() => setForm(f => ({ ...f, hitl_enabled: !f.hitl_enabled }))}
                  className={`relative w-12 h-6 rounded-full flex-shrink-0 transition-colors ${form.hitl_enabled ? 'bg-primary' : 'bg-white/20'}`}
                >
                  <div className={`absolute top-1 w-4 h-4 rounded-full bg-white transition-transform ${form.hitl_enabled ? 'translate-x-7' : 'translate-x-1'}`} />
                </button>
              </div>
              {form.hitl_enabled && (
                <>
                  <div className="p-3 bg-yellow-500/10 border border-yellow-500/20 rounded-lg">
                    <p className="text-xs text-yellow-400 font-technical">HITL suspends the call asynchronously. The origin service receives a 202 immediately — no TCP hold. If no operator acts within the timeout window, the trace is automatically denied.</p>
                  </div>
                  <div>
                    <label className="text-[10px] uppercase font-technical text-on-surface-muted tracking-widest block mb-1">Resume Webhook URL *</label>
                    <input value={form.hitl_webhook_url} onChange={e => setForm(f => ({ ...f, hitl_webhook_url: e.target.value }))}
                      placeholder="https://your-system.com/cicada/resume"
                      className="w-full bg-black/40 border border-white/10 rounded-lg p-3 text-sm font-technical focus:outline-none focus:border-primary transition-colors"
                    />
                    <p className="text-[10px] text-on-surface-muted/50 font-technical mt-1">The Saga Executor will POST the approval or denial decision to this URL.</p>
                  </div>
                  <div>
                    <label className="text-[10px] uppercase font-technical text-on-surface-muted tracking-widest block mb-1">Timeout Hours</label>
                    <input type="number" min="1" max="168" value={form.hitl_timeout_hours} onChange={e => setForm(f => ({ ...f, hitl_timeout_hours: e.target.value }))}
                      className="w-32 bg-black/40 border border-white/10 rounded-lg p-3 text-sm font-technical focus:outline-none focus:border-primary transition-colors"
                    />
                    <p className="text-[10px] text-on-surface-muted/50 font-technical mt-1">If no operator acts within this window, the suspended trace is automatically denied by a background cron.</p>
                  </div>
                </>
              )}
              {!form.hitl_enabled && (
                <p className="text-xs text-on-surface-muted/50 font-technical">Off — calls proceed through Swarm verification only.</p>
              )}
            </div>
          </>
        )}

        {/* ── Step 8 — API Key ─────────────────────────────────────────────── */}
        {step === 8 && (
          <>
            <div>
              <h2 className="text-xl font-headline font-bold mb-1">Bind your API key</h2>
              <p className="text-sm text-on-surface-muted">Your key is encrypted immediately using AES-256 and stored only in its encrypted form. Cicada never sees your raw API key after this point.</p>
            </div>
            <div className="space-y-4">
              <div>
                <label className="text-[10px] uppercase font-technical text-on-surface-muted tracking-widest block mb-1">LLM Provider</label>
                <select value={form.api_provider} onChange={e => setForm(f => ({ ...f, api_provider: e.target.value }))}
                  className="w-full bg-black/40 border border-white/10 rounded-lg p-3 text-sm focus:outline-none focus:border-primary transition-colors"
                >
                  <option value="openai">OpenAI</option>
                  <option value="anthropic">Anthropic</option>
                  <option value="google">Google Gemini</option>
                  <option value="cohere">Cohere</option>
                </select>
              </div>
              <div>
                <label className="text-[10px] uppercase font-technical text-on-surface-muted tracking-widest block mb-1">API Key *</label>
                <input type="password" value={form.api_key} onChange={e => setForm(f => ({ ...f, api_key: e.target.value }))}
                  placeholder="sk-..."
                  className="w-full bg-black/40 border border-white/10 rounded-lg p-3 text-sm font-mono focus:outline-none focus:border-primary transition-colors"
                />
              </div>
              <div>
                <label className="text-[10px] uppercase font-technical text-on-surface-muted tracking-widest block mb-1">Target Model</label>
                <input value={form.target_model} onChange={e => setForm(f => ({ ...f, target_model: e.target.value }))}
                  placeholder="gpt-4o"
                  className="w-full bg-black/40 border border-white/10 rounded-lg p-3 text-sm focus:outline-none focus:border-primary transition-colors"
                />
              </div>
            </div>

            {/* Registration summary */}
            <div className="p-4 bg-white/[0.02] border border-white/5 rounded-xl space-y-2 text-xs font-technical">
              <p className="text-on-surface-muted uppercase tracking-widest text-[10px] mb-3">Registration Summary</p>
              <div className="grid grid-cols-2 gap-x-6 gap-y-1.5">
                <div><span className="text-neutral-500">Name:</span> <span className="text-white">{form.agent_name}</span></div>
                <div><span className="text-neutral-500">Owner:</span> <span className="text-white">{form.owner_name || '—'}</span></div>
                <div><span className="text-neutral-500">Type:</span> <span className="text-white">{form.agent_type || '—'}</span></div>
                <div><span className="text-neutral-500">Role:</span> <span className="text-white">{form.role}</span></div>
                <div><span className="text-neutral-500">Criticality:</span> <span className="text-white">{form.criticality_level}</span></div>
                <div><span className="text-neutral-500">Classification:</span> <span className="text-white">{form.data_classification}</span></div>
                <div><span className="text-neutral-500">Scopes:</span> <span className="text-white">{form.scopes.length} declared</span></div>
                <div><span className="text-neutral-500">Tools:</span> <span className="text-white">{form.tools.filter(t => t.tool_name.trim()).length} declared</span></div>
                {form.expected_velocity && <div><span className="text-neutral-500">Velocity:</span> <span className="text-white">{form.expected_velocity}/hr</span></div>}
                {form.monthly_budget_usd && <div><span className="text-neutral-500">Budget:</span> <span className="text-white">${form.monthly_budget_usd}/mo</span></div>}
                {form.regulatory_frameworks.length > 0 && <div className="col-span-2"><span className="text-neutral-500">Frameworks:</span> <span className="text-white">{form.regulatory_frameworks.join(', ')}</span></div>}
              </div>
            </div>

            {error && <p className="text-sm text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg p-3 whitespace-pre-wrap">{error}</p>}
          </>
        )}

        {/* ── Navigation ───────────────────────────────────────────────────── */}
        <div className="flex items-center justify-between pt-2">
          <button onClick={() => setStep(s => s - 1)} disabled={step === 1}
            className="px-5 py-2.5 rounded-xl font-headline font-bold text-sm text-on-surface-muted hover:text-on-surface disabled:opacity-30 transition-colors"
          >
            ← Back
          </button>
          {step < 8 ? (
            <button onClick={() => setStep(s => s + 1)} disabled={!canNext()}
              className="px-6 py-2.5 bg-primary text-black rounded-xl font-headline font-bold text-sm hover:brightness-110 disabled:opacity-40 transition-all"
            >
              Continue →
            </button>
          ) : (
            <button onClick={submit} disabled={!canNext() || submitting}
              className="px-6 py-2.5 bg-primary text-black rounded-xl font-headline font-bold text-sm hover:brightness-110 disabled:opacity-40 transition-all"
            >
              {submitting ? 'Registering...' : 'Register & Get EVAR →'}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
