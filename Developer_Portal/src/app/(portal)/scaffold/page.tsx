// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

'use client';

import React, { useState, useCallback, useMemo } from 'react';
import { useSession } from '../layout';
import { mapScaffoldToProvisionPayload, type ProvisionResponse, type ProvisionErrorResponse } from '@/lib/agent-mapping';

const CORE_API = process.env.NEXT_PUBLIC_CORE_API_URL || 'http://localhost:8000';

/* ─── Tool catalogue ──────────────────────────────────────────────────────── */
const TOOL_CATALOGUE = [
  { id: 'stripe',    label: 'Stripe',     icon: '💳', desc: 'Payment processing', urls: ['https://api.stripe.com/v1/*'],            methods: ['GET','POST'],            risk: 'high',     destructive: false, criticality: 'high' },
  { id: 'slack',     label: 'Slack',      icon: '💬', desc: 'Messaging',          urls: ['https://slack.com/api/*'],                 methods: ['GET','POST'],            risk: 'medium',   destructive: false, criticality: 'low' },
  { id: 'github',    label: 'GitHub',     icon: '🐙', desc: 'Code management',    urls: ['https://api.github.com/*'],                methods: ['GET','POST','PUT','DELETE'], risk: 'high', destructive: false, criticality: 'medium' },
  { id: 'sendgrid',  label: 'SendGrid',   icon: '📧', desc: 'Email delivery',     urls: ['https://api.sendgrid.com/v3/*'],           methods: ['GET','POST'],            risk: 'medium',   destructive: false, criticality: 'medium' },
  { id: 'openai',    label: 'OpenAI',     icon: '🤖', desc: 'LLM API',            urls: ['https://api.openai.com/v1/*'],             methods: ['POST'],                  risk: 'medium',   destructive: false, criticality: 'low' },
  { id: 'anthropic', label: 'Anthropic',  icon: '🧠', desc: 'Claude API',         urls: ['https://api.anthropic.com/v1/*'],          methods: ['POST'],                  risk: 'medium',   destructive: false, criticality: 'low' },
  { id: 'postgres',  label: 'PostgreSQL', icon: '🐘', desc: 'Database access',    urls: ['https://api.internal.example.com/v1/db/*'],methods: ['GET','POST','PUT','DELETE'], risk: 'high', destructive: true, criticality: 'high' },
  { id: 'shell',     label: 'Shell',      icon: '🖥️', desc: 'Shell execution',    urls: ['https://api.internal.example.com/v1/exec/*'],methods: ['POST'],                risk: 'critical', destructive: true, criticality: 'high' },
  { id: 'datadog',   label: 'Datadog',    icon: '📊', desc: 'Monitoring',         urls: ['https://api.datadoghq.com/api/v1/*'],      methods: ['GET'],                   risk: 'low',      destructive: false, criticality: 'low' },
  { id: 'aws-s3',    label: 'AWS S3',     icon: '☁️', desc: 'Object storage',     urls: ['https://s3.amazonaws.com/*'],              methods: ['GET','PUT','DELETE'],     risk: 'high',     destructive: true, criticality: 'high' },
  { id: 'jira',      label: 'Jira',       icon: '📋', desc: 'Issue tracking',     urls: ['https://*.atlassian.net/rest/api/*'],      methods: ['GET','POST','PUT'],       risk: 'medium',   destructive: false, criticality: 'low' },
  { id: 'twilio',    label: 'Twilio',     icon: '📱', desc: 'SMS & voice',        urls: ['https://api.twilio.com/*'],                methods: ['GET','POST'],            risk: 'medium',   destructive: false, criticality: 'medium' },
];

const FRAMEWORK_OPTIONS = [
  { id: 'langchain', label: 'LangChain',  icon: '🔗', desc: 'Python agent framework with tool-calling and memory' },
  { id: 'crewai',    label: 'CrewAI',     icon: '👥', desc: 'Multi-agent teams with role-based collaboration' },
  { id: 'python',    label: 'Python',     icon: '🐍', desc: 'Raw Python — no framework, maximum control' },
  { id: 'node',      label: 'Node.js',    icon: '⬢',  desc: 'Node.js with @cicada/sdk (native fetch)' },
  { id: 'autogen',   label: 'AutoGen',    icon: '🔄', desc: 'Multi-agent orchestration with group chat' },
];

const COMPLIANCE_OPTIONS = ['SOC2', 'GDPR', 'ISO27001', 'HIPAA', 'PCI-DSS', 'FedRAMP', 'NIST-800-53', 'EU AI Act', 'CCPA', 'DORA'];
const REGIONS = ['US', 'EU', 'UK', 'APAC', 'GLOBAL'];

const STEPS = [
  { n: 1, label: 'Framework',   icon: 'code' },
  { n: 2, label: 'Identity',    icon: 'badge' },
  { n: 3, label: 'Tools',       icon: 'build' },
  { n: 4, label: 'Enforcement', icon: 'shield' },
  { n: 5, label: 'Compliance',  icon: 'gavel' },
  { n: 6, label: 'Download',    icon: 'download' },
];

type CustomTool = {
  name: string;
  description: string;
  url_pattern: string;
  methods: string[];
  destructive: boolean;
  criticality_level: 'low' | 'medium' | 'high';
  allowed_upstreams: string;
  input_schema: string;
};

/* ─── YAML generator ─────────────────────────────────────────────────────── */
function generateYAML(state: any): string {
  const { framework, identity, selectedTools, customTools, enforcement, compliance } = state;

  const allTools = [
    ...selectedTools.map((id: string) => {
      const cat = TOOL_CATALOGUE.find(t => t.id === id)!;
      return {
        name: cat.id + '-api',
        description: cat.desc + ' via ' + cat.label + ' API',
        url_patterns: cat.urls,
        methods: cat.methods,
        destructive: cat.destructive,
        risk_level: cat.risk,
        criticality_level: cat.criticality,
      };
    }),
    ...customTools.map((t: CustomTool) => ({
      name: t.name.toLowerCase().replace(/\s+/g, '-'),
      description: t.description,
      url_patterns: [t.url_pattern],
      methods: t.methods,
      destructive: t.destructive,
      risk_level: t.destructive ? 'critical' : 'medium',
      criticality_level: t.criticality_level,
      allowed_upstreams: t.allowed_upstreams.trim() ? t.allowed_upstreams.split(',').map((s: string) => s.trim()).filter(Boolean) : [],
      input_schema: t.input_schema.trim() || null,
    })),
  ];

  const hasDestructive = allTools.some((t: any) => t.destructive) || enforcement.destructive;
  const hitlEnabled = enforcement.hitl || hasDestructive;

  let yaml = `# cicada.yaml — Cicada Agent Governance Policy\n`;
  yaml += `# Scaffolded via Developer Portal on ${new Date().toISOString().split('T')[0]}\n`;
  yaml += `# Framework: ${framework}\n\n`;
  yaml += `apiVersion: cicada/v1\nkind: AgentPolicy\n\n`;

  // Identity
  yaml += `identity:\n`;
  yaml += `  name: "${identity.name}"\n`;
  yaml += `  description: "${identity.description}"\n`;
  yaml += `  type: ${identity.type}\n`;
  yaml += `  role: ${identity.role}\n`;
  yaml += `  owner: ${identity.owner}\n`;
  if (identity.businessUnit) yaml += `  business_unit: ${identity.businessUnit}\n`;
  yaml += `  data_classification: ${identity.dataClassification}\n`;
  yaml += `  criticality: ${identity.criticality}\n`;

  // Tools
  yaml += `\ntools:\n`;
  for (const tool of allTools) {
    yaml += `  - name: ${tool.name}\n`;
    yaml += `    description: "${tool.description}"\n`;
    yaml += `    url_patterns:\n`;
    for (const u of tool.url_patterns) yaml += `      - "${u}"\n`;
    yaml += `    methods: [${tool.methods.join(', ')}]\n`;
    if (tool.destructive) yaml += `    destructive: true\n`;
    yaml += `    risk_level: ${tool.risk_level}\n`;
    yaml += `    criticality_level: ${tool.criticality_level}\n`;
    if ((tool as any).allowed_upstreams?.length > 0) {
      yaml += `    allowed_upstreams:\n`;
      for (const u of (tool as any).allowed_upstreams) yaml += `      - "${u}"\n`;
    }
    if ((tool as any).input_schema) {
      yaml += `    input_schema: |\n`;
      for (const line of (tool as any).input_schema.split('\n')) yaml += `      ${line}\n`;
    }
  }

  // Enforcement
  yaml += `\nenforcement:\n`;
  yaml += `  velocity:\n`;
  yaml += `    max_reads_per_minute: ${enforcement.maxReads}\n`;
  yaml += `    max_writes_per_minute: ${enforcement.maxWrites}\n`;
  yaml += `    max_deletes_per_minute: ${enforcement.maxDeletes}\n`;
  yaml += `    circuit_breaker_threshold: ${enforcement.circuitBreaker}\n`;
  yaml += `  hitl:\n`;
  yaml += `    enabled: ${hitlEnabled}\n`;
  if (hitlEnabled && enforcement.hitlWebhook) yaml += `    webhook_url: "${enforcement.hitlWebhook}"\n`;
  yaml += `    timeout_seconds: ${enforcement.hitlTimeout}\n`;
  yaml += `    auto_deny_on_timeout: true\n`;
  yaml += `    risk_threshold: ${enforcement.riskThreshold}\n`;
  yaml += `  shadow_mode: ${enforcement.shadowMode}\n`;
  yaml += `  destructive_capability: ${hasDestructive}\n`;

  // Provenance
  yaml += `\nprovenance:\n`;
  yaml += `  evar_binding: true\n`;
  yaml += `  content_tagging: ${enforcement.contentTagging}\n`;
  yaml += `  audit_retention_days: ${compliance.retentionDays}\n`;

  // Compliance
  if (compliance.frameworks.length > 0) {
    yaml += `\ncompliance:\n`;
    yaml += `  frameworks: [${compliance.frameworks.join(', ')}]\n`;
    yaml += `  regulatory_region: ${compliance.region}\n`;
    if (compliance.budgetCap) yaml += `  budget_cap_usd: ${compliance.budgetCap}\n`;
    if (compliance.costCentre) yaml += `  cost_centre: "${compliance.costCentre}"\n`;
  }

  return yaml;
}

/* ─── Download helper ────────────────────────────────────────────────────── */
function downloadFile(filename: string, content: string) {
  const blob = new Blob([content], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename; a.click();
  URL.revokeObjectURL(url);
}

function downloadZip(files: { name: string; content: string }[]) {
  // Simple multi-file download — each file individually
  // In production, use JSZip for proper ZIP bundling
  files.forEach((f, i) => {
    setTimeout(() => downloadFile(f.name, f.content), i * 300);
  });
}

/* ═══════════════════════════════════════════════════════════════════════════ */

export default function ScaffoldPage() {
  const session = useSession();
  const [step, setStep] = useState(1);

  // ── State ───────────────────────────────────────────────────────────────
  const [framework, setFramework] = useState('');
  const [identity, setIdentity] = useState({
    name: '', description: '', type: 'autonomous', role: 'processor',
    owner: session?.contact.email || '', businessUnit: '', dataClassification: 'internal', criticality: 'medium',
  });
  const [selectedTools, setSelectedTools] = useState<string[]>([]);
  const [customTools, setCustomTools] = useState<CustomTool[]>([]);
  const [enforcement, setEnforcement] = useState({
    maxReads: 100, maxWrites: 20, maxDeletes: 5, circuitBreaker: 10,
    hitl: false, hitlWebhook: '', hitlTimeout: 3600, riskThreshold: 0.6,
    shadowMode: false, destructive: false, contentTagging: true,
  });
  const [compliance, setCompliance] = useState({
    frameworks: [] as string[], region: 'GLOBAL', retentionDays: 365,
    budgetCap: '', costCentre: '',
  });

  // ── BYOK + Registration State ──────────────────────────────────────────
  const [apiProvider, setApiProvider] = useState('openai');
  const [apiKey, setApiKey] = useState('');
  const [targetModel, setTargetModel] = useState('gpt-4o');
  const [registering, setRegistering] = useState(false);
  const [registerError, setRegisterError] = useState('');
  const [registerResult, setRegisterResult] = useState<ProvisionResponse['data'] | null>(null);

  // ── Computed risk analysis ──────────────────────────────────────────────
  const riskAnalysis = useMemo(() => {
    const hasDestructive = selectedTools.some(id => TOOL_CATALOGUE.find(t => t.id === id)?.destructive) ||
                           customTools.some(t => t.destructive) || enforcement.destructive;
    const hasHighRisk = selectedTools.some(id => {
      const t = TOOL_CATALOGUE.find(c => c.id === id);
      return t?.risk === 'high' || t?.risk === 'critical';
    });
    const needsHITL = hasDestructive;
    const hitlMissing = needsHITL && !enforcement.hitl;

    const issues: string[] = [];
    if (hitlMissing) issues.push('Destructive tools detected — HITL will be auto-enabled');
    if (hasHighRisk && !enforcement.hitl) issues.push('High-risk tools without HITL — consider enabling');
    if (identity.criticality === 'critical' && !enforcement.hitl) issues.push('Critical agent without HITL');
    if (selectedTools.length === 0 && customTools.length === 0) issues.push('No tools declared');

    return { hasDestructive, hasHighRisk, needsHITL, hitlMissing, issues };
  }, [selectedTools, customTools, enforcement, identity.criticality]);

  // ── Validation ──────────────────────────────────────────────────────────
  const canNext = useCallback(() => {
    if (step === 1) return framework !== '';
    if (step === 2) return identity.name.trim().length >= 3 && identity.owner.trim().length > 0;
    if (step === 3) return selectedTools.length > 0 || customTools.length > 0;
    if (step === 4) return true;
    if (step === 5) return true;
    return true;
  }, [step, framework, identity, selectedTools, customTools]);

  // ── YAML preview ────────────────────────────────────────────────────────
  const yamlPreview = useMemo(() => {
    if (step < 6) return '';
    return generateYAML({ framework, identity, selectedTools, customTools, enforcement, compliance });
  }, [step, framework, identity, selectedTools, customTools, enforcement, compliance]);

  function toggleTool(id: string) {
    setSelectedTools(prev => prev.includes(id) ? prev.filter(t => t !== id) : [...prev, id]);
  }
  function toggleFramework(id: string) {
    setCompliance(c => ({
      ...c,
      frameworks: c.frameworks.includes(id) ? c.frameworks.filter(f => f !== id) : [...c.frameworks, id],
    }));
  }
  function addCustomTool() {
    setCustomTools(prev => [...prev, { name: '', description: '', url_pattern: '', methods: ['GET','POST'], destructive: false, criticality_level: 'low', allowed_upstreams: '', input_schema: '' }]);
  }
  function updateCustomTool(i: number, field: keyof CustomTool, val: any) {
    setCustomTools(prev => { const t = [...prev]; t[i] = { ...t[i], [field]: val }; return t; });
  }
  function removeCustomTool(i: number) {
    setCustomTools(prev => prev.filter((_, idx) => idx !== i));
  }

  return (
    <div className="p-8">

      {/* ── Header ─────────────────────────────────────────────────────────── */}
      <div className="mb-8">
        <div className="flex items-center gap-3 mb-2">
          <span className="material-symbols-outlined text-3xl text-primary">construction</span>
          <h1 className="text-3xl font-black font-headline tracking-tighter">Scaffold an Agent</h1>
        </div>
        <p className="text-on-surface-muted text-sm">
          Generate a complete, governance-compliant agent project. Select your framework, declare your tools,
          configure enforcement — download a ready-to-run agent with <span className="font-technical text-primary">cicada.yaml</span> baked in.
        </p>
      </div>

      {/* ── Step Indicator ─────────────────────────────────────────────────── */}
      <div className="flex items-center gap-1 mb-8 overflow-x-auto pb-2">
        {STEPS.map((s, i) => (
          <React.Fragment key={s.n}>
            <button
              onClick={() => { if (s.n < step || canNext()) setStep(s.n); }}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-technical transition-colors whitespace-nowrap flex-shrink-0 ${
                step === s.n ? 'bg-primary text-black' :
                step > s.n  ? 'bg-primary/20 text-primary cursor-pointer' :
                'bg-white/5 text-on-surface-muted'
              }`}
            >
              <span className="material-symbols-outlined text-[13px]">{step > s.n ? 'check_circle' : s.icon}</span>
              <span className="hidden sm:block">{s.label}</span>
            </button>
            {i < STEPS.length - 1 && <div className={`w-3 h-px flex-shrink-0 ${step > s.n ? 'bg-primary/40' : 'bg-white/10'}`} />}
          </React.Fragment>
        ))}
      </div>

      {/* ── Risk Banner ────────────────────────────────────────────────────── */}
      {riskAnalysis.issues.length > 0 && step > 2 && step < 6 && (
        <div className="mb-6 p-4 rounded-xl border border-amber-500/30 bg-amber-500/5">
          <div className="flex items-center gap-2 mb-2">
            <span className="material-symbols-outlined text-amber-400 text-[18px]">warning</span>
            <p className="text-sm font-headline font-bold text-amber-400">Risk Assessment</p>
          </div>
          {riskAnalysis.issues.map((issue, i) => (
            <p key={i} className="text-xs text-amber-300/80 font-technical ml-6">• {issue}</p>
          ))}
        </div>
      )}

      <div className="bg-surface-container border border-[rgba(255,159,74,0.12)] rounded-2xl p-8 space-y-6">

        {/* ═══ Step 1 — Framework ═══════════════════════════════════════════ */}
        {step === 1 && (
          <>
            <div>
              <h2 className="text-xl font-headline font-bold mb-1">Choose your framework</h2>
              <p className="text-sm text-on-surface-muted">
                The scaffolder generates framework-specific code with Cicada SDK integration.
                Your LLM provider, model, and business logic remain yours.
              </p>
            </div>
            <div className="grid grid-cols-1 gap-3">
              {FRAMEWORK_OPTIONS.map(f => (
                <button key={f.id} onClick={() => setFramework(f.id)}
                  className={`flex items-center gap-4 p-5 rounded-xl border text-left transition-all ${
                    framework === f.id ? 'border-primary bg-primary/5 glow-active' : 'border-white/10 hover:border-white/20 hover:bg-white/[0.02]'
                  }`}
                >
                  <span className="text-3xl">{f.icon}</span>
                  <div className="flex-1">
                    <p className="font-headline font-bold">{f.label}</p>
                    <p className="text-xs text-on-surface-muted mt-0.5">{f.desc}</p>
                  </div>
                  <div className={`w-5 h-5 rounded-full border-2 flex-shrink-0 flex items-center justify-center ${
                    framework === f.id ? 'border-primary bg-primary' : 'border-white/30'
                  }`}>
                    {framework === f.id && <span className="material-symbols-outlined text-black text-[14px]">check</span>}
                  </div>
                </button>
              ))}
            </div>
          </>
        )}

        {/* ═══ Step 2 — Identity ════════════════════════════════════════════ */}
        {step === 2 && (
          <>
            <div>
              <h2 className="text-xl font-headline font-bold mb-1">Agent identity</h2>
              <p className="text-sm text-on-surface-muted">Define who this agent is and what it does.</p>
            </div>
            <div className="space-y-4">
              <div>
                <label className="text-[10px] uppercase font-technical text-on-surface-muted tracking-widest block mb-1">Agent Name *</label>
                <input value={identity.name} onChange={e => setIdentity(s => ({ ...s, name: e.target.value }))}
                  placeholder="e.g. billing-reconciliation-agent"
                  className="w-full bg-black/40 border border-white/10 rounded-lg p-3 text-sm font-technical focus:outline-none focus:border-primary transition-colors"
                />
                <p className="text-[10px] text-on-surface-muted/50 font-technical mt-1">Lowercase, hyphens/underscores. Min 3 chars.</p>
              </div>
              <div>
                <label className="text-[10px] uppercase font-technical text-on-surface-muted tracking-widest block mb-1">Description</label>
                <textarea value={identity.description} onChange={e => setIdentity(s => ({ ...s, description: e.target.value }))}
                  placeholder="Describe what this agent does. This is used by the semantic intent engine for alignment scoring."
                  rows={3}
                  className="w-full bg-black/40 border border-white/10 rounded-lg p-3 text-sm focus:outline-none focus:border-primary transition-colors resize-none"
                />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-[10px] uppercase font-technical text-on-surface-muted tracking-widest block mb-1">Owner Email *</label>
                  <input value={identity.owner} onChange={e => setIdentity(s => ({ ...s, owner: e.target.value }))}
                    placeholder="owner@company.com"
                    className="w-full bg-black/40 border border-white/10 rounded-lg p-3 text-sm focus:outline-none focus:border-primary transition-colors"
                  />
                </div>
                <div>
                  <label className="text-[10px] uppercase font-technical text-on-surface-muted tracking-widest block mb-1">Business Unit</label>
                  <input value={identity.businessUnit} onChange={e => setIdentity(s => ({ ...s, businessUnit: e.target.value }))}
                    placeholder="e.g. finance"
                    className="w-full bg-black/40 border border-white/10 rounded-lg p-3 text-sm focus:outline-none focus:border-primary transition-colors"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-[10px] uppercase font-technical text-on-surface-muted tracking-widest block mb-2">Agent Type</label>
                  <div className="space-y-2">
                    {['autonomous', 'semi-autonomous', 'supervised', 'orchestrator', 'sub-agent'].map(t => (
                      <button key={t} onClick={() => setIdentity(s => ({ ...s, type: t }))}
                        className={`w-full text-left px-3 py-2 rounded-lg border text-xs font-technical transition-colors ${
                          identity.type === t ? 'border-primary bg-primary/10 text-primary' : 'border-white/10 text-on-surface-muted hover:border-white/20'
                        }`}
                      >{t}</button>
                    ))}
                  </div>
                </div>
                <div>
                  <label className="text-[10px] uppercase font-technical text-on-surface-muted tracking-widest block mb-2">Criticality</label>
                  <div className="space-y-2">
                    {[
                      { v: 'low', c: 'text-emerald-400 border-emerald-500/30 bg-emerald-500/5' },
                      { v: 'medium', c: 'text-blue-400 border-blue-500/30 bg-blue-500/5' },
                      { v: 'high', c: 'text-orange-400 border-orange-500/30 bg-orange-500/5' },
                      { v: 'critical', c: 'text-red-400 border-red-500/30 bg-red-500/5' },
                    ].map(({ v, c }) => (
                      <button key={v} onClick={() => setIdentity(s => ({ ...s, criticality: v }))}
                        className={`w-full text-left px-3 py-2 rounded-lg border text-xs font-headline font-bold transition-colors ${
                          identity.criticality === v ? c : 'border-white/10 text-on-surface-muted hover:border-white/20'
                        }`}
                      >{v}</button>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </>
        )}

        {/* ═══ Step 3 — Tools ═══════════════════════════════════════════════ */}
        {step === 3 && (
          <>
            <div>
              <h2 className="text-xl font-headline font-bold mb-1">Declare tools</h2>
              <p className="text-sm text-on-surface-muted">
                Select every API your agent will call. Undeclared tool calls are blocked by the Sentry Gateway.
                URL allowlists are auto-populated from your selections.
              </p>
            </div>

            {/* Catalogue */}
            <div>
              <p className="text-[10px] uppercase font-technical text-on-surface-muted tracking-widest mb-3">Integrations Catalogue</p>
              <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-2">
                {TOOL_CATALOGUE.map(t => (
                  <button key={t.id} onClick={() => toggleTool(t.id)}
                    className={`flex items-center gap-2.5 p-3 rounded-xl border text-left transition-all ${
                      selectedTools.includes(t.id)
                        ? t.destructive
                          ? 'border-red-500/40 bg-red-500/5'
                          : 'border-primary/40 bg-primary/5'
                        : 'border-white/10 hover:border-white/20'
                    }`}
                  >
                    <span className="text-xl flex-shrink-0">{t.icon}</span>
                    <div className="min-w-0">
                      <p className="font-headline font-bold text-xs truncate">{t.label}</p>
                      <p className="text-[10px] text-on-surface-muted truncate">{t.desc}</p>
                    </div>
                    {selectedTools.includes(t.id) && (
                      <span className="material-symbols-outlined text-primary text-[16px] ml-auto flex-shrink-0">check_circle</span>
                    )}
                  </button>
                ))}
              </div>
            </div>

            {/* Destructive warning */}
            {riskAnalysis.hasDestructive && (
              <div className="p-3 border border-red-500/30 bg-red-500/5 rounded-xl">
                <div className="flex items-center gap-2">
                  <span className="material-symbols-outlined text-red-400 text-[16px]">warning</span>
                  <p className="text-xs text-red-400 font-technical">
                    Destructive tools detected — HITL (human approval) will be mandatory for write operations.
                  </p>
                </div>
              </div>
            )}

            {/* Custom tools */}
            <div className="border-t border-white/5 pt-4">
              <p className="text-[10px] uppercase font-technical text-on-surface-muted tracking-widest mb-3">Custom Tools</p>
              {customTools.map((t, i) => (
                <div key={i} className="mb-3 p-4 bg-black/30 border border-white/10 rounded-xl space-y-3">
                  <div className="flex items-center justify-between">
                    <p className="text-xs font-technical text-on-surface-muted">Custom Tool {i + 1}</p>
                    <button onClick={() => removeCustomTool(i)} className="text-neutral-600 hover:text-red-400 transition-colors">
                      <span className="material-symbols-outlined text-[16px]">delete</span>
                    </button>
                  </div>
                  <div className="grid grid-cols-2 gap-3">
                    <input value={t.name} onChange={e => updateCustomTool(i, 'name', e.target.value)}
                      placeholder="Tool name" className="bg-black/40 border border-white/10 rounded-lg p-2.5 text-sm font-technical focus:outline-none focus:border-primary transition-colors" />
                    <input value={t.url_pattern} onChange={e => updateCustomTool(i, 'url_pattern', e.target.value)}
                      placeholder="https://api.example.com/v1/*" className="bg-black/40 border border-white/10 rounded-lg p-2.5 text-sm font-technical focus:outline-none focus:border-primary transition-colors" />
                  </div>
                  <input value={t.description} onChange={e => updateCustomTool(i, 'description', e.target.value)}
                    placeholder="What does this tool do?" className="w-full bg-black/40 border border-white/10 rounded-lg p-2.5 text-sm focus:outline-none focus:border-primary transition-colors" />
                  <div className="flex items-center gap-3">
                    <label className="flex items-center gap-2 cursor-pointer">
                      <input type="checkbox" checked={t.destructive} onChange={e => updateCustomTool(i, 'destructive', e.target.checked)}
                        className="accent-red-500" />
                      <span className="text-xs text-on-surface-muted font-technical">Destructive</span>
                    </label>
                    <div className="flex items-center gap-2">
                      <span className="text-[10px] uppercase font-technical text-on-surface-muted tracking-widest">Criticality:</span>
                      {(['low', 'medium', 'high'] as const).map(level => (
                        <button key={level} onClick={() => updateCustomTool(i, 'criticality_level', level)}
                          className={`px-2.5 py-1 rounded-lg border text-[10px] font-technical font-bold transition-colors ${
                            t.criticality_level === level
                              ? level === 'high' ? 'border-red-500/40 bg-red-500/10 text-red-400'
                                : level === 'medium' ? 'border-amber-500/40 bg-amber-500/10 text-amber-400'
                                : 'border-emerald-500/40 bg-emerald-500/10 text-emerald-400'
                              : 'border-white/10 text-on-surface-muted hover:border-white/20'
                          }`}
                        >{level}</button>
                      ))}
                    </div>
                  </div>
                  <div>
                    <label className="text-[10px] uppercase font-technical text-on-surface-muted tracking-widest block mb-1">Allowed Upstreams (comma-separated agent IDs)</label>
                    <input value={t.allowed_upstreams} onChange={e => updateCustomTool(i, 'allowed_upstreams', e.target.value)}
                      placeholder="agent-id-1, agent-id-2 (leave empty for any)"
                      className="w-full bg-black/40 border border-white/10 rounded-lg p-2.5 text-sm font-technical focus:outline-none focus:border-primary transition-colors" />
                  </div>
                  <div>
                    <label className="text-[10px] uppercase font-technical text-on-surface-muted tracking-widest block mb-1">Input Schema (JSON Schema — optional)</label>
                    <textarea value={t.input_schema} onChange={e => updateCustomTool(i, 'input_schema', e.target.value)}
                      placeholder='{"type": "object", "properties": {"amount": {"type": "number"}}, "required": ["amount"]}'
                      rows={3}
                      className="w-full bg-black/40 border border-white/10 rounded-lg p-2.5 text-xs font-mono focus:outline-none focus:border-primary transition-colors resize-none" />
                  </div>
                </div>
              ))}
              <button onClick={addCustomTool}
                className="w-full flex items-center justify-center gap-2 px-4 py-3 border border-dashed border-white/20 rounded-xl text-sm text-on-surface-muted hover:border-primary hover:text-primary transition-colors"
              >
                <span className="material-symbols-outlined text-[16px]">add</span>
                Add Custom Tool
              </button>
            </div>
          </>
        )}

        {/* ═══ Step 4 — Enforcement ════════════════════════════════════════ */}
        {step === 4 && (
          <>
            <div>
              <h2 className="text-xl font-headline font-bold mb-1">Enforcement configuration</h2>
              <p className="text-sm text-on-surface-muted">Configure the Sentry Gateway's seven-layer pipeline for this agent.</p>
            </div>

            {/* Velocity */}
            <div className="space-y-4">
              <p className="text-[10px] uppercase font-technical text-on-surface-muted tracking-widest">Velocity Limits (per minute)</p>
              <div className="grid grid-cols-3 gap-4">
                {[
                  { label: 'Reads', key: 'maxReads' as const, max: 1000 },
                  { label: 'Writes', key: 'maxWrites' as const, max: 200 },
                  { label: 'Deletes', key: 'maxDeletes' as const, max: 50 },
                ].map(v => (
                  <div key={v.key}>
                    <label className="text-xs text-on-surface-muted font-technical block mb-1">{v.label}</label>
                    <input type="number" min="0" max={v.max}
                      value={enforcement[v.key]}
                      onChange={e => setEnforcement(s => ({ ...s, [v.key]: parseInt(e.target.value) || 0 }))}
                      className="w-full bg-black/40 border border-white/10 rounded-lg p-2.5 text-sm font-technical focus:outline-none focus:border-primary transition-colors"
                    />
                  </div>
                ))}
              </div>
              <div>
                <label className="text-xs text-on-surface-muted font-technical block mb-1">Circuit Breaker Threshold (consecutive failures)</label>
                <input type="number" min="1" max="100"
                  value={enforcement.circuitBreaker}
                  onChange={e => setEnforcement(s => ({ ...s, circuitBreaker: parseInt(e.target.value) || 10 }))}
                  className="w-40 bg-black/40 border border-white/10 rounded-lg p-2.5 text-sm font-technical focus:outline-none focus:border-primary transition-colors"
                />
              </div>
            </div>

            {/* HITL */}
            <div className="p-5 rounded-xl border border-white/10 space-y-4">
              <div className="flex items-start justify-between gap-4">
                <div>
                  <p className="font-headline font-bold text-sm">Human-in-the-Loop</p>
                  <p className="text-xs text-on-surface-muted mt-1">Require human approval for write operations.
                    {riskAnalysis.needsHITL && <span className="text-red-400 font-bold"> Mandatory — destructive tools detected.</span>}
                  </p>
                </div>
                <button onClick={() => setEnforcement(s => ({ ...s, hitl: !s.hitl }))}
                  disabled={riskAnalysis.needsHITL}
                  className={`relative w-12 h-6 rounded-full flex-shrink-0 transition-colors ${
                    enforcement.hitl || riskAnalysis.needsHITL ? 'bg-primary' : 'bg-white/20'
                  } ${riskAnalysis.needsHITL ? 'opacity-60' : ''}`}
                >
                  <div className={`absolute top-1 w-4 h-4 rounded-full bg-white transition-transform ${
                    enforcement.hitl || riskAnalysis.needsHITL ? 'translate-x-7' : 'translate-x-1'
                  }`} />
                </button>
              </div>
              {(enforcement.hitl || riskAnalysis.needsHITL) && (
                <>
                  <div>
                    <label className="text-[10px] uppercase font-technical text-on-surface-muted tracking-widest block mb-1">Resume Webhook URL</label>
                    <input value={enforcement.hitlWebhook} onChange={e => setEnforcement(s => ({ ...s, hitlWebhook: e.target.value }))}
                      placeholder="https://your-system.com/cicada/resume"
                      className="w-full bg-black/40 border border-white/10 rounded-lg p-2.5 text-sm font-technical focus:outline-none focus:border-primary transition-colors"
                    />
                  </div>
                  <div>
                    <label className="text-xs text-on-surface-muted font-technical block mb-1">Risk Threshold (0.0–1.0)</label>
                    <input type="number" min="0" max="1" step="0.1"
                      value={enforcement.riskThreshold}
                      onChange={e => setEnforcement(s => ({ ...s, riskThreshold: parseFloat(e.target.value) || 0.6 }))}
                      className="w-32 bg-black/40 border border-white/10 rounded-lg p-2.5 text-sm font-technical focus:outline-none focus:border-primary transition-colors"
                    />
                  </div>
                </>
              )}
            </div>

            {/* Shadow Mode */}
            <div className="p-5 rounded-xl border border-white/10">
              <div className="flex items-start justify-between gap-4">
                <div>
                  <p className="font-headline font-bold text-sm">Shadow Mode</p>
                  <p className="text-xs text-on-surface-muted mt-1">Log violations without blocking. Use this to establish baselines before hard enforcement.</p>
                </div>
                <button onClick={() => setEnforcement(s => ({ ...s, shadowMode: !s.shadowMode }))}
                  className={`relative w-12 h-6 rounded-full flex-shrink-0 transition-colors ${enforcement.shadowMode ? 'bg-amber-500' : 'bg-white/20'}`}
                >
                  <div className={`absolute top-1 w-4 h-4 rounded-full bg-white transition-transform ${enforcement.shadowMode ? 'translate-x-7' : 'translate-x-1'}`} />
                </button>
              </div>
            </div>

            {/* Content Provenance */}
            <div className="p-5 rounded-xl border border-white/10">
              <div className="flex items-start justify-between gap-4">
                <div>
                  <p className="font-headline font-bold text-sm">Content Provenance Tagging</p>
                  <p className="text-xs text-on-surface-muted mt-1">Auto-tag retrieved content for elevated IPI scan sensitivity. Essential for RAG pipelines.</p>
                </div>
                <button onClick={() => setEnforcement(s => ({ ...s, contentTagging: !s.contentTagging }))}
                  className={`relative w-12 h-6 rounded-full flex-shrink-0 transition-colors ${enforcement.contentTagging ? 'bg-primary' : 'bg-white/20'}`}
                >
                  <div className={`absolute top-1 w-4 h-4 rounded-full bg-white transition-transform ${enforcement.contentTagging ? 'translate-x-7' : 'translate-x-1'}`} />
                </button>
              </div>
            </div>
          </>
        )}

        {/* ═══ Step 5 — Compliance ═════════════════════════════════════════ */}
        {step === 5 && (
          <>
            <div>
              <h2 className="text-xl font-headline font-bold mb-1">Compliance & regulatory</h2>
              <p className="text-sm text-on-surface-muted">Select applicable compliance frameworks and data residency requirements.</p>
            </div>

            <div>
              <p className="text-[10px] uppercase font-technical text-on-surface-muted tracking-widest mb-3">Compliance Frameworks</p>
              <div className="flex flex-wrap gap-2">
                {COMPLIANCE_OPTIONS.map(f => (
                  <button key={f} onClick={() => toggleFramework(f)}
                    className={`px-3 py-2 rounded-lg border text-xs font-technical font-bold transition-colors ${
                      compliance.frameworks.includes(f)
                        ? 'border-primary bg-primary/10 text-primary'
                        : 'border-white/10 text-on-surface-muted hover:border-white/20'
                    }`}
                  >{f}</button>
                ))}
              </div>
            </div>

            <div>
              <label className="text-[10px] uppercase font-technical text-on-surface-muted tracking-widest block mb-2">Regulatory Region</label>
              <div className="flex gap-2">
                {REGIONS.map(r => (
                  <button key={r} onClick={() => setCompliance(c => ({ ...c, region: r }))}
                    className={`px-4 py-2 rounded-lg border text-xs font-technical transition-colors ${
                      compliance.region === r ? 'border-primary bg-primary/10 text-primary' : 'border-white/10 text-on-surface-muted hover:border-white/20'
                    }`}
                  >{r}</button>
                ))}
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="text-[10px] uppercase font-technical text-on-surface-muted tracking-widest block mb-1">Budget Cap (USD/month)</label>
                <input type="number" min="0" step="100" value={compliance.budgetCap}
                  onChange={e => setCompliance(c => ({ ...c, budgetCap: e.target.value }))}
                  placeholder="Optional"
                  className="w-full bg-black/40 border border-white/10 rounded-lg p-3 text-sm font-technical focus:outline-none focus:border-primary transition-colors"
                />
              </div>
              <div>
                <label className="text-[10px] uppercase font-technical text-on-surface-muted tracking-widest block mb-1">Audit Retention (days)</label>
                <input type="number" min="30" max="3650" value={compliance.retentionDays}
                  onChange={e => setCompliance(c => ({ ...c, retentionDays: parseInt(e.target.value) || 365 }))}
                  className="w-full bg-black/40 border border-white/10 rounded-lg p-3 text-sm font-technical focus:outline-none focus:border-primary transition-colors"
                />
              </div>
            </div>
          </>
        )}

        {/* ═══ Step 6 — Download & Register ════════════════════════════════ */}
        {step === 6 && (
          <>
            <div>
              <h2 className="text-xl font-headline font-bold mb-1">Your agent is ready</h2>
              <p className="text-sm text-on-surface-muted">
                Review the generated <span className="font-technical text-primary">cicada.yaml</span> below, then download your project or register the agent directly.
              </p>
            </div>

            {/* YAML preview */}
            <div className="relative">
              <div className="absolute top-3 right-3 flex gap-2">
                <button onClick={() => navigator.clipboard.writeText(yamlPreview)}
                  className="flex items-center gap-1 px-2.5 py-1 rounded-lg bg-white/10 text-[10px] font-technical text-on-surface-muted hover:text-white hover:bg-white/20 transition-colors"
                >
                  <span className="material-symbols-outlined text-[14px]">content_copy</span> Copy
                </button>
              </div>
              <pre className="bg-black/60 border border-white/10 rounded-xl p-5 pr-24 text-xs font-technical text-emerald-300 overflow-x-auto max-h-[400px] overflow-y-auto leading-relaxed">
                {yamlPreview}
              </pre>
            </div>

            {/* Download buttons */}
            <div className="grid grid-cols-2 gap-4">
              <button
                onClick={() => downloadFile('cicada.yaml', yamlPreview)}
                className="flex items-center justify-center gap-2 p-4 rounded-xl border border-primary/30 bg-primary/5 text-primary font-headline font-bold text-sm hover:bg-primary/10 transition-colors"
              >
                <span className="material-symbols-outlined text-[20px]">description</span>
                Download cicada.yaml
              </button>
              <button
                onClick={() => downloadZip([
                  { name: 'cicada.yaml', content: yamlPreview },
                  { name: '.env.template', content: `# Cicada Gateway\nCICADA_GATEWAY_URL=http://localhost:8080\nCICADA_SESSION_TOKEN=your-ed25519-session-token-here\n\n# LLM Provider\nOPENAI_API_KEY=sk-your-openai-key-here\n` },
                ])}
                className="flex items-center justify-center gap-2 p-4 rounded-xl btn-gradient text-black font-headline font-bold text-sm hover:brightness-110 transition-all"
              >
                <span className="material-symbols-outlined text-[20px]">folder_zip</span>
                Download Full Project
              </button>
            </div>

            {/* ── Or Register Directly ──────────────────────────────────────── */}
            <div className="border-t border-white/10 pt-6">
              <div className="flex items-center gap-3 mb-4">
                <div className="flex-1 h-px bg-white/10" />
                <span className="text-[10px] uppercase font-technical text-on-surface-muted tracking-widest">Or Register Directly</span>
                <div className="flex-1 h-px bg-white/10" />
              </div>

              {registerResult ? (
                /* ── Success Card ──────────────────────────────────────────── */
                <div className="p-6 rounded-xl border border-emerald-500/30 bg-emerald-500/5 space-y-4">
                  <div className="flex items-center gap-3">
                    <span className="material-symbols-outlined text-emerald-400 text-2xl">check_circle</span>
                    <div>
                      <p className="font-headline font-bold text-emerald-400">Agent Registered Successfully</p>
                      <p className="text-xs text-on-surface-muted mt-0.5">
                        {registerResult.verification?.verdict === 'ALLOW'
                          ? 'Verified by the Swarm — EVAR issued.'
                          : `Trust tier: ${registerResult.verification?.trust_tier ?? 'pending'}`
                        }
                      </p>
                    </div>
                  </div>

                  <div className="space-y-3">
                    {/* Agent ID */}
                    <div>
                      <p className="text-[10px] uppercase font-technical text-on-surface-muted tracking-widest mb-1">Agent ID</p>
                      <div className="flex items-center gap-2">
                        <code className="flex-1 bg-black/60 border border-white/10 rounded-lg px-3 py-2 text-xs font-mono text-white break-all">
                          {registerResult.agent_id}
                        </code>
                        <button onClick={() => navigator.clipboard.writeText(registerResult.agent_id)}
                          className="flex-shrink-0 p-2 rounded-lg bg-white/10 hover:bg-white/20 transition-colors"
                          title="Copy Agent ID"
                        >
                          <span className="material-symbols-outlined text-[14px] text-on-surface-muted">content_copy</span>
                        </button>
                      </div>
                    </div>

                    {/* EVAR Token */}
                    <div>
                      <p className="text-[10px] uppercase font-technical text-on-surface-muted tracking-widest mb-1">EVAR Token <span className="text-amber-400">(save this — it won't be shown again)</span></p>
                      <div className="flex items-center gap-2">
                        <code className="flex-1 bg-black/60 border border-amber-500/20 rounded-lg px-3 py-2 text-xs font-mono text-amber-300 break-all max-h-24 overflow-y-auto">
                          {registerResult.evar}
                        </code>
                        <button onClick={() => navigator.clipboard.writeText(registerResult.evar)}
                          className="flex-shrink-0 p-2 rounded-lg bg-amber-500/10 hover:bg-amber-500/20 transition-colors"
                          title="Copy EVAR Token"
                        >
                          <span className="material-symbols-outlined text-[14px] text-amber-400">content_copy</span>
                        </button>
                      </div>
                    </div>

                    {/* Gateway URL */}
                    <div>
                      <p className="text-[10px] uppercase font-technical text-on-surface-muted tracking-widest mb-1">Gateway Endpoint</p>
                      <code className="block bg-black/60 border border-white/10 rounded-lg px-3 py-2 text-xs font-mono text-primary break-all">
                        {registerResult.gateway_target}
                      </code>
                    </div>

                    {/* Verification details */}
                    {registerResult.verification && (
                      <div className="grid grid-cols-3 gap-3 pt-2 border-t border-white/5">
                        <div>
                          <p className="text-[10px] font-technical text-on-surface-muted">Verdict</p>
                          <p className={`text-xs font-headline font-bold ${
                            registerResult.verification.verdict === 'ALLOW' ? 'text-emerald-400' : 'text-amber-400'
                          }`}>{registerResult.verification.verdict ?? 'Pending'}</p>
                        </div>
                        <div>
                          <p className="text-[10px] font-technical text-on-surface-muted">Confidence</p>
                          <p className="text-xs font-headline font-bold text-white">{(registerResult.verification.score * 100).toFixed(0)}%</p>
                        </div>
                        <div>
                          <p className="text-[10px] font-technical text-on-surface-muted">Trust Tier</p>
                          <p className="text-xs font-headline font-bold text-white capitalize">{registerResult.verification.trust_tier}</p>
                        </div>
                      </div>
                    )}
                  </div>

                  <a href={`/agents/${registerResult.agent_id}`}
                    className="flex items-center justify-center gap-2 w-full p-3 rounded-xl border border-emerald-500/30 text-emerald-400 text-sm font-headline font-bold hover:bg-emerald-500/10 transition-colors"
                  >
                    <span className="material-symbols-outlined text-[18px]">open_in_new</span>
                    View Agent in Registry
                  </a>
                </div>
              ) : (
                /* ── BYOK fields + Register button ─────────────────────────── */
                <div className="space-y-4">
                  <p className="text-xs text-on-surface-muted">
                    Bind your LLM API key and register this agent directly with the Cicada platform.
                    Your key is encrypted immediately using AES-256 — Cicada never stores it in plaintext.
                  </p>

                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="text-[10px] uppercase font-technical text-on-surface-muted tracking-widest block mb-1">LLM Provider</label>
                      <select value={apiProvider} onChange={e => setApiProvider(e.target.value)}
                        className="w-full bg-black/40 border border-white/10 rounded-lg p-3 text-sm focus:outline-none focus:border-primary transition-colors"
                      >
                        <option value="openai">OpenAI</option>
                        <option value="anthropic">Anthropic</option>
                        <option value="google">Google Gemini</option>
                        <option value="cohere">Cohere</option>
                      </select>
                    </div>
                    <div>
                      <label className="text-[10px] uppercase font-technical text-on-surface-muted tracking-widest block mb-1">Target Model</label>
                      <input value={targetModel} onChange={e => setTargetModel(e.target.value)}
                        placeholder="gpt-4o"
                        className="w-full bg-black/40 border border-white/10 rounded-lg p-3 text-sm font-technical focus:outline-none focus:border-primary transition-colors"
                      />
                    </div>
                  </div>

                  <div>
                    <label className="text-[10px] uppercase font-technical text-on-surface-muted tracking-widest block mb-1">API Key *</label>
                    <input type="password" value={apiKey} onChange={e => setApiKey(e.target.value)}
                      placeholder="sk-..."
                      className="w-full bg-black/40 border border-white/10 rounded-lg p-3 text-sm font-mono focus:outline-none focus:border-primary transition-colors"
                    />
                    <p className="text-[10px] text-on-surface-muted/50 font-technical mt-1">
                      Required for registration. Your key is encrypted at rest via AES-256-GCM and never stored in plaintext.
                    </p>
                  </div>

                  {registerError && (
                    <div className="p-3 rounded-xl border border-red-500/30 bg-red-500/5">
                      <div className="flex items-start gap-2">
                        <span className="material-symbols-outlined text-red-400 text-[16px] mt-0.5">error</span>
                        <p className="text-sm text-red-400 font-technical whitespace-pre-wrap">{registerError}</p>
                      </div>
                    </div>
                  )}

                  <button
                    onClick={async () => {
                      if (!apiKey.trim()) return;
                      setRegistering(true);
                      setRegisterError('');
                      try {
                        const payload = mapScaffoldToProvisionPayload(
                          identity,
                          selectedTools,
                          customTools,
                          enforcement,
                          compliance,
                          { apiProvider, apiKey, targetModel },
                          TOOL_CATALOGUE,
                        );
                        const res = await fetch(`${CORE_API}/api/v1/portal/provision/agent`, {
                          method:  'POST',
                          headers: {
                            'Content-Type': 'application/json',
                            Accept: 'application/json',
                            Authorization: `Bearer ${session?.token}`,
                          },
                          body: JSON.stringify(payload),
                        });
                        const data = await res.json();
                        if (!res.ok) {
                          if (data.reasons && data.reasons.length > 0) {
                            setRegisterError(`Verification Swarm Blocked:\n${data.reasons.join('\n')}`);
                          } else {
                            throw new Error(data.message ?? 'Registration failed');
                          }
                          return;
                        }
                        setRegisterResult(data.data);
                      } catch (e: unknown) {
                        setRegisterError(e instanceof Error ? e.message : 'Something went wrong. Please try again.');
                      } finally {
                        setRegistering(false);
                      }
                    }}
                    disabled={!apiKey.trim() || registering}
                    className="w-full flex items-center justify-center gap-2 p-4 rounded-xl border-2 border-emerald-500/40 bg-emerald-500/5 text-emerald-400 font-headline font-bold text-sm hover:bg-emerald-500/10 hover:border-emerald-500/60 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
                  >
                    {registering ? (
                      <>
                        <div className="w-4 h-4 border-2 border-emerald-400 border-t-transparent rounded-full animate-spin" />
                        Registering — running Swarm verification...
                      </>
                    ) : (
                      <>
                        <span className="material-symbols-outlined text-[20px]">verified</span>
                        Register This Agent
                      </>
                    )}
                  </button>

                  {!apiKey.trim() && (
                    <p className="text-[10px] text-center text-on-surface-muted/50 font-technical">
                      Enter your API key above to enable registration
                    </p>
                  )}
                </div>
              )}
            </div>

            {/* Next steps */}
            <div className="p-5 bg-white/[0.02] border border-white/5 rounded-xl">
              <p className="text-[10px] uppercase font-technical text-on-surface-muted tracking-widest mb-3">Next Steps</p>
              <div className="space-y-2 text-xs text-on-surface-muted">
                {registerResult ? (
                  <>
                    <p>1. Copy your <span className="font-technical text-amber-400">EVAR token</span> above — store it securely</p>
                    <p>2. Set it as <span className="font-technical text-primary">CICADA_SESSION_TOKEN</span> in your environment</p>
                    <p>3. Install the SDK: <span className="font-technical text-primary">{framework === 'node' ? 'npm install @cicada/sdk' : 'pip install cicada-guard'}</span></p>
                    <p>4. Run your agent — all traffic routes through the Cicada Sentry Gateway</p>
                  </>
                ) : (
                  <>
                    <p>1. Place <span className="font-technical text-primary">cicada.yaml</span> in your project root</p>
                    <p>2. Install the SDK: <span className="font-technical text-primary">{framework === 'node' ? 'npm install @cicada/sdk' : 'pip install cicada-guard'}</span></p>
                    <p>3. Copy <span className="font-technical text-primary">.env.template</span> to <span className="font-technical text-primary">.env</span> and fill in your Gateway token</p>
                    <p>4. Register your agent: <span className="font-technical text-primary">cicada register ./cicada.yaml</span></p>
                    <p>5. Run your agent — all traffic routes through the Cicada Sentry Gateway</p>
                  </>
                )}
              </div>
            </div>
          </>
        )}

        {/* ── Navigation ───────────────────────────────────────────────────── */}
        <div className="flex items-center justify-between pt-2">
          <button onClick={() => setStep(s => s - 1)} disabled={step === 1}
            className="px-5 py-2.5 rounded-xl font-headline font-bold text-sm text-on-surface-muted hover:text-on-surface disabled:opacity-30 transition-colors"
          >← Back</button>
          {step < 6 ? (
            <button onClick={() => setStep(s => s + 1)} disabled={!canNext()}
              className="px-6 py-2.5 bg-primary text-black rounded-xl font-headline font-bold text-sm hover:brightness-110 disabled:opacity-40 transition-all"
            >Continue →</button>
          ) : (
            <button onClick={() => { setStep(1); setFramework(''); setSelectedTools([]); setCustomTools([]); }}
              className="px-6 py-2.5 rounded-xl border border-white/20 font-headline font-bold text-sm text-on-surface-muted hover:text-on-surface hover:border-white/40 transition-colors"
            >Scaffold Another</button>
          )}
        </div>
      </div>
    </div>
  );
}
