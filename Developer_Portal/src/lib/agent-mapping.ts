// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * agent-mapping.ts — Shared mapping utilities between the Visual Scaffolder,
 * the Registration Wizard, and the Provisioning API.
 *
 * This module provides bidirectional mapping:
 *   Scaffolder state  →  Provisioning API payload   (mapScaffoldToProvisionPayload)
 *   YAML parsed obj   →  Registration Wizard state  (mapYAMLToWizardForm)  — Prompt 2
 *
 * The Provisioning API lives at POST /api/v1/portal/provision/agent and is handled
 * by Core_API/app/Http/Controllers/ProvisioningController.php
 */

/* ─── Tool catalogue reference (must match scaffold/page.tsx) ──────────── */
export interface CatalogueTool {
  id: string;
  label: string;
  icon: string;
  desc: string;
  urls: string[];
  methods: string[];
  risk: string;
  destructive: boolean;
}

export interface CustomTool {
  name: string;
  description: string;
  url_pattern: string;
  methods: string[];
  destructive: boolean;
}

/* ─── Scaffolder state shapes ─────────────────────────────────────────── */
export interface ScaffoldIdentity {
  name: string;
  description: string;
  type: string;
  role: string;
  owner: string;
  businessUnit: string;
  dataClassification: string;
  criticality: string;
}

export interface ScaffoldEnforcement {
  maxReads: number;
  maxWrites: number;
  maxDeletes: number;
  circuitBreaker: number;
  hitl: boolean;
  hitlWebhook: string;
  hitlTimeout: number;       // stored in seconds in the scaffolder
  riskThreshold: number;
  shadowMode: boolean;
  destructive: boolean;
  contentTagging: boolean;
}

export interface ScaffoldCompliance {
  frameworks: string[];
  region: string;
  retentionDays: number;
  budgetCap: string;
  costCentre: string;
}

export interface ScaffoldBYOK {
  apiProvider: string;
  apiKey: string;
  targetModel: string;
}

/* ─── Provisioning API payload shape ──────────────────────────────────── */
export interface ProvisionPayload {
  agent_name: string;
  description?: string;
  version: string;
  agent_type?: string;
  role: string;
  owner_email?: string;
  business_unit?: string;
  data_classification: string;
  criticality_level: string;
  declared_purpose?: string;
  expected_velocity?: number;
  monthly_budget_usd?: number;
  cost_center?: string;
  data_residency_region?: string;
  regulatory_frameworks?: string[];
  hitl_enabled: boolean;
  hitl_webhook_url?: string;
  hitl_timeout_hours?: number;
  observe_only_mode: boolean;
  destructive_capability: boolean;
  scopes: string[];
  tools: { tool_id: string; tool_name: string; tool_description?: string }[];
  api_provider: string;
  api_key: string;
  target_model: string;
}

/**
 * Maps the Visual Scaffolder's state objects to the exact JSON payload
 * expected by POST /api/v1/portal/provision/agent.
 *
 * Key transformations:
 *  - hitlTimeout: seconds → hours (scaffolder stores 3600, API expects 1)
 *  - selectedTools: catalogue IDs → {tool_id, tool_name, tool_description}
 *  - customTools: name/desc/url → {tool_id, tool_name, tool_description}
 *  - destructive: derived from tools OR enforcement.destructive
 *  - scopes: inferred from tool methods (read/write/chat)
 */
export function mapScaffoldToProvisionPayload(
  identity: ScaffoldIdentity,
  selectedTools: string[],
  customTools: CustomTool[],
  enforcement: ScaffoldEnforcement,
  compliance: ScaffoldCompliance,
  byok: ScaffoldBYOK,
  toolCatalogue: CatalogueTool[],
): ProvisionPayload {

  // ── Map tools ──────────────────────────────────────────────────────────
  const mappedCatalogueTools = selectedTools.map(id => {
    const cat = toolCatalogue.find(t => t.id === id);
    if (!cat) return null;
    return {
      tool_id:          cat.id + '-api',
      tool_name:        cat.label,
      tool_description: cat.desc + ' via ' + cat.label + ' API',
    };
  }).filter(Boolean) as { tool_id: string; tool_name: string; tool_description: string }[];

  const mappedCustomTools = customTools
    .filter(t => t.name.trim())
    .map(t => ({
      tool_id:          t.name.toLowerCase().replace(/\s+/g, '_'),
      tool_name:        t.name,
      tool_description: t.description || undefined,
    }));

  const allTools = [...mappedCatalogueTools, ...mappedCustomTools];

  // ── Derive destructive capability ──────────────────────────────────────
  const hasDestructive =
    selectedTools.some(id => toolCatalogue.find(t => t.id === id)?.destructive) ||
    customTools.some(t => t.destructive) ||
    enforcement.destructive;

  // HITL is auto-enabled when destructive tools are present
  const hitlEnabled = enforcement.hitl || hasDestructive;

  // ── Infer scopes from tool methods ─────────────────────────────────────
  const scopeSet = new Set<string>(['proxy:chat']); // always include chat
  for (const id of selectedTools) {
    const cat = toolCatalogue.find(t => t.id === id);
    if (!cat) continue;
    if (cat.methods.includes('GET'))    scopeSet.add('proxy:read');
    if (cat.methods.includes('POST'))   scopeSet.add('proxy:write');
    if (cat.methods.includes('PUT'))    scopeSet.add('proxy:write');
    if (cat.methods.includes('DELETE')) scopeSet.add('proxy:write');
    if (cat.destructive)                scopeSet.add('proxy:transact');
  }
  for (const t of customTools) {
    if (t.methods.includes('GET'))    scopeSet.add('proxy:read');
    if (t.methods.includes('POST'))   scopeSet.add('proxy:write');
    if (t.methods.includes('PUT'))    scopeSet.add('proxy:write');
    if (t.methods.includes('DELETE')) scopeSet.add('proxy:write');
    if (t.destructive)                scopeSet.add('proxy:transact');
  }

  return {
    agent_name:           identity.name,
    description:          identity.description || undefined,
    version:              '1.0.0',
    agent_type:           identity.type || undefined,
    role:                 identity.role === 'processor' ? 'autonomous' : identity.role,
    owner_email:          identity.owner || undefined,
    business_unit:        identity.businessUnit || undefined,
    data_classification:  identity.dataClassification,
    criticality_level:    identity.criticality,
    declared_purpose:     identity.description || undefined, // scaffolder uses description as purpose
    expected_velocity:    enforcement.maxReads || undefined,
    monthly_budget_usd:   compliance.budgetCap ? parseFloat(compliance.budgetCap) : undefined,
    cost_center:          compliance.costCentre || undefined,
    regulatory_frameworks: compliance.frameworks.length > 0 ? compliance.frameworks : undefined,
    hitl_enabled:         hitlEnabled,
    hitl_webhook_url:     hitlEnabled && enforcement.hitlWebhook ? enforcement.hitlWebhook : undefined,
    hitl_timeout_hours:   hitlEnabled ? Math.max(1, Math.round(enforcement.hitlTimeout / 3600)) : undefined,
    observe_only_mode:    enforcement.shadowMode,
    destructive_capability: hasDestructive,
    scopes:               Array.from(scopeSet),
    tools:                allTools,
    api_provider:         byok.apiProvider,
    api_key:              byok.apiKey,
    target_model:         byok.targetModel,
  };
}

/* ─── Provisioning API response shape ─────────────────────────────────── */
export interface ProvisionResponse {
  status: string;
  message: string;
  data: {
    tenant_id: string;
    agent_id: string;
    evar: string;
    gateway_target: string;
    verification: {
      verdict: string | null;
      score: number;
      trust_tier: string;
      reasons: string[];
    };
  };
}

export interface ProvisionErrorResponse {
  status: string;
  message: string;
  reasons?: string[];
}

/* ─── Registration Wizard form state shape ────────────────────────────── */
export interface WizardFormState {
  agent_name: string;
  description: string;
  version: string;
  owner_name: string;
  owner_email: string;
  business_unit: string;
  declared_purpose: string;
  criticality_level: string;
  data_classification: string;
  expected_velocity: string;
  monthly_budget_usd: string;
  cost_center: string;
  regulatory_frameworks: string[];
  registration_purpose_statement: string;
  agent_type: string;
  role: string;
  orchestrator_id: string;
  scopes: string[];
  tools: { tool_id: string; tool_name: string; tool_description: string }[];
  failure_scope: string;
  hitl_enabled: boolean;
  hitl_webhook_url: string;
  hitl_timeout_hours: string;
  shadow_mode: boolean;
  api_provider: string;
  api_key: string;
  target_model: string;
}

/**
 * Maps a parsed cicada.yaml object to the Registration Wizard's form state.
 *
 * cicada.yaml structure (see Cicada_SDK/templates/ for examples):
 *   identity: { name, type, role, owner, criticality }
 *   tools: [{ name, url_patterns, methods, destructive }]
 *   enforcement: { velocity: { max_reads_per_minute }, hitl: { enabled }, shadow_mode }
 *   provenance: { content_tagging, audit_retention_days }
 *   compliance?: { frameworks }
 *
 * This function gracefully handles missing keys — the wizard allows empty fields.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function mapYAMLToWizardForm(yaml: Record<string, any>): Partial<WizardFormState> {
  const identity    = yaml.identity    || {};
  const enforcement = yaml.enforcement || {};
  const provenance  = yaml.provenance  || {};
  const compliance  = yaml.compliance  || {};
  const velocity    = enforcement.velocity || {};
  const hitl        = enforcement.hitl     || {};
  const tools       = yaml.tools       || [];

  // Map tools from YAML's {name, url_patterns, methods} to wizard's {tool_id, tool_name, tool_description}
  const mappedTools = (tools as Array<Record<string, unknown>>).map((t: Record<string, unknown>) => ({
    tool_id:          ((t.name as string) || '').toLowerCase().replace(/\s+/g, '_'),
    tool_name:        (t.name as string) || '',
    tool_description: ((t.url_patterns as string[]) || []).join(', ') +
                      (t.methods ? ` [${(t.methods as string[]).join(', ')}]` : '') +
                      (t.destructive ? ' ⚠️ destructive' : ''),
  }));

  // Infer scopes from tool methods
  const scopeSet = new Set<string>();
  for (const t of tools as Array<Record<string, unknown>>) {
    const methods = (t.methods as string[]) || [];
    if (methods.includes('GET'))    scopeSet.add('proxy:read');
    if (methods.includes('POST'))   { scopeSet.add('proxy:write'); scopeSet.add('proxy:chat'); }
    if (methods.includes('PUT'))    scopeSet.add('proxy:write');
    if (methods.includes('DELETE')) scopeSet.add('proxy:write');
    if (t.destructive)              scopeSet.add('proxy:transact');
  }
  // Default: at least chat if nothing inferred
  if (scopeSet.size === 0) scopeSet.add('proxy:chat');

  // Determine failure scope from YAML (if present)
  const failureScope = enforcement.failure_behaviour || enforcement.failure_scope || '';

  // Map HITL timeout: YAML may store in seconds (e.g. 86400), wizard wants hours as string
  const hitlTimeoutSeconds = hitl.auto_deny_timeout_seconds || hitl.timeout || 0;
  const hitlTimeoutHours   = hitlTimeoutSeconds > 0 ? String(Math.round(hitlTimeoutSeconds / 3600)) : '24';

  return {
    agent_name:         identity.name         || '',
    description:        identity.description  || identity.purpose || '',
    version:            yaml.apiVersion       || '1.0.0',
    owner_name:         identity.owner        || '',
    owner_email:        identity.owner        || '', // YAML often stores email in owner field
    business_unit:      identity.business_unit || identity.businessUnit || '',
    declared_purpose:   identity.purpose      || identity.description  || '',
    criticality_level:  identity.criticality  || 'medium',
    data_classification: identity.data_classification || identity.dataClassification || 'internal',
    expected_velocity:  velocity.max_reads_per_minute ? String(velocity.max_reads_per_minute * 60) : // per-minute → per-hour
                        velocity.max_calls_per_hour   ? String(velocity.max_calls_per_hour) : '',
    monthly_budget_usd: compliance.budget_cap  ? String(compliance.budget_cap) : '',
    cost_center:        compliance.cost_centre || compliance.cost_center || '',
    regulatory_frameworks: compliance.frameworks || [],
    registration_purpose_statement: '',
    agent_type:         identity.type         || '',
    role:               identity.role         || 'autonomous',
    orchestrator_id:    identity.orchestrator_id || '',
    scopes:             Array.from(scopeSet),
    tools:              mappedTools,
    failure_scope:      failureScope,
    hitl_enabled:       hitl.enabled === true,
    hitl_webhook_url:   hitl.webhook_url      || '',
    hitl_timeout_hours: hitlTimeoutHours,
    shadow_mode:        enforcement.shadow_mode === true,
    api_provider:       '', // Never stored in YAML — must be entered manually
    api_key:            '', // Never stored in YAML — security: must be entered manually
    target_model:       identity.intended_model || 'gpt-4o',
  };
}
