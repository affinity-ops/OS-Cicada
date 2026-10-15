// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @cicada/sdk — Policy loader and validator.
 *
 * Loads cicada.yaml files, validates them against the JSON Schema,
 * and provides structured access to governance settings.
 */

const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');

const SCHEMA_PATH = path.join(__dirname, '..', '..', 'schema', 'cicada-policy-v1.json');

/**
 * Parsed cicada.yaml policy representation.
 */
class CicadaPolicy {
  constructor(raw) {
    this.apiVersion = raw.apiVersion || 'cicada/v1';
    this.kind = raw.kind || 'AgentPolicy';

    // Identity
    const id = raw.identity || {};
    this.identity = {
      name: id.name || '',
      description: id.description || '',
      type: id.type || 'autonomous',
      role: id.role || 'processor',
      owner: id.owner || '',
      businessUnit: id.business_unit || '',
      dataClassification: id.data_classification || 'internal',
      criticality: id.criticality || 'medium',
    };

    // Tools — each tool declares a skill contract with optional payload schema,
    // upstream delegation constraints, and per-tool criticality classification.
    this.tools = (raw.tools || []).map(t => ({
      name: t.name || '',
      description: t.description || '',
      urlPatterns: t.url_patterns || [],
      methods: t.methods || ['GET'],
      destructive: t.destructive || false,
      riskLevel: t.risk_level || 'medium',
      inputSchema: t.input_schema || null,
      allowedUpstreams: t.allowed_upstreams || [],
      criticalityLevel: t.criticality_level || 'low',
    }));

    // Enforcement
    const enf = raw.enforcement || {};
    const vel = enf.velocity || {};
    const hitl = enf.hitl || {};
    this.enforcement = {
      velocity: {
        maxReadsPerMinute: vel.max_reads_per_minute || 100,
        maxWritesPerMinute: vel.max_writes_per_minute || 20,
        maxDeletesPerMinute: vel.max_deletes_per_minute || 5,
        circuitBreakerThreshold: vel.circuit_breaker_threshold || 10,
      },
      hitl: {
        enabled: hitl.enabled || false,
        webhookUrl: hitl.webhook_url || '',
        timeoutSeconds: hitl.timeout_seconds || 3600,
        autoDenyOnTimeout: hitl.auto_deny_on_timeout !== false,
        riskThreshold: hitl.risk_threshold || 0.6,
      },
      shadowMode: enf.shadow_mode || false,
      destructiveCapability: enf.destructive_capability || false,
    };

    // Provenance
    const prov = raw.provenance || {};
    this.provenance = {
      evarBinding: prov.evar_binding !== false,
      contentTagging: prov.content_tagging || false,
      auditRetentionDays: prov.audit_retention_days || 365,
    };

    // Compliance
    const comp = raw.compliance || {};
    this.compliance = {
      frameworks: comp.frameworks || [],
      regulatoryRegion: comp.regulatory_region || 'GLOBAL',
      budgetCapUsd: comp.budget_cap_usd || null,
      costCentre: comp.cost_centre || '',
    };
  }

  /** Agent name shortcut */
  get agentName() {
    return this.identity.name;
  }

  /** Whether HITL is enabled */
  get hitlEnabled() {
    return this.enforcement.hitl.enabled;
  }

  /** Whether the agent has destructive capability */
  get isDestructive() {
    if (this.enforcement.destructiveCapability) return true;
    return this.tools.some(t => t.destructive);
  }

  /** Flat list of all allowed URL patterns */
  get allowedUrls() {
    return this.tools.flatMap(t => t.urlPatterns);
  }

  /**
   * Validate the policy for logical consistency.
   * @returns {string[]} List of issues (empty = valid)
   */
  validate() {
    const issues = [];

    if (!this.identity.name) issues.push('identity.name is required');
    if (!this.identity.owner) issues.push('identity.owner is required');
    if (this.tools.length === 0) issues.push('at least one tool must be declared');

    if (this.isDestructive && !this.hitlEnabled) {
      issues.push(
        'agent has destructive capabilities but HITL is not enabled — ' +
        'the Sentry Gateway will block all write operations'
      );
    }

    for (const tool of this.tools) {
      if (tool.methods.includes('DELETE') && !tool.destructive) {
        issues.push(`tool '${tool.name}' allows DELETE but destructive=false`);
      }
      if (tool.criticalityLevel === 'high' && !this.hitlEnabled) {
        issues.push(
          `tool '${tool.name}' has criticality_level=high but HITL is not enabled — ` +
          'the Sentry Gateway will enforce mandatory CIBA holds on this tool'
        );
      }
    }

    return issues;
  }
}

/**
 * Load and parse a cicada.yaml policy file.
 *
 * @param {string} [filePath='cicada.yaml'] - Path to the policy file
 * @returns {CicadaPolicy} Parsed policy
 */
function loadPolicy(filePath = 'cicada.yaml') {
  const resolvedPath = path.resolve(filePath);
  if (!fs.existsSync(resolvedPath)) {
    throw new Error(`Policy file not found: ${resolvedPath}`);
  }

  const content = fs.readFileSync(resolvedPath, 'utf-8');
  const raw = yaml.load(content);

  if (!raw || typeof raw !== 'object') {
    throw new Error('Policy file must be a YAML mapping');
  }

  return new CicadaPolicy(raw);
}

module.exports = { CicadaPolicy, loadPolicy };
