<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

class Agent extends Model
{
    /** UUID primary key — no auto-increment. */
    protected $keyType = 'string';
    public $incrementing = false;

    protected $fillable = [
        'id',
        'tenant_id',
        'name',
        'description',
        'pub_key_hash',
        'scope_entitlements',
        'trust_tier',
        'agent_type',
        'role',
        'version',
        'failure_scope',
        'hitl_enabled',
        'hitl_webhook_url',
        'hitl_timeout_hours',
        'hitl_resume_webhook_url',
        'owner_name',
        'owner_email',
        'business_unit',
        'declared_purpose',
        'registration_purpose_statement',
        'criticality_level',
        'data_classification',
        'expected_velocity',
        'monthly_budget_usd',
        'cost_center',
        'regulatory_frameworks',
        'potential_impact',
        'custom_guardrails',
        'ghost_mode_allowed',
        'swarm_confidence_score',
        'swarm_verdict',
        'swarm_reasons',
        'orchestrator_id',
        'approval_status',
        'certified_at',
        'recertification_due_at',
        'revoked_at',
        'verified_at',
        'quarantined_at',
        'governance_updated_at',
    ];

    protected $casts = [
        'scope_entitlements'     => 'array',
        'failure_scope'          => 'array',
        'regulatory_frameworks'  => 'array',
        'potential_impact'       => 'array',
        'swarm_reasons'          => 'array',
        'hitl_enabled'           => 'boolean',
        'ghost_mode_allowed'     => 'boolean',
        'swarm_confidence_score' => 'decimal:4',
        'monthly_budget_usd'     => 'decimal:2',
        'expected_velocity'      => 'integer',
        'certified_at'           => 'datetime',
        'recertification_due_at' => 'datetime',
        'revoked_at'             => 'datetime',
        'verified_at'            => 'datetime',
        'quarantined_at'         => 'datetime',
        'governance_updated_at'  => 'datetime',
    ];

    // ── Relationships ─────────────────────────────────────────────────────────

    public function tenant(): BelongsTo
    {
        return $this->belongsTo(Tenant::class);
    }

    public function tools(): HasMany
    {
        return $this->hasMany(AgentTool::class);
    }

    public function resourcePolicies(): HasMany
    {
        return $this->hasMany(AgentResourcePolicy::class);
    }

    public function ledgerEntries(): HasMany
    {
        return $this->hasMany(ActionLedger::class);
    }

    public function keys(): HasMany
    {
        return $this->hasMany(TenantKey::class, 'tenant_id', 'tenant_id');
    }

    // ── Scopes ────────────────────────────────────────────────────────────────

    /** Active agents — not revoked. */
    public function scopeActive($query)
    {
        return $query->whereNull('revoked_at');
    }

    /** Verified agents — not in the 'unverified' trust tier. */
    public function scopeVerified($query)
    {
        return $query->where('trust_tier', '!=', 'unverified');
    }

    /** Agents with a configured monthly budget. */
    public function scopeBudgeted($query)
    {
        return $query->whereNotNull('monthly_budget_usd')
                     ->where('monthly_budget_usd', '>', 0);
    }
}
