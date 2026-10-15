<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class AgentResourcePolicy extends Model
{
    protected $table = 'agent_resource_policies';

    /** UUID primary key — no auto-increment. */
    protected $keyType = 'string';
    public $incrementing = false;

    /** Only created_at is managed by the schema — no updated_at. */
    const UPDATED_AT = null;

    protected $fillable = [
        'id',
        'agent_id',
        'resource_pattern',
        'allowed_methods',
        'active',
    ];

    protected $casts = [
        'allowed_methods' => 'array',
        'active'          => 'boolean',
        'created_at'      => 'datetime',
    ];

    // ── Relationships ─────────────────────────────────────────────────────────

    public function agent(): BelongsTo
    {
        return $this->belongsTo(Agent::class);
    }

    // ── Scopes ────────────────────────────────────────────────────────────────

    /** Only currently active policies. */
    public function scopeActive($query)
    {
        return $query->where('active', true);
    }
}
