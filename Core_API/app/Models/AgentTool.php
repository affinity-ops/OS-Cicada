<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class AgentTool extends Model
{
    protected $table = 'agent_tools';

    /** UUID primary key — no auto-increment. */
    protected $keyType = 'string';
    public $incrementing = false;

    /** Only created_at is managed by the schema — no updated_at. */
    const UPDATED_AT = null;

    protected $fillable = [
        'id',
        'agent_id',
        'tool_id',
        'tool_name',
        'tool_description',
        'is_active',
    ];

    protected $casts = [
        'is_active'  => 'boolean',
        'created_at' => 'datetime',
    ];

    // ── Relationships ─────────────────────────────────────────────────────────

    public function agent(): BelongsTo
    {
        return $this->belongsTo(Agent::class);
    }

    // ── Scopes ────────────────────────────────────────────────────────────────

    /** Only currently active tools. */
    public function scopeActive($query)
    {
        return $query->where('is_active', true);
    }
}
