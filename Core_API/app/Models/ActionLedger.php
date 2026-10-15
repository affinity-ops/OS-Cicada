<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class ActionLedger extends Model
{
    protected $table = 'action_ledger';

    /** Primary key is trace_id (UUID string), not auto-increment. */
    protected $primaryKey = 'trace_id';
    protected $keyType = 'string';
    public $incrementing = false;

    /** The ledger only has created_at — no updated_at (immutable design). */
    const UPDATED_AT = null;

    protected $fillable = [
        'trace_id',
        'tenant_id',
        'agent_id',
        'action_type',
        'payload_hash',
        'target_api',
        'status',
        'swarm_confidence_score',
        'semantic_alignment_score',
        'policy_violations',
        'shadow_violation',
        'human_user_context',
        'reasoning_trace',
        'reason',
        'evidence',
    ];

    protected $casts = [
        'swarm_confidence_score'    => 'decimal:4',
        'semantic_alignment_score'  => 'decimal:4',
        'policy_violations'         => 'array',
        'human_user_context'        => 'array',
        'shadow_violation'          => 'boolean',
        'created_at'                => 'datetime',
    ];

    // ── Relationships ─────────────────────────────────────────────────────────

    public function agent(): BelongsTo
    {
        return $this->belongsTo(Agent::class);
    }

    public function tenant(): BelongsTo
    {
        return $this->belongsTo(Tenant::class);
    }
}
