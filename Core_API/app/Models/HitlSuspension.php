<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class HitlSuspension extends Model
{
    protected $table = 'hitl_suspensions';

    /** Primary key is trace_id (string), not auto-increment. */
    protected $primaryKey = 'trace_id';
    protected $keyType = 'string';
    public $incrementing = false;

    protected $fillable = [
        'trace_id',
        'agent_id',
        'original_payload_encrypted',
        'target_url',
        'webhook_url',
        'approval_token',
        'decision',
        'operator_id',
        'resolution_locked_at',
        'dispatched_at',
        'resolved_at',
    ];

    protected $casts = [
        'resolution_locked_at' => 'datetime',
        'dispatched_at'        => 'datetime',
        'resolved_at'          => 'datetime',
    ];

    // ── Relationships ─────────────────────────────────────────────────────────

    public function agent(): BelongsTo
    {
        return $this->belongsTo(Agent::class);
    }

    // ── Scopes ────────────────────────────────────────────────────────────────

    /** Suspensions still awaiting a decision. */
    public function scopePending($query)
    {
        return $query->where('decision', 'pending');
    }
}
