<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;

class Tenant extends Model
{
    /** UUID primary key — no auto-increment. */
    protected $keyType = 'string';
    public $incrementing = false;

    protected $fillable = [
        'id',
        'name',
        'status',
        'plan',
        'company_email',
        'company_phone',
        'company_address',
        'company_website',
        'admin_notes',
        'plan_started_at',
        'email_verified_at',
    ];

    protected $casts = [
        'plan_started_at'    => 'datetime',
        'email_verified_at'  => 'datetime',
    ];

    // ── Relationships ─────────────────────────────────────────────────────────

    public function agents(): HasMany
    {
        return $this->hasMany(Agent::class);
    }

    public function contacts(): HasMany
    {
        return $this->hasMany(Contact::class);
    }

    public function keys(): HasMany
    {
        return $this->hasMany(TenantKey::class);
    }
}
