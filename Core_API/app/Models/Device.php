<?php
/**
 * © 2026 Patrick Matthews (Affinity Ops / Affinity Smart AI)
 * SPDX-License-Identifier: Apache-2.0
 */
namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Device extends Model
{
    use HasFactory;

    protected $fillable = [
        'owner_id',
        'public_key',
        'device_name',
        'registered_at',
        'last_seen_at'
    ];

    protected $casts = [
        'registered_at' => 'datetime',
        'last_seen_at' => 'datetime',
    ];

    public function owner()
    {
        return $this->belongsTo(Contact::class, 'owner_id');
    }
}
