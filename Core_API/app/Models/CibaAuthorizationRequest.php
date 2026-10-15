<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class CibaAuthorizationRequest extends Model
{
    use HasFactory;

    protected $table = 'ciba_authorization_requests';
    protected $primaryKey = 'trace_id';
    public $incrementing = false;
    protected $keyType = 'string';

    protected $fillable = [
        'id',
        'trace_id',
        'agent_id',
        'tenant_id',
        'agent_name',
        'action_summary',
        'target_url',
        'payload_preview',
        'risk_score',
        'risk_reason',
        'status',
        'expires_at',
        'device_id',
        'responded_by',
        'responded_at'
    ];
}
