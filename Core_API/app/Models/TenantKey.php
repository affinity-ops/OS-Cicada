<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use App\Casts\VaultEncryptionCast;

class TenantKey extends Model
{
    // Indicates the table strictly
    protected $table = 'tenant_keys';

    protected $fillable = ['tenant_id', 'provider', 'payload_encrypted'];

    protected $casts = [
        'payload_encrypted' => VaultEncryptionCast::class,
    ];
}
