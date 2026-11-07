<?php
/**
 * © 2026 Patrick Matthews (Affinity Ops / Affinity Smart AI)
 * SPDX-License-Identifier: Apache-2.0
 */
namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Contact extends Model
{
    use HasFactory;

    protected $fillable = ['id', 'tenant_id', 'name', 'email', 'phone'];
}
