<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Crypt;
use App\Services\AuditService;

class TenantController extends Controller
{
    /**
     * Store and encrypt a Bring-Your-Own-Key (BYOK) for a specific enterprise tenant.
     * 
     * In the Cicada architecture, tenants provide their own external API keys 
     * (e.g., OpenAI, Anthropic) which the Verification Swarm uses during auditing.
     * This ensures Cicada does not foot the bill for extreme token processing.
     *
     * Note: In a true production deployment, this endpoint operates behind the 
     * 'auth:sanctum' middleware to ensure only authenticated dashboard users can invoke it.
     *
     * @param \Illuminate\Http\Request $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function bindKey(Request $request)
    {
        // 1. Validate payload enforcing strict type-safety and presence constraints.
        $validated = $request->validate([
            'tenant_id' => 'required|uuid',
            'api_provider' => 'required|string',
            'api_key' => 'required|string',
        ]);

        // 2. Encryption
        // We never store raw API keys. We use Laravel's Crypt facade, which intrinsically 
        // implements AES-256-GCM symmetric encryption using the APP_KEY environment variable.
        $encryptedKey = Crypt::encryptString($validated['api_key']);

        $existing = DB::table('tenant_keys')->where('tenant_id', $validated['tenant_id'])->where('provider', $validated['api_provider'])->first();

        // 3. Persistent Storage
        // We use updateOrInsert to handle key rotation gracefully, matching against 
        // the unique constraint (tenant_id + provider) defined in our migration schema.
        DB::table('tenant_keys')->updateOrInsert(
            ['tenant_id' => $validated['tenant_id'], 'provider' => $validated['api_provider']],
            ['payload_encrypted' => $encryptedKey, 'updated_at' => now()]
        );

        AuditService::log(
            $request,
            'api_key_rotated',
            'api_key',
            $validated['tenant_id'] . ':' . $validated['api_provider'],
            $existing ? ['action' => 'rotated'] : ['action' => 'created'],
            ['provider' => $validated['api_provider']],
            'Operator bound or rotated API key'
        );

        return response()->json([
            'status' => 'success',
            'message' => 'BYOK credentials bound securely.'
        ], 200);
    }
}
