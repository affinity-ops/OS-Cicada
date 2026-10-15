<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

/**
 * OperatorWebAuthnController
 * 
 * Internal bridging API specifically reserved for the Next.js Dashboard.
 * Stores and manages the physical hardware Passkey configurations for the single
 * Root Operator. Prevents Next.js frontend from requiring direct Postgres credentials.
 */
class OperatorWebAuthnController extends Controller
{
    public function getCredential()
    {
        // Enforce Singleton: only one root operator identity exists globally for the platform
        $credential = DB::table('operator_credentials')->first();
        if (!$credential) {
            return response()->json(['status' => 'not_found'], 404);
        }
        
        return response()->json([
            'status' => 'success',
            'data' => $credential
        ]);
    }

    public function storeCredential(Request $request)
    {
        $validated = $request->validate([
            'credential_id' => 'required|string',
            'public_key'    => 'required|string',
            'sign_count'    => 'required|numeric',
            'transports'    => 'nullable|array',
        ]);

        // Wipe any previous root keys — hardware key resets are absolute overrides
        DB::table('operator_credentials')->delete();

        DB::table('operator_credentials')->insert([
            'id'            => (string) Str::uuid(),
            'credential_id' => $validated['credential_id'],
            'public_key'    => $validated['public_key'],
            'sign_count'    => $validated['sign_count'],
            'transports'    => json_encode($validated['transports'] ?? []),
            'created_at'    => now(),
            'updated_at'    => now(),
        ]);

        return response()->json(['status' => 'success']);
    }

    public function updateCounter(Request $request)
    {
        $validated = $request->validate([
            'credential_id' => 'required|string',
            'sign_count'    => 'required|numeric',
        ]);

        $rows = DB::table('operator_credentials')
            ->where('credential_id', $validated['credential_id'])
            ->update([
                'sign_count' => $validated['sign_count'],
                'updated_at' => now(),
            ]);

        if ($rows === 0) {
            return response()->json(['status' => 'not_found'], 404);
        }

        return response()->json(['status' => 'success']);
    }
}
