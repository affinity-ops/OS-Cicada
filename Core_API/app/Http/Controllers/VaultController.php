<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class VaultController extends Controller
{
    /**
     * Verify an EVAR token and return the agent's trust certificate.
     * 
     * This endpoint is called by external enterprise firewalls (gatekeepers) 
     * acting on behalf of the client to cryptographically verify if an AI agent 
     * attempting to access their system is certified by Cicada.
     *
     * @param string $evar The Encrypted Verifiable Agent Registry hash (pub_key_hash)
     * @return \Illuminate\Http\JsonResponse
     */
    public function verifyEvar($evar)
    {
        // Query the core PostgreSQL 'agents' table to locate the specific identity.
        // We evaluate against 'pub_key_hash' which represents the EVAR signature.
        $agent = DB::table('agents')
                    ->where('pub_key_hash', $evar)
                    ->first();

        // If the agent signature is missing, it implies a rogue agent or revoked status.
        if (!$agent) {
            return response()->json([
                'status' => 'error',
                'message' => 'Agent EVAR not found or revoked'
            ], 404);
        }

        // Return the certified trust tier to the enterprise gatekeeper.
        // The boolean transformation on 'revoked_at' evaluates if the agent is actively quarantined.
        return response()->json([
            'status' => 'success',
            'data' => [
                'evar' => $agent->pub_key_hash,
                'tier' => $agent->trust_tier, // e.g., 'nominal', 'elevated', 'critical'
                'is_quarantined' => !is_null($agent->revoked_at),
                'created_at' => $agent->created_at,
            ]
        ], 200);
    }
}
