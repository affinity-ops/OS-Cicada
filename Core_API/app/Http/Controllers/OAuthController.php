<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\Agent;
use App\Services\FederatedIssuer;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

/**
 * Handles OAuth 2.1 Private Key Machine-to-Machine JWT identity federation.
 */
class OAuthController extends Controller
{
    public function token(Request $request)
    {
        // 1. Conform natively to OAuth2 Client Credentials
        if ($request->input('grant_type') !== 'client_credentials') {
            return response()->json(['error' => 'unsupported_grant_type'], 400);
        }

        // Expected assertion profile: RFC 7523 (Private Key JWT)
        if ($request->input('client_assertion_type') !== 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer') {
            return response()->json(['error' => 'invalid_client', 'error_description' => 'Use RFC 7523 assertion types strictly'], 400);
        }

        $assertion = $request->input('client_assertion');
        if (!$assertion) {
            return response()->json(['error' => 'invalid_request', 'error_description' => 'client_assertion missing'], 400);
        }

        // 2. Extrapolate payload pre-verification to ascertain the originating Agent ID
        $parts = explode('.', $assertion);
        if (count($parts) !== 3) {
            return response()->json(['error' => 'invalid_client'], 400);
        }

        $payload = json_decode(base64_decode(strtr($parts[1], '-_', '+/')), true);
        $agentId = $payload['sub'] ?? null;

        $agent = Agent::find($agentId);
        if (!$agent || $agent->trust_tier === 'revoked') {
            return response()->json(['error' => 'invalid_client', 'error_description' => 'Agent identity permanently revoked or non-existent'], 401);
        }

        // 3. Mathematical Ed25519 Verify Check via Agent's Public Key mapped in the DB
        $pubKeyDecoded = base64_decode($agent->pub_key_hash);
        try {
            JWT::decode($assertion, new Key($pubKeyDecoded, 'EdDSA'));
        } catch (\Exception $e) {
            return response()->json(['error' => 'invalid_client', 'error_description' => 'Ed25519 signature mathematical validation forcefully rejected'], 401);
        }

        // 4. Verification Successful -> Mint 15m Federated OAuth JWT
        $issuerKeys = FederatedIssuer::getKeys();
        $privateKeyDecoded = base64_decode($issuerKeys['private']);

        $tokenPayload = [
            'iss' => url('/'),
            // Broad scope audiences so tokens natively bypass third-party gateways (e.g. AWS/Azure nodes)
            'aud' => ['cicada.gateway', 'external.federation'], 
            'sub' => $agent->id,
            'tenant_id' => $agent->tenant_id,
            'trust_tier' => $agent->trust_tier,
            'scopes' => $agent->scope_entitlements, // Natively embed RBAC capacities within the token!
            'iat' => time(),
            'exp' => time() + 900, // Strict 15 minute TTL limits vulnerability windows
            'jti' => uniqid('jwt_', true)
        ];

        // Core API signs it flawlessly
        $accessToken = JWT::encode($tokenPayload, $privateKeyDecoded, 'EdDSA', $issuerKeys['kid']);

        return response()->json([
            'access_token' => $accessToken,
            'token_type' => 'Bearer',
            'expires_in' => 900,
        ]);
    }

    public function jwks()
    {
        return response()->json(FederatedIssuer::getJwks());
    }
}
