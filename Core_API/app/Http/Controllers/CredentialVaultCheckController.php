<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;

/**
 * CredentialVaultCheckController — Vault-aware credential cross-reference.
 *
 * This controller provides a secure, hash-only endpoint that allows the Sentry
 * Gateway to determine whether a detected credential in an outbound request body
 * is in fact the tenant's own vaulted BYOK API key.
 *
 * Why this exists:
 * The exfiltration scanner in the Gateway detects credential patterns (sk-, AKIA, etc.)
 * in outbound POST/PUT bodies. However, it cannot distinguish between:
 *   (a) a legitimate credential being sent to its intended service (Stripe key → Stripe)
 *   (b) the tenant's own BYOK key being exfiltrated by a compromised agent
 *
 * This endpoint closes that gap by accepting a SHA-256 hash of the suspected credential
 * and comparing it against SHA-256 hashes of the tenant's decrypted vault entries.
 * The actual credential value never crosses the network — only hashes are compared.
 *
 * Security model:
 * - Authenticated via X-Gateway-Secret header (GatewayAuth middleware)
 * - Scoped to a specific tenant_id (prevents cross-tenant vault probing)
 * - Input is a hash, not a raw credential (no replay risk)
 * - Response is boolean only — no credential metadata leaked
 *
 * Integration with the pipeline:
 * Gateway → detects credential in body → SHA-256 hashes it → POSTs here
 *   → if match: elevate exfiltration severity to CRITICAL
 *   → if no match: standard exfiltration_risk flag (unchanged behaviour)
 */
class CredentialVaultCheckController extends Controller
{
    /**
     * Check whether a SHA-256 hash matches any credential stored in the tenant's vault.
     *
     * The Gateway sends a hash of a detected credential. This endpoint decrypts
     * each of the tenant's stored BYOK keys, hashes them, and checks for a match.
     * This is deliberately N × decrypt → compare because:
     *   (a) typical tenant has 1–5 keys (low cardinality)
     *   (b) the alternative (storing plaintext hashes) weakens vault security
     *   (c) this endpoint is called only on exfiltration_risk events (rare)
     *
     * @param Request $request
     * @return \Illuminate\Http\JsonResponse
     *
     * Request body:
     *   {
     *     "tenant_id": "uuid",
     *     "credential_hash": "sha256hex..."
     *   }
     *
     * Response:
     *   { "match": true|false }
     */
    public function checkHash(Request $request)
    {
        $validated = $request->validate([
            'tenant_id'       => 'required|uuid',
            'credential_hash' => 'required|string|size:64', // SHA-256 hex = 64 chars
        ]);

        $tenantId       = $validated['tenant_id'];
        $credentialHash = strtolower($validated['credential_hash']);

        try {
            // Retrieve all encrypted BYOK keys for this tenant.
            // The `payload_encrypted` column is AES-256-GCM encrypted by Laravel Crypt.
            $vaultEntries = DB::table('tenant_keys')
                ->where('tenant_id', $tenantId)
                ->pluck('payload_encrypted');

            if ($vaultEntries->isEmpty()) {
                // No keys stored for this tenant — no match possible.
                // This is not an error; fresh tenants may not have keys yet.
                return response()->json(['match' => false], 200);
            }

            // Decrypt each key and compare its SHA-256 hash against the supplied hash.
            // If any match, the detected credential IS the tenant's own BYOK key.
            foreach ($vaultEntries as $encrypted) {
                try {
                    $decrypted = Crypt::decryptString($encrypted);
                    $hash = hash('sha256', $decrypted);

                    if (hash_equals($hash, $credentialHash)) {
                        Log::warning('Vault credential match detected', [
                            'tenant_id' => $tenantId,
                            // Deliberately NOT logging the hash — it's a derived secret.
                            // The ledger entry from the Gateway will contain the full context.
                        ]);

                        return response()->json(['match' => true], 200);
                    }
                } catch (\Exception $decryptEx) {
                    // Corrupted or re-keyed entry — skip, don't fail the whole check.
                    // This can happen if APP_KEY was rotated without re-encrypting vault entries.
                    Log::warning('Vault entry decryption failed — skipping', [
                        'tenant_id' => $tenantId,
                        'error'     => $decryptEx->getMessage(),
                    ]);
                    continue;
                }
            }

            // No match found across all vault entries.
            return response()->json(['match' => false], 200);

        } catch (\Exception $e) {
            Log::error('Vault check-hash failed', [
                'tenant_id' => $tenantId,
                'error'     => $e->getMessage(),
            ]);

            // Return false rather than 500 — Gateway will treat as "no match" and
            // continue with standard (non-elevated) exfiltration handling.
            // We do NOT want a vault check failure to prevent legitimate agent traffic.
            return response()->json(['match' => false], 200);
        }
    }
}
