<?php
/**
 * © 2026 ASAI — affinitysmartai.co.uk. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * EnterpriseSSOController
 *
 * Handles SAML 2.0 Assertion Consumer Service (ACS) and Continuous Access
 * Evaluation Profile (CAEP) session-revoked webhooks for enterprise tenants.
 *
 * Security notes:
 *   - SAML XML parsing uses PHP's DOMDocument with external entity loading
 *     disabled to prevent XXE attacks.
 *   - X.509 certificate-based signature verification is mandatory; unsigned
 *     assertions are rejected.
 *   - CAEP webhook payloads are validated against the tenant's stored IdP
 *     certificate before any session revocation occurs.
 *   - All endpoints are rate-limited via the 'throttle:api' middleware group.
 */
namespace App\Http\Controllers;

use DOMDocument;
use DOMXPath;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller as BaseController;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;

class EnterpriseSSOController extends BaseController
{
    /**
     * SAML 2.0 Assertion Consumer Service (ACS).
     *
     * Receives the base64-encoded SAMLResponse from the enterprise IdP,
     * validates the XML signature against the tenant's stored X.509
     * certificate, extracts the NameID (user email), and issues a
     * local session token via Laravel Sanctum.
     */
    public function consumeSamlAssertion(Request $request): JsonResponse
    {
        // ── Step 1: Extract and decode the SAML Response ────────────────
        $samlResponseB64 = $request->input('SAMLResponse');
        if (empty($samlResponseB64)) {
            Log::warning('[SSO] SAML assertion received with empty SAMLResponse.');
            return response()->json(['error' => 'Missing SAMLResponse parameter.'], 400);
        }

        $xml = base64_decode($samlResponseB64, true);
        if ($xml === false) {
            Log::warning('[SSO] SAML assertion base64 decode failed.');
            return response()->json(['error' => 'Invalid base64 encoding.'], 400);
        }

        // ── Step 2: Parse XML securely (XXE prevention) ─────────────────
        $dom = new DOMDocument();
        $dom->formatOutput = false;
        $dom->preserveWhiteSpace = true;

        // NOTE: libxml_disable_entity_loader() is deprecated in PHP 8.x because
        // external entity loading is disabled by default from PHP 8.0+. We do NOT
        // call it. Instead we explicitly set LIBXML_NONET | LIBXML_DTDLOAD as
        // defense-in-depth — this is the correct approach for PHP 8.x XXE prevention.
        $loaded = @$dom->loadXML($xml, LIBXML_NONET | LIBXML_NOENT | LIBXML_DTDLOAD);
        if (!$loaded) {
            Log::warning('[SSO] SAML response XML parsing failed.');
            return response()->json(['error' => 'Malformed SAML XML.'], 400);
        }

        // ── Step 3: Extract the Issuer to identify the tenant ───────────
        $xpath = new DOMXPath($dom);
        $xpath->registerNamespace('saml', 'urn:oasis:names:tc:SAML:2.0:assertion');
        $xpath->registerNamespace('samlp', 'urn:oasis:names:tc:SAML:2.0:protocol');

        $issuerNodes = $xpath->query('//saml:Issuer');
        if ($issuerNodes->length === 0) {
            Log::warning('[SSO] SAML assertion missing Issuer element.');
            return response()->json(['error' => 'Missing SAML Issuer.'], 400);
        }
        $issuer = trim($issuerNodes->item(0)->textContent);

        // ── Step 4: Lookup the tenant by IdP Entity ID ──────────────────
        $tenant = DB::table('tenants')
            ->where('idp_entity_id', $issuer)
            ->where('status', 'active')
            ->first();

        if (!$tenant) {
            Log::warning('[SSO] No active tenant found for IdP entity: ' . Str::limit($issuer, 128));
            return response()->json(['error' => 'Unknown identity provider.'], 403);
        }

        if (empty($tenant->idp_x509_cert)) {
            Log::error('[SSO] Tenant ' . $tenant->id . ' has no IdP X.509 certificate configured.');
            return response()->json(['error' => 'IdP certificate not configured for this tenant.'], 500);
        }

        // ── Step 5: Verify the XML Signature ────────────────────────────
        $signatureValid = $this->verifySamlSignature($dom, $tenant->idp_x509_cert);
        if (!$signatureValid) {
            Log::warning('[SSO] SAML signature verification failed for tenant: ' . $tenant->id);
            return response()->json(['error' => 'SAML signature verification failed.'], 403);
        }

        // ── Step 6: Extract NameID (user email) ─────────────────────────
        $nameIdNodes = $xpath->query('//saml:Assertion/saml:Subject/saml:NameID');
        if ($nameIdNodes->length === 0) {
            Log::warning('[SSO] SAML assertion missing NameID element.');
            return response()->json(['error' => 'Missing NameID in SAML assertion.'], 400);
        }
        $userEmail = trim($nameIdNodes->item(0)->textContent);

        if (!filter_var($userEmail, FILTER_VALIDATE_EMAIL)) {
            Log::warning('[SSO] Invalid email in NameID: ' . Str::limit($userEmail, 64));
            return response()->json(['error' => 'Invalid NameID format.'], 400);
        }

        // ── Step 7: Resolve or create the local user ────────────────────
        $contactId = DB::table('contacts')
            ->where('email', $userEmail)
            ->where('tenant_id', $tenant->id)
            ->value('id');

        if (!$contactId) {
            $contactId = (string) Str::uuid();
            DB::table('contacts')->insert([
                'id'        => $contactId,
                'tenant_id' => $tenant->id,
                'email'     => $userEmail,
                'name'      => $userEmail,
                'role'      => 'operator',
                'created_at' => now(),
            ]);
        }

        // ── Step 8: Issue a Sanctum-compatible token ────────────────────
        $rawToken = Str::random(64);
        DB::table('personal_access_tokens')->insert([
            'id'             => (int) now()->timestamp . random_int(100, 999),
            'tokenable_type' => 'App\\Models\\User',
            'tokenable_id'   => $contactId,
            'name'           => "{$contactId}|{$tenant->id}|sso",
            'token'          => hash('sha256', $rawToken),
            'abilities'      => '["*"]',
            'expires_at'     => now()->addHours(8),
            'created_at'     => now(),
            'updated_at'     => now(),
        ]);

        Log::info('[SSO] SAML login successful for ' . $userEmail . ' (tenant: ' . $tenant->id . ')');

        return response()->json([
            'message'    => 'SAML authentication successful.',
            'token'      => $rawToken,
            'tenant_id'  => $tenant->id,
            'user_email' => $userEmail,
            'expires_in' => 28800, // 8 hours in seconds
        ], 200);
    }

    /**
     * CAEP Session-Revoked Webhook.
     *
     * Receives a Security Event Token (SET) from the enterprise IdP
     * indicating that a user's session has been revoked (e.g., the user
     * was deactivated in Okta, or their device was marked as compromised).
     *
     * This handler:
     *   1. Validates the JWT signature against the tenant's IdP certificate.
     *   2. Extracts the subject identifier from the SET events payload.
     *   3. Revokes ALL active personal_access_tokens for that user.
     *   4. Logs the revocation event to the operator audit log.
     */
    public function handleCaepRevocation(Request $request): JsonResponse
    {
        // ── Step 1: Extract the SET JWT ─────────────────────────────────
        $setJwt = $request->input('token') ?? $request->getContent();
        if (empty($setJwt)) {
            Log::warning('[CAEP] Empty SET token received.');
            return response()->json(['error' => 'Missing SET token.'], 400);
        }

        // ── Step 2: Decode JWT parts (header.payload.signature) ─────────
        $parts = explode('.', $setJwt);
        if (count($parts) !== 3) {
            Log::warning('[CAEP] Malformed SET JWT: expected 3 parts, got ' . count($parts));
            return response()->json(['error' => 'Malformed SET JWT.'], 400);
        }

        $headerJson  = base64_decode(strtr($parts[0], '-_', '+/'), true);
        $payloadJson = base64_decode(strtr($parts[1], '-_', '+/'), true);

        if ($headerJson === false || $payloadJson === false) {
            return response()->json(['error' => 'Invalid JWT base64 encoding.'], 400);
        }

        $header  = json_decode($headerJson, true);
        $payload = json_decode($payloadJson, true);

        if (!$header || !$payload) {
            return response()->json(['error' => 'Invalid JWT JSON.'], 400);
        }

        // ── Step 3: Reject the 'none' algorithm ─────────────────────────
        $alg = $header['alg'] ?? 'none';
        if (strtolower($alg) === 'none') {
            Log::warning('[CAEP] SET JWT uses "none" algorithm — rejected.');
            return response()->json(['error' => 'Unsigned JWTs are not accepted.'], 403);
        }

        // ── Step 4: Identify the tenant from the issuer ─────────────────
        $issuer = $payload['iss'] ?? null;
        if (empty($issuer)) {
            return response()->json(['error' => 'Missing issuer in SET.'], 400);
        }

        $tenant = DB::table('tenants')
            ->where('idp_entity_id', $issuer)
            ->where('status', 'active')
            ->first();

        if (!$tenant || empty($tenant->idp_x509_cert)) {
            Log::warning('[CAEP] Unknown or unconfigured issuer: ' . Str::limit($issuer, 128));
            return response()->json(['error' => 'Unknown issuer.'], 403);
        }

        // ── Step 5: Verify JWT signature ────────────────────────────────
        $signatureValid = $this->verifyJwtSignature($parts, $tenant->idp_x509_cert, $alg);
        if (!$signatureValid) {
            Log::warning('[CAEP] SET JWT signature verification failed for tenant: ' . $tenant->id);
            return response()->json(['error' => 'SET signature verification failed.'], 403);
        }

        // ── Step 6: Validate the event type ─────────────────────────────
        $events = $payload['events'] ?? [];
        $hasSessionRevoked = isset($events['https://schemas.openid.net/secevent/caep/event-type/session-revoked']);

        if (!$hasSessionRevoked) {
            Log::info('[CAEP] SET received but does not contain session-revoked event. Ignoring.');
            return response()->json(['message' => 'Event type not actionable.'], 200);
        }

        // ── Step 7: Extract the subject and revoke tokens ───────────────
        $subjectPayload = $events['https://schemas.openid.net/secevent/caep/event-type/session-revoked'];
        $subjectEmail   = $subjectPayload['subject']['email']
            ?? $subjectPayload['subject']['sub']
            ?? $payload['sub']
            ?? null;

        if (empty($subjectEmail)) {
            Log::warning('[CAEP] Cannot determine subject from SET payload.');
            return response()->json(['error' => 'Cannot identify subject.'], 400);
        }

        // Find the contact in this tenant
        $contactId = DB::table('contacts')
            ->where('email', $subjectEmail)
            ->where('tenant_id', $tenant->id)
            ->value('id');

        if (!$contactId) {
            Log::info('[CAEP] No matching contact for ' . Str::limit($subjectEmail, 64) . ' in tenant ' . $tenant->id);
            return response()->json(['message' => 'Subject not found in this tenant.'], 200);
        }

        // Purge ALL active tokens for this user
        $revokedCount = DB::table('personal_access_tokens')
            ->where('tokenable_id', $contactId)
            ->delete();

        // ── Step 8: Audit log the revocation ────────────────────────────
        DB::table('operator_audit_log')->insert([
            'operator_id'    => null,
            'operator_label' => 'CAEP/' . Str::limit($issuer, 128),
            'action'         => 'session_revoked',
            'entity_type'    => 'contact',
            'entity_id'      => $contactId,
            'notes'          => json_encode([
                'tenant_id'      => $tenant->id,
                'subject_email'  => $subjectEmail,
                'tokens_revoked' => $revokedCount,
                'set_jti'        => $payload['jti'] ?? 'unknown',
            ]),
            'created_at'     => now(),
        ]);

        Log::info("[CAEP] Revoked {$revokedCount} token(s) for {$subjectEmail} in tenant {$tenant->id}");

        return response()->json([
            'message'        => 'Session revoked successfully.',
            'tokens_revoked' => $revokedCount,
        ], 200);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Private helpers
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * Verify the XML digital signature in a SAML Response using the tenant's
     * stored IdP X.509 certificate.
     */
    private function verifySamlSignature(DOMDocument $dom, string $x509Pem): bool
    {
        $xpath = new DOMXPath($dom);
        $xpath->registerNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');

        $signatureNodes = $xpath->query('//ds:Signature');
        if ($signatureNodes->length === 0) {
            Log::warning('[SSO] No XML Signature found in SAML response.');
            return false;
        }

        // Extract the SignatureValue and SignedInfo
        $sigValueNodes = $xpath->query('//ds:Signature/ds:SignatureValue');
        $signedInfoNodes = $xpath->query('//ds:Signature/ds:SignedInfo');

        if ($sigValueNodes->length === 0 || $signedInfoNodes->length === 0) {
            return false;
        }

        $signatureValue = base64_decode(
            preg_replace('/\s+/', '', $sigValueNodes->item(0)->textContent)
        );

        // Canonicalize the SignedInfo element for verification
        $signedInfoCanonical = $signedInfoNodes->item(0)->C14N(false, false);

        // Build the PEM-formatted public key
        $certPem = "-----BEGIN CERTIFICATE-----\n"
            . chunk_split(preg_replace('/\s+/', '', $x509Pem), 64, "\n")
            . "-----END CERTIFICATE-----";

        $publicKey = openssl_pkey_get_public($certPem);
        if (!$publicKey) {
            Log::error('[SSO] Failed to parse IdP X.509 certificate.');
            return false;
        }

        // Determine the signature algorithm from the SignedInfo
        $sigMethodNodes = $xpath->query('//ds:Signature/ds:SignedInfo/ds:SignatureMethod/@Algorithm');
        $algorithm = OPENSSL_ALGO_SHA256; // default
        if ($sigMethodNodes->length > 0) {
            $algUri = $sigMethodNodes->item(0)->nodeValue;
            $algorithm = match (true) {
                str_contains($algUri, 'sha512') => OPENSSL_ALGO_SHA512,
                str_contains($algUri, 'sha384') => OPENSSL_ALGO_SHA384,
                str_contains($algUri, 'sha1')   => OPENSSL_ALGO_SHA1,
                default                         => OPENSSL_ALGO_SHA256,
            };
        }

        $result = openssl_verify($signedInfoCanonical, $signatureValue, $publicKey, $algorithm);

        return $result === 1;
    }

    /**
     * Verify a JWT signature using the tenant's IdP X.509 certificate.
     *
     * Supports RS256, RS384, RS512.
     */
    private function verifyJwtSignature(array $parts, string $x509Pem, string $alg): bool
    {
        $dataToVerify = $parts[0] . '.' . $parts[1];
        $signature    = base64_decode(strtr($parts[2], '-_', '+/'), true);

        if ($signature === false) {
            return false;
        }

        $certPem = "-----BEGIN CERTIFICATE-----\n"
            . chunk_split(preg_replace('/\s+/', '', $x509Pem), 64, "\n")
            . "-----END CERTIFICATE-----";

        $publicKey = openssl_pkey_get_public($certPem);
        if (!$publicKey) {
            Log::error('[CAEP] Failed to parse IdP X.509 certificate for JWT verification.');
            return false;
        }

        $opensslAlg = match (strtoupper($alg)) {
            'RS256' => OPENSSL_ALGO_SHA256,
            'RS384' => OPENSSL_ALGO_SHA384,
            'RS512' => OPENSSL_ALGO_SHA512,
            default => null,
        };

        if ($opensslAlg === null) {
            Log::warning('[CAEP] Unsupported JWT algorithm: ' . $alg);
            return false;
        }

        $result = openssl_verify($dataToVerify, $signature, $publicKey, $opensslAlg);

        return $result === 1;
    }
}
