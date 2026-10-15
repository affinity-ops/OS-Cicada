<?php
/**
 * © 2026 ASAI — affinitysmartai.co.uk. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * EnterpriseSSOControllerTest
 *
 * Validates the SAML 2.0 ACS and CAEP session-revocation endpoints using
 * self-signed test certificates and synthetic payloads.
 */
namespace Tests\Feature;

use Tests\TestCase;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

class EnterpriseSSOControllerTest extends TestCase
{
    use DatabaseTransactions;

    private string $tenantId = '';
    private string $contactId = '';
    private string $privateKeyPem = '';
    private string $x509CertPem = '';

    protected function setUp(): void
    {
        parent::setUp();

        // Generate a self-signed RSA keypair for test signature verification
        $keyConfig = [
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ];
        $keyPair = openssl_pkey_new($keyConfig);
        openssl_pkey_export($keyPair, $this->privateKeyPem);

        // Create a self-signed X.509 certificate
        $csr = openssl_csr_new([
            'commonName' => 'test-idp.cicada.local',
        ], $keyPair);
        $x509 = openssl_csr_sign($csr, null, $keyPair, 365);
        openssl_x509_export($x509, $certPem);

        // Strip the PEM headers for storage (the controller re-wraps them)
        $this->x509CertPem = str_replace(
            ['-----BEGIN CERTIFICATE-----', '-----END CERTIFICATE-----', "\n", "\r"],
            '',
            $certPem
        );

        // Seed tenant with IdP configuration
        $this->tenantId = (string) Str::uuid();
        DB::table('tenants')->insert([
            'id'             => $this->tenantId,
            'name'           => 'SSO Test Tenant',
            'status'         => 'active',
            'plan'           => 'enterprise',
            'idp_entity_id'  => 'https://test-idp.cicada.local',
            'idp_sso_url'    => 'https://test-idp.cicada.local/sso',
            'idp_x509_cert'  => $this->x509CertPem,
            'created_at'     => now(),
            'updated_at'     => now(),
        ]);

        // Seed a contact for CAEP revocation tests
        $this->contactId = (string) Str::uuid();
        DB::table('contacts')->insert([
            'id'         => $this->contactId,
            'tenant_id'  => $this->tenantId,
            'name'       => 'SSO Test User',
            'email'      => 'sso-user@cicada.local',
            'is_primary' => true,
            'created_at' => now(),
            'updated_at' => now(),
        ]);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // SAML ACS Tests
    // ═══════════════════════════════════════════════════════════════════════

    public function test_saml_rejects_empty_response(): void
    {
        $response = $this->postJson('/api/v1/enterprise/sso/saml/consume', []);
        $response->assertStatus(400);
        $response->assertJsonFragment(['error' => 'Missing SAMLResponse parameter.']);
    }

    public function test_saml_rejects_invalid_base64(): void
    {
        $response = $this->postJson('/api/v1/enterprise/sso/saml/consume', [
            'SAMLResponse' => '!!!not-base64!!!',
        ]);
        // Will fail at XML parse stage
        $response->assertStatus(400);
    }

    public function test_saml_rejects_malformed_xml(): void
    {
        $response = $this->postJson('/api/v1/enterprise/sso/saml/consume', [
            'SAMLResponse' => base64_encode('<not-saml>broken</not-saml>'),
        ]);
        $response->assertStatus(400);
    }

    public function test_saml_rejects_unknown_issuer(): void
    {
        $xml = $this->buildSamlResponse('https://unknown-idp.example.com', 'user@unknown.com');
        $response = $this->postJson('/api/v1/enterprise/sso/saml/consume', [
            'SAMLResponse' => base64_encode($xml),
        ]);
        $response->assertStatus(403);
        $response->assertJsonFragment(['error' => 'Unknown identity provider.']);
    }

    public function test_saml_rejects_unsigned_assertion(): void
    {
        // Build a valid-looking SAML response with the correct issuer but no signature
        $xml = $this->buildSamlResponse('https://test-idp.cicada.local', 'sso-user@cicada.local');
        $response = $this->postJson('/api/v1/enterprise/sso/saml/consume', [
            'SAMLResponse' => base64_encode($xml),
        ]);
        $response->assertStatus(403);
    }

    public function test_saml_accepts_validly_signed_assertion(): void
    {
        $xml = $this->buildSignedSamlResponse(
            'https://test-idp.cicada.local',
            'sso-user@cicada.local'
        );

        $response = $this->postJson('/api/v1/enterprise/sso/saml/consume', [
            'SAMLResponse' => base64_encode($xml),
        ]);

        $response->assertStatus(200);
        $response->assertJsonStructure(['message', 'token', 'tenant_id', 'user_email', 'expires_in']);
        $this->assertEquals('sso-user@cicada.local', $response->json('user_email'));
        $this->assertEquals($this->tenantId, $response->json('tenant_id'));

        // Verify a token was created in the database
        $this->assertDatabaseHas('personal_access_tokens', [
            'tokenable_id' => $this->contactId,
        ]);
    }

    public function test_saml_creates_new_contact_for_unknown_email(): void
    {
        $xml = $this->buildSignedSamlResponse(
            'https://test-idp.cicada.local',
            'brand-new-user@cicada.local'
        );

        $response = $this->postJson('/api/v1/enterprise/sso/saml/consume', [
            'SAMLResponse' => base64_encode($xml),
        ]);

        $response->assertStatus(200);
        $this->assertDatabaseHas('contacts', [
            'email'     => 'brand-new-user@cicada.local',
            'tenant_id' => $this->tenantId,
        ]);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // CAEP Revocation Tests
    // ═══════════════════════════════════════════════════════════════════════

    public function test_caep_rejects_empty_set(): void
    {
        $response = $this->postJson('/api/v1/enterprise/sso/caep/webhook', []);
        $response->assertStatus(400);
    }

    public function test_caep_rejects_none_algorithm(): void
    {
        $header  = base64_encode(json_encode(['alg' => 'none', 'typ' => 'secevent+jwt']));
        $payload = base64_encode(json_encode(['iss' => 'https://test-idp.cicada.local', 'sub' => 'sso-user@cicada.local']));
        $jwt = "{$header}.{$payload}.";

        $response = $this->postJson('/api/v1/enterprise/sso/caep/webhook', [
            'token' => $jwt,
        ]);
        $response->assertStatus(403);
    }

    public function test_caep_revokes_tokens_for_valid_set(): void
    {
        // First, create some active tokens for this contact
        for ($i = 0; $i < 3; $i++) {
            DB::table('personal_access_tokens')->insert([
                'tokenable_type' => 'App\\Models\\User',
                'tokenable_id'   => $this->contactId,
                'name'           => "{$this->contactId}|{$this->tenantId}|sso-{$i}",
                'token'          => hash('sha256', Str::random(64)),
                'abilities'      => '["*"]',
                'expires_at'     => now()->addHours(8),
                'created_at'     => now(),
                'updated_at'     => now(),
            ]);
        }

        $this->assertDatabaseCount('personal_access_tokens', 3);

        // Build and sign a CAEP SET JWT
        $jwt = $this->buildSignedCaepSet('sso-user@cicada.local');

        $response = $this->postJson('/api/v1/enterprise/sso/caep/webhook', [
            'token' => $jwt,
        ]);

        $response->assertStatus(200);
        $response->assertJsonFragment(['tokens_revoked' => 3]);

        // All tokens should be purged
        $remaining = DB::table('personal_access_tokens')
            ->where('tokenable_id', $this->contactId)
            ->count();
        $this->assertEquals(0, $remaining);

        // Audit log entry should exist
        $this->assertDatabaseHas('operator_audit_log', [
            'action'      => 'session_revoked',
            'entity_type' => 'contact',
            'entity_id'   => $this->contactId,
        ]);
    }

    public function test_caep_ignores_non_revocation_events(): void
    {
        $jwt = $this->buildSignedCaepSet('sso-user@cicada.local', 'https://schemas.openid.net/secevent/caep/event-type/credential-change');

        $response = $this->postJson('/api/v1/enterprise/sso/caep/webhook', [
            'token' => $jwt,
        ]);

        $response->assertStatus(200);
        $response->assertJsonFragment(['message' => 'Event type not actionable.']);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Helpers — SAML Response Builders
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * Build a minimal unsigned SAML Response XML.
     */
    private function buildSamlResponse(string $issuer, string $nameId): string
    {
        $id       = '_' . Str::uuid();
        $assertId = '_' . Str::uuid();
        $now      = now()->toIso8601ZuluString();
        $later    = now()->addMinutes(5)->toIso8601ZuluString();

        return <<<XML
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="{$id}" Version="2.0" IssueInstant="{$now}">
  <saml:Issuer>{$issuer}</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion ID="{$assertId}" Version="2.0" IssueInstant="{$now}">
    <saml:Issuer>{$issuer}</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{$nameId}</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="{$later}"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="{$now}" NotOnOrAfter="{$later}"/>
  </saml:Assertion>
</samlp:Response>
XML;
    }

    /**
     * Build a signed SAML Response using the test RSA key.
     *
     * This creates a real enveloped XML Digital Signature using the
     * self-signed certificate generated in setUp(). The signature is
     * placed as the first child of the Response element so the controller's
     * XPath query //ds:Signature finds it.
     */
    private function buildSignedSamlResponse(string $issuer, string $nameId): string
    {
        $xml = $this->buildSamlResponse($issuer, $nameId);

        $dom = new \DOMDocument();
        $dom->loadXML($xml);

        // We need to build the Signature element, insert it into the DOM,
        // then compute the digest and signature over the final canonical form.

        // Step 1: Compute the digest of the entire document (with enveloped-signature transform).
        // For simplicity, we digest the whole document canonical form.
        $c14nDoc = $dom->C14N(true, false);
        $digestValue = base64_encode(hash('sha256', $c14nDoc, true));

        // Step 2: Build the complete Signature element with the digest
        $signatureXml = <<<SIGXML
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:SignedInfo>
    <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
    <ds:Reference URI="">
      <ds:Transforms>
        <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
        <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      </ds:Transforms>
      <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
      <ds:DigestValue>{$digestValue}</ds:DigestValue>
    </ds:Reference>
  </ds:SignedInfo>
  <ds:SignatureValue></ds:SignatureValue>
</ds:Signature>
SIGXML;

        // Step 3: Insert the Signature into the DOM
        $sigDom = new \DOMDocument();
        $sigDom->loadXML($signatureXml);
        $sigNode = $dom->importNode($sigDom->documentElement, true);
        $dom->documentElement->insertBefore($sigNode, $dom->documentElement->firstChild);

        // Step 4: Now extract the SignedInfo from the live DOM and canonicalize it
        $xpath = new \DOMXPath($dom);
        $xpath->registerNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');
        $signedInfoNode = $xpath->query('//ds:Signature/ds:SignedInfo')->item(0);
        $signedInfoCanonical = $signedInfoNode->C14N(false, false);

        // Step 5: Sign the canonical SignedInfo
        $privateKey = openssl_pkey_get_private($this->privateKeyPem);
        openssl_sign($signedInfoCanonical, $signature, $privateKey, OPENSSL_ALGO_SHA256);
        $signatureValue = base64_encode($signature);

        // Step 6: Inject the signature value into the SignatureValue element
        $sigValueNode = $xpath->query('//ds:Signature/ds:SignatureValue')->item(0);
        $sigValueNode->textContent = $signatureValue;

        return $dom->saveXML();
    }

    /**
     * Build a signed CAEP Security Event Token (SET) JWT.
     */
    private function buildSignedCaepSet(
        string $subjectEmail,
        string $eventType = 'https://schemas.openid.net/secevent/caep/event-type/session-revoked'
    ): string {
        $header = [
            'alg' => 'RS256',
            'typ' => 'secevent+jwt',
        ];

        $payload = [
            'iss'    => 'https://test-idp.cicada.local',
            'iat'    => time(),
            'jti'    => (string) Str::uuid(),
            'aud'    => 'cicada-core-api',
            'events' => [
                $eventType => [
                    'subject' => [
                        'subject_type' => 'email',
                        'email'        => $subjectEmail,
                    ],
                ],
            ],
        ];

        $headerB64  = rtrim(strtr(base64_encode(json_encode($header)), '+/', '-_'), '=');
        $payloadB64 = rtrim(strtr(base64_encode(json_encode($payload)), '+/', '-_'), '=');

        $dataToSign = "{$headerB64}.{$payloadB64}";

        $privateKey = openssl_pkey_get_private($this->privateKeyPem);
        openssl_sign($dataToSign, $signature, $privateKey, OPENSSL_ALGO_SHA256);
        $signatureB64 = rtrim(strtr(base64_encode($signature), '+/', '-_'), '=');

        return "{$headerB64}.{$payloadB64}.{$signatureB64}";
    }
}
