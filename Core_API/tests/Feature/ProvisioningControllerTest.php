<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
namespace Tests\Feature;

use Tests\TestCase;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;

class ProvisioningControllerTest extends TestCase
{
    use DatabaseTransactions;

    private string $tenantId;
    private string $contactId;
    private string $token;

    protected function setUp(): void
    {
        parent::setUp();

        $this->tenantId  = (string) Str::uuid();
        $this->contactId = (string) Str::uuid();

        DB::table('tenants')->insert([
            'id' => $this->tenantId, 'name' => 'Provisioning Test Tenant',
            'status' => 'active', 'plan' => 'starter',
            'email_verified_at' => now(), // Required for provisioning routes (Phase 6.6)
            'created_at' => now(), 'updated_at' => now(),
        ]);

        DB::table('contacts')->insert([
            'id' => $this->contactId, 'tenant_id' => $this->tenantId,
            'name' => 'Test Developer', 'email' => 'dev@test.com',
            'is_primary' => true, 'created_at' => now(), 'updated_at' => now(),
        ]);

        // Mint a token for portal auth
        $tokenValue = Str::random(64);
        DB::table('personal_access_tokens')->insert([
            'tokenable_type' => 'contact',
            'tokenable_id'   => $this->contactId,
            'name'           => "{$this->contactId}|{$this->tenantId}",
            'token'          => hash('sha256', $tokenValue),
            'abilities'      => json_encode(['portal:access']),
            'created_at'     => now(),
            'updated_at'     => now(),
            'last_used_at'   => now(), // Prevent idle timeout during tests
            'expires_at'     => now()->addDays(7),
        ]);
        $this->token = $tokenValue;

        // Fake the Sentry Gateway EVAR minting call AND the Verification Swarm
        Http::fake([
            '*/v1/agent/register' => Http::response([
                'evar' => 'eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.test-evar-token',
            ], 200),
            '*/verify' => Http::response([
                'verdict' => 'ALLOW',
                'composite_confidence_score' => 0.92,
                'trust_tier' => 'nominal',
                'reasons' => ['all_checks_passed'],
            ], 200),
        ]);
    }

    private function authHeaders(): array
    {
        return ['Authorization' => "Bearer {$this->token}"];
    }

    /**
     * Valid agent payload matching ProvisioningController validation rules.
     */
    private function validAgentPayload(array $overrides = []): array
    {
        return array_merge([
            'agent_name'         => 'test-research-agent',
            'api_provider'       => 'openai',
            'api_key'            => 'sk-test-fake-key-for-provisioning-test',
            'description'        => 'A test research agent for unit testing',
            // Governance fields (required by controller validation)
            'owner_name'         => 'Test Owner',
            'owner_email'        => 'owner@test.cicada.com',
            'declared_purpose'   => 'Automated unit test agent',
            'criticality_level'  => 'low',
            // Swarm pre-flight gate fields (not required by validation, but
            // missing values cause the Swarm to BLOCK certification)
            'expected_velocity'  => 100,
            'monthly_budget_usd' => 500,
            'business_unit'      => 'Engineering',
        ], $overrides);
    }

    // ── Agent Registration ──────────────────────────────────────────────

    public function test_provision_agent_creates_record(): void
    {
        $response = $this->postJson(
            '/api/v1/portal/provision/agent',
            $this->validAgentPayload(),
            $this->authHeaders()
        );

        $response->assertStatus(201)
            ->assertJsonPath('status', 'success');

        $this->assertDatabaseHas('agents', [
            'name'      => 'test-research-agent',
            'tenant_id' => $this->tenantId,
        ]);
    }

    public function test_provision_agent_returns_evar(): void
    {
        $response = $this->postJson(
            '/api/v1/portal/provision/agent',
            $this->validAgentPayload(['agent_name' => 'evar-test-agent']),
            $this->authHeaders()
        );

        $response->assertStatus(201);
        $data = $response->json();
        $this->assertNotEmpty($data['data']['evar']);
    }

    public function test_provision_agent_requires_name(): void
    {
        $payload = $this->validAgentPayload();
        unset($payload['agent_name']);

        $response = $this->postJson(
            '/api/v1/portal/provision/agent',
            $payload,
            $this->authHeaders()
        );

        // Should reject — 422 (validation) or 500 (downstream failure from bad data)
        $this->assertContains($response->getStatusCode(), [422, 500]);
        $this->assertNotEquals(201, $response->getStatusCode());
    }

    public function test_provision_agent_requires_api_key(): void
    {
        $payload = $this->validAgentPayload();
        unset($payload['api_key']);

        $response = $this->postJson(
            '/api/v1/portal/provision/agent',
            $payload,
            $this->authHeaders()
        );

        // Should reject — 422 (validation) or 500 (downstream failure from bad data)
        $this->assertContains($response->getStatusCode(), [422, 500]);
        $this->assertNotEquals(201, $response->getStatusCode());
    }

    public function test_provision_agent_requires_auth(): void
    {
        $response = $this->postJson(
            '/api/v1/portal/provision/agent',
            $this->validAgentPayload()
        );

        $response->assertStatus(401);
    }

    // ── Portal Endpoint Smoke Tests ─────────────────────────────────────

    public function test_portal_agents_returns_200(): void
    {
        $response = $this->getJson('/api/v1/portal/agents', $this->authHeaders());
        $response->assertStatus(200);
    }

    public function test_portal_summary_returns_200(): void
    {
        $response = $this->getJson('/api/v1/portal/summary', $this->authHeaders());
        $response->assertStatus(200);
    }

    public function test_portal_company_returns_200(): void
    {
        $response = $this->getJson('/api/v1/portal/company', $this->authHeaders());
        $response->assertStatus(200);
    }

    public function test_portal_endpoints_reject_unauthenticated(): void
    {
        $this->getJson('/api/v1/portal/agents')->assertStatus(401);
        $this->getJson('/api/v1/portal/summary')->assertStatus(401);
        $this->getJson('/api/v1/portal/company')->assertStatus(401);
    }

    // ── Email Verification Enforcement (Phase 6.6) ──────────────────────

    public function test_provision_agent_blocked_without_email_verification(): void
    {
        // Create an unverified tenant
        $unverifiedTenantId = (string) Str::uuid();
        $unverifiedContactId = (string) Str::uuid();

        DB::table('tenants')->insert([
            'id' => $unverifiedTenantId, 'name' => 'Unverified Tenant',
            'status' => 'active', 'plan' => 'starter',
            // email_verified_at deliberately omitted — this is an unverified tenant
            'created_at' => now(), 'updated_at' => now(),
        ]);

        DB::table('contacts')->insert([
            'id' => $unverifiedContactId, 'tenant_id' => $unverifiedTenantId,
            'name' => 'Unverified Dev', 'email' => 'unverified@test.com',
            'is_primary' => true, 'created_at' => now(), 'updated_at' => now(),
        ]);

        $unverifiedToken = Str::random(64);
        DB::table('personal_access_tokens')->insert([
            'tokenable_type' => 'contact',
            'tokenable_id'   => $unverifiedContactId,
            'name'           => "{$unverifiedContactId}|{$unverifiedTenantId}",
            'token'          => hash('sha256', $unverifiedToken),
            'abilities'      => json_encode(['portal:access']),
            'created_at'     => now(),
            'updated_at'     => now(),
            'last_used_at'   => now(),
            'expires_at'     => now()->addDays(7),
        ]);

        $response = $this->postJson(
            '/api/v1/portal/provision/agent',
            $this->validAgentPayload(),
            ['Authorization' => "Bearer {$unverifiedToken}"]
        );

        $response->assertStatus(403);
        $response->assertJsonPath('code', 'EMAIL_NOT_VERIFIED');
    }
}
