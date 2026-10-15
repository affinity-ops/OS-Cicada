<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
namespace Tests\Feature;

use Tests\TestCase;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

class AuthControllerTest extends TestCase
{
    use DatabaseTransactions;

    /**
     * Seed a dev tenant + contact for tests that need an existing session.
     */
    private function seedDevUser(): array
    {
        $tenantId  = (string) Str::uuid();
        $contactId = (string) Str::uuid();

        DB::table('tenants')->insert([
            'id' => $tenantId, 'name' => 'Test Tenant', 'status' => 'active',
            'plan' => 'starter', 'created_at' => now(), 'updated_at' => now(),
        ]);

        DB::table('contacts')->insert([
            'id' => $contactId, 'tenant_id' => $tenantId, 'name' => 'Test User',
            'email' => 'test@cicada.local', 'is_primary' => true,
            'created_at' => now(), 'updated_at' => now(),
        ]);

        return ['tenant_id' => $tenantId, 'contact_id' => $contactId];
    }

    /**
     * Mint a real token for a contact, matching AuthController::mintSanctumToken logic.
     */
    private function mintToken(string $contactId, string $tenantId): string
    {
        $tokenValue = Str::random(64);
        DB::table('personal_access_tokens')->insert([
            'tokenable_type' => 'contact',
            'tokenable_id'   => $contactId,
            'name'           => "{$contactId}|{$tenantId}",
            'token'          => hash('sha256', $tokenValue),
            'abilities'      => json_encode(['portal:access']),
            'created_at'     => now(),
            'updated_at'     => now(),
            'expires_at'     => now()->addDays(7),
        ]);
        return $tokenValue;
    }

    // ── Dev Login Tests ─────────────────────────────────────────────────

    public function test_dev_login_is_blocked_outside_local_env(): void
    {
        // APP_ENV=testing (from phpunit.xml), so dev login should be blocked
        $response = $this->get('/auth/dev-login');
        $response->assertStatus(403);
    }

    public function test_dev_login_redirects_to_developer_portal(): void
    {
        // Override to local for this test
        app()['config']->set('app.env', 'local');

        $response = $this->get('/auth/dev-login');

        $response->assertStatus(302);
        $location = $response->headers->get('Location');
        $this->assertStringContainsString('/auth/callback#token=', $location);
        $this->assertStringContainsString('tenant=', $location);
        $this->assertStringContainsString('plan=enterprise', $location);
    }

    public function test_dev_login_redirects_to_gateway_portal(): void
    {
        app()['config']->set('app.env', 'local');

        $response = $this->get('/auth/dev-login?portal=gateway');

        $response->assertStatus(302);
        $location = $response->headers->get('Location');
        $this->assertStringContainsString('localhost:3002/auth/callback#token=', $location);
    }

    public function test_dev_login_seeds_tenant_and_contact(): void
    {
        app()['config']->set('app.env', 'local');

        $this->get('/auth/dev-login');

        $this->assertDatabaseHas('tenants', ['name' => 'Cicada Dev Workspace']);
        $this->assertDatabaseHas('contacts', ['email' => 'dev@cicada.local']);
    }

    public function test_dev_login_mints_sanctum_token(): void
    {
        app()['config']->set('app.env', 'local');

        $this->get('/auth/dev-login');

        $this->assertDatabaseCount('personal_access_tokens', 1);
        $token = DB::table('personal_access_tokens')->first();
        $this->assertEquals('contact', $token->tokenable_type);
        $this->assertNotNull($token->expires_at);
    }

    public function test_dev_login_is_idempotent(): void
    {
        app()['config']->set('app.env', 'local');

        $this->get('/auth/dev-login');
        $this->get('/auth/dev-login');

        $this->assertDatabaseCount('contacts', 1);
        $this->assertDatabaseCount('tenants', 1);
        // Two tokens — one per login
        $this->assertDatabaseCount('personal_access_tokens', 2);
    }

    public function test_dev_login_defaults_invalid_portal_to_developer(): void
    {
        app()['config']->set('app.env', 'local');

        $response = $this->get('/auth/dev-login?portal=evil');

        $response->assertStatus(302);
        $location = $response->headers->get('Location');
        $this->assertStringContainsString('localhost:3001', $location);
    }

    // ── Auth/Me Tests ───────────────────────────────────────────────────

    public function test_me_returns_user_with_valid_token(): void
    {
        $user = $this->seedDevUser();
        $token = $this->mintToken($user['contact_id'], $user['tenant_id']);

        $response = $this->getJson('/api/v1/auth/me', [
            'Authorization' => "Bearer {$token}",
        ]);

        // me() returns the token row data — verify it's a 200 with content
        $response->assertStatus(200);
        $data = $response->json();
        $this->assertNotEmpty($data);
    }

    public function test_me_rejects_missing_token(): void
    {
        $response = $this->getJson('/api/v1/auth/me');

        // Should be 401 or redirect depending on middleware
        $this->assertContains($response->getStatusCode(), [401, 403, 302]);
    }

    public function test_me_rejects_invalid_token(): void
    {
        $response = $this->getJson('/api/v1/auth/me', [
            'Authorization' => 'Bearer totally-fake-token-that-does-not-exist',
        ]);

        $this->assertContains($response->getStatusCode(), [401, 403, 302]);
    }

    // ── OAuth Provider Validation ───────────────────────────────────────

    public function test_redirect_rejects_invalid_provider(): void
    {
        $response = $this->get('/auth/facebook');

        // Should reject — 400, 404, or 422 are all acceptable
        $this->assertGreaterThanOrEqual(400, $response->getStatusCode());
    }
}
