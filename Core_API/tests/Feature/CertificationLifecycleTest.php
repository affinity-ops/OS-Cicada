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

class CertificationLifecycleTest extends TestCase
{
    use DatabaseTransactions;

    private string $tenantId;
    private string $contactId;
    private string $token;
    private string $agentId;

    protected function setUp(): void
    {
        parent::setUp();

        $this->tenantId  = (string) Str::uuid();
        $this->contactId = (string) Str::uuid();
        $this->agentId   = (string) Str::uuid();

        DB::table('tenants')->insert([
            'id' => $this->tenantId, 'name' => 'Cert Test Tenant',
            'status' => 'active', 'plan' => 'starter',
            'email_verified_at' => now(), // Required for portal auth (Phase 6.6)
            'created_at' => now(), 'updated_at' => now(),
        ]);

        DB::table('contacts')->insert([
            'id' => $this->contactId, 'tenant_id' => $this->tenantId,
            'name' => 'Test Operator', 'email' => 'operator@test.com',
            'is_primary' => true, 'created_at' => now(), 'updated_at' => now(),
        ]);

        // Create a test agent in pending_review state
        DB::table('agents')->insert([
            'id'                 => $this->agentId,
            'tenant_id'          => $this->tenantId,
            'name'               => 'test-cert-agent',
            'agent_type'         => 'autonomous',
            'version'            => '1.0.0',
            'trust_tier'         => 'nominal',
            'role'               => 'autonomous',
            'approval_status'    => 'pending_review',
            'scope_entitlements' => json_encode(['proxy:chat']),
            'pub_key_hash'       => hash('sha256', $this->agentId),
            'created_at'         => now(),
            'updated_at'         => now(),
        ]);

        // Mint a portal auth token
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
    }

    private function authHeaders(): array
    {
        return ['Authorization' => "Bearer {$this->token}"];
    }

    // ── Certify Agent ──────────────────────────────────────────────

    public function test_certify_agent_sets_status_to_certified(): void
    {
        $response = $this->postJson(
            "/api/v1/portal/agents/{$this->agentId}/certify",
            ['reason' => 'Policy reviewed and approved'],
            $this->authHeaders()
        );

        $response->assertStatus(200)
            ->assertJsonPath('status', 'success')
            ->assertJsonPath('data.approval_status', 'certified');

        $this->assertDatabaseHas('agents', [
            'id'              => $this->agentId,
            'approval_status' => 'certified',
        ]);

        // certified_at should be set
        $agent = DB::table('agents')->where('id', $this->agentId)->first();
        $this->assertNotNull($agent->certified_at);
        $this->assertNotNull($agent->recertification_due_at);
    }

    public function test_certify_creates_certification_event(): void
    {
        $this->postJson(
            "/api/v1/portal/agents/{$this->agentId}/certify",
            ['reason' => 'Test certification'],
            $this->authHeaders()
        );

        $this->assertDatabaseHas('certification_events', [
            'agent_id'   => $this->agentId,
            'tenant_id'  => $this->tenantId,
            'event_type' => 'certified',
            'reason'     => 'Test certification',
        ]);
    }

    public function test_certify_agent_requires_auth(): void
    {
        $response = $this->postJson("/api/v1/portal/agents/{$this->agentId}/certify");
        $response->assertStatus(401);
    }

    public function test_cannot_certify_terminated_agent(): void
    {
        // Terminate the agent first
        DB::table('agents')->where('id', $this->agentId)->update([
            'revoked_at'      => now(),
            'approval_status' => 'terminated',
        ]);

        $response = $this->postJson(
            "/api/v1/portal/agents/{$this->agentId}/certify",
            ['reason' => 'Should fail'],
            $this->authHeaders()
        );

        $response->assertStatus(422);
    }

    // ── Suspend Agent ──────────────────────────────────────────────

    public function test_suspend_agent_sets_status_to_suspended(): void
    {
        $response = $this->postJson(
            "/api/v1/portal/agents/{$this->agentId}/suspend",
            ['reason' => 'Suspicious activity detected'],
            $this->authHeaders()
        );

        $response->assertStatus(200)
            ->assertJsonPath('status', 'success')
            ->assertJsonPath('data.approval_status', 'suspended');

        $this->assertDatabaseHas('agents', [
            'id'              => $this->agentId,
            'approval_status' => 'suspended',
        ]);
    }

    public function test_suspend_creates_certification_event(): void
    {
        $this->postJson(
            "/api/v1/portal/agents/{$this->agentId}/suspend",
            ['reason' => 'Under investigation'],
            $this->authHeaders()
        );

        $this->assertDatabaseHas('certification_events', [
            'agent_id'   => $this->agentId,
            'event_type' => 'suspended',
            'reason'     => 'Under investigation',
        ]);
    }

    // ── Terminate Agent ──────────────────────────────────────────

    public function test_terminate_agent_sets_revoked_and_terminated(): void
    {
        $response = $this->postJson(
            "/api/v1/portal/agents/{$this->agentId}/terminate",
            ['reason' => 'Permanent revocation'],
            $this->authHeaders()
        );

        $response->assertStatus(200)
            ->assertJsonPath('status', 'success')
            ->assertJsonPath('data.approval_status', 'terminated');

        $agent = DB::table('agents')->where('id', $this->agentId)->first();
        $this->assertEquals('terminated', $agent->approval_status);
        $this->assertNotNull($agent->revoked_at);
    }

    public function test_terminate_creates_certification_event(): void
    {
        $this->postJson(
            "/api/v1/portal/agents/{$this->agentId}/terminate",
            ['reason' => 'Compliance violation'],
            $this->authHeaders()
        );

        $this->assertDatabaseHas('certification_events', [
            'agent_id'   => $this->agentId,
            'event_type' => 'terminated',
            'reason'     => 'Compliance violation',
        ]);
    }

    // ── Recertify Agent ──────────────────────────────────────────

    public function test_recertify_agent_resets_certification(): void
    {
        // First certify
        $this->postJson(
            "/api/v1/portal/agents/{$this->agentId}/certify",
            ['reason' => 'Initial cert'],
            $this->authHeaders()
        );

        // Then recertify
        $response = $this->postJson(
            "/api/v1/portal/agents/{$this->agentId}/recertify",
            ['reason' => '90-day renewal'],
            $this->authHeaders()
        );

        $response->assertStatus(200)
            ->assertJsonPath('status', 'success')
            ->assertJsonPath('data.approval_status', 'certified');

        $agent = DB::table('agents')->where('id', $this->agentId)->first();
        $this->assertNotNull($agent->certified_at);
        $this->assertNotNull($agent->recertification_due_at);
    }

    public function test_cannot_recertify_terminated_agent(): void
    {
        DB::table('agents')->where('id', $this->agentId)->update([
            'revoked_at'      => now(),
            'approval_status' => 'terminated',
        ]);

        $response = $this->postJson(
            "/api/v1/portal/agents/{$this->agentId}/recertify",
            ['reason' => 'Should fail'],
            $this->authHeaders()
        );

        $response->assertStatus(422);
    }

    // ── Certification Events ─────────────────────────────────────

    public function test_certification_events_returns_audit_trail(): void
    {
        // Certify then suspend to create 2 events
        $this->postJson(
            "/api/v1/portal/agents/{$this->agentId}/certify",
            ['reason' => 'Approved'],
            $this->authHeaders()
        );
        $this->postJson(
            "/api/v1/portal/agents/{$this->agentId}/suspend",
            ['reason' => 'Under review'],
            $this->authHeaders()
        );

        $response = $this->getJson(
            "/api/v1/portal/agents/{$this->agentId}/certification-events",
            $this->authHeaders()
        );

        $response->assertStatus(200)
            ->assertJsonPath('status', 'success');

        $events = $response->json('data.events');
        $this->assertGreaterThanOrEqual(2, count($events));

        // Both event types must be present in the audit trail
        $eventTypes = array_column($events, 'event_type');
        $this->assertContains('certified', $eventTypes);
        $this->assertContains('suspended', $eventTypes);
    }

    public function test_certification_events_requires_auth(): void
    {
        $response = $this->getJson("/api/v1/portal/agents/{$this->agentId}/certification-events");
        $response->assertStatus(401);
    }

    public function test_certification_events_404_for_wrong_tenant(): void
    {
        $fakeAgentId = (string) Str::uuid();
        $response = $this->getJson(
            "/api/v1/portal/agents/{$fakeAgentId}/certification-events",
            $this->authHeaders()
        );

        $response->assertStatus(404);
    }

    // ── Full Lifecycle ───────────────────────────────────────────

    public function test_full_certification_lifecycle(): void
    {
        // Step 1: Agent starts as pending_review
        $agent = DB::table('agents')->where('id', $this->agentId)->first();
        $this->assertEquals('pending_review', $agent->approval_status);

        // Step 2: Certify
        $this->postJson(
            "/api/v1/portal/agents/{$this->agentId}/certify",
            ['reason' => 'Policy reviewed'],
            $this->authHeaders()
        )->assertStatus(200);

        $agent = DB::table('agents')->where('id', $this->agentId)->first();
        $this->assertEquals('certified', $agent->approval_status);
        $this->assertNotNull($agent->certified_at);

        // Step 3: Suspend
        $this->postJson(
            "/api/v1/portal/agents/{$this->agentId}/suspend",
            ['reason' => 'Anomaly detected'],
            $this->authHeaders()
        )->assertStatus(200);

        $agent = DB::table('agents')->where('id', $this->agentId)->first();
        $this->assertEquals('suspended', $agent->approval_status);

        // Step 4: Re-certify (from suspended)
        // First update to something recertifiable
        DB::table('agents')->where('id', $this->agentId)->update(['approval_status' => 'certified']);
        $this->postJson(
            "/api/v1/portal/agents/{$this->agentId}/recertify",
            ['reason' => 'Issue resolved'],
            $this->authHeaders()
        )->assertStatus(200);

        $agent = DB::table('agents')->where('id', $this->agentId)->first();
        $this->assertEquals('certified', $agent->approval_status);

        // Step 5: Terminate (permanent)
        $this->postJson(
            "/api/v1/portal/agents/{$this->agentId}/terminate",
            ['reason' => 'End of life'],
            $this->authHeaders()
        )->assertStatus(200);

        $agent = DB::table('agents')->where('id', $this->agentId)->first();
        $this->assertEquals('terminated', $agent->approval_status);
        $this->assertNotNull($agent->revoked_at);

        // Step 6: Verify full audit trail exists
        $events = DB::table('certification_events')
            ->where('agent_id', $this->agentId)
            ->orderBy('created_at')
            ->get();

        $this->assertGreaterThanOrEqual(4, $events->count(), 'Expected at least 4 certification events in full lifecycle');

        $eventTypes = $events->pluck('event_type')->toArray();
        $this->assertContains('certified', $eventTypes);
        $this->assertContains('suspended', $eventTypes);
        $this->assertContains('recertified', $eventTypes);
        $this->assertContains('terminated', $eventTypes);
    }
}
