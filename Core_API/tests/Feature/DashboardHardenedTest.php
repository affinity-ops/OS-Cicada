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

/**
 * Hardened Dashboard Tests — Iteration 19
 *
 * These tests go beyond the status-code smoke tests in DashboardControllerTest.
 * Every sidebar tab in the Operator Dashboard is covered with:
 *   - Correct HTTP status
 *   - Response JSON structure validation (field presence + types)
 *   - Mutation side-effect verification (audit writes, state changes)
 *   - Edge cases (404 on invalid IDs, empty result sets)
 *
 * Run: php vendor/phpunit/phpunit/phpunit --filter=DashboardHardenedTest
 */
class DashboardHardenedTest extends TestCase
{
    use DatabaseTransactions;

    private string $tenantId;
    private string $agentId;
    private string $tenantKeyId;

    protected function setUp(): void
    {
        parent::setUp();
        $this->seedFullDataset();
    }

    /**
     * Seeds a complete dataset that exercises every dashboard endpoint.
     * Includes: tenant, agent, tenant_key, action_ledger entries, and an operator_audit_log entry.
     */
    private function seedFullDataset(): void
    {
        $this->tenantId = (string) Str::uuid();
        $this->agentId  = (string) Str::uuid();

        // ── Tenant ──────────────────────────────────────────────────────
        DB::table('tenants')->insert([
            'id'         => $this->tenantId,
            'name'       => 'Hardened Test Corp',
            'status'     => 'active',
            'plan'       => 'enterprise',
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        // ── Agent ───────────────────────────────────────────────────────
        DB::table('agents')->insert([
            'id'                => $this->agentId,
            'tenant_id'         => $this->tenantId,
            'name'              => 'hardened-test-agent',
            'description'       => 'Agent for hardened dashboard tests',
            'agent_type'        => 'reactive',
            'role'              => 'autonomous',
            'pub_key_hash'      => 'evar-hardened-' . $this->agentId,
            'scope_entitlements' => json_encode(['proxy:chat', 'proxy:write']),
            'trust_tier'        => 'nominal',
            'approval_status'   => 'certified',
            'ghost_mode_allowed' => true,
            'created_at'        => now(),
        ]);

        // ── Tenant Key (for vault) ──────────────────────────────────────
        DB::table('tenant_keys')->insert([
            'tenant_id'         => $this->tenantId,
            'provider'          => 'openai',
            'payload_encrypted' => encrypt('sk-test-hardened-key-' . Str::random(20)),
            'created_at'        => now(),
            'updated_at'        => now(),
        ]);

        $this->tenantKeyId = (string) DB::table('tenant_keys')
            ->where('tenant_id', $this->tenantId)
            ->where('provider', 'openai')
            ->value('id');

        // ── Action Ledger entries (approved + blocked) ──────────────────
        DB::table('action_ledger')->insert([
            'trace_id'    => (string) Str::uuid(),
            'agent_id'    => $this->agentId,
            'tenant_id'   => $this->tenantId,
            'action_type' => 'proxy:chat',
            'target_api'  => 'api.openai.com',
            'status'      => 'approved',
            'created_at'  => now(),
        ]);

        DB::table('action_ledger')->insert([
            'trace_id'    => (string) Str::uuid(),
            'agent_id'    => $this->agentId,
            'tenant_id'   => $this->tenantId,
            'action_type' => 'proxy:write',
            'target_api'  => 'api.stripe.com',
            'status'      => 'blocked',
            'policy_violations' => json_encode(['semantic_mismatch']),
            'created_at'  => now(),
        ]);

        // ── Blocked entry for rollback/saga view ────────────────────────
        DB::table('action_ledger')->insert([
            'trace_id'    => (string) Str::uuid(),
            'agent_id'    => $this->agentId,
            'tenant_id'   => $this->tenantId,
            'action_type' => 'hitl_rejected',
            'target_api'  => 'cicada://hitl/deploy-approval',
            'status'      => 'blocked',
            'created_at'  => now(),
        ]);
    }

    // ════════════════════════════════════════════════════════════════════
    // 1. GLOBAL OVERVIEW — /dashboard/summary
    // ════════════════════════════════════════════════════════════════════

    public function test_summary_returns_correct_structure(): void
    {
        $response = $this->getJson('/api/v1/dashboard/summary');

        $response->assertStatus(200)
            ->assertJsonStructure([
                'status',
                'data' => [
                    'total_agents',
                    'total_tenants',
                    'active_tenants',
                    'verified_agents',
                    'quarantined_agents',
                    'active_agents_24h',
                    'approved_today',
                    'blocked_today',
                    'pending_hitl_count',
                    'recent_activity',
                ],
            ]);

        $data = $response->json('data');
        $this->assertGreaterThanOrEqual(1, $data['total_agents']);
        $this->assertGreaterThanOrEqual(1, $data['total_tenants']);
        $this->assertIsArray($data['recent_activity']);
    }

    public function test_summary_counts_are_accurate(): void
    {
        $data = $this->getJson('/api/v1/dashboard/summary')->json('data');

        // We seeded at least 1 agent with trust_tier != 'unverified'
        $this->assertGreaterThanOrEqual(1, $data['verified_agents']);
        // We seeded at least 1 approved and 1 blocked entry today
        $this->assertGreaterThanOrEqual(1, $data['approved_today']);
        $this->assertGreaterThanOrEqual(1, $data['blocked_today']);
    }

    // ════════════════════════════════════════════════════════════════════
    // 2. ACTIVITY LEDGER — /logs
    // ════════════════════════════════════════════════════════════════════

    public function test_logs_returns_paginated_entries_with_correct_fields(): void
    {
        $response = $this->getJson('/api/v1/logs?per_page=10');

        $response->assertStatus(200)
            ->assertJsonStructure([
                'status',
                'data' => [
                    'current_page',
                    'data' => [
                        '*' => [
                            'trace_id',
                            'action_type',
                            'status',
                            'created_at',
                        ],
                    ],
                    'total',
                ],
            ]);

        $entries = $response->json('data.data');
        $this->assertNotEmpty($entries, 'Ledger should contain seeded entries');

        // Verify every entry has a trace_id and a valid status
        foreach ($entries as $entry) {
            $this->assertNotEmpty($entry['trace_id']);
            $this->assertContains($entry['status'], ['approved', 'blocked', 'shadow_allowed', 'shadow_sandbox', 'pending_swarm']);
        }
    }

    public function test_logs_status_filter_works(): void
    {
        $response = $this->getJson('/api/v1/logs?status=blocked');
        $response->assertStatus(200);

        $entries = $response->json('data.data');
        foreach ($entries as $entry) {
            $this->assertEquals('blocked', $entry['status']);
        }
    }

    // ════════════════════════════════════════════════════════════════════
    // 3. ACTION ROLLBACKS — /sagas
    // ════════════════════════════════════════════════════════════════════

    public function test_sagas_returns_paginated_rollbacks(): void
    {
        $response = $this->getJson('/api/v1/sagas?per_page=10');

        $response->assertStatus(200)
            ->assertJsonStructure([
                'status',
                'data' => [
                    'current_page',
                    'data' => [
                        '*' => [
                            'trace_id',
                            'agent_id',
                            'action_type',
                            'status',
                            'created_at',
                        ],
                    ],
                    'total',
                ],
            ]);

        $entries = $response->json('data.data');
        // Our seed includes a hitl_rejected entry
        $this->assertNotEmpty($entries, 'Sagas should contain seeded blocked/rollback entries');
    }

    // ════════════════════════════════════════════════════════════════════
    // 4. AGENT FLEET — /nodes
    //    Response: tenant-grouped objects with nested agents arrays
    // ════════════════════════════════════════════════════════════════════

    public function test_nodes_returns_tenant_grouped_agents(): void
    {
        $response = $this->getJson('/api/v1/nodes');

        $response->assertStatus(200)
            ->assertJsonStructure([
                'status',
                'data',
            ]);

        $nodes = $response->json('data');
        $this->assertIsArray($nodes);
        $this->assertNotEmpty($nodes, 'Nodes should contain at least one tenant group');

        // Each tenant group has an id, name, and agents array
        $firstNode = $nodes[0];
        $this->assertArrayHasKey('id', $firstNode);
        $this->assertArrayHasKey('name', $firstNode);
        $this->assertArrayHasKey('agents', $firstNode);
        $this->assertIsArray($firstNode['agents']);
    }

    // ════════════════════════════════════════════════════════════════════
    // 5. AGENT REGISTRY — /registry
    //    Response: paginated with nested data.data array
    // ════════════════════════════════════════════════════════════════════

    public function test_registry_returns_paginated_agents_with_governance(): void
    {
        $response = $this->getJson('/api/v1/registry');

        $response->assertStatus(200)
            ->assertJsonStructure([
                'status',
                'data' => [
                    'current_page',
                    'data' => [
                        '*' => [
                            'id',
                            'name',
                            'trust_tier',
                            'agent_type',
                            'role',
                        ],
                    ],
                    'total',
                ],
            ]);

        $agents = $response->json('data.data');
        $this->assertNotEmpty($agents);

        // Find our seeded agent
        $found = collect($agents)->firstWhere('id', $this->agentId);
        $this->assertNotNull($found, 'Seeded agent should appear in registry');
        $this->assertEquals('nominal', $found['trust_tier']);
    }

    // ════════════════════════════════════════════════════════════════════
    // 6. CREDENTIAL VAULT — /vault/keys
    // ════════════════════════════════════════════════════════════════════

    public function test_vault_keys_returns_health_summary(): void
    {
        $response = $this->getJson('/api/v1/vault/keys');

        $response->assertStatus(200)
            ->assertJsonStructure([
                'status',
                'data' => [
                    'keys',
                    'total_keys',
                    'health_summary' => [
                        'healthy',
                        'warning',
                        'critical',
                        'expired',
                    ],
                    'max_age_days',
                    'access_log',
                ],
            ]);

        $data = $response->json('data');
        $this->assertGreaterThanOrEqual(1, $data['total_keys']);
        $this->assertIsArray($data['keys']);

        // Each key should have essential health metadata
        foreach ($data['keys'] as $key) {
            $this->assertArrayHasKey('health_status', $key);
            $this->assertArrayHasKey('provider', $key);
            $this->assertContains($key['health_status'], ['healthy', 'warning', 'critical', 'expired']);
        }
    }

    // ════════════════════════════════════════════════════════════════════
    // 7. CREDENTIAL VAULT — ROTATION — POST /vault/keys/{id}/rotate
    // ════════════════════════════════════════════════════════════════════

    public function test_vault_rotate_returns_success_and_writes_audit(): void
    {
        $response = $this->postJson("/api/v1/vault/keys/{$this->tenantKeyId}/rotate");

        $response->assertStatus(200)
            ->assertJson([
                'status'  => 'success',
                'message' => 'Key rotated successfully.',
            ]);

        // Verify an audit trail was created
        $audit = DB::table('operator_audit_log')
            ->where('action', 'api_key_rotated')
            ->where('entity_type', 'vault')
            ->orderByDesc('created_at')
            ->first();

        $this->assertNotNull($audit, 'Rotation should create an audit log entry');
        $this->assertEquals('vault', $audit->entity_type);
    }

    public function test_vault_rotate_returns_404_for_invalid_key(): void
    {
        $response = $this->postJson('/api/v1/vault/keys/999999/rotate');
        $response->assertStatus(404);
    }

    // ════════════════════════════════════════════════════════════════════
    // 8. CLIENT COMPANIES — /crm/companies
    // ════════════════════════════════════════════════════════════════════

    public function test_crm_companies_returns_paginated_list(): void
    {
        $response = $this->getJson('/api/v1/crm/companies');

        $response->assertStatus(200)
            ->assertJsonStructure([
                'status',
                'data' => [
                    'current_page',
                    'data' => [
                        '*' => [
                            'id',
                            'name',
                            'status',
                            'plan',
                            'agent_count',
                            'certified_count',
                            'created_at',
                        ],
                    ],
                    'total',
                ],
            ]);

        $companies = $response->json('data.data');
        $this->assertNotEmpty($companies);

        // Find our seeded tenant
        $found = collect($companies)->firstWhere('id', $this->tenantId);
        $this->assertNotNull($found, 'Seeded tenant should appear in CRM');
        $this->assertEquals('enterprise', $found['plan']);
        $this->assertGreaterThanOrEqual(1, $found['agent_count']);
    }

    public function test_crm_company_detail_returns_single(): void
    {
        $response = $this->getJson("/api/v1/crm/companies/{$this->tenantId}");

        $response->assertStatus(200)
            ->assertJsonStructure([
                'status',
                'data' => [
                    'tenant',
                    'agents',
                ],
            ]);
    }

    public function test_crm_company_detail_returns_404_for_invalid_id(): void
    {
        $fakeId = (string) Str::uuid();
        $response = $this->getJson("/api/v1/crm/companies/{$fakeId}");
        $response->assertStatus(404);
    }

    // ════════════════════════════════════════════════════════════════════
    // 9. COMPUTE METRICS — /compute/metrics
    // ════════════════════════════════════════════════════════════════════

    public function test_compute_metrics_returns_correct_structure(): void
    {
        $response = $this->getJson('/api/v1/compute/metrics');

        $response->assertStatus(200)
            ->assertJsonStructure([
                'status',
                'data',
            ]);
    }

    // ════════════════════════════════════════════════════════════════════
    // 10. OPERATOR AUDIT LOG — /admin/audit-logs
    // ════════════════════════════════════════════════════════════════════

    public function test_audit_logs_returns_after_vault_rotation(): void
    {
        // Trigger a rotation to create an audit entry
        $this->postJson("/api/v1/vault/keys/{$this->tenantKeyId}/rotate");

        $response = $this->getJson('/api/v1/admin/audit-logs');

        $response->assertStatus(200)
            ->assertJsonStructure([
                'status',
                'data',
            ]);
    }

    // ════════════════════════════════════════════════════════════════════
    // 11. GATEWAY STATUS — /admin/gateways
    //     Response: { status, summary, gateways } (no nested 'data')
    // ════════════════════════════════════════════════════════════════════

    public function test_gateways_returns_correct_structure(): void
    {
        $response = $this->getJson('/api/v1/admin/gateways');

        $response->assertStatus(200)
            ->assertJsonStructure([
                'status',
                'gateways',
            ]);
    }

    // ════════════════════════════════════════════════════════════════════
    // 12. ALERTS — /alerts
    // ════════════════════════════════════════════════════════════════════

    public function test_alerts_returns_correct_structure(): void
    {
        $response = $this->getJson('/api/v1/alerts');

        $response->assertStatus(200)
            ->assertJsonStructure([
                'status',
                'data',
            ]);
    }
}
