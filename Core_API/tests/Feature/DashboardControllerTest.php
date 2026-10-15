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
 * Tests for the Operator Dashboard (Zone 4) endpoints.
 * These routes use operator.auth middleware which inspects OPERATOR_API_KEY.
 * When not set, it allows all requests (graceful mode).
 */
class DashboardControllerTest extends TestCase
{
    use DatabaseTransactions;

    private function seedSampleData(): void
    {
        $tenantId = (string) Str::uuid();
        $agentId  = (string) Str::uuid();

        DB::table('tenants')->insert([
            'id' => $tenantId, 'name' => 'Dashboard Test Tenant',
            'status' => 'active', 'plan' => 'starter',
            'created_at' => now(), 'updated_at' => now(),
        ]);

        DB::table('agents')->insert([
            'id' => $agentId, 'tenant_id' => $tenantId,
            'name' => 'dashboard-test-agent', 'agent_type' => 'reactive',
            'pub_key_hash' => 'test-evar-' . $agentId,
            'scope_entitlements' => json_encode(['proxy:chat']),
            'trust_tier' => 'unverified',
            'created_at' => now(),
        ]);
    }

    // ── Summary & Agent List ────────────────────────────────────────────

    public function test_dashboard_summary_returns_200(): void
    {
        $this->seedSampleData();

        $this->getJson('/api/v1/dashboard/summary')
            ->assertStatus(200);
    }

    public function test_agents_list_returns_200(): void
    {
        $this->seedSampleData();

        $this->getJson('/api/v1/agents')
            ->assertStatus(200);
    }

    // ── Biography Endpoints ─────────────────────────────────────────────

    public function test_biographies_list_returns_200(): void
    {
        $this->seedSampleData();

        $this->getJson('/api/v1/agents/biographies')
            ->assertStatus(200);
    }

    // ── Threat Signals & Compliance ─────────────────────────────────────

    public function test_threat_signals_returns_200(): void
    {
        $this->getJson('/api/v1/admin/threat-signals')
            ->assertStatus(200);
    }

    public function test_compliance_report_returns_200(): void
    {
        $this->getJson('/api/v1/admin/compliance-report')
            ->assertStatus(200);
    }

    // ── HITL Queue ──────────────────────────────────────────────────────

    public function test_hitl_queue_returns_200(): void
    {
        $this->getJson('/api/v1/admin/hitl/queue')
            ->assertStatus(200);
    }

    // ── Logs & Registry ─────────────────────────────────────────────────

    public function test_logs_returns_200(): void
    {
        $this->getJson('/api/v1/logs')
            ->assertStatus(200);
    }

    public function test_registry_returns_200(): void
    {
        $this->getJson('/api/v1/registry')
            ->assertStatus(200);
    }

    // ── Admin Audit Logs ────────────────────────────────────────────────

    public function test_audit_logs_returns_200(): void
    {
        $this->getJson('/api/v1/admin/audit-logs')
            ->assertStatus(200);
    }

    // ── CRM Endpoints ──────────────────────────────────────────────────

    public function test_crm_companies_returns_200(): void
    {
        $this->seedSampleData();

        $this->getJson('/api/v1/crm/companies')
            ->assertStatus(200);
    }

    // ── Alert Rules ────────────────────────────────────────────────────

    public function test_alert_rules_returns_200(): void
    {
        $this->getJson('/api/v1/admin/alert-rules')
            ->assertStatus(200);
    }

    // ── Gateways ───────────────────────────────────────────────────────

    public function test_gateways_returns_200(): void
    {
        $this->getJson('/api/v1/admin/gateways')
            ->assertStatus(200);
    }

    // ── Gap 9: Embedding Model Drift and Retraining ─────────────────────────

    public function test_flag_false_positive_returns_200_and_updates_db(): void
    {
        $traceId = (string) Str::uuid();
        DB::table('action_ledger')->insert([
            'trace_id' => $traceId,
            'agent_id' => (string) Str::uuid(),
            'status' => 'blocked',
            'action_type' => 'proxy:transact',
            'is_false_positive' => false,
            'created_at' => now()
        ]);

        $this->postJson("/api/v1/logs/{$traceId}/false-positive")
            ->assertStatus(200);

        $record = DB::table('action_ledger')->where('trace_id', $traceId)->first();
        $this->assertTrue((bool)$record->is_false_positive);
    }

    public function test_export_retraining_dataset_returns_jsonl(): void
    {
        $this->get('/api/v1/admin/retraining-dataset')
            ->assertStatus(200)
            ->assertHeader('Content-Type', 'application/jsonl');
    }
}
