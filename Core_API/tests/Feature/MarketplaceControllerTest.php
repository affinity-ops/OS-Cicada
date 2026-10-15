<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
namespace Tests\Feature;

use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Tests\TestCase;

class MarketplaceControllerTest extends TestCase
{
    use DatabaseTransactions;

    private function seedTenant()
    {
        $tenantId = (string) Str::uuid();
        DB::table('tenants')->insert([
            'id' => $tenantId, 'name' => 'Marketplace Tester',
            'status' => 'active', 'plan' => 'starter',
            'created_at' => now(), 'updated_at' => now(),
        ]);
        return $tenantId;
    }

    private function getAuthHeaders($tenantId)
    {
        $contactId = (string) Str::uuid();
        
        // Ensure Contact exists and is linked to the tenant
        DB::table('contacts')->insertOrIgnore([
            'id' => $contactId,
            'tenant_id' => $tenantId,
            'name' => 'Marketplace Tester',
            'email' => 'tester@marketplace.cicada.com',
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $tokenValue = Str::random(64);
        DB::table('personal_access_tokens')->insert([
            'tokenable_type' => 'contact',
            'tokenable_id'   => $contactId,
            'name'           => "{$contactId}|{$tenantId}",
            'token'          => hash('sha256', $tokenValue),
            'abilities'      => json_encode(['portal:access']),
            'created_at'     => now(),
            'updated_at'     => now(),
            'last_used_at'   => now(),
            'expires_at'     => now()->addDays(7),
        ]);
        return ['Authorization' => "Bearer {$tokenValue}"];
    }

    public function test_marketplace_list_returns_templates()
    {
        $tenantId = $this->seedTenant();
        
        // Seed a verified template
        DB::table('agent_templates')->insert([
            'id' => (string) Str::uuid(),
            'name' => 'Official Data Analyst',
            'description' => 'A verified analytics agent.',
            'is_verified' => true,
            'status' => 'published',
            'created_at' => now(),
            'updated_at' => now()
        ]);
        
        // Seed a draft template (should not be returned)
        DB::table('agent_templates')->insert([
            'id' => (string) Str::uuid(),
            'name' => 'Draft Agent',
            'description' => 'Still working on it.',
            'is_verified' => false,
            'status' => 'draft',
            'created_at' => now(),
            'updated_at' => now()
        ]);

        $headers = $this->getAuthHeaders($tenantId);
        $response = $this->getJson('/api/v1/portal/marketplace/templates', $headers);
        $response->assertStatus(200);
        $data = $response->json('data.templates');
        
        $this->assertCount(1, $data);
        $this->assertEquals('Official Data Analyst', $data[0]['name']);
    }

    public function test_marketplace_publish_creates_template()
    {
        $tenantId = $this->seedTenant();
        $agentId = (string) Str::uuid();

        DB::table('agents')->insert([
            'id' => $agentId,
            'tenant_id' => $tenantId,
            'name' => 'Custom Support Bot',
            'description' => 'My secret sauce support bot.',
            'agent_type' => 'reactive',
            'role' => 'autonomous',
            'trust_tier' => 'unverified',
            'approval_status' => 'certified',
            'pub_key_hash' => 'hash-123',
            'created_at' => now()
        ]);

        $headers = $this->getAuthHeaders($tenantId);
        $response = $this->postJson('/api/v1/portal/marketplace/publish', [
            'agent_id' => $agentId,
            'name' => 'Community Support Bot',
            'description' => 'A community contributed support bot.'
        ], $headers);

        $response->assertStatus(201);
        $templateId = $response->json('template_id');

        $template = DB::table('agent_templates')->where('id', $templateId)->first();
        $this->assertNotNull($template);
        $this->assertEquals('Community Support Bot', $template->name);
        $this->assertEquals($tenantId, $template->author_tenant_id);
    }

    public function test_marketplace_import_creates_draft_agent()
    {
        $tenantId = $this->seedTenant();
        $templateId = (string) Str::uuid();

        DB::table('agent_templates')->insert([
            'id' => $templateId,
            'name' => 'Official Data Analyst',
            'description' => 'A verified analytics agent.',
            'is_verified' => true,
            'status' => 'published',
            'created_at' => now(),
            'updated_at' => now()
        ]);

        $headers = $this->getAuthHeaders($tenantId);
        $response = $this->postJson("/api/v1/portal/marketplace/templates/{$templateId}/import", [], $headers);

        $response->assertStatus(201);
        $newAgentId = $response->json('agent_id');

        $agent = DB::table('agents')->where('id', $newAgentId)->first();
        $this->assertNotNull($agent);
        $this->assertEquals($tenantId, $agent->tenant_id);
        $this->assertEquals('Imported: Official Data Analyst', $agent->name);
        $this->assertEquals('pending_review', $agent->approval_status);
        $this->assertEquals('unverified', $agent->trust_tier);
    }
}
