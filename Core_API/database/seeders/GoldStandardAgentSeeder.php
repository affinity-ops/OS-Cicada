<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
namespace Database\Seeders;

use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

/**
 * GoldStandardAgentSeeder — Creates a fully populated "Gold Standard" agent
 * with every governance field set to realistic production values.
 *
 * This seeder demonstrates the full data model and ensures the Biography page
 * renders every section with real data instead of null dashes.
 *
 * Run with: php artisan db:seed --class=GoldStandardAgentSeeder
 */
class GoldStandardAgentSeeder extends Seeder
{
    public function run(): void
    {
        $now = now();

        // ─── 1. Tenant ─────────────────────────────────────────────────────
        $tenantId = (string) Str::uuid();
        DB::table('tenants')->insert([
            'id'            => $tenantId,
            'name'          => 'Nexus Dynamics Ltd',
            'status'        => 'active',
            'plan'          => 'enterprise',
            'company_email' => 'security@nexusdynamics.io',
            'created_at'    => $now->copy()->subMonths(3),
        ]);

        // ─── 2. Gold Standard Agent ────────────────────────────────────────
        $agentId = (string) Str::uuid();
        DB::table('agents')->insert([
            'id'                => $agentId,
            'tenant_id'         => $tenantId,
            'pub_key_hash'      => 'ed25519:' . hash('sha256', 'nexus-ci-orchestrator-prod-key-2026'),

            // Identity
            'name'              => 'CI Orchestrator',
            'description'       => 'Production CI/CD pipeline orchestrator agent. Manages build triggers, deployment approvals, and cross-service integration testing via Slack, Jira, and GitHub.',
            'agent_type'        => 'autonomous',
            'role'              => 'orchestrator',
            'version'           => '2.4.1',
            'scope_entitlements'=> json_encode(['proxy:write', 'proxy:read', 'tool:invoke', 'deploy:staging']),

            // Trust & certification
            'trust_tier'         => 'elevated',
            'certified_at'       => $now->copy()->subDays(14),
            'recertification_due_at' => $now->copy()->addMonths(2),

            // Ownership
            'owner_name'        => 'Sarah Chen',
            'owner_email'       => 'sarah.chen@nexusdynamics.io',
            'business_unit'     => 'Platform Engineering',

            // Governance — Purpose & Criticality
            'declared_purpose'  => 'Automate CI/CD pipeline operations including build triggering, test orchestration, deployment gating, and cross-team notification for the Nexus Platform monorepo.',
            'criticality_level' => 'high',
            'data_classification' => 'confidential',

            // Governance — The Leash
            'expected_velocity'  => 60,       // 60 calls per hour
            'monthly_budget_usd' => 50.00,
            'cost_center'        => 'ENG-042',

            // Governance — Compliance
            'regulatory_frameworks'          => json_encode(['SOC2', 'ISO27001']),
            'registration_purpose_statement' => 'This agent is registered under the Nexus Dynamics Automated Operations Policy (AOP-2026-04). It is authorised to perform CI/CD actions on behalf of the Platform Engineering team. All actions are subject to immutable audit logging and swarm verification. Human-in-the-loop approval is required for production deployments.',
            'potential_impact' => json_encode([
                'data_access'    => 'Read/write to GitHub repos, Jira projects, Slack channels',
                'blast_radius'   => 'Can trigger deployments to staging; production requires HITL',
                'financial_risk' => 'API call costs capped at $50/month via Cicada budget enforcement',
                'compliance_note'=> 'All actions logged to immutable ledger; SOC2 evidence chain maintained',
            ]),

            // Governance — Custom guardrails
            'custom_guardrails' => json_encode([
                'No production deployments without HITL approval',
                'Block any API call containing PII keywords: SSN, credit_card, password',
                'Rate limit: max 5 deployment triggers per hour',
                'Restricted hours: no deployments between 22:00-06:00 UTC',
            ]),

            // HITL
            'hitl_enabled'     => true,
            'hitl_webhook_url' => 'https://hooks.nexusdynamics.io/cicada/hitl/ci-orchestrator',

            // Failure behaviour
            'failure_scope'    => json_encode(['retry_with_backoff', 'notify_owner', 'log_to_ledger']),

            // Timestamps
            'created_at'       => $now->copy()->subMonths(2),
            'updated_at'       => $now->copy()->subDays(3),
            'governance_updated_at' => $now->copy()->subDays(3),
        ]);

        // ─── 3. Tool Access Manifest ───────────────────────────────────────
        $tools = [
            [
                'agent_id'         => $agentId,
                'tool_id'          => 'github:actions:trigger',
                'tool_name'        => 'GitHub Actions — Trigger Workflow',
                'tool_description' => 'Triggers CI/CD workflow runs on the Nexus Platform monorepo. Scoped to staging and integration branches only.',
                'is_active'        => true,
                'created_at'       => $now,
            ],
            [
                'agent_id'         => $agentId,
                'tool_id'          => 'jira:issues:transition',
                'tool_name'        => 'Jira — Transition Issues',
                'tool_description' => 'Moves Jira tickets between workflow states (e.g., In Progress → Code Review → QA). Cannot create or delete issues.',
                'is_active'        => true,
                'created_at'       => $now,
            ],
            [
                'agent_id'         => $agentId,
                'tool_id'          => 'slack:messages:post',
                'tool_name'        => 'Slack — Post Messages',
                'tool_description' => 'Posts deployment notifications and build status updates to #eng-deployments and #ci-alerts channels. Cannot read messages or access DMs.',
                'is_active'        => true,
                'created_at'       => $now,
            ],
        ];
        foreach ($tools as $tool) {
            DB::table('agent_tools')->insert($tool);
        }

        // ─── 4. Resource Policies (FGA) ────────────────────────────────────
        $policies = [
            [
                'agent_id'         => $agentId,
                'resource_pattern' => 'https://api.github.com/repos/nexus-dynamics/*/actions/workflows/*/dispatches',
                'allowed_methods'  => json_encode(['POST']),
                'active'           => true,
                'created_at'       => $now,
            ],
            [
                'agent_id'         => $agentId,
                'resource_pattern' => 'https://nexusdynamics.atlassian.net/rest/api/3/issue/*/transitions',
                'allowed_methods'  => json_encode(['GET', 'POST']),
                'active'           => true,
                'created_at'       => $now,
            ],
            [
                'agent_id'         => $agentId,
                'resource_pattern' => 'https://slack.com/api/chat.postMessage',
                'allowed_methods'  => json_encode(['POST']),
                'active'           => true,
                'created_at'       => $now,
            ],
            [
                'agent_id'         => $agentId,
                'resource_pattern' => 'https://api.stripe.com/*',
                'allowed_methods'  => json_encode([]),  // Explicitly blocked
                'active'           => true,
                'created_at'       => $now,
            ],
        ];
        foreach ($policies as $policy) {
            DB::table('agent_resource_policies')->insert($policy);
        }

        // ─── 5. Action Ledger — Realistic telemetry ───────────────────────
        $actionTypes = ['proxy_call', 'tool_invoke', 'deploy_trigger', 'status_check', 'notification_send'];
        $statuses    = ['approved', 'approved', 'approved', 'approved', 'blocked', 'approved', 'shadow_sandbox'];
        $targets     = [
            'https://api.github.com/repos/nexus-dynamics/platform/actions/workflows/ci.yml/dispatches',
            'https://nexusdynamics.atlassian.net/rest/api/3/issue/PLAT-1842/transitions',
            'https://slack.com/api/chat.postMessage',
            'https://api.github.com/repos/nexus-dynamics/platform/actions/runs/12345',
            'https://nexusdynamics.atlassian.net/rest/api/3/search',
        ];

        for ($i = 0; $i < 80; $i++) {
            $ledgerData = [
                'tenant_id'              => $tenantId,
                'agent_id'               => $agentId,
                'action_type'            => $actionTypes[array_rand($actionTypes)],
                'payload_hash'           => hash('sha256', "action-{$i}-" . microtime()),
                'target_api'             => $targets[array_rand($targets)],
                'status'                 => $statuses[array_rand($statuses)],
                'swarm_confidence_score' => round(mt_rand(55, 98) / 100, 4),
                'created_at'             => $now->copy()->subHours(mt_rand(1, 720)),
            ];

            DB::table('action_ledger')->insert($ledgerData);
        }

        // Add specific HITL events
        $hitlTypes = ['hitl_pending', 'hitl_approved', 'hitl_approved', 'hitl_rejected', 'hitl_timeout'];
        foreach ($hitlTypes as $idx => $type) {
            DB::table('action_ledger')->insert([
                'tenant_id'              => $tenantId,
                'agent_id'               => $agentId,
                'action_type'            => $type,
                'payload_hash'           => hash('sha256', "hitl-{$idx}-" . microtime()),
                'target_api'             => 'cicada://hitl/deploy-approval',
                'status'                 => $type === 'hitl_approved' ? 'approved' : ($type === 'hitl_rejected' ? 'blocked' : 'pending_swarm'),
                'swarm_confidence_score' => round(mt_rand(60, 95) / 100, 4),
                'created_at'             => $now->copy()->subHours(mt_rand(1, 168)),
            ]);
        }

        // Add a canary event
        DB::table('action_ledger')->insert([
            'tenant_id'              => $tenantId,
            'agent_id'               => $agentId,
            'action_type'            => 'canary_issued',
            'payload_hash'           => hash('sha256', 'canary-issue-' . microtime()),
            'target_api'             => 'cicada://canary/token-issuance',
            'status'                 => 'approved',
            'swarm_confidence_score' => 0.92,
            'created_at'             => $now->copy()->subDays(7),
        ]);

        // Add a certification event
        DB::table('action_ledger')->insert([
            'tenant_id'              => $tenantId,
            'agent_id'               => $agentId,
            'action_type'            => 'agent_certified',
            'payload_hash'           => hash('sha256', 'certification-' . microtime()),
            'target_api'             => 'cicada://swarm/certification',
            'status'                 => 'approved',
            'swarm_confidence_score' => 0.91,
            'created_at'             => $now->copy()->subDays(14),
        ]);

        $this->command->info("✓ Seeded Gold Standard agent: CI Orchestrator ({$agentId})");
        $this->command->info("  Tenant: Nexus Dynamics Ltd ({$tenantId})");
        $this->command->info("  Tools: 3 | Resource Policies: 4 | Ledger Events: 88");
    }
}
