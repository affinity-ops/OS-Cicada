<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
namespace Database\Seeders;

use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Carbon\Carbon;

/**
 * FullPlatformSeeder — Comprehensive seed for every table in the Cicada schema.
 *
 * Creates a realistic, fully cross-referenced dataset that exercises:
 *   - All agent types, trust tiers, roles, EVAR lifecycle states
 *   - Full CIBA flow: authorization requests, decision nonces, hold payloads, quorum votes
 *   - Mobile device pairings with PQC key material placeholders
 *   - Credential rotation events and certification lifecycle
 *   - Operator audit trail, alert rules, retention policies
 *   - Platform governance policies with OPA rule configs
 *   - Gateway fleet across 8 countries
 *   - 350+ action ledger entries with realistic telemetry
 *
 * Run with: php artisan db:seed --class=FullPlatformSeeder
 */
class FullPlatformSeeder extends Seeder
{
    public function run(): void
    {
        $now = Carbon::now();

        // ═════════════════════════════════════════════════════════════════════
        // 1. TENANTS (10 companies across industries and geographies)
        // ═════════════════════════════════════════════════════════════════════
        $tenants = [
            ['id' => (string) Str::uuid(), 'name' => 'Nexus Dynamics Ltd',       'plan' => 'enterprise',    'status' => 'active',     'company_email' => 'ops@nexusdynamics.io',            'created_at' => $now->copy()->subMonths(6)],
            ['id' => (string) Str::uuid(), 'name' => 'Meridian Health Systems',  'plan' => 'enterprise',    'status' => 'active',     'company_email' => 'infosec@meridianhealth.com',      'created_at' => $now->copy()->subMonths(4)],
            ['id' => (string) Str::uuid(), 'name' => 'Solstice Financial AG',    'plan' => 'enterprise',    'status' => 'active',     'company_email' => 'ai-ops@solstice-fin.ch',          'created_at' => $now->copy()->subMonths(5)],
            ['id' => (string) Str::uuid(), 'name' => 'Kurogane Robotics K.K.',   'plan' => 'enterprise',    'status' => 'active',     'company_email' => 'admin@kurogane.co.jp',            'created_at' => $now->copy()->subMonths(3)],
            ['id' => (string) Str::uuid(), 'name' => 'Aether Intelligence',      'plan' => 'professional',  'status' => 'active',     'company_email' => 'devops@aetherintel.ai',           'created_at' => $now->copy()->subMonths(2)],
            ['id' => (string) Str::uuid(), 'name' => 'Pinnacle Defence Group',   'plan' => 'enterprise',    'status' => 'active',     'company_email' => 'security@pinnacledefence.gov.au', 'created_at' => $now->copy()->subMonths(7)],
            ['id' => (string) Str::uuid(), 'name' => 'CloudBridge SaaS Inc',     'plan' => 'professional',  'status' => 'active',     'company_email' => 'ops@cloudbridge.io',              'created_at' => $now->copy()->subMonths(1)],
            ['id' => (string) Str::uuid(), 'name' => 'Étoile Logistics SA',      'plan' => 'starter',       'status' => 'active',     'company_email' => 'tech@etoile-logistics.fr',        'created_at' => $now->copy()->subMonths(1)],
            ['id' => (string) Str::uuid(), 'name' => 'Maple Fintech Corp',       'plan' => 'professional',  'status' => 'active',     'company_email' => 'platform@maplefintech.ca',        'created_at' => $now->copy()->subWeeks(3)],
            ['id' => (string) Str::uuid(), 'name' => 'Emerald Systems plc',      'plan' => 'enterprise',    'status' => 'active',     'company_email' => 'ciso@emeraldsystems.ie',          'created_at' => $now->copy()->subMonths(8)],
        ];

        foreach ($tenants as $t) {
            if (!DB::table('tenants')->where('company_email', $t['company_email'])->exists()) {
                DB::table('tenants')->insert($t);
            }
        }

        // Resolve actual tenant IDs
        $tenantMap = [];
        foreach ($tenants as $t) {
            $row = DB::table('tenants')->where('company_email', $t['company_email'])->first();
            if ($row) $tenantMap[$t['name']] = $row->id;
        }

        $this->command->info("✓ Tenants: " . count($tenantMap));

        // ═════════════════════════════════════════════════════════════════════
        // 2. TENANT KEYS (encrypted provider API keys per tenant)
        // ═════════════════════════════════════════════════════════════════════
        $providers = ['openai', 'anthropic', 'google', 'azure_openai', 'cohere'];
        foreach ($tenantMap as $name => $tid) {
            $providerSubset = array_slice($providers, 0, mt_rand(1, count($providers)));
            foreach ($providerSubset as $provider) {
                if (!DB::table('tenant_keys')->where('tenant_id', $tid)->where('provider', $provider)->exists()) {
                    DB::table('tenant_keys')->insert([
                        'tenant_id'         => $tid,
                        'provider'          => $provider,
                        'payload_encrypted' => 'enc:aes-256-gcm:' . bin2hex(random_bytes(32)),
                        'created_at'        => $now->copy()->subDays(mt_rand(1, 60)),
                    ]);
                }
            }
        }
        $this->command->info("✓ Tenant Keys seeded");

        // ═════════════════════════════════════════════════════════════════════
        // 3. CONTACTS & OAUTH IDENTITIES (CRM data)
        // ═════════════════════════════════════════════════════════════════════
        $contactData = [
            ['tenant' => 'Nexus Dynamics Ltd',       'name' => 'Sarah Chen',         'email' => 'sarah.chen@nexusdynamics.io',       'role' => 'CTO',                  'is_primary' => true],
            ['tenant' => 'Nexus Dynamics Ltd',       'name' => 'James Okoye',        'email' => 'james.okoye@nexusdynamics.io',      'role' => 'Platform Lead',        'is_primary' => false],
            ['tenant' => 'Meridian Health Systems',  'name' => 'Dr. Priya Nair',     'email' => 'priya.nair@meridianhealth.com',     'role' => 'CISO',                 'is_primary' => true],
            ['tenant' => 'Solstice Financial AG',    'name' => 'Lukas Bauer',        'email' => 'lukas.bauer@solstice-fin.ch',       'role' => 'Head of AI Ops',       'is_primary' => true],
            ['tenant' => 'Kurogane Robotics K.K.',   'name' => 'Yuki Tanaka',        'email' => 'yuki.tanaka@kurogane.co.jp',        'role' => 'Engineering Director', 'is_primary' => true],
            ['tenant' => 'Aether Intelligence',      'name' => 'Marcus Rivera',      'email' => 'marcus@aetherintel.ai',             'role' => 'Founder / CTO',        'is_primary' => true],
            ['tenant' => 'Pinnacle Defence Group',   'name' => 'Col. Kate Morrison', 'email' => 'k.morrison@pinnacledefence.gov.au', 'role' => 'Security Director',    'is_primary' => true],
            ['tenant' => 'CloudBridge SaaS Inc',     'name' => 'Zain Ahmed',         'email' => 'zain@cloudbridge.io',               'role' => 'VP Engineering',       'is_primary' => true],
            ['tenant' => 'Étoile Logistics SA',      'name' => 'Camille Dumont',     'email' => 'camille@etoile-logistics.fr',       'role' => 'Tech Lead',            'is_primary' => true],
            ['tenant' => 'Maple Fintech Corp',       'name' => 'Ava Thompson',       'email' => 'ava@maplefintech.ca',               'role' => 'Platform Architect',   'is_primary' => true],
            ['tenant' => 'Emerald Systems plc',      'name' => 'Ciarán Kelly',       'email' => 'ciaran@emeraldsystems.ie',          'role' => 'CISO',                 'is_primary' => true],
        ];

        $contactIds = [];
        foreach ($contactData as $c) {
            $tid = $tenantMap[$c['tenant']] ?? null;
            if (!$tid) continue;
            if (DB::table('contacts')->where('email', $c['email'])->exists()) {
                $contactIds[$c['email']] = DB::table('contacts')->where('email', $c['email'])->value('id');
                continue;
            }
            $cid = (string) Str::uuid();
            DB::table('contacts')->insert([
                'id'         => $cid,
                'tenant_id'  => $tid,
                'name'       => $c['name'],
                'email'      => $c['email'],
                'role'       => $c['role'],
                'is_primary' => $c['is_primary'],
                'created_at' => $now->copy()->subDays(mt_rand(10, 180)),
                'updated_at' => $now->copy()->subDays(mt_rand(0, 10)),
            ]);
            $contactIds[$c['email']] = $cid;

            // OAuth identity for some contacts
            if (mt_rand(0, 1)) {
                DB::table('oauth_identities')->insert([
                    'id'              => (string) Str::uuid(),
                    'contact_id'      => $cid,
                    'provider'        => ['github', 'google', 'azure_ad'][mt_rand(0, 2)],
                    'provider_id'     => (string) mt_rand(100000, 999999),
                    'provider_email'  => $c['email'],
                    'created_at'      => $now->copy()->subDays(mt_rand(10, 90)),
                ]);
            }
        }
        $this->command->info("✓ Contacts: " . count($contactIds) . " (with OAuth identities)");

        // ═════════════════════════════════════════════════════════════════════
        // 4. AGENTS (38 agents across all trust tiers, roles, and configs)
        // ═════════════════════════════════════════════════════════════════════
        $agentDefs = [
            // Nexus Dynamics — 12 agents (enterprise, mature deployment)
            ['tenant' => 'Nexus Dynamics Ltd', 'name' => 'CI Orchestrator',           'type' => 'autonomous',  'role' => 'orchestrator',  'trust' => 'elevated',    'hitl' => true,  'destructive' => false, 'velocity' => 60,  'budget' => 50.00,  'criticality' => 'high',      'classification' => 'confidential', 'purpose' => 'CI/CD pipeline orchestrator. Manages build triggers, deployment approvals, and cross-service integration testing.',                                         'frameworks' => ['SOC2', 'ISO27001']],
            ['tenant' => 'Nexus Dynamics Ltd', 'name' => 'Data Pipeline Manager',     'type' => 'autonomous',  'role' => 'executor',      'trust' => 'elevated',    'hitl' => true,  'destructive' => true,  'velocity' => 120, 'budget' => 200.00, 'criticality' => 'critical',  'classification' => 'restricted',   'purpose' => 'ETL pipeline orchestration for customer data warehousing. Handles PII-adjacent data transformations.',                                                        'frameworks' => ['SOC2', 'GDPR', 'ISO27001']],
            ['tenant' => 'Nexus Dynamics Ltd', 'name' => 'Slack Notifier',            'type' => 'reactive',    'role' => 'autonomous',    'trust' => 'nominal',    'hitl' => false, 'destructive' => false, 'velocity' => 200, 'budget' => 5.00,   'criticality' => 'low',       'classification' => 'internal',     'purpose' => 'Posts deployment notifications and status updates to engineering Slack channels.',                                                                            'frameworks' => ['SOC2']],
            ['tenant' => 'Nexus Dynamics Ltd', 'name' => 'Cost Optimizer',            'type' => 'autonomous',  'role' => 'observer',      'trust' => 'elevated',    'hitl' => false, 'destructive' => false, 'velocity' => 30,  'budget' => 15.00,  'criticality' => 'medium',    'classification' => 'internal',     'purpose' => 'Monitors cloud spend and suggests rightsizing. Read-only access to billing APIs.',                                                                           'frameworks' => ['SOC2']],
            ['tenant' => 'Nexus Dynamics Ltd', 'name' => 'Security Scanner',          'type' => 'autonomous',  'role' => 'observer',      'trust' => 'nominal',    'hitl' => false, 'destructive' => false, 'velocity' => 15,  'budget' => 10.00,  'criticality' => 'high',      'classification' => 'confidential', 'purpose' => 'Continuous vulnerability scanning of deployed services. Generates CVE reports and opens Jira tickets for critical findings.',                                   'frameworks' => ['SOC2', 'ISO27001', 'PCI-DSS']],
            ['tenant' => 'Nexus Dynamics Ltd', 'name' => 'Incident Responder',        'type' => 'autonomous',  'role' => 'executor',      'trust' => 'elevated',    'hitl' => true,  'destructive' => true,  'velocity' => 10,  'budget' => 25.00,  'criticality' => 'critical',  'classification' => 'restricted',   'purpose' => 'Automated incident response: can isolate services, rollback deployments, and page on-call engineers.',                                                       'frameworks' => ['SOC2', 'ISO27001']],
            ['tenant' => 'Nexus Dynamics Ltd', 'name' => 'Log Aggregator',            'type' => 'reactive',    'role' => 'autonomous',    'trust' => 'nominal',    'hitl' => false, 'destructive' => false, 'velocity' => 500, 'budget' => 30.00,  'criticality' => 'medium',    'classification' => 'internal',     'purpose' => 'Collects and indexes application logs from all microservices. Feeds into the observability pipeline.',                                                        'frameworks' => ['SOC2']],
            ['tenant' => 'Nexus Dynamics Ltd', 'name' => 'Customer Onboarding Bot',   'type' => 'autonomous',  'role' => 'executor',      'trust' => 'nominal',    'hitl' => true,  'destructive' => false, 'velocity' => 20,  'budget' => 40.00,  'criticality' => 'high',      'classification' => 'confidential', 'purpose' => 'Guides new enterprise customers through onboarding. Creates accounts, provisions resources, sends welcome emails.',                                          'frameworks' => ['SOC2', 'GDPR']],
            ['tenant' => 'Nexus Dynamics Ltd', 'name' => 'Compliance Auditor',        'type' => 'autonomous',  'role' => 'observer',      'trust' => 'elevated',    'hitl' => false, 'destructive' => false, 'velocity' => 5,   'budget' => 8.00,   'criticality' => 'high',      'classification' => 'confidential', 'purpose' => 'Weekly audit of access controls, key rotations, and policy compliance. Generates SOC2 evidence reports.',                                                     'frameworks' => ['SOC2', 'ISO27001', 'HIPAA']],
            ['tenant' => 'Nexus Dynamics Ltd', 'name' => 'API Gateway Proxy',         'type' => 'reactive',    'role' => 'autonomous',    'trust' => 'elevated',    'hitl' => false, 'destructive' => false, 'velocity' => 1000,'budget' => 75.00,  'criticality' => 'critical',  'classification' => 'confidential', 'purpose' => 'High-throughput API proxy. Routes, rate-limits, and logs all inter-service communication.',                                                                   'frameworks' => ['SOC2', 'PCI-DSS']],
            ['tenant' => 'Nexus Dynamics Ltd', 'name' => 'ML Model Deployer',         'type' => 'autonomous',  'role' => 'executor',      'trust' => 'nominal',    'hitl' => true,  'destructive' => true,  'velocity' => 8,   'budget' => 120.00, 'criticality' => 'high',      'classification' => 'restricted',   'purpose' => 'Deploys trained ML models to inference endpoints. Can swap production model versions.',                                                                      'frameworks' => ['SOC2', 'EU-AI-Act']],
            ['tenant' => 'Nexus Dynamics Ltd', 'name' => 'Doc Generator',             'type' => 'reactive',    'role' => 'autonomous',    'trust' => 'unverified',  'hitl' => false, 'destructive' => false, 'velocity' => 50,  'budget' => 3.00,   'criticality' => 'low',       'classification' => 'public',       'purpose' => 'Auto-generates API documentation from OpenAPI specs.',                                                                                                       'frameworks' => []],

            // Meridian Health — 8 agents (healthcare, strict compliance)
            ['tenant' => 'Meridian Health Systems', 'name' => 'Patient Record Accessor',  'type' => 'autonomous',  'role' => 'executor',   'trust' => 'elevated',    'hitl' => true,  'destructive' => false, 'velocity' => 40,  'budget' => 60.00,  'criticality' => 'critical',  'classification' => 'restricted',   'purpose' => 'Retrieves and cross-references patient records for clinical decision support. HIPAA-governed.',                                                              'frameworks' => ['HIPAA', 'ISO27001', 'NHS-DSPT']],
            ['tenant' => 'Meridian Health Systems', 'name' => 'Appointment Scheduler',    'type' => 'reactive',    'role' => 'autonomous', 'trust' => 'nominal',    'hitl' => false, 'destructive' => false, 'velocity' => 100, 'budget' => 15.00,  'criticality' => 'medium',    'classification' => 'confidential', 'purpose' => 'Manages clinic appointment booking via NHS Spine integration.',                                                                                               'frameworks' => ['HIPAA', 'NHS-DSPT']],
            ['tenant' => 'Meridian Health Systems', 'name' => 'Radiology AI Triage',      'type' => 'autonomous',  'role' => 'observer',   'trust' => 'elevated',    'hitl' => true,  'destructive' => false, 'velocity' => 20,  'budget' => 200.00, 'criticality' => 'critical',  'classification' => 'restricted',   'purpose' => 'Prioritises radiology scans using ML. All recommendations require clinician confirmation.',                                                                  'frameworks' => ['HIPAA', 'EU-AI-Act', 'FDA-SaMD']],
            ['tenant' => 'Meridian Health Systems', 'name' => 'Pharmacy Stock Agent',     'type' => 'autonomous',  'role' => 'executor',   'trust' => 'nominal',    'hitl' => true,  'destructive' => false, 'velocity' => 25,  'budget' => 30.00,  'criticality' => 'high',      'classification' => 'confidential', 'purpose' => 'Monitors pharmacy inventory levels and triggers reorder workflows.',                                                                                          'frameworks' => ['HIPAA']],
            ['tenant' => 'Meridian Health Systems', 'name' => 'Clinical Notes Summarizer','type' => 'autonomous',  'role' => 'observer',   'trust' => 'nominal',    'hitl' => false, 'destructive' => false, 'velocity' => 50,  'budget' => 90.00,  'criticality' => 'high',      'classification' => 'restricted',   'purpose' => 'Summarises clinical notes for handover briefings. Never modifies source records.',                                                                           'frameworks' => ['HIPAA', 'NHS-DSPT']],
            ['tenant' => 'Meridian Health Systems', 'name' => 'Bed Management Optimizer', 'type' => 'autonomous',  'role' => 'executor',   'trust' => 'nominal',    'hitl' => true,  'destructive' => false, 'velocity' => 15,  'budget' => 12.00,  'criticality' => 'medium',    'classification' => 'internal',     'purpose' => 'Optimises hospital bed allocation based on predicted admissions and discharges.',                                                                             'frameworks' => ['NHS-DSPT']],
            ['tenant' => 'Meridian Health Systems', 'name' => 'Lab Results Notifier',     'type' => 'reactive',    'role' => 'autonomous', 'trust' => 'nominal',    'hitl' => false, 'destructive' => false, 'velocity' => 80,  'budget' => 5.00,   'criticality' => 'high',      'classification' => 'confidential', 'purpose' => 'Delivers lab results to clinicians via secure messaging. Cannot modify results.',                                                                             'frameworks' => ['HIPAA']],
            ['tenant' => 'Meridian Health Systems', 'name' => 'Consent Manager',          'type' => 'autonomous',  'role' => 'executor',   'trust' => 'elevated',    'hitl' => true,  'destructive' => false, 'velocity' => 10,  'budget' => 8.00,   'criticality' => 'critical',  'classification' => 'restricted',   'purpose' => 'Manages patient consent records for data sharing and clinical trials.',                                                                                      'frameworks' => ['HIPAA', 'GDPR', 'ISO27001']],

            // Solstice Financial — 6 agents (fintech, PCI/DORA)
            ['tenant' => 'Solstice Financial AG', 'name' => 'Trade Execution Monitor',  'type' => 'autonomous',  'role' => 'observer',   'trust' => 'elevated',    'hitl' => false, 'destructive' => false, 'velocity' => 500, 'budget' => 300.00, 'criticality' => 'critical',  'classification' => 'restricted',   'purpose' => 'Real-time monitoring of automated trade executions. Flags anomalous patterns for compliance review.',                                                        'frameworks' => ['PCI-DSS', 'DORA', 'MiFID-II']],
            ['tenant' => 'Solstice Financial AG', 'name' => 'KYC Document Processor',   'type' => 'autonomous',  'role' => 'executor',   'trust' => 'elevated',    'hitl' => true,  'destructive' => false, 'velocity' => 30,  'budget' => 80.00,  'criticality' => 'critical',  'classification' => 'restricted',   'purpose' => 'Processes Know Your Customer documents using OCR and ML verification.',                                                                                      'frameworks' => ['PCI-DSS', 'GDPR', 'AML-5AMLD']],
            ['tenant' => 'Solstice Financial AG', 'name' => 'Fraud Detection Engine',   'type' => 'autonomous',  'role' => 'observer',   'trust' => 'elevated',    'hitl' => true,  'destructive' => true,  'velocity' => 200, 'budget' => 150.00, 'criticality' => 'critical',  'classification' => 'restricted',   'purpose' => 'Real-time transaction fraud scoring. Can freeze accounts on confirmed fraud.',                                                                               'frameworks' => ['PCI-DSS', 'DORA']],
            ['tenant' => 'Solstice Financial AG', 'name' => 'Regulatory Reporter',      'type' => 'autonomous',  'role' => 'executor',   'trust' => 'nominal',    'hitl' => true,  'destructive' => false, 'velocity' => 5,   'budget' => 20.00,  'criticality' => 'high',      'classification' => 'confidential', 'purpose' => 'Generates and submits regulatory reports to FINMA and ECB.',                                                                                                  'frameworks' => ['DORA', 'MiFID-II']],
            ['tenant' => 'Solstice Financial AG', 'name' => 'Portfolio Rebalancer',     'type' => 'autonomous',  'role' => 'executor',   'trust' => 'elevated',    'hitl' => true,  'destructive' => true,  'velocity' => 15,  'budget' => 500.00, 'criticality' => 'critical',  'classification' => 'restricted',   'purpose' => 'Automatically rebalances client portfolios based on risk models. Requires HITL for trades above CHF 100k.',                                                  'frameworks' => ['PCI-DSS', 'MiFID-II']],
            ['tenant' => 'Solstice Financial AG', 'name' => 'Market Data Fetcher',      'type' => 'reactive',    'role' => 'autonomous', 'trust' => 'nominal',    'hitl' => false, 'destructive' => false, 'velocity' => 1000,'budget' => 40.00,  'criticality' => 'medium',    'classification' => 'internal',     'purpose' => 'Fetches real-time market data from Bloomberg and Reuters feeds.',                                                                                             'frameworks' => []],

            // Kurogane Robotics — 4 agents
            ['tenant' => 'Kurogane Robotics K.K.', 'name' => 'Assembly Line Controller', 'type' => 'autonomous', 'role' => 'executor',   'trust' => 'elevated',    'hitl' => true,  'destructive' => true,  'velocity' => 60,  'budget' => 0.00,   'criticality' => 'critical',  'classification' => 'restricted',   'purpose' => 'Controls robotic assembly line sequences. Emergency stop requires HITL override.',                                                                           'frameworks' => ['ISO27001', 'IEC-62443']],
            ['tenant' => 'Kurogane Robotics K.K.', 'name' => 'Vision QA Inspector',     'type' => 'autonomous',  'role' => 'observer',   'trust' => 'nominal',    'hitl' => false, 'destructive' => false, 'velocity' => 200, 'budget' => 100.00, 'criticality' => 'high',      'classification' => 'internal',     'purpose' => 'Machine vision quality assurance on manufactured components.',                                                                                                'frameworks' => ['ISO27001']],
            ['tenant' => 'Kurogane Robotics K.K.', 'name' => 'Predictive Maintenance',  'type' => 'autonomous',  'role' => 'observer',   'trust' => 'nominal',    'hitl' => false, 'destructive' => false, 'velocity' => 10,  'budget' => 30.00,  'criticality' => 'medium',    'classification' => 'internal',     'purpose' => 'Predicts equipment failures from sensor telemetry. Generates maintenance work orders.',                                                                      'frameworks' => []],
            ['tenant' => 'Kurogane Robotics K.K.', 'name' => 'Safety Compliance Agent',  'type' => 'autonomous', 'role' => 'observer',   'trust' => 'elevated',    'hitl' => true,  'destructive' => false, 'velocity' => 5,   'budget' => 0.00,   'criticality' => 'critical',  'classification' => 'confidential', 'purpose' => 'Audits safety compliance across all factory operations. Can halt production lines.',                                                                          'frameworks' => ['IEC-62443', 'ISO-45001']],

            // Remaining tenants — 2 agents each (8 total)
            ['tenant' => 'Aether Intelligence',    'name' => 'Research Assistant',      'type' => 'autonomous',  'role' => 'executor',   'trust' => 'nominal',    'hitl' => false, 'destructive' => false, 'velocity' => 100, 'budget' => 80.00,  'criticality' => 'medium',    'classification' => 'internal',     'purpose' => 'Assists ML researchers with literature review, experiment tracking, and hyperparameter search.',                                                             'frameworks' => []],
            ['tenant' => 'Aether Intelligence',    'name' => 'Model Training Scheduler','type' => 'autonomous',  'role' => 'executor',   'trust' => 'nominal',    'hitl' => false, 'destructive' => false, 'velocity' => 20,  'budget' => 500.00, 'criticality' => 'high',      'classification' => 'confidential', 'purpose' => 'Schedules GPU clusters for model training jobs. Manages spot instance bidding.',                                                                              'frameworks' => []],
            ['tenant' => 'Pinnacle Defence Group', 'name' => 'Threat Intel Aggregator', 'type' => 'autonomous',  'role' => 'observer',   'trust' => 'elevated',    'hitl' => false, 'destructive' => false, 'velocity' => 50,  'budget' => 0.00,   'criticality' => 'critical',  'classification' => 'restricted',   'purpose' => 'Aggregates threat intelligence from OSINT and classified feeds. All output is air-gapped.',                                                                  'frameworks' => ['IRAP', 'ISM', 'ISO27001']],
            ['tenant' => 'Pinnacle Defence Group', 'name' => 'Access Review Bot',       'type' => 'autonomous',  'role' => 'observer',   'trust' => 'elevated',    'hitl' => true,  'destructive' => false, 'velocity' => 5,   'budget' => 0.00,   'criticality' => 'critical',  'classification' => 'restricted',   'purpose' => 'Quarterly access reviews for classified systems. Revokes stale access automatically.',                                                                       'frameworks' => ['IRAP', 'ISM']],
            ['tenant' => 'CloudBridge SaaS Inc',   'name' => 'Tenant Provisioner',      'type' => 'reactive',    'role' => 'executor',   'trust' => 'nominal',    'hitl' => false, 'destructive' => false, 'velocity' => 10,  'budget' => 5.00,   'criticality' => 'medium',    'classification' => 'internal',     'purpose' => 'Provisions new SaaS tenant environments: database, storage, DNS records.',                                                                                   'frameworks' => ['SOC2']],
            ['tenant' => 'CloudBridge SaaS Inc',   'name' => 'Usage Analytics Agent',   'type' => 'autonomous',  'role' => 'observer',   'trust' => 'nominal',    'hitl' => false, 'destructive' => false, 'velocity' => 30,  'budget' => 10.00,  'criticality' => 'low',       'classification' => 'internal',     'purpose' => 'Tracks tenant usage patterns for billing and capacity planning.',                                                                                             'frameworks' => []],
            ['tenant' => 'Maple Fintech Corp',     'name' => 'Transaction Processor',   'type' => 'autonomous',  'role' => 'executor',   'trust' => 'elevated',    'hitl' => true,  'destructive' => true,  'velocity' => 300, 'budget' => 200.00, 'criticality' => 'critical',  'classification' => 'restricted',   'purpose' => 'Processes interbank transactions via SWIFT network. Requires HITL for transfers above CAD 50k.',                                                             'frameworks' => ['PCI-DSS', 'OSFI-B13']],
            ['tenant' => 'Maple Fintech Corp',     'name' => 'AML Screening Agent',     'type' => 'autonomous',  'role' => 'observer',   'trust' => 'elevated',    'hitl' => true,  'destructive' => false, 'velocity' => 100, 'budget' => 50.00,  'criticality' => 'critical',  'classification' => 'restricted',   'purpose' => 'Anti-Money Laundering screening against FINTRAC watchlists.',                                                                                                'frameworks' => ['PCI-DSS', 'OSFI-B13', 'AML-PCMLTFA']],
        ];

        $agentIds = [];
        $agentTenantMap = [];
        $evarStatuses = ['active', 'active', 'active', 'pending_rotation', 'expired'];
        $approvalStatuses = ['approved', 'approved', 'approved', 'approved', 'pending_review', 'approved'];

        foreach ($agentDefs as $idx => $a) {
            $tid = $tenantMap[$a['tenant']] ?? null;
            if (!$tid) continue;

            $agentId = (string) Str::uuid();
            $keyHash = 'ed25519:' . hash('sha256', $a['tenant'] . ':' . $a['name'] . ':seed-key-2026');

            if (DB::table('agents')->where('pub_key_hash', $keyHash)->exists()) {
                $existing = DB::table('agents')->where('pub_key_hash', $keyHash)->first();
                $agentIds[] = $existing->id;
                $agentTenantMap[$existing->id] = $tid;
                continue;
            }

            $evarStatus = $evarStatuses[array_rand($evarStatuses)];
            $evarIssuedAt = $now->copy()->subDays(mt_rand(10, 90));

            // Map role names to the valid DB enum: orchestrator, sub_agent, peer, autonomous, tool_executor
            $roleMap = [
                'orchestrator'  => 'orchestrator',
                'executor'      => 'tool_executor',
                'observer'      => 'autonomous',
                'autonomous'    => 'autonomous',
                'sub_agent'     => 'sub_agent',
                'peer'          => 'peer',
                'tool_executor' => 'tool_executor',
            ];
            $dbRole = $roleMap[$a['role']] ?? 'autonomous';

            DB::table('agents')->insert([
                'id'                            => $agentId,
                'tenant_id'                     => $tid,
                'pub_key_hash'                  => $keyHash,
                'name'                          => $a['name'],
                'description'                   => $a['purpose'],
                'agent_type'                    => $a['type'],
                'role'                          => $dbRole,
                'version'                       => '2.' . mt_rand(0, 9) . '.' . mt_rand(0, 9),
                'scope_entitlements'            => json_encode(array_slice(['proxy:write', 'proxy:read', 'tool:invoke', 'deploy:staging', 'deploy:production', 'data:read', 'data:write', 'admin:audit'], 0, mt_rand(2, 5))),
                'trust_tier'                    => $a['trust'],
                'hitl_enabled'                  => $a['hitl'],
                'hitl_webhook_url'              => $a['hitl'] ? 'https://hooks.' . explode('@', $contactData[$idx % count($contactData)]['email'])[1] . '/cicada/hitl/' . Str::slug($a['name']) : null,
                'hitl_timeout_hours'            => $a['hitl'] ? [4, 8, 12, 24][mt_rand(0, 3)] : 24,
                'hitl_resume_webhook_url'       => $a['hitl'] ? 'https://hooks.' . explode('@', $contactData[$idx % count($contactData)]['email'])[1] . '/cicada/resume/' . Str::slug($a['name']) : null,
                'destructive_capability'        => $a['destructive'],
                'owner_name'                    => $contactData[$idx % count($contactData)]['name'],
                'owner_email'                   => $contactData[$idx % count($contactData)]['email'],
                'business_unit'                 => ['Platform Engineering', 'Data Science', 'Infrastructure', 'Security', 'Clinical Systems', 'Trading Desk', 'Manufacturing', 'Customer Success'][mt_rand(0, 7)],
                'declared_purpose'              => $a['purpose'],
                'criticality_level'             => $a['criticality'],
                'data_classification'           => $a['classification'],
                'expected_velocity'             => $a['velocity'],
                'monthly_budget_usd'            => $a['budget'],
                'cost_center'                   => strtoupper(substr($a['tenant'], 0, 3)) . '-' . str_pad(mt_rand(1, 999), 3, '0', STR_PAD_LEFT),
                'regulatory_frameworks'         => json_encode($a['frameworks']),
                'registration_purpose_statement'=> 'This agent is registered under the ' . $a['tenant'] . ' Automated Operations Policy. All actions subject to immutable audit logging, swarm verification, and governance enforcement.',
                'potential_impact'              => json_encode([
                    'data_access'    => $a['classification'] === 'restricted' ? 'Access to PII/sensitive data via scoped API' : 'Internal operational data only',
                    'blast_radius'   => $a['destructive'] ? 'Can modify production state — HITL required' : 'Read-only or scoped write access',
                    'financial_risk' => $a['budget'] > 0 ? 'API costs capped at $' . number_format($a['budget'], 2) . '/month' : 'No external API costs',
                ]),
                'custom_guardrails'             => json_encode([
                    $a['destructive'] ? 'No destructive actions without HITL approval' : 'Standard rate limiting applies',
                    'Block any API call containing PII keywords: SSN, credit_card, password',
                    'Velocity cap: max ' . $a['velocity'] . ' calls per hour',
                ]),
                'failure_scope'                 => json_encode(['retry_with_backoff', 'notify_owner', 'log_to_ledger']),
                'certified_at'                  => $now->copy()->subDays(mt_rand(7, 60)),
                'recertification_due_at'        => $now->copy()->addDays(mt_rand(30, 90)),
                'governance_updated_at'         => $now->copy()->subDays(mt_rand(1, 30)),
                'data_residency_region'         => ['us-east-1', 'eu-west-1', 'eu-central-1', 'ap-northeast-1', 'ap-southeast-2', 'ca-central-1'][mt_rand(0, 5)],
                'external_model_id'             => ['gpt-4o', 'claude-3.5-sonnet', 'gemini-2.0-flash', 'llama-3.1-70b', null][mt_rand(0, 4)],
                'swarm_confidence_score'        => round(mt_rand(7500, 9800) / 10000, 4),
                'swarm_verdict'                 => ['pass', 'pass', 'pass', 'warn', 'pass'][mt_rand(0, 4)],
                'swarm_reasons'                 => json_encode(['Identity verified', 'Scope within bounds', 'No anomalous patterns']),
                'verified_at'                   => $now->copy()->subDays(mt_rand(7, 60)),
                'ghost_mode_allowed'            => mt_rand(0, 10) < 2,
                'evar_issued_at'                => $evarIssuedAt,
                'evar_expires_at'               => $evarIssuedAt->copy()->addDays(90),
                'evar_rotation_count'           => mt_rand(0, 8),
                'evar_last_rotated_at'          => $now->copy()->subDays(mt_rand(1, 30)),
                'evar_rotation_status'          => $evarStatus,
                'approval_status'               => $approvalStatuses[array_rand($approvalStatuses)],
                'created_at'                    => $now->copy()->subDays(mt_rand(30, 180)),
                'updated_at'                    => $now->copy()->subDays(mt_rand(0, 7)),
            ]);

            $agentIds[] = $agentId;
            $agentTenantMap[$agentId] = $tid;
        }

        $this->command->info("✓ Agents: " . count($agentIds));

        // ═════════════════════════════════════════════════════════════════════
        // 5. AGENT TOOLS (3-5 tools per agent)
        // ═════════════════════════════════════════════════════════════════════
        $toolTemplates = [
            ['id' => 'github:actions:trigger',    'name' => 'GitHub Actions — Trigger Workflow',  'desc' => 'Triggers CI/CD workflow runs.'],
            ['id' => 'github:repos:read',         'name' => 'GitHub — Read Repository',           'desc' => 'Read access to repository files and metadata.'],
            ['id' => 'jira:issues:transition',     'name' => 'Jira — Transition Issues',           'desc' => 'Moves tickets between workflow states.'],
            ['id' => 'jira:issues:create',         'name' => 'Jira — Create Issues',               'desc' => 'Creates new issues in configured projects.'],
            ['id' => 'slack:messages:post',         'name' => 'Slack — Post Messages',              'desc' => 'Posts messages to designated channels.'],
            ['id' => 'stripe:billing:read',         'name' => 'Stripe — Read Billing',              'desc' => 'Read-only access to billing and subscription data.'],
            ['id' => 'aws:ec2:describe',            'name' => 'AWS EC2 — Describe Instances',       'desc' => 'Lists and describes EC2 instances.'],
            ['id' => 'aws:s3:read',                 'name' => 'AWS S3 — Read Objects',              'desc' => 'Read access to S3 buckets and objects.'],
            ['id' => 'datadog:metrics:query',       'name' => 'Datadog — Query Metrics',            'desc' => 'Queries observability metrics and dashboards.'],
            ['id' => 'pagerduty:incidents:trigger', 'name' => 'PagerDuty — Trigger Incident',       'desc' => 'Creates incidents and pages on-call engineers.'],
            ['id' => 'db:postgres:query',           'name' => 'PostgreSQL — Execute Query',         'desc' => 'Executes read-only SQL queries against configured databases.'],
            ['id' => 'email:send',                  'name' => 'Email — Send Notification',          'desc' => 'Sends templated email notifications.'],
        ];

        $toolCount = 0;
        foreach ($agentIds as $agentId) {
            $numTools = mt_rand(2, 5);
            $selectedTools = array_rand($toolTemplates, min($numTools, count($toolTemplates)));
            if (!is_array($selectedTools)) $selectedTools = [$selectedTools];

            foreach ($selectedTools as $tIdx) {
                $tool = $toolTemplates[$tIdx];
                DB::table('agent_tools')->insert([
                    'agent_id'         => $agentId,
                    'tool_id'          => $tool['id'],
                    'tool_name'        => $tool['name'],
                    'tool_description' => $tool['desc'],
                    'is_active'        => mt_rand(0, 10) > 1,
                    'created_at'       => $now->copy()->subDays(mt_rand(5, 60)),
                ]);
                $toolCount++;
            }
        }
        $this->command->info("✓ Agent Tools: $toolCount");

        // ═════════════════════════════════════════════════════════════════════
        // 6. AGENT RESOURCE POLICIES (FGA — 2-4 per agent)
        // ═════════════════════════════════════════════════════════════════════
        $resourcePatterns = [
            ['pattern' => 'https://api.github.com/repos/*/actions/workflows/*/dispatches', 'methods' => ['POST']],
            ['pattern' => 'https://*.atlassian.net/rest/api/3/issue/*/transitions',         'methods' => ['GET', 'POST']],
            ['pattern' => 'https://slack.com/api/chat.postMessage',                         'methods' => ['POST']],
            ['pattern' => 'https://api.stripe.com/*',                                       'methods' => []],
            ['pattern' => 'https://*.s3.amazonaws.com/*',                                   'methods' => ['GET']],
            ['pattern' => 'https://api.datadog.com/api/v1/query',                           'methods' => ['GET']],
        ];

        $policyCount = 0;
        foreach ($agentIds as $agentId) {
            $numPolicies = mt_rand(2, 4);
            $selected = array_rand($resourcePatterns, min($numPolicies, count($resourcePatterns)));
            if (!is_array($selected)) $selected = [$selected];

            foreach ($selected as $pIdx) {
                $rp = $resourcePatterns[$pIdx];
                DB::table('agent_resource_policies')->insert([
                    'agent_id'          => $agentId,
                    'resource_pattern'  => $rp['pattern'],
                    'allowed_methods'   => json_encode($rp['methods']),
                    'active'            => true,
                    'created_at'        => $now->copy()->subDays(mt_rand(5, 90)),
                ]);
                $policyCount++;
            }
        }
        $this->command->info("✓ Resource Policies: $policyCount");

        // ═════════════════════════════════════════════════════════════════════
        // 7. CERTIFICATION EVENTS (lifecycle per agent)
        // ═════════════════════════════════════════════════════════════════════
        $certCount = 0;
        foreach ($agentIds as $agentId) {
            $tid = $agentTenantMap[$agentId] ?? null;
            if (!$tid) continue;

            $events = ['registered', 'swarm_verified', 'certified'];
            if (mt_rand(0, 3) === 0) $events[] = 'recertification_due';

            foreach ($events as $eventIdx => $eventType) {
                DB::table('certification_events')->insert([
                    'id'           => (string) Str::uuid(),
                    'agent_id'     => $agentId,
                    'tenant_id'    => $tid,
                    'event_type'   => $eventType,
                    'performed_by' => ['system', 'swarm_engine', 'operator'][mt_rand(0, 2)],
                    'reason'       => "Lifecycle event: $eventType",
                    'metadata'     => json_encode(['source' => 'seeder', 'note' => "Certification lifecycle: $eventType"]),
                    'created_at'   => $now->copy()->subDays(mt_rand(7, 60))->addHours($eventIdx),
                ]);
                $certCount++;
            }
        }
        $this->command->info("✓ Certification Events: $certCount");

        // ═════════════════════════════════════════════════════════════════════
        // 8. CREDENTIAL ROTATION EVENTS
        // ═════════════════════════════════════════════════════════════════════
        $rotCount = 0;
        foreach (array_slice($agentIds, 0, 20) as $agentId) {
            $tid = $agentTenantMap[$agentId] ?? null;
            if (!$tid) continue;

            $numRotations = mt_rand(1, 4);
            for ($r = 0; $r < $numRotations; $r++) {
                DB::table('credential_rotation_events')->insert([
                    'id'                  => (string) Str::uuid(),
                    'agent_id'            => $agentId,
                    'tenant_id'           => $tid,
                    'event_type'          => ['rotation', 'manual_rotation', 'notification', 'expiry', 'suspension'][mt_rand(0, 4)],
                    'old_evar_hash'       => hash('sha256', "old-evar-$agentId-$r"),
                    'new_evar_hash'       => hash('sha256', "new-evar-$agentId-$r"),
                    'rotation_reason'     => ['Scheduled 90-day rotation', 'Key compromise suspected', 'Manual operator request', 'Trust tier upgrade'][mt_rand(0, 3)],
                    'notification_tier'   => ['info', 'warn', 'critical'][mt_rand(0, 2)],
                    'notification_target' => ['dashboard', 'email', 'webhook'][mt_rand(0, 2)],
                    'initiated_by'        => ['system', 'operator', 'policy_engine'][mt_rand(0, 2)],
                    'ip_address'          => mt_rand(1, 254) . '.' . mt_rand(1, 254) . '.' . mt_rand(1, 254) . '.' . mt_rand(1, 254),
                    'created_at'          => $now->copy()->subDays(mt_rand(1, 60)),
                ]);
                $rotCount++;
            }
        }
        $this->command->info("✓ Credential Rotation Events: $rotCount");

        // ═════════════════════════════════════════════════════════════════════
        // 9. GATEWAY INSTANCES (global fleet — 12 nodes)
        // ═════════════════════════════════════════════════════════════════════
        $gateways = [
            ['gw_id' => 'sentry-nexus-us-east-1',          'tenant' => 'Nexus Dynamics Ltd',       'country' => 'US', 'region' => 'us-east-1',       'ip' => '54.221.118.42',   'agents' => 12, 'calls' => 4280,  'blocked' => 31,  'tls' => true, 'mtls' => true,  'canary' => 4,  'version' => '1.9.2', 'hours' => 1],
            ['gw_id' => 'sentry-nexus-us-west-2',          'tenant' => 'Nexus Dynamics Ltd',       'country' => 'US', 'region' => 'us-west-2',       'ip' => '35.160.72.19',    'agents' => 3,  'calls' => 890,   'blocked' => 2,   'tls' => true, 'mtls' => true,  'canary' => 1,  'version' => '1.9.2', 'hours' => 2],
            ['gw_id' => 'sentry-meridian-eu-west-2',       'tenant' => 'Meridian Health Systems',  'country' => 'UK', 'region' => 'eu-west-2',       'ip' => '18.130.44.201',   'agents' => 8,  'calls' => 2140,  'blocked' => 87,  'tls' => true, 'mtls' => true,  'canary' => 6,  'version' => '1.9.1', 'hours' => 1],
            ['gw_id' => 'sentry-solstice-eu-central-1',    'tenant' => 'Solstice Financial AG',    'country' => 'DE', 'region' => 'eu-central-1',    'ip' => '3.120.18.55',     'agents' => 15, 'calls' => 7920,  'blocked' => 156, 'tls' => true, 'mtls' => true,  'canary' => 8,  'version' => '1.9.2', 'hours' => 0],
            ['gw_id' => 'sentry-solstice-ch-zrh-1',        'tenant' => 'Solstice Financial AG',    'country' => 'CH', 'region' => 'ch-zrh-1',        'ip' => '194.209.45.12',   'agents' => 15, 'calls' => 6100,  'blocked' => 120, 'tls' => true, 'mtls' => true,  'canary' => 5,  'version' => '1.9.2', 'hours' => 1],
            ['gw_id' => 'sentry-kurogane-ap-northeast-1',  'tenant' => 'Kurogane Robotics K.K.',   'country' => 'JP', 'region' => 'ap-northeast-1',  'ip' => '13.115.202.41',   'agents' => 22, 'calls' => 11400, 'blocked' => 342, 'tls' => true, 'mtls' => true,  'canary' => 12, 'version' => '1.9.2', 'hours' => 0],
            ['gw_id' => 'sentry-aether-us-west-1',         'tenant' => 'Aether Intelligence',      'country' => 'US', 'region' => 'us-west-1',       'ip' => '13.56.180.92',    'agents' => 5,  'calls' => 1200,  'blocked' => 8,   'tls' => true, 'mtls' => false, 'canary' => 0,  'version' => '1.8.4', 'hours' => 4],
            ['gw_id' => 'sentry-pinnacle-ap-southeast-2',  'tenant' => 'Pinnacle Defence Group',   'country' => 'AU', 'region' => 'ap-southeast-2',  'ip' => '13.238.44.109',   'agents' => 6,  'calls' => 1800,  'blocked' => 210, 'tls' => true, 'mtls' => true,  'canary' => 10, 'version' => '1.9.2', 'hours' => 2],
            ['gw_id' => 'sentry-cloudbridge-eu-west-1',    'tenant' => 'CloudBridge SaaS Inc',     'country' => 'IE', 'region' => 'eu-west-1',       'ip' => '52.17.88.203',    'agents' => 4,  'calls' => 640,   'blocked' => 3,   'tls' => true, 'mtls' => false, 'canary' => 0,  'version' => '1.9.0', 'hours' => 6],
            ['gw_id' => 'sentry-etoile-eu-west-3',         'tenant' => 'Étoile Logistics SA',      'country' => 'FR', 'region' => 'eu-west-3',       'ip' => '15.237.12.67',    'agents' => 2,  'calls' => 310,   'blocked' => 1,   'tls' => true, 'mtls' => false, 'canary' => 0,  'version' => '1.8.4', 'hours' => 12],
            ['gw_id' => 'sentry-maple-ca-central-1',       'tenant' => 'Maple Fintech Corp',       'country' => 'CA', 'region' => 'ca-central-1',    'ip' => '35.182.55.140',   'agents' => 7,  'calls' => 2100,  'blocked' => 45,  'tls' => true, 'mtls' => true,  'canary' => 3,  'version' => '1.9.1', 'hours' => 1],
            ['gw_id' => 'sentry-emerald-eu-west-1',        'tenant' => 'Emerald Systems plc',      'country' => 'IE', 'region' => 'eu-west-1',       'ip' => '52.18.120.45',    'agents' => 9,  'calls' => 3400,  'blocked' => 78,  'tls' => true, 'mtls' => true,  'canary' => 5,  'version' => '1.9.2', 'hours' => 0],
        ];

        foreach ($gateways as $gw) {
            $tid = $tenantMap[$gw['tenant']] ?? null;
            if (!$tid) continue;
            if (DB::table('gateway_instances')->where('gateway_id', $gw['gw_id'])->exists()) continue;

            DB::table('gateway_instances')->insert([
                'id'                        => (string) Str::uuid(),
                'gateway_id'                => $gw['gw_id'],
                'tenant_id'                 => $tid,
                'gateway_version'           => $gw['version'],
                'region'                    => $gw['region'],
                'country'                   => $gw['country'],
                'ip_address'                => $gw['ip'],
                'agents_registered'         => $gw['agents'],
                'calls_last_window'         => $gw['calls'],
                'calls_blocked_last_window' => $gw['blocked'],
                'tls_enabled'               => $gw['tls'],
                'mtls_enabled'              => $gw['mtls'],
                'canary_tokens_active'      => $gw['canary'],
                'quarantined_agents'        => mt_rand(0, 2),
                'status'                    => 'online',
                'last_seen_at'              => $now->copy()->subHours($gw['hours']),
                'first_registered_at'       => $now->copy()->subWeeks(mt_rand(2, 16)),
            ]);
        }
        $this->command->info("✓ Gateway Instances: " . count($gateways));

        // ═════════════════════════════════════════════════════════════════════
        // 10. ACTION LEDGER (350+ entries with varied statuses)
        // ═════════════════════════════════════════════════════════════════════
        $actionTypes = ['proxy_call', 'tool_invoke', 'deploy_trigger', 'status_check', 'notification_send', 'hitl_pending', 'hitl_approved', 'hitl_rejected', 'hitl_timeout', 'canary_issued', 'agent_certified', 'shadow_sandbox', 'evar_rotation'];
        $ledgerStatuses = ['approved', 'approved', 'approved', 'approved', 'blocked', 'pending_swarm', 'shadow_sandbox', 'quarantined'];
        $targets = [
            'https://api.github.com/repos/nexus/platform/actions/workflows/ci.yml/dispatches',
            'https://nexusdynamics.atlassian.net/rest/api/3/issue/PLAT-1842/transitions',
            'https://slack.com/api/chat.postMessage',
            'https://api.datadog.com/api/v1/query',
            'https://api.stripe.com/v1/customers',
            'cicada://hitl/deploy-approval',
            'cicada://canary/token-issuance',
            'cicada://swarm/certification',
        ];

        $ledgerCount = 0;
        foreach ($agentIds as $agentId) {
            $tid = $agentTenantMap[$agentId] ?? null;
            if (!$tid) continue;

            $numEntries = mt_rand(5, 15);
            for ($i = 0; $i < $numEntries; $i++) {
                DB::table('action_ledger')->insert([
                    'trace_id'               => (string) Str::uuid(),
                    'tenant_id'              => $tid,
                    'agent_id'               => $agentId,
                    'action_type'            => $actionTypes[array_rand($actionTypes)],
                    'payload_hash'           => hash('sha256', "$agentId-action-$i-" . microtime()),
                    'target_api'             => $targets[array_rand($targets)],
                    'status'                 => $ledgerStatuses[array_rand($ledgerStatuses)],
                    'swarm_confidence_score' => round(mt_rand(5500, 9900) / 10000, 4),
                    'created_at'             => $now->copy()->subHours(mt_rand(1, 720)),
                ]);
                $ledgerCount++;
            }
        }
        $this->command->info("✓ Action Ledger: $ledgerCount entries");

        // ═════════════════════════════════════════════════════════════════════
        // 11. CIBA AUTHORIZATION REQUESTS (20 requests across agents)
        // ═════════════════════════════════════════════════════════════════════
        $cibaStatuses = ['pending', 'approved', 'denied', 'expired', 'pending', 'approved', 'approved'];
        $cibaCount = 0;
        $cibaHoldRefs = [];

        foreach (array_slice($agentIds, 0, 15) as $agentId) {
            $tid = $agentTenantMap[$agentId] ?? null;
            if (!$tid) continue;
            $agent = DB::table('agents')->where('id', $agentId)->first();

            $holdRef = 'hold-' . Str::random(12);
            $nonce   = Str::random(32);
            $status  = $cibaStatuses[array_rand($cibaStatuses)];
            $cibaHoldRefs[] = ['hold_ref' => $holdRef, 'nonce' => $nonce, 'agent_id' => $agentId, 'status' => $status];

            DB::table('ciba_authorization_requests')->insert([
                'id'                 => (string) Str::uuid(),
                'trace_id'           => 'trace-' . Str::random(16),
                'agent_id'           => $agentId,
                'tenant_id'          => $tid,
                'agent_name'         => $agent->name ?? 'Unknown Agent',
                'action_summary'     => ['Deploy to production', 'Delete customer records', 'Transfer funds > $50k', 'Modify access policies', 'Execute trade order', 'Override safety interlock'][mt_rand(0, 5)],
                'target_url'         => $targets[array_rand($targets)],
                'payload_preview'    => '{"action":"' . ['deploy', 'delete', 'transfer', 'modify', 'execute'][mt_rand(0, 4)] . '","target":"production","risk":"elevated"}',
                'risk_score'         => round(mt_rand(30, 95) / 100, 2),
                'risk_reason'        => ['High-value transaction', 'Destructive action detected', 'Anomalous velocity', 'Out-of-hours operation', 'Policy violation candidate'][mt_rand(0, 4)],
                'status'             => $status,
                'responded_by'       => $status !== 'pending' ? 'operator-' . Str::random(8) : null,
                'responded_at'       => $status !== 'pending' ? $now->copy()->subHours(mt_rand(0, 48)) : null,
                'expires_at'         => $now->copy()->addMinutes(mt_rand(-30, 120)),
                'decision_nonce'     => $nonce,
                'hold_payload_hash'  => hash('sha256', $holdRef),
                'required_votes'     => [1, 1, 2, 3][mt_rand(0, 3)],
                'created_at'         => $now->copy()->subHours(mt_rand(1, 72)),
                'updated_at'         => $now->copy()->subHours(mt_rand(0, 24)),
            ]);
            $cibaCount++;
        }
        $this->command->info("✓ CIBA Requests: $cibaCount");

        // ═════════════════════════════════════════════════════════════════════
        // 12. DECISION NONCES & HOLD PAYLOADS (matching CIBA requests)
        // ═════════════════════════════════════════════════════════════════════
        foreach ($cibaHoldRefs as $ref) {
            DB::table('decision_nonces')->insert([
                'nonce'       => $ref['nonce'],
                'hold_ref'    => $ref['hold_ref'],
                'consumed_at' => $ref['status'] !== 'pending' ? $now->copy()->subHours(mt_rand(0, 24)) : null,
                'consumed_by' => $ref['status'] !== 'pending' ? 'device-' . Str::random(8) : null,
                'created_at'  => $now->copy()->subHours(mt_rand(1, 72)),
                'expires_at'  => $now->copy()->addMinutes(mt_rand(5, 120)),
            ]);

            DB::table('hold_payloads')->insert([
                'hold_ref'      => $ref['hold_ref'],
                'ciphertext'    => base64_encode(random_bytes(128)),
                'ephemeral_pub' => base64_encode(random_bytes(32)),
                'nonce'         => base64_encode(random_bytes(24)),
                'target_device' => 'device-' . Str::random(8),
                'created_at'    => $now->copy()->subHours(mt_rand(1, 72)),
                'expires_at'    => $now->copy()->addMinutes(mt_rand(10, 120)),
            ]);
        }
        $this->command->info("✓ Decision Nonces & Hold Payloads: " . count($cibaHoldRefs));

        // ═════════════════════════════════════════════════════════════════════
        // 13. QUORUM VOTES (for multi-approval CIBA requests)
        // ═════════════════════════════════════════════════════════════════════
        $voteCount = 0;
        foreach ($cibaHoldRefs as $ref) {
            if ($ref['status'] === 'pending') continue;
            $numVotes = mt_rand(1, 3);
            for ($v = 0; $v < $numVotes; $v++) {
                DB::table('quorum_votes')->insert([
                    'id'                 => (string) Str::uuid(),
                    'hold_ref'           => $ref['hold_ref'],
                    'device_fingerprint' => hash('sha256', 'device-' . $v . '-' . $ref['hold_ref']),
                    'vote'               => $ref['status'] === 'approved' ? 'approve' : 'reject',
                    'signature'          => base64_encode(random_bytes(64)),
                    'voted_at'           => $now->copy()->subHours(mt_rand(0, 24)),
                ]);
                $voteCount++;
            }
        }
        $this->command->info("✓ Quorum Votes: $voteCount");

        // ═════════════════════════════════════════════════════════════════════
        // 14. MOBILE DEVICES (Aegis companion devices)
        // ═════════════════════════════════════════════════════════════════════
        $mobileDevices = [
            ['tenant' => 'Nexus Dynamics Ltd',      'model' => 'Pixel 8 Pro',      'platform' => 'android'],
            ['tenant' => 'Nexus Dynamics Ltd',      'model' => 'iPhone 15 Pro',    'platform' => 'ios'],
            ['tenant' => 'Meridian Health Systems', 'model' => 'Samsung Galaxy S24','platform' => 'android'],
            ['tenant' => 'Solstice Financial AG',   'model' => 'iPhone 15 Pro Max','platform' => 'ios'],
            ['tenant' => 'Kurogane Robotics K.K.',  'model' => 'Sony Xperia 1 VI', 'platform' => 'android'],
            ['tenant' => 'Pinnacle Defence Group',  'model' => 'iPhone SE (3rd)',   'platform' => 'ios'],
        ];

        foreach ($mobileDevices as $md) {
            $tid = $tenantMap[$md['tenant']] ?? null;
            if (!$tid) continue;

            DB::table('mobile_devices')->insert([
                'id'                => (string) Str::uuid(),
                'tenant_id'         => $tid,
                'ed25519_pub'       => base64_encode(random_bytes(32)),
                'x25519_pub'        => base64_encode(random_bytes(32)),
                'ml_dsa65_pub'      => '',
                'ml_kem768_pub'     => '',
                'push_token'        => 'fcm:' . Str::random(152),
                'push_platform'     => $md['platform'],
                'status'            => 'active',
                'last_heartbeat_at' => $now->copy()->subMinutes(mt_rand(1, 120)),
                'paired_at'         => $now->copy()->subDays(mt_rand(5, 60)),
                'device_model'      => $md['model'],
                'created_at'        => $now->copy()->subDays(mt_rand(5, 60)),
                'updated_at'        => $now->copy()->subMinutes(mt_rand(1, 120)),
            ]);
        }
        $this->command->info("✓ Mobile Devices: " . count($mobileDevices));

        // ═════════════════════════════════════════════════════════════════════
        // 15. AEGIS DEVICES (enriched device telemetry)
        // ═════════════════════════════════════════════════════════════════════
        $nexusTid = $tenantMap['Nexus Dynamics Ltd'] ?? null;
        if ($nexusTid) {
            $gwNodeId = DB::table('gateway_instances')->where('gateway_id', 'sentry-nexus-us-east-1')->value('id');
            DB::table('aegis_devices')->insert([
                'id'                       => (string) Str::uuid(),
                'operator_evar_id'         => 'evar-' . Str::random(16),
                'tenant_id'                => $nexusTid,
                'gateway_node_id'          => $gwNodeId ?? (string) Str::uuid(),
                'device_id'                => 'aegis-' . Str::random(12),
                'platform'                 => 'android',
                'os_version'               => 'Android 15',
                'model'                    => 'Pixel 8 Pro',
                'manufacturer'             => 'Google',
                'app_version'              => '1.4.2',
                'biometric_enrolled'       => true,
                'secure_enclave_available' => true,
                'attestation_status'       => 'verified',
                'screen_lock_enabled'      => true,
                'pairing_ip'               => '192.168.1.42',
                'pairing_timestamp'        => $now->copy()->subDays(14),
                'last_seen_at'             => $now->copy()->subMinutes(15),
                'is_active'                => true,
                'created_at'               => $now->copy()->subDays(14),
                'updated_at'               => $now->copy()->subMinutes(15),
            ]);
        }
        $this->command->info("✓ Aegis Devices: 1");

        // ═════════════════════════════════════════════════════════════════════
        // 16. HITL SUSPENSIONS (in-flight hold-and-resume decisions)
        // ═════════════════════════════════════════════════════════════════════
        $suspCount = 0;
        foreach (array_slice($agentIds, 0, 6) as $agentId) {
            $decision = ['pending', 'approved', 'denied'][mt_rand(0, 2)];
            DB::table('hitl_suspensions')->insert([
                'trace_id'                   => 'trace-susp-' . Str::random(12),
                'agent_id'                   => $agentId,
                'original_payload_encrypted' => base64_encode(random_bytes(64)),
                'target_url'                 => $targets[array_rand($targets)],
                'webhook_url'                => 'https://hooks.example.com/cicada/resume',
                'approval_token'             => Str::random(48),
                'decision'                   => $decision,
                'dispatched_at'              => $now->copy()->subHours(mt_rand(1, 48)),
                'created_at'                 => $now->copy()->subHours(mt_rand(1, 48)),
                'updated_at'                 => $now->copy()->subHours(mt_rand(0, 12)),
            ]);
            $suspCount++;
        }
        $this->command->info("✓ HITL Suspensions: $suspCount");

        // ═════════════════════════════════════════════════════════════════════
        // 17. PLATFORM POLICIES (OPA governance rules)
        // ═════════════════════════════════════════════════════════════════════
        $policies = [
            ['slug' => 'velocity-cap',          'name' => 'Velocity Rate Limiting',       'desc' => 'Enforces per-agent call rate limits based on declared expected velocity.',      'env' => 'production', 'status' => 'active'],
            ['slug' => 'pii-filter',            'name' => 'PII Data Filter',              'desc' => 'Blocks API calls containing PII keywords in request payloads.',                'env' => 'production', 'status' => 'active'],
            ['slug' => 'destructive-hitl-gate', 'name' => 'Destructive Action HITL Gate', 'desc' => 'Requires HITL approval for any agent with destructive_capability enabled.',    'env' => 'production', 'status' => 'active'],
            ['slug' => 'budget-enforcement',    'name' => 'Monthly Budget Enforcement',   'desc' => 'Rejects calls when an agent exceeds its monthly_budget_usd.',                  'env' => 'production', 'status' => 'active'],
            ['slug' => 'trust-tier-minimum',    'name' => 'Trust Tier Minimum',           'desc' => 'Unverified agents are blocked from proxy_call actions.',                       'env' => 'production', 'status' => 'active'],
            ['slug' => 'restricted-hours',      'name' => 'Restricted Operating Hours',   'desc' => 'Blocks critical deployments between 22:00-06:00 UTC.',                        'env' => 'production', 'status' => 'draft'],
            ['slug' => 'geo-compliance',        'name' => 'Data Residency Compliance',    'desc' => 'Ensures agents only access data within their declared residency region.',      'env' => 'production', 'status' => 'active'],
            ['slug' => 'canary-detection',      'name' => 'Canary Token Detection',       'desc' => 'Monitors for canary token usage and triggers quarantine on detection.',        'env' => 'production', 'status' => 'active'],
        ];

        foreach ($policies as $p) {
            if (DB::table('platform_policies')->where('slug', $p['slug'])->exists()) continue;
            DB::table('platform_policies')->insert([
                'id'            => (string) Str::uuid(),
                'slug'          => $p['slug'],
                'name'          => $p['name'],
                'description'   => $p['desc'],
                'filename'      => $p['slug'] . '.rego',
                'environment'   => $p['env'],
                'status'        => $p['status'],
                'rule_config'   => json_encode(['enabled' => true, 'severity' => 'high']),
                'exceptions'    => json_encode([]),
                'line_count'    => mt_rand(20, 80),
                'context_similarity_threshold' => 0.85,
                'created_at'    => $now->copy()->subDays(mt_rand(30, 120)),
                'updated_at'    => $now->copy()->subDays(mt_rand(0, 15)),
            ]);
        }
        $this->command->info("✓ Platform Policies: " . count($policies));

        // ═════════════════════════════════════════════════════════════════════
        // 18. POLICY VERSIONS (OPA rego version history)
        // ═════════════════════════════════════════════════════════════════════
        foreach (array_slice($policies, 0, 5) as $p) {
            $numVersions = mt_rand(1, 3);
            for ($v = 1; $v <= $numVersions; $v++) {
                DB::table('policy_versions')->insert([
                    'id'           => (string) Str::uuid(),
                    'policy_name'  => $p['slug'],
                    'version'      => $v,
                    'rego_content' => "package cicada.{$p['slug']}\n\ndefault allow = false\n\nallow {\n    input.trust_tier != \"unverified\"\n}\n",
                    'created_by'   => 'system',
                    'active'       => $v === $numVersions, // Only latest is active
                    'created_at'   => $now->copy()->subDays(mt_rand(10, 60)),
                ]);
            }
        }
        $this->command->info("✓ Policy Versions seeded");

        // ═════════════════════════════════════════════════════════════════════
        // 19. ALERT RULES & OPERATOR ALERTS
        // ═════════════════════════════════════════════════════════════════════
        $alertRules = [
            ['event' => 'agent_quarantined',       'channel' => 'webhook',  'dest' => 'https://hooks.slack.com/cicada/quarantine'],
            ['event' => 'hitl_timeout',            'channel' => 'email',    'dest' => 'ops-alerts@cicada.platform'],
            ['event' => 'evar_rotation_failed',    'channel' => 'webhook',  'dest' => 'https://hooks.slack.com/cicada/cred-rotation'],
            ['event' => 'budget_exceeded',         'channel' => 'dashboard','dest' => 'operator_dashboard'],
            ['event' => 'canary_triggered',        'channel' => 'webhook',  'dest' => 'https://hooks.slack.com/cicada/canary-alert'],
            ['event' => 'velocity_breach',         'channel' => 'email',    'dest' => 'security@cicada.platform'],
        ];

        foreach ($alertRules as $ar) {
            DB::table('alert_rules')->insert([
                'id'          => (string) Str::uuid(),
                'event_type'  => $ar['event'],
                'channel'     => $ar['channel'],
                'destination' => $ar['dest'],
                'enabled'     => true,
                'created_at'  => $now->copy()->subDays(mt_rand(10, 60)),
            ]);
        }

        // Operator alerts (historical)
        $alertSeverities = ['critical', 'warning', 'info'];
        $alertEvents = ['velocity_breach', 'hitl_timeout', 'canary_triggered', 'budget_exceeded', 'scope_escalation', 'evar_rotation_overdue'];
        $alertSummaries = ['Velocity breach detected — agent exceeded declared rate', 'HITL timeout — decision auto-denied after 24h', 'Canary token accessed by unauthorized agent', 'Budget threshold 80% reached — action may be throttled', 'Unauthorized scope escalation attempt blocked', 'EVAR rotation overdue — credential expiry imminent'];
        for ($a = 0; $a < 25; $a++) {
            $agentId = $agentIds[array_rand($agentIds)];
            $evtIdx = mt_rand(0, count($alertEvents) - 1);
            DB::table('operator_alerts')->insert([
                'id'          => (string) Str::uuid(),
                'tenant_id'   => (string) ($agentTenantMap[$agentId] ?? array_values($tenantMap)[0]),
                'agent_id'    => (string) $agentId,
                'event_type'  => $alertEvents[$evtIdx],
                'severity'    => $alertSeverities[array_rand($alertSeverities)],
                'summary'     => $alertSummaries[$evtIdx],
                'context'     => json_encode(['source' => ['gateway', 'swarm', 'policy_engine', 'ciba'][mt_rand(0, 3)], 'details' => 'Automated alert generated by the governance pipeline.']),
                'status'      => ['open', 'acknowledged', 'resolved'][mt_rand(0, 2)],
                'created_at'  => $now->copy()->subHours(mt_rand(1, 720)),
            ]);
        }
        $this->command->info("✓ Alert Rules: " . count($alertRules) . " | Operator Alerts: 25");

        // ═════════════════════════════════════════════════════════════════════
        // 20. RETENTION POLICIES
        // ═════════════════════════════════════════════════════════════════════
        $retPolicies = [
            ['id' => 'ledger-standard',  'label' => 'Action Ledger — Standard',  'desc' => 'Standard retention for action ledger entries.',  'days' => 365,  'delete' => false, 'archive' => true],
            ['id' => 'ledger-compliance','label' => 'Action Ledger — Compliance','desc' => 'Extended retention for regulated industries.',   'days' => 2555, 'delete' => false, 'archive' => true],
            ['id' => 'alerts-standard',  'label' => 'Alerts — Standard',         'desc' => 'Operator alerts retention.',                     'days' => 90,   'delete' => true,  'archive' => false],
            ['id' => 'audit-log',        'label' => 'Audit Log — Immutable',     'desc' => 'Operator audit log. Cannot be deleted.',         'days' => 3650, 'delete' => false, 'archive' => true],
        ];

        foreach ($retPolicies as $rp) {
            if (DB::table('retention_policies')->where('id', $rp['id'])->exists()) continue;
            DB::table('retention_policies')->insert([
                'id'                    => $rp['id'],
                'label'                 => $rp['label'],
                'description'           => $rp['desc'],
                'retention_days'        => $rp['days'],
                'auto_delete'           => $rp['delete'],
                'archive_before_delete' => $rp['archive'],
                'created_at'            => $now->copy()->subMonths(3),
            ]);
        }
        $this->command->info("✓ Retention Policies: " . count($retPolicies));

        // ═════════════════════════════════════════════════════════════════════
        // 21. OPERATOR AUDIT LOG (admin activity trail)
        // ═════════════════════════════════════════════════════════════════════
        $auditActions = [
            ['action' => 'agent.approved',       'entity' => 'agent',    'notes' => 'Approved agent registration after swarm verification.'],
            ['action' => 'agent.quarantined',    'entity' => 'agent',    'notes' => 'Quarantined due to anomalous velocity pattern.'],
            ['action' => 'agent.revoked',        'entity' => 'agent',    'notes' => 'Revoked access after security review.'],
            ['action' => 'policy.updated',       'entity' => 'policy',   'notes' => 'Updated velocity cap from 100 to 60 calls/hour.'],
            ['action' => 'evar.rotated',         'entity' => 'agent',    'notes' => 'Manual EVAR rotation triggered by operator.'],
            ['action' => 'tenant.plan_upgraded', 'entity' => 'tenant',   'notes' => 'Upgraded from professional to enterprise plan.'],
            ['action' => 'device.paired',        'entity' => 'device',   'notes' => 'New Aegis companion device paired via TOFU.'],
            ['action' => 'alert.acknowledged',   'entity' => 'alert',    'notes' => 'Operator acknowledged canary trigger alert.'],
        ];

        for ($al = 0; $al < 30; $al++) {
            $template = $auditActions[array_rand($auditActions)];
            DB::table('operator_audit_log')->insert([
                'operator_label' => ['admin@cicada', 'security-ops', 'platform-team'][mt_rand(0, 2)],
                'action'         => $template['action'],
                'entity_type'    => $template['entity'],
                'entity_id'      => (string) Str::uuid(),
                'notes'          => $template['notes'],
                'ip_address'     => '192.168.1.' . mt_rand(10, 254),
                'created_at'     => $now->copy()->subHours(mt_rand(1, 720)),
            ]);
        }
        $this->command->info("✓ Operator Audit Log: 30 entries");

        // ═════════════════════════════════════════════════════════════════════
        // 22. SYSTEM CONFIGS
        // ═════════════════════════════════════════════════════════════════════
        $configs = [
            ['key' => 'platform.version',              'value' => '"1.9.2"'],
            ['key' => 'gateway.pqc_enforcement',       'value' => 'false'],
            ['key' => 'swarm.default_confidence',      'value' => '0.85'],
            ['key' => 'ciba.default_timeout_minutes',  'value' => '5'],
            ['key' => 'ciba.quorum_default',           'value' => '1'],
            ['key' => 'evar.rotation_interval_days',   'value' => '90'],
            ['key' => 'canary.enabled',                'value' => 'true'],
        ];

        foreach ($configs as $cfg) {
            DB::table('system_configs')->updateOrInsert(
                ['key' => $cfg['key']],
                ['value' => $cfg['value'], 'created_at' => $now->copy()->subMonths(2), 'updated_at' => $now]
            );
        }
        $this->command->info("✓ System Configs: " . count($configs));

        // ═════════════════════════════════════════════════════════════════════
        // 23. REVOCATION WEBHOOKS
        // ═════════════════════════════════════════════════════════════════════
        foreach (array_slice(array_values($tenantMap), 0, 4) as $tid) {
            DB::table('revocation_webhooks')->insert([
                'id'            => (string) Str::uuid(),
                'tenant_id'     => $tid,
                'name'          => 'Primary Revocation Webhook',
                'endpoint_url'  => 'https://hooks.example.com/cicada/revocation',
                'event_types'   => json_encode(['agent.revoked', 'evar.expired', 'agent.quarantined']),
                'auth_method'   => 'hmac_sha256',
                'enabled'       => true,
                'consecutive_failures' => 0,
                'created_at'    => $now->copy()->subDays(mt_rand(10, 60)),
                'updated_at'    => $now->copy()->subDays(mt_rand(0, 5)),
            ]);
        }
        $this->command->info("✓ Revocation Webhooks: 4");

        // ═════════════════════════════════════════════════════════════════════
        // 24. AGENT TEMPLATES (marketplace-ready templates)
        // ═════════════════════════════════════════════════════════════════════
        $templates = [
            ['name' => 'CI/CD Orchestrator',     'type' => 'autonomous', 'role' => 'orchestrator', 'desc' => 'Pre-configured CI/CD pipeline agent with GitHub Actions, Jira, and Slack integrations.'],
            ['name' => 'Compliance Auditor',     'type' => 'autonomous', 'role' => 'observer',     'desc' => 'SOC2/ISO27001 compliance audit agent. Generates evidence reports on schedule.'],
            ['name' => 'Customer Support Bot',   'type' => 'reactive',   'role' => 'executor',     'desc' => 'Customer-facing support agent with ticket creation and knowledge base access.'],
            ['name' => 'Data Pipeline Manager',  'type' => 'autonomous', 'role' => 'executor',     'desc' => 'ETL orchestration agent for data warehouse management.'],
        ];

        foreach ($templates as $tmpl) {
            DB::table('agent_templates')->insert([
                'id'              => (string) Str::uuid(),
                'name'            => $tmpl['name'],
                'description'     => $tmpl['desc'],
                'agent_type'      => $tmpl['type'],
                'role'            => $tmpl['role'],
                'scopes'          => json_encode(['proxy:read', 'proxy:write', 'tool:invoke']),
                'custom_guardrails'=> 'Standard guardrails apply. Customise per deployment.',
                'tools'           => json_encode([['tool_id' => 'github:repos:read', 'tool_name' => 'GitHub Read']]),
                'is_verified'     => true,
                'status'          => 'published',
                'import_count'    => mt_rand(5, 50),
                'created_at'      => $now->copy()->subMonths(mt_rand(1, 3)),
                'updated_at'      => $now->copy()->subDays(mt_rand(0, 14)),
            ]);
        }
        $this->command->info("✓ Agent Templates: " . count($templates));

        // ═════════════════════════════════════════════════════════════════════
        // SUMMARY
        // ═════════════════════════════════════════════════════════════════════
        $this->command->info("");
        $this->command->info("╔═══════════════════════════════════════════════════════╗");
        $this->command->info("║   FULL PLATFORM SEED COMPLETE                       ║");
        $this->command->info("╚═══════════════════════════════════════════════════════╝");
        $this->command->info("  Tenants: " . count($tenantMap));
        $this->command->info("  Agents: " . count($agentIds) . " (across all trust tiers & roles)");
        $this->command->info("  Action Ledger: $ledgerCount entries");
        $this->command->info("  CIBA Requests: $cibaCount (with nonces, hold payloads, quorum votes)");
        $this->command->info("  Gateway Fleet: " . count($gateways) . " nodes across 8 countries");
        $this->command->info("  All tables populated — ready for E2E and K6 testing");
        $this->command->info("");
    }
}
