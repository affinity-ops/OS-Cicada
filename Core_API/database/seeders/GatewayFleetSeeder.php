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
 * GatewayFleetSeeder — Seeds a realistic global fleet of Sentry Gateway instances
 * so the Command Matrix globe and Heartbeat Status table display meaningful data.
 *
 * Each gateway is linked to a tenant and placed in a real-world country with a
 * realistic IP address, agent count, and call volume.
 *
 * Run with: php artisan db:seed --class=GatewayFleetSeeder
 */
class GatewayFleetSeeder extends Seeder
{
    public function run(): void
    {
        $now = Carbon::now();

        // ─── Tenants ────────────────────────────────────────────────────────
        // Seed a diverse set of companies across industries and geographies.
        $tenants = [
            ['id' => (string) Str::uuid(), 'name' => 'Nexus Dynamics Ltd',       'plan' => 'enterprise', 'status' => 'active', 'company_email' => 'ops@nexusdynamics.io',       'created_at' => $now->copy()->subMonths(6)],
            ['id' => (string) Str::uuid(), 'name' => 'Meridian Health Systems',  'plan' => 'enterprise', 'status' => 'active', 'company_email' => 'infosec@meridianhealth.com', 'created_at' => $now->copy()->subMonths(4)],
            ['id' => (string) Str::uuid(), 'name' => 'Solstice Financial AG',    'plan' => 'enterprise', 'status' => 'active', 'company_email' => 'ai-ops@solstice-fin.ch',     'created_at' => $now->copy()->subMonths(5)],
            ['id' => (string) Str::uuid(), 'name' => 'Kurogane Robotics K.K.',   'plan' => 'enterprise', 'status' => 'active', 'company_email' => 'admin@kurogane.co.jp',       'created_at' => $now->copy()->subMonths(3)],
            ['id' => (string) Str::uuid(), 'name' => 'Aether Intelligence',      'plan' => 'professional', 'status' => 'active', 'company_email' => 'devops@aetherintel.ai',      'created_at' => $now->copy()->subMonths(2)],
            ['id' => (string) Str::uuid(), 'name' => 'Pinnacle Defence Group',   'plan' => 'enterprise', 'status' => 'active', 'company_email' => 'security@pinnacledefence.gov.au', 'created_at' => $now->copy()->subMonths(7)],
            ['id' => (string) Str::uuid(), 'name' => 'CloudBridge SaaS Inc',     'plan' => 'professional',     'status' => 'active', 'company_email' => 'ops@cloudbridge.io',          'created_at' => $now->copy()->subMonths(1)],
            ['id' => (string) Str::uuid(), 'name' => 'Étoile Logistics SA',      'plan' => 'starter',    'status' => 'active', 'company_email' => 'tech@etoile-logistics.fr',    'created_at' => $now->copy()->subMonths(1)],
            ['id' => (string) Str::uuid(), 'name' => 'Maple Fintech Corp',       'plan' => 'professional',     'status' => 'active', 'company_email' => 'platform@maplefintech.ca',    'created_at' => $now->copy()->subWeeks(3)],
            ['id' => (string) Str::uuid(), 'name' => 'Emerald Systems plc',      'plan' => 'enterprise', 'status' => 'active', 'company_email' => 'ciso@emeraldsystems.ie',      'created_at' => $now->copy()->subMonths(8)],
        ];

        foreach ($tenants as $t) {
            // Upsert: skip if tenant already exists
            if (!DB::table('tenants')->where('company_email', $t['company_email'])->exists()) {
                DB::table('tenants')->insert($t);
            }
        }

        // Get actual tenant IDs (in case some were pre-existing)
        $tenantMap = [];
        foreach ($tenants as $t) {
            $row = DB::table('tenants')->where('company_email', $t['company_email'])->first();
            if ($row) {
                $tenantMap[$t['name']] = $row->id;
            }
        }

        // ─── Gateway Fleet ──────────────────────────────────────────────────
        $gateways = [
            // Nexus Dynamics — US East (primary) + US West (DR)
            ['gateway_id' => 'sentry-nexus-us-east-1',  'tenant' => 'Nexus Dynamics Ltd',       'country' => 'US',  'region' => 'us-east-1',      'ip' => '54.221.118.42',   'agents' => 12, 'calls' => 4280,  'blocked' => 31,  'tls' => true,  'mtls' => true,  'canary' => 4, 'version' => '1.9.2', 'age_hours' => 1],
            ['gateway_id' => 'sentry-nexus-us-west-2',  'tenant' => 'Nexus Dynamics Ltd',       'country' => 'US',  'region' => 'us-west-2',      'ip' => '35.160.72.19',    'agents' => 3,  'calls' => 890,   'blocked' => 2,   'tls' => true,  'mtls' => true,  'canary' => 1, 'version' => '1.9.2', 'age_hours' => 2],

            // Meridian Health — UK (NHS-adjacent)
            ['gateway_id' => 'sentry-meridian-eu-west-2', 'tenant' => 'Meridian Health Systems', 'country' => 'UK',  'region' => 'eu-west-2',     'ip' => '18.130.44.201',   'agents' => 8,  'calls' => 2140,  'blocked' => 87,  'tls' => true,  'mtls' => true,  'canary' => 6, 'version' => '1.9.1', 'age_hours' => 1],

            // Solstice Financial — Switzerland + Frankfurt DR
            ['gateway_id' => 'sentry-solstice-eu-central-1', 'tenant' => 'Solstice Financial AG', 'country' => 'DE', 'region' => 'eu-central-1', 'ip' => '3.120.18.55',     'agents' => 15, 'calls' => 7920,  'blocked' => 156, 'tls' => true,  'mtls' => true,  'canary' => 8, 'version' => '1.9.2', 'age_hours' => 0],
            ['gateway_id' => 'sentry-solstice-ch-zrh-1',     'tenant' => 'Solstice Financial AG', 'country' => 'DE', 'region' => 'ch-zrh-1',     'ip' => '194.209.45.12',   'agents' => 15, 'calls' => 6100,  'blocked' => 120, 'tls' => true,  'mtls' => true,  'canary' => 5, 'version' => '1.9.2', 'age_hours' => 1],

            // Kurogane Robotics — Tokyo
            ['gateway_id' => 'sentry-kurogane-ap-northeast-1', 'tenant' => 'Kurogane Robotics K.K.', 'country' => 'JP', 'region' => 'ap-northeast-1', 'ip' => '13.115.202.41', 'agents' => 22, 'calls' => 11400, 'blocked' => 342, 'tls' => true,  'mtls' => true,  'canary' => 12, 'version' => '1.9.2', 'age_hours' => 0],

            // Aether Intelligence — US (Silicon Valley startup)
            ['gateway_id' => 'sentry-aether-us-west-1',  'tenant' => 'Aether Intelligence',      'country' => 'US',  'region' => 'us-west-1',     'ip' => '13.56.180.92',    'agents' => 5,  'calls' => 1200,  'blocked' => 8,   'tls' => true,  'mtls' => false, 'canary' => 0, 'version' => '1.8.4', 'age_hours' => 4],

            // Pinnacle Defence — Sydney
            ['gateway_id' => 'sentry-pinnacle-ap-southeast-2', 'tenant' => 'Pinnacle Defence Group', 'country' => 'AU', 'region' => 'ap-southeast-2', 'ip' => '13.238.44.109', 'agents' => 6, 'calls' => 1800, 'blocked' => 210, 'tls' => true,  'mtls' => true,  'canary' => 10, 'version' => '1.9.2', 'age_hours' => 2],

            // CloudBridge — Ireland (EU-based SaaS)
            ['gateway_id' => 'sentry-cloudbridge-eu-west-1', 'tenant' => 'CloudBridge SaaS Inc',  'country' => 'IE',  'region' => 'eu-west-1',     'ip' => '52.17.88.203',    'agents' => 4,  'calls' => 640,   'blocked' => 3,   'tls' => true,  'mtls' => false, 'canary' => 0, 'version' => '1.9.0', 'age_hours' => 6],

            // Étoile Logistics — Paris
            ['gateway_id' => 'sentry-etoile-eu-west-3',   'tenant' => 'Étoile Logistics SA',     'country' => 'FR',  'region' => 'eu-west-3',     'ip' => '15.237.12.67',    'agents' => 2,  'calls' => 310,   'blocked' => 1,   'tls' => true,  'mtls' => false, 'canary' => 0, 'version' => '1.8.4', 'age_hours' => 12],

            // Maple Fintech — Canada
            ['gateway_id' => 'sentry-maple-ca-central-1',  'tenant' => 'Maple Fintech Corp',     'country' => 'CA',  'region' => 'ca-central-1',  'ip' => '35.182.55.140',   'agents' => 7,  'calls' => 2100,  'blocked' => 45,  'tls' => true,  'mtls' => true,  'canary' => 3, 'version' => '1.9.1', 'age_hours' => 1],

            // Emerald Systems — Ireland (second gateway, different tenant)
            ['gateway_id' => 'sentry-emerald-eu-west-1',  'tenant' => 'Emerald Systems plc',     'country' => 'IE',  'region' => 'eu-west-1',     'ip' => '52.18.120.45',    'agents' => 9,  'calls' => 3400,  'blocked' => 78,  'tls' => true,  'mtls' => true,  'canary' => 5, 'version' => '1.9.2', 'age_hours' => 0],
        ];

        foreach ($gateways as $gw) {
            $tenantId = $tenantMap[$gw['tenant']] ?? null;
            if (!$tenantId) continue;

            // Skip if already seeded
            if (DB::table('gateway_instances')->where('gateway_id', $gw['gateway_id'])->exists()) {
                continue;
            }

            DB::table('gateway_instances')->insert([
                'id'                        => (string) Str::uuid(),
                'gateway_id'                => $gw['gateway_id'],
                'tenant_id'                 => $tenantId,
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
                'quarantined_agents'        => 0,
                'status'                    => 'online',
                'last_seen_at'              => $now->copy()->subHours($gw['age_hours']),
                'first_registered_at'       => $now->copy()->subWeeks(mt_rand(1, 12)),
            ]);
        }

        $this->command->info("✓ Seeded Gateway Fleet: " . count($gateways) . " Sentry Gateway instances across " . count($tenants) . " tenants");
        $this->command->info("  Countries: US, UK, DE, JP, AU, IE, FR, CA");
        $this->command->info("  Total agents: " . array_sum(array_column($gateways, 'agents')));
    }
}
