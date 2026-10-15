<?php
/**
 * © 2026 ASAI — affinitysmartai.co.uk. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

return new class extends Migration
{
    public function up(): void
    {
        // Add IdP configuration columns for Enterprise SSO (SAML 2.0 + CAEP).
        $cols = DB::select("SELECT column_name FROM information_schema.columns WHERE table_name = 'tenants'");
        $existing = array_column($cols, 'column_name');

        $additions = [
            'idp_entity_id' => 'VARCHAR(512) NULL',
            'idp_sso_url'   => 'VARCHAR(1024) NULL',
            'idp_x509_cert' => 'TEXT NULL',
        ];

        foreach ($additions as $col => $definition) {
            if (!in_array($col, $existing)) {
                DB::statement("ALTER TABLE tenants ADD COLUMN {$col} {$definition}");
            }
        }
    }

    public function down(): void
    {
        // Intentionally narrow — dropping IdP columns would break SSO for tenants.
    }
};
