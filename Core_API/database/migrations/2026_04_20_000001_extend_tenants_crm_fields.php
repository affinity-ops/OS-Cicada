<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        // Add CRM fields to tenants without dropping existing Gateway columns.
        $cols = DB::select("SELECT column_name FROM information_schema.columns WHERE table_name = 'tenants'");
        $existing = array_column($cols, 'column_name');

        $additions = [
            'plan'             => "VARCHAR(50) NOT NULL DEFAULT 'starter' CHECK (plan IN ('starter','professional','enterprise'))",
            'company_email'    => 'VARCHAR(255) NULL',
            'company_phone'    => 'VARCHAR(50) NULL',
            'company_address'  => 'TEXT NULL',
            'company_website'  => 'VARCHAR(255) NULL',
            'admin_notes'      => 'TEXT NULL',   // writable by Cicada operators only
            'plan_started_at'  => 'TIMESTAMP WITH TIME ZONE NULL',
            'updated_at'       => 'TIMESTAMP WITH TIME ZONE NULL',
        ];

        foreach ($additions as $col => $definition) {
            if (!in_array($col, $existing)) {
                DB::statement("ALTER TABLE tenants ADD COLUMN {$col} {$definition}");
            }
        }

        // Widen status constraint to allow 'pending' for unverified signups.
        DB::statement("ALTER TABLE tenants DROP CONSTRAINT IF EXISTS tenants_status_check");
        DB::statement("ALTER TABLE tenants ADD CONSTRAINT tenants_status_check CHECK (status IN ('pending','active','suspended'))");
    }

    public function down(): void
    {
        // Intentionally left narrow — dropping CRM columns would destroy data.
    }
};
