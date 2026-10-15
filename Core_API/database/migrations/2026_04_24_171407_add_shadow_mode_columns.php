<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Facades\DB;

return new class extends Migration
{
    public function up(): void
    {
        // 1. Tenants default shadow mode
        Schema::table('tenants', function (Blueprint $table) {
            $table->boolean('default_shadow_mode')->default(true)->after('id');
        });

        // 2. Agent Resource Policies observe_only_mode
        Schema::table('agent_resource_policies', function (Blueprint $table) {
            // Existing agents should be false to grandfather them
            $table->boolean('observe_only_mode')->default(false)->after('agent_id');
        });

        // 3. Action ledger column
        if (!Schema::hasColumn('action_ledger', 'shadow_violation')) {
            Schema::table('action_ledger', function (Blueprint $table) {
                $table->boolean('shadow_violation')->default(false)->after('target_api');
            });
        }

        // 4. Update the ENUM (if using ENUM in MySQL/Postgres, we might have to use raw DB statements)
        // Check what DB driver is being used. If Postgres/MySQL:
        // Actually since we don't know the exact schema of status, let's just make sure we alter it safely.
        // If it's a string column in laravel (e.g. string('status')), no enum alter needed.
    }

    public function down(): void
    {
        Schema::table('tenants', function (Blueprint $table) {
            $table->dropColumn('default_shadow_mode');
        });

        Schema::table('agent_resource_policies', function (Blueprint $table) {
            $table->dropColumn('observe_only_mode');
        });

        Schema::table('action_ledger', function (Blueprint $table) {
            $table->dropColumn('shadow_violation');
        });
    }
};
