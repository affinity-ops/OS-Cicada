<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Adds CIBA notification preference columns to the tenants table.
 *
 * These columns tell the CibaController WHERE to send authorization
 * requests so the operator actually receives them instead of them
 * sitting in the database unnoticed until they expire.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('tenants', function (Blueprint $table) {
            // Preferred notification channel: 'email', 'dashboard', or 'companion_app'
            // Defaults to 'dashboard' (poll-only) — the only channel that works without external config
            $table->string('ciba_notification_channel', 30)->default('dashboard')->after('default_shadow_mode');

            // Email address specifically for CIBA alerts (may differ from company_email)
            // Falls back to company_email if NULL
            $table->string('ciba_notification_email')->nullable()->after('ciba_notification_channel');
        });
    }

    public function down(): void
    {
        Schema::table('tenants', function (Blueprint $table) {
            $table->dropColumn(['ciba_notification_channel', 'ciba_notification_email']);
        });
    }
};
