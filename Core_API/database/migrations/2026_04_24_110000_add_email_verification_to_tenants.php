<?php
/**
 * © 2026 Patrick Matthews (Affinity Ops / Affinity Smart AI)
 * SPDX-License-Identifier: Apache-2.0
 */
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('tenants', function (Blueprint $table) {
            $table->timestampTz('email_verified_at')->nullable();
            $table->string('verification_token')->nullable()->unique();
        });
    }

    public function down(): void
    {
        Schema::table('tenants', function (Blueprint $table) {
            $table->dropColumn(['email_verified_at', 'verification_token']);
        });
    }
};
