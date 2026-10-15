<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        if (Schema::hasTable('agents')) {
            return;
        }

        Schema::create('agents', function (Blueprint $table) {
            $table->uuid('id')->primary();
            $table->uuid('tenant_id');
            $table->text('pub_key_hash')->unique();
            $table->jsonb('scope_entitlements')->default('[]');
            $table->string('trust_tier', 50)->default('unverified');
            $table->timestampTz('created_at')->useCurrent();
            $table->timestampTz('revoked_at')->nullable();

            $table->foreign('tenant_id')->references('id')->on('tenants')->onDelete('cascade');
        });

        DB::statement("ALTER TABLE agents ADD CONSTRAINT agents_trust_tier_check CHECK (trust_tier IN ('unverified', 'nominal', 'elevated', 'critical'))");
        DB::statement('CREATE INDEX IF NOT EXISTS idx_agents_pub_key ON agents(pub_key_hash)');
    }

    public function down(): void
    {
        Schema::dropIfExists('agents');
    }
};
