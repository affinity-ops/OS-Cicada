<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('gateway_instances', function (Blueprint $table) {
            $table->uuid('id')->primary()->default(DB::raw('gen_random_uuid()'));
            $table->string('gateway_id', 255)->unique();
            $table->foreignUuid('tenant_id')->constrained('tenants')->cascadeOnDelete();

            $table->string('gateway_version', 50)->default('unknown');
            $table->string('region', 100)->nullable();
            $table->string('country', 100)->nullable();
            $table->string('ip_address', 45)->nullable();

            $table->integer('agents_registered')->default(0);
            $table->bigInteger('calls_last_window')->default(0);
            $table->bigInteger('calls_blocked_last_window')->default(0);

            $table->boolean('tls_enabled')->default(false);
            $table->boolean('mtls_enabled')->default(false);
            $table->integer('canary_tokens_active')->default(0);
            $table->integer('quarantined_agents')->default(0);

            $table->string('status', 20)->default('pending');
            $table->timestamp('last_seen_at')->nullable();
            $table->timestamp('first_registered_at')->useCurrent();

            $table->jsonb('metadata')->nullable();
        });

        Schema::table('gateway_instances', function (Blueprint $table) {
            $table->index('tenant_id');
            $table->index('status');
            $table->index('country');
            $table->index('last_seen_at');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('gateway_instances');
    }
};
