<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Create the action_ledger table.
 * This table was originally created outside of migrations.
 * This migration ensures test + fresh environments can rebuild it.
 */
return new class extends Migration
{
    public function up(): void
    {
        if (Schema::hasTable('action_ledger')) {
            return;
        }

        Schema::create('action_ledger', function (Blueprint $table) {
            $table->uuid('trace_id')->primary();
            $table->uuid('tenant_id')->index();
            $table->uuid('agent_id')->index();
            $table->string('action_type', 100);
            $table->string('payload_hash', 128)->nullable();
            $table->string('target_api', 500)->nullable();
            $table->string('status', 50)->default('completed');
            $table->decimal('swarm_confidence_score', 5, 4)->nullable();
            $table->jsonb('policy_violations')->nullable();
            $table->boolean('shadow_violation')->default(false);
            $table->jsonb('human_user_context')->nullable();
            $table->timestampTz('created_at')->useCurrent();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('action_ledger');
    }
};
