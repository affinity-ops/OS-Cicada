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
        Schema::create('ciba_authorization_requests', function (Blueprint $table) {
            $table->uuid('id')->primary();
            $table->string('trace_id')->index();
            $table->uuid('agent_id')->index();
            $table->uuid('tenant_id')->index();
            $table->string('agent_name')->nullable();
            $table->string('action_summary');
            $table->string('target_url')->nullable();
            $table->text('payload_preview')->nullable();
            $table->decimal('risk_score', 4, 2)->default(0);
            $table->string('risk_reason')->nullable();
            $table->enum('status', ['pending', 'approved', 'denied', 'expired'])->default('pending')->index();
            $table->string('responded_by')->nullable();
            $table->timestamp('responded_at')->nullable();
            $table->timestamp('expires_at');
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('ciba_authorization_requests');
    }
};
