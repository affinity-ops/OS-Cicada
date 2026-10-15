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
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('hitl_suspensions', function (Blueprint $table) {
            $table->string('trace_id')->primary();
            $table->uuid('agent_id');
            $table->text('original_payload_encrypted'); // strictly text for AES-256-GCM ciphertext
            $table->string('target_url', 2048);
            $table->string('webhook_url', 2048)->nullable();
            $table->string('approval_token', 1024)->nullable(); 
            $table->enum('decision', ['pending', 'approved', 'denied'])->default('pending');
            $table->uuid('operator_id')->nullable();
            $table->timestamp('resolution_locked_at')->nullable();
            $table->timestamp('dispatched_at')->nullable();
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('hitl_suspensions');
    }
};
