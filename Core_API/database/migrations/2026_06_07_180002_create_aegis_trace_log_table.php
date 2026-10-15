<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Aegis Trace Log — full decision chain for every Aegis reasoning cycle.
 * Each cycle produces multiple rows (trigger → context → reasoning → decision → gate → execution → result).
 * Grouped by trace_id for reconstruction.
 */
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Facades\DB;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('aegis_trace_log', function (Blueprint $table) {
            $table->uuid('id')->primary()->default(DB::raw('gen_random_uuid()'));
            $table->string('trace_id')->index();
            $table->string('step');              // trigger | context | reasoning | decision | gate | execution | result
            $table->integer('step_order');
            $table->jsonb('content');             // step-specific payload
            $table->string('model_id')->nullable();
            $table->integer('tokens_in')->default(0);
            $table->integer('tokens_out')->default(0);
            $table->integer('duration_ms')->default(0);
            $table->timestamp('created_at')->default(DB::raw('NOW()'));
        });

        // Index for efficient time-range queries
        Schema::table('aegis_trace_log', function (Blueprint $table) {
            $table->index('created_at', 'idx_aegis_trace_created');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('aegis_trace_log');
    }
};
