<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Creates the retention_policies table for operator-configured data lifecycle management.
 * Controls how long each data category is retained before auto-deletion/archival.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('retention_policies', function (Blueprint $table) {
            $table->string('id')->primary();            // e.g. 'action_ledger', 'session_tokens'
            $table->string('label');                     // Human-readable name
            $table->text('description')->nullable();
            $table->integer('retention_days')->default(365);
            $table->boolean('auto_delete')->default(false);
            $table->boolean('archive_before_delete')->default(true);
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('retention_policies');
    }
};
