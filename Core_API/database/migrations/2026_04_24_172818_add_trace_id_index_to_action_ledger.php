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
        Schema::table('action_ledger', function (Blueprint $table) {
            if (!Schema::hasColumn('action_ledger', 'trace_id')) {
                $table->string('trace_id')->nullable()->after('id');
            }
            $table->index('trace_id');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('action_ledger', function (Blueprint $table) {
            //
        });
    }
};
