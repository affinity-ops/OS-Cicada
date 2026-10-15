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
        Schema::table('action_ledger', function (Blueprint $table) {
            if (!Schema::hasColumn('action_ledger', 'reasoning_trace')) {
                $table->text('reasoning_trace')->nullable();
            }
            if (!Schema::hasColumn('action_ledger', 'semantic_alignment_score')) {
                $table->decimal('semantic_alignment_score', 5, 4)->nullable();
            }
            if (!Schema::hasColumn('action_ledger', 'model')) {
                $table->string('model', 100)->nullable();
            }
        });
    }

    public function down(): void
    {
        Schema::table('action_ledger', function (Blueprint $table) {
            $table->dropColumn(['reasoning_trace', 'semantic_alignment_score', 'model']);
        });
    }
};
