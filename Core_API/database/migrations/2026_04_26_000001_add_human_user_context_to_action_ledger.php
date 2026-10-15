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
        if (!Schema::hasColumn('action_ledger', 'human_user_context')) {
            Schema::table('action_ledger', function (Blueprint $table) {
                $table->jsonb('human_user_context')->nullable()->after('shadow_violation');
            });
        }
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('action_ledger', function (Blueprint $table) {
            $table->dropColumn('human_user_context');
        });
    }
};
