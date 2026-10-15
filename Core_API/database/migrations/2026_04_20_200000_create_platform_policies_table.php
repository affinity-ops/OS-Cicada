<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Facades\DB;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('platform_policies', function (Blueprint $table) {
            $table->uuid('id')->primary()->default(DB::raw('gen_random_uuid()'));
            $table->string('slug')->unique();
            $table->string('name');
            $table->text('description')->nullable();
            $table->string('filename');
            $table->string('environment')->default('production'); // production | staging
            $table->string('status')->default('healthy');         // healthy | warning | error
            $table->jsonb('rule_config')->nullable();             // configurable thresholds
            $table->jsonb('exceptions')->default('[]');           // array of agent IDs exempted
            $table->integer('line_count')->default(0);
            $table->timestamps();
        });

        // Seed the two initial platform policies
        DB::table('platform_policies')->insert([
            [
                'slug'        => 'block_untrusted_traffic',
                'name'        => 'Block Untrusted Traffic',
                'description' => 'Blocks all requests from sources not in the trusted zones list.',
                'filename'    => 'rules_global.yaml',
                'environment' => 'production',
                'status'      => 'healthy',
                'rule_config' => json_encode(['trusted_zones' => ['cicada_verified', 'partner_network']]),
                'exceptions'  => '[]',
                'line_count'  => 242,
                'created_at'  => now(),
                'updated_at'  => now(),
            ],
            [
                'slug'        => 'trust_score_check',
                'name'        => 'Trust Score Check',
                'description' => 'Blocks agents whose trust score falls below the minimum threshold.',
                'filename'    => 'auth_eval_v4.yaml',
                'environment' => 'staging',
                'status'      => 'warning',
                'rule_config' => json_encode(['min_trust_score' => 80]),
                'exceptions'  => '[]',
                'line_count'  => 84,
                'created_at'  => now(),
                'updated_at'  => now(),
            ],
        ]);
    }

    public function down(): void
    {
        Schema::dropIfExists('platform_policies');
    }
};
