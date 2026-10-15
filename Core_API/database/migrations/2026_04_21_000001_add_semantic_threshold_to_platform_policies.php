<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

/**
 * Phase 8: Add per-policy semantic similarity threshold configuration.
 *
 * The Sentry Gateway's semantic memory isolation check (memory.CheckSemanticContamination)
 * uses a similarity threshold to decide when two messages are "close enough" to
 * constitute a contamination event. The default is 0.40 (set via the
 * SEMANTIC_SIMILARITY_THRESHOLD environment variable on the Gateway).
 *
 * This migration adds a context_similarity_threshold column to platform_policies
 * so operators can configure the threshold per-policy via the Security Policies
 * screen in the Operator Dashboard, without touching environment variables or
 * restarting the Gateway.
 *
 * Column semantics:
 *   NULL   — use the Gateway's environment variable default (0.40)
 *   0.20   — high sensitivity: flag loosely similar content (more false positives)
 *   0.40   — balanced default: catches paraphrases of structured data
 *   0.70   — low sensitivity: only flag near-verbatim paraphrases
 *   1.00   — effectively disables semantic check (only exact SimHash matches)
 *
 * The threshold is read by SecurityPolicyController and returned in the
 * GET /api/v1/security/policies response so the Dashboard can display it
 * and the Gateway can read it on policy fetch.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('platform_policies', function (Blueprint $table) {
            // Nullable so existing policies inherit the Gateway default without
            // requiring a data migration.
            $table->decimal('context_similarity_threshold', 4, 3)
                ->nullable()
                ->default(null)
                ->after('rule_config')
                ->comment('Semantic similarity threshold for Phase 8 cross-agent memory isolation. NULL = use Gateway default (0.40).');
        });

        // Update the two existing seed policies to use explicit defaults so
        // the Dashboard displays a value rather than NULL.
        DB::table('platform_policies')
            ->whereIn('slug', ['block_untrusted_traffic', 'trust_score_check'])
            ->update(['context_similarity_threshold' => 0.40]);
    }

    public function down(): void
    {
        Schema::table('platform_policies', function (Blueprint $table) {
            $table->dropColumn('context_similarity_threshold');
        });
    }
};
