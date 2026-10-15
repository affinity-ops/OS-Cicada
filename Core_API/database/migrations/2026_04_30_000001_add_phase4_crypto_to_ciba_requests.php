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
     * Phase 4: Adds cryptographic fields to the CIBA requests table
     * to support the non-repudiable signed decision envelope.
     */
    public function up(): void
    {
        Schema::table('ciba_authorization_requests', function (Blueprint $table) {
            $table->string('decision_nonce')->nullable()->after('updated_at');
            $table->text('signature_ed25519')->nullable()->after('decision_nonce');
            $table->text('signature_ml_dsa65')->nullable()->after('signature_ed25519');
            $table->string('hold_payload_hash')->nullable()->after('signature_ml_dsa65');
            $table->text('attestation_token')->nullable()->after('hold_payload_hash');
            $table->string('ed25519_pub', 128)->nullable()->after('attestation_token');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('ciba_authorization_requests', function (Blueprint $table) {
            $table->dropColumn([
                'decision_nonce',
                'signature_ed25519',
                'signature_ml_dsa65',
                'hold_payload_hash',
                'attestation_token',
                'ed25519_pub'
            ]);
        });
    }
};
