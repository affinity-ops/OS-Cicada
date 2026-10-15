<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * oauth_identities — the cryptographic traceability chain.
     *
     * Every agent action can be traced:
     *   action_ledger → agent → tenant → contact → oauth_identity → verified GitHub/Google account
     *
     * A contact may have both GitHub and Google linked.
     * provider_id is the immutable ID assigned by the OAuth provider — email alone is insufficient
     * because users can change their email address.
     */
    public function up(): void
    {
        if (Schema::hasTable('oauth_identities')) {
            return;
        }

        Schema::create('oauth_identities', function (Blueprint $table) {
            $table->uuid('id')->primary()->default(DB::raw('gen_random_uuid()'));
            $table->uuid('contact_id');
            $table->string('provider', 50);           // 'github' | 'google'
            $table->string('provider_id', 255);       // immutable ID from OAuth provider
            $table->string('provider_email', 255);    // email at time of auth
            $table->string('provider_username', 255)->nullable();  // GitHub username if applicable
            $table->text('provider_avatar_url')->nullable();
            $table->timestampTz('created_at')->useCurrent();
            $table->timestampTz('last_used_at')->nullable();

            $table->unique(['provider', 'provider_id']);
            $table->foreign('contact_id')->references('id')->on('contacts')->onDelete('cascade');
        });

        DB::statement('CREATE INDEX idx_oauth_contact ON oauth_identities(contact_id)');
        DB::statement('CREATE INDEX idx_oauth_provider ON oauth_identities(provider, provider_id)');
    }

    public function down(): void
    {
        Schema::dropIfExists('oauth_identities');
    }
};
