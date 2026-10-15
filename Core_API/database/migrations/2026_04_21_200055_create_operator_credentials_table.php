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
        Schema::create('operator_credentials', function (Blueprint $table) {
            $table->uuid('id')->primary();
            $table->string('credential_id')->unique();
            $table->text('public_key'); // Base64 or Hex encoded Uint8Array
            $table->bigInteger('sign_count')->default(0);
            $table->json('transports')->nullable();
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('operator_credentials');
    }
};
