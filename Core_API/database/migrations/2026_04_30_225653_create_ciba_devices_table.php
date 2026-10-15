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
        Schema::create('devices', function (Blueprint $table) {
            $table->id();
            $table->foreignUuid('owner_id')->constrained('contacts')->onDelete('cascade');
            $table->string('public_key', 512)->unique();
            $table->string('device_name', 100);
            $table->timestamp('registered_at');
            $table->timestamp('last_seen_at')->nullable();
            $table->timestamps();
            
            $table->unique('owner_id'); // SINGLE DEVICE ENFORCEMENT
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('devices');
    }
};
