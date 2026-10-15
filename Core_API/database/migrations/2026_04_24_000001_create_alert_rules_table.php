<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Creates the alert_rules table for operator-configured security alerting.
 * Each rule maps a specific event type to a notification channel (email, webhook, Aegis).
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('alert_rules', function (Blueprint $table) {
            $table->uuid('id')->primary()->default(DB::raw('gen_random_uuid()'));
            $table->string('event_type');          // e.g. 'agent_blocked', 'circuit_breaker_trip'
            $table->string('channel');              // 'email', 'webhook', 'aegis'
            $table->string('destination');           // email address, webhook URL, or 'aegis'
            $table->boolean('enabled')->default(true);
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('alert_rules');
    }
};
