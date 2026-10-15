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
        Schema::create('operator_audit_log', function (Blueprint $table) {
            $table->id(); // bigserial PK
            $table->uuid('operator_id')->nullable(); 
            // We use nullable here because edge cases or programmatic overrides 
            // might not have a strict bound operator credential UUID in the current design.
            
            $table->string('operator_label')->default('root_admin@cicada.local');
            $table->string('action');
            $table->string('entity_type');
            $table->string('entity_id');
            $table->jsonb('before_state')->nullable();
            $table->jsonb('after_state')->nullable();
            $table->text('notes')->nullable();
            
            $table->ipAddress('ip_address')->nullable();
            
            $table->timestampTz('created_at')->useCurrent();
        });

        Schema::table('operator_audit_log', function (Blueprint $table) {
            $table->index(['entity_type', 'entity_id']);
            $table->index('created_at');
            $table->index('action');
            $table->index('operator_id');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('operator_audit_log');
    }
};
