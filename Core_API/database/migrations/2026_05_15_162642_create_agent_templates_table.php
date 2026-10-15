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
        Schema::create('agent_templates', function (Blueprint $table) {
            $table->uuid('id')->primary();
            $table->string('name');
            $table->text('description');
            $table->string('agent_type')->default('reactive');
            $table->string('role')->default('autonomous');
            $table->jsonb('scopes')->nullable();
            $table->text('custom_guardrails')->nullable();
            $table->jsonb('tools')->nullable();
            
            // The tenant that published this template (null for Cicada official)
            $table->uuid('author_tenant_id')->nullable();
            
            // Community verification
            $table->boolean('is_verified')->default(false);
            $table->string('status')->default('published'); // draft, published, rejected
            
            $table->integer('import_count')->default(0);
            
            $table->timestamps();
            
            $table->foreign('author_tenant_id')->references('id')->on('tenants')->onDelete('set null');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('agent_templates');
    }
};
