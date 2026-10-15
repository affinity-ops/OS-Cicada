<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Create the agent_skills table — relational sibling to agent_resource_policies.
 *
 * Stores per-tool skill contracts declared in cicada.yaml. Each row represents
 * a single skill binding: the structural payload schema (JSON Schema), the list
 * of upstream agent IDs permitted to invoke this skill via delegation, and the
 * per-skill criticality classification that drives CIBA escalation thresholds.
 *
 * The compound index on (agent_id, skill_name) enables O(1) lookups during
 * agentcache Redis hydration in the Sentry Gateway.
 */
return new class extends Migration {
    public function up(): void
    {
        Schema::create('agent_skills', function (Blueprint $table) {
            $table->uuid('id')->primary();
            $table->foreignUuid('agent_id')->constrained('agents')->onDelete('cascade');
            $table->string('skill_name', 64);
            $table->jsonb('input_schema')->nullable();  // JSON Schema constraint block
            $table->jsonb('allowed_upstreams')->default('[]'); // Array of agent ID strings
            $table->string('criticality_level', 16)->default('low');
            $table->timestamps();

            // Compound index for O(1) cache hydration lookups
            $table->unique(['agent_id', 'skill_name']);
            $table->index('criticality_level');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('agent_skills');
    }
};
