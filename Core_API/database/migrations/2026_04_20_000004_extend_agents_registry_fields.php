<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        $cols = DB::select("SELECT column_name FROM information_schema.columns WHERE table_name = 'agents'");
        $existing = array_column($cols, 'column_name');

        $additions = [
            // Human-readable identity
            'name'                   => 'VARCHAR(255) NULL',
            'description'            => 'TEXT NULL',

            // Architecture type — informs how the Swarm tests failure paths
            'agent_type'             => "VARCHAR(50) NOT NULL DEFAULT 'reactive' CHECK (agent_type IN ('reactive','heartbeat','scheduled','autonomous'))",

            // Semantic version of the agent code — required for re-certification tracking
            'version'                => "VARCHAR(50) NOT NULL DEFAULT '1.0.0'",

            // Certified failure behaviour — what the agent MAY do when blocked or rejected.
            // NULL = no failure actions permitted beyond silent exit.
            'failure_scope'          => 'JSONB NULL',

            // Certification lifecycle
            'certified_at'           => 'TIMESTAMP WITH TIME ZONE NULL',
            'recertification_due_at' => 'TIMESTAMP WITH TIME ZONE NULL',

            'updated_at'             => 'TIMESTAMP WITH TIME ZONE NULL',
        ];

        foreach ($additions as $col => $definition) {
            if (!in_array($col, $existing)) {
                DB::statement("ALTER TABLE agents ADD COLUMN {$col} {$definition}");
            }
        }
    }

    public function down(): void
    {
        // Intentionally left narrow — dropping registry columns would destroy data.
    }
};
