<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

// Role registry fields on the agents table.
//
// role declares how an agent participates in multi-agent workflows:
//   orchestrator  — can spawn and direct sub-agents
//   sub_agent     — may only act when invoked by its declared orchestrator
//   peer          — communicates laterally; cannot spawn
//   autonomous    — operates without an orchestrator (highest swarm threshold)
//   tool_executor — passive; only executes tools when called by another agent
//
// orchestrator_id is meaningful only for sub_agent role: it binds the sub-agent
// to a specific orchestrator. Using a specific ID rather than "any certified
// orchestrator" prevents an attacker from registering a fake orchestrator to
// unlock a sub_agent's permissions — the binding is declared by the developer
// at registration time and cannot be changed without re-registering.
//
// Default: 'autonomous' — the most scrutinised role, appropriate for any agent
// that doesn't explicitly declare membership in an orchestration hierarchy.
return new class extends Migration
{
    public function up(): void
    {
        if (!$this->columnExists('agents', 'role')) {
            DB::statement("
                ALTER TABLE agents
                ADD COLUMN role VARCHAR(50) NOT NULL DEFAULT 'autonomous'
                    CHECK (role IN ('orchestrator','sub_agent','peer','autonomous','tool_executor'))
            ");
        }
        if (!$this->columnExists('agents', 'orchestrator_id')) {
            DB::statement('
                ALTER TABLE agents
                ADD COLUMN orchestrator_id UUID NULL REFERENCES agents(id) ON DELETE SET NULL
            ');
        }
    }

    public function down(): void
    {
        DB::statement('ALTER TABLE agents DROP COLUMN IF EXISTS role');
        DB::statement('ALTER TABLE agents DROP COLUMN IF EXISTS orchestrator_id');
    }

    private function columnExists(string $table, string $column): bool
    {
        return DB::select(
            "SELECT 1 FROM information_schema.columns
              WHERE table_name = ? AND column_name = ?",
            [$table, $column]
        ) !== [];
    }
};
