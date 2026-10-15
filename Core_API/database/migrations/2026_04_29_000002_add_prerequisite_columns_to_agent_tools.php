<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

// Migration: Adds prerequisite enforcement columns to agent_tools.
//
// Two new columns enable the Forward Saga pattern (Pillar 3 of Multi-Faceted
// Agent Governance):
//
//   tool_scope: Binds each tool to a specific permission facet (read/write/delete/transact).
//               The Gateway validates that the agent's current HTTP method matches the
//               tool's declared scope. A tool scoped to "read" cannot be used in a POST.
//
//   requires_previous_tool: Links to another tool_id that MUST have been successfully
//                           executed (recorded in the action_ledger) within the last
//                           10 minutes before this tool can be called. This creates
//                           the Forward Saga: "no Delete without a prior Backup."
//
// Example:
//   tool_id="storage:delete_volume"  requires_previous_tool="storage:verify_backup"
//   → Gateway queries ledger: "Has this agent successfully called verify_backup recently?"
//   → No backup in ledger = Delete rejected (action chain broken)
return new class extends Migration
{
    public function up(): void
    {
        // tool_scope: which class of operation this tool is allowed for.
        // Values: read, write, delete, transact (matches HTTP method classification).
        // NULL means the tool is unrestricted (backwards compatible with existing data).
        DB::statement("
            ALTER TABLE agent_tools
            ADD COLUMN IF NOT EXISTS tool_scope VARCHAR(50) NULL
            CHECK (tool_scope IN ('read', 'write', 'delete', 'transact'))
        ");
        DB::statement("COMMENT ON COLUMN agent_tools.tool_scope IS 'Permission facet: read/write/delete/transact. NULL = unrestricted.'");

        // requires_previous_tool: the tool_id that must appear in the ledger
        // (for this agent, within the prerequisite window) before this tool can execute.
        // NULL means no prerequisite (tool can be called freely).
        DB::statement("
            ALTER TABLE agent_tools
            ADD COLUMN IF NOT EXISTS requires_previous_tool VARCHAR(255) NULL
        ");
        DB::statement("COMMENT ON COLUMN agent_tools.requires_previous_tool IS 'tool_id that must have been executed successfully before this tool can be called (Forward Saga pattern).'");

        // Index for fast prerequisite lookups: given an agent_id and tool_id,
        // quickly find whether this tool has a prerequisite.
        DB::statement("CREATE INDEX IF NOT EXISTS idx_agent_tools_prerequisite ON agent_tools (agent_id, tool_id, requires_previous_tool) WHERE requires_previous_tool IS NOT NULL");
    }

    public function down(): void
    {
        DB::statement("DROP INDEX IF EXISTS idx_agent_tools_prerequisite");
        DB::statement("ALTER TABLE agent_tools DROP COLUMN IF EXISTS requires_previous_tool");
        DB::statement("ALTER TABLE agent_tools DROP COLUMN IF EXISTS tool_scope");
    }
};
