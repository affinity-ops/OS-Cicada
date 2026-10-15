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
        // We only perform native partitioning on PostgreSQL
        if (DB::getDriverName() !== 'pgsql') {
            return;
        }

        // Rename the existing unpartitioned table
        DB::statement('ALTER TABLE action_ledger RENAME TO action_ledger_old');

        // Create the new partitioned table
        // We include all current columns
        DB::statement("
            CREATE TABLE action_ledger (
                trace_id UUID NOT NULL,
                tenant_id UUID,
                agent_id UUID,
                action_type VARCHAR(100),
                payload_hash VARCHAR(128),
                target_api VARCHAR(500),
                status VARCHAR(50) DEFAULT 'completed',
                swarm_confidence_score NUMERIC(5, 4),
                policy_violations JSONB,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                shadow_violation BOOLEAN DEFAULT false,
                human_user_context JSONB,
                reasoning_trace TEXT,
                semantic_alignment_score NUMERIC(5, 4),
                model VARCHAR(100),
                PRIMARY KEY (trace_id, created_at)
            ) PARTITION BY RANGE (created_at);
        ");

        // Define partitions for current and next few months (assuming present is May 2026)
        DB::statement("CREATE TABLE action_ledger_y2026m04 PARTITION OF action_ledger FOR VALUES FROM ('2026-04-01') TO ('2026-05-01');");
        DB::statement("CREATE TABLE action_ledger_y2026m05 PARTITION OF action_ledger FOR VALUES FROM ('2026-05-01') TO ('2026-06-01');");
        DB::statement("CREATE TABLE action_ledger_y2026m06 PARTITION OF action_ledger FOR VALUES FROM ('2026-06-01') TO ('2026-07-01');");
        DB::statement("CREATE TABLE action_ledger_y2026m07 PARTITION OF action_ledger FOR VALUES FROM ('2026-07-01') TO ('2026-08-01');");
        
        // A default partition catches anything out of bounds (past or future not specified)
        DB::statement("CREATE TABLE action_ledger_default PARTITION OF action_ledger DEFAULT;");

        // Migrate data from old table to new partitioned table
        DB::statement('
            INSERT INTO action_ledger (
                trace_id, tenant_id, agent_id, action_type, payload_hash, target_api, status, 
                swarm_confidence_score, policy_violations, created_at, shadow_violation, 
                human_user_context, reasoning_trace, semantic_alignment_score, model
            )
            SELECT 
                trace_id, tenant_id, agent_id, action_type, payload_hash, target_api, status, 
                swarm_confidence_score, policy_violations, created_at, shadow_violation, 
                human_user_context, reasoning_trace, semantic_alignment_score, model
            FROM action_ledger_old;
        ');

        // Drop the old table (which also drops its indexes)
        DB::statement('DROP TABLE action_ledger_old;');

        // Create indexes on the partitioned table using new names to avoid transaction conflicts
        DB::statement('CREATE INDEX idx_part_action_ledger_trace_id ON action_ledger (trace_id);');
        DB::statement('CREATE INDEX idx_part_action_ledger_alignment ON action_ledger (agent_id, semantic_alignment_score);');
        DB::statement('CREATE INDEX idx_part_action_ledger_model ON action_ledger (agent_id, model);');
        DB::statement('CREATE INDEX idx_part_ledger_status ON action_ledger (status);');
        DB::statement('CREATE INDEX idx_part_ledger_tenant_time ON action_ledger (tenant_id, created_at);');
    }

    public function down(): void
    {
        if (DB::getDriverName() !== 'pgsql') {
            return;
        }

        // Rename partitioned table back
        DB::statement('ALTER TABLE action_ledger RENAME TO action_ledger_partitioned');

        // Recreate the unpartitioned table
        DB::statement("
            CREATE TABLE action_ledger (
                trace_id UUID NOT NULL PRIMARY KEY,
                tenant_id UUID,
                agent_id UUID,
                action_type VARCHAR(100),
                payload_hash VARCHAR(128),
                target_api VARCHAR(500),
                status VARCHAR(50) DEFAULT 'completed',
                swarm_confidence_score NUMERIC(5, 4),
                policy_violations JSONB,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                shadow_violation BOOLEAN DEFAULT false,
                human_user_context JSONB,
                reasoning_trace TEXT,
                semantic_alignment_score NUMERIC(5, 4),
                model VARCHAR(100)
            );
        ");

        // Migrate data back
        DB::statement('
            INSERT INTO action_ledger (
                trace_id, tenant_id, agent_id, action_type, payload_hash, target_api, status, 
                swarm_confidence_score, policy_violations, created_at, shadow_violation, 
                human_user_context, reasoning_trace, semantic_alignment_score, model
            )
            SELECT 
                trace_id, tenant_id, agent_id, action_type, payload_hash, target_api, status, 
                swarm_confidence_score, policy_violations, created_at, shadow_violation, 
                human_user_context, reasoning_trace, semantic_alignment_score, model
            FROM action_ledger_partitioned;
        ');

        // Drop the partitioned table
        DB::statement('DROP TABLE action_ledger_partitioned CASCADE;');

        // Create original indexes
        DB::statement('CREATE INDEX action_ledger_trace_id_index ON action_ledger (trace_id);');
        DB::statement('CREATE INDEX idx_action_ledger_alignment ON action_ledger (agent_id, semantic_alignment_score);');
        DB::statement('CREATE INDEX idx_action_ledger_model ON action_ledger (agent_id, model);');
        DB::statement('CREATE INDEX idx_ledger_status ON action_ledger (status);');
        DB::statement('CREATE INDEX idx_ledger_tenant_time ON action_ledger (tenant_id, created_at);');
    }
};
