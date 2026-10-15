-- Semantic alignment score: cosine similarity between the agent's declared purpose
-- (from registration) and the actual payload of each call. Computed by the
-- Verification Swarm and synced here by the edge ledger reconciliation loop.
-- NULL means the score has not yet been computed for that call.
ALTER TABLE action_ledger ADD COLUMN IF NOT EXISTS semantic_alignment_score NUMERIC(5,4) NULL;

CREATE INDEX IF NOT EXISTS idx_action_ledger_alignment
    ON action_ledger (agent_id, semantic_alignment_score)
    WHERE semantic_alignment_score IS NOT NULL;
