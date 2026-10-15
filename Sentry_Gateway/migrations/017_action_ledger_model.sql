-- Migration 013: Add model column to action_ledger
--
-- Records which LLM model was used for each proxied call.
-- Both OpenAI (e.g. "gpt-4o") and Anthropic (e.g. "claude-3-5-sonnet-20241022")
-- include the model name in the top-level JSON body of every request.
-- The Gateway's LLM proxy handler now extracts this value and persists it.
--
-- NULL for non-LLM actions (agent/proxy, inbound validation, aegis directives).

ALTER TABLE action_ledger ADD COLUMN IF NOT EXISTS model VARCHAR(100) NULL;

-- Index for the flow-data aggregate query (agent → model → target_api grouping)
CREATE INDEX IF NOT EXISTS idx_action_ledger_model
    ON action_ledger (agent_id, model)
    WHERE model IS NOT NULL;
