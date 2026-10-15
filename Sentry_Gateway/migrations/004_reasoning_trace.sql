-- Migration 004: Add reasoning_trace to action_ledger
--
-- The Sentry Gateway extracts chain-of-thought reasoning from Claude <thinking>
-- blocks and OpenAI reasoning_content and stores it in the SQLite edge ledger.
-- This column closes the sync gap so reasoning traces reach the central Postgres
-- vault and become available to the biography and compliance export endpoints.
--
-- The trigger on action_ledger prevents UPDATE, so this column is write-once.
-- NULL means the call had no reasoning trace (non-thinking model or non-LLM proxy).

ALTER TABLE action_ledger
    ADD COLUMN IF NOT EXISTS reasoning_trace TEXT NULL;

COMMENT ON COLUMN action_ledger.reasoning_trace IS
    'Raw chain-of-thought reasoning captured at the edge (Claude <thinking> / OpenAI reasoning_content). NULL when not present.';
