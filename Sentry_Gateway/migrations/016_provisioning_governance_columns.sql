-- Migration 016: Add missing provisioning governance columns
--
-- The ProvisioningController writes to these columns during agent
-- registration, but they were never added to the Go-managed schema.
-- This closes the ghost_mode_allowed bug that caused all provisioning
-- tests to 500.

-- Ghost Mode: operator flag allowing agent to operate in stealth/shadow mode
ALTER TABLE agents ADD COLUMN IF NOT EXISTS ghost_mode_allowed BOOLEAN NOT NULL DEFAULT FALSE;

-- Swarm Verification: stores the adversarial verification results
ALTER TABLE agents ADD COLUMN IF NOT EXISTS swarm_confidence_score DOUBLE PRECISION DEFAULT 0.0;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS swarm_verdict TEXT DEFAULT NULL;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS swarm_reasons JSONB DEFAULT NULL;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS verified_at TIMESTAMPTZ DEFAULT NULL;

-- Index on verification status for dashboard queries
CREATE INDEX IF NOT EXISTS idx_agents_verified ON agents (verified_at) WHERE verified_at IS NOT NULL;
