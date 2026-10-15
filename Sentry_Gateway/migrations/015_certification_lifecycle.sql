-- Migration 015: Agent Certification Lifecycle
-- Adds approval_status to agents and creates certification_events audit trail.
--
-- approval_status values:
--   pending_review        — registered, provisional EVAR issued, shadow-only proxy
--   escalation_required   — sanitizer flagged high-severity violations, NO EVAR issued
--   certified             — operator approved, full EVAR active, full enforcement
--   suspended             — operator suspended, 403 at proxy
--   terminated            — operator terminated / revoked, 403 at proxy
--
-- Safe to re-run: uses IF NOT EXISTS / ADD COLUMN IF NOT EXISTS.

-- ── 1. Add approval_status to agents ─────────────────────────────────────────
ALTER TABLE agents ADD COLUMN IF NOT EXISTS approval_status TEXT NOT NULL DEFAULT 'pending_review';

-- Backfill: agents that already have certified_at set should be 'certified'.
-- Agents with revoked_at set should be 'terminated'.
UPDATE agents SET approval_status = 'certified'  WHERE certified_at IS NOT NULL AND approval_status = 'pending_review';
UPDATE agents SET approval_status = 'terminated'  WHERE revoked_at  IS NOT NULL AND approval_status != 'terminated';

-- Index for proxy-layer lookups (called on every request)
CREATE INDEX IF NOT EXISTS idx_agents_approval_status ON agents (approval_status);

-- ── 2. Certification events audit trail ──────────────────────────────────────
CREATE TABLE IF NOT EXISTS certification_events (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id        UUID NOT NULL,
    tenant_id       UUID NOT NULL,
    event_type      TEXT NOT NULL,
    -- event_type values:
    --   registered              — agent first registered
    --   escalation_flagged      — sanitizer flagged high-severity violations
    --   certified               — operator certified the agent
    --   recertified             — operator recertified after expiry
    --   suspended               — operator suspended the agent
    --   terminated              — operator terminated/revoked the agent
    --   recertification_due     — monitor detected recertification expiry
    performed_by    TEXT NOT NULL,          -- operator email, 'system', or 'sanitizer'
    reason          TEXT,                   -- human-readable justification
    metadata        JSONB DEFAULT '{}',     -- sanitizer violations, policy snapshot, etc.
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cert_events_agent ON certification_events (agent_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_cert_events_tenant ON certification_events (tenant_id, created_at DESC);
