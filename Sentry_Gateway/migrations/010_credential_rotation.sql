-- 010_credential_rotation.sql
-- S6.6 / S6.7 / S6.9: Credential Rotation Lifecycle
--
-- Tracks EVAR credential issuance and rotation history for every agent.
-- The rotation_events table is append-only (like the action_ledger) to provide
-- a tamper-evident audit trail for Tier-1 auditors.
--
-- Configuration:
--   CICADA_ROTATION_PERIOD_DAYS — defaults to 90
--   CICADA_ROTATION_NOTIFY_DAYS — comma-separated pre-notification days (default: 7,1)

-- Agent credential metadata (extends agents table)
ALTER TABLE agents
    ADD COLUMN IF NOT EXISTS evar_issued_at         TIMESTAMP WITH TIME ZONE,
    ADD COLUMN IF NOT EXISTS evar_expires_at         TIMESTAMP WITH TIME ZONE,
    ADD COLUMN IF NOT EXISTS evar_rotation_count     INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS evar_last_rotated_at    TIMESTAMP WITH TIME ZONE,
    ADD COLUMN IF NOT EXISTS evar_rotation_status    VARCHAR(50) DEFAULT 'active'
        CHECK (evar_rotation_status IN ('active', 'expiring_soon', 'expired', 'rotated', 'suspended'));

COMMENT ON COLUMN agents.evar_issued_at IS
    'Timestamp when the current EVAR was minted. Used to calculate rotation eligibility.';
COMMENT ON COLUMN agents.evar_expires_at IS
    'Hard expiry based on CICADA_ROTATION_PERIOD_DAYS. After this, the EVAR is rejected.';
COMMENT ON COLUMN agents.evar_rotation_count IS
    'Total number of times the credential has been rotated. Monotonic counter for audit.';
COMMENT ON COLUMN agents.evar_last_rotated_at IS
    'Timestamp of the most recent rotation event.';
COMMENT ON COLUMN agents.evar_rotation_status IS
    'Current lifecycle state: active → expiring_soon → expired/rotated.';

-- Index for the rotation monitor query (find agents needing rotation)
CREATE INDEX IF NOT EXISTS idx_agents_rotation_status
    ON agents(evar_rotation_status) WHERE evar_rotation_status != 'active';

-- Credential rotation audit trail (append-only)
CREATE TABLE IF NOT EXISTS credential_rotation_events (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id            UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    tenant_id           UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Event classification
    event_type          VARCHAR(50) NOT NULL
        CHECK (event_type IN ('rotation', 'notification', 'expiry', 'manual_rotation', 'suspension')),

    -- Rotation details
    old_evar_hash       TEXT,                -- SHA-256 of the previous EVAR JWT (first 16 chars stored)
    new_evar_hash       TEXT,                -- SHA-256 of the new EVAR JWT
    rotation_reason     VARCHAR(255),        -- 'scheduled_90day', 'manual', 'policy_violation', 'compromise'

    -- Pre-notification tracking (S6.7)
    notification_tier   VARCHAR(20),         -- '7d', '24h', '1h' — which notification was sent
    notification_target VARCHAR(512),        -- webhook URL or email that received the notification

    -- Audit metadata
    initiated_by        VARCHAR(255),        -- 'system/rotation-monitor', 'operator/admin@example.com'
    ip_address          INET,                -- Source IP of manual rotation requests
    user_agent          TEXT,                -- HTTP User-Agent for manual rotations

    created_at          TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for audit queries
CREATE INDEX IF NOT EXISTS idx_rotation_events_agent
    ON credential_rotation_events(agent_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_rotation_events_tenant
    ON credential_rotation_events(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_rotation_events_type
    ON credential_rotation_events(event_type, created_at DESC);

-- Enforce append-only on the audit trail (same pattern as action_ledger)
CREATE OR REPLACE FUNCTION prevent_rotation_event_updates()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'UPDATE' OR TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'Immutable audit trail violation: credential_rotation_events cannot be altered.';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_rotation_events_immutable
BEFORE UPDATE OR DELETE ON credential_rotation_events
FOR EACH ROW EXECUTE FUNCTION prevent_rotation_event_updates();

-- RLS policy for tenant isolation
ALTER TABLE credential_rotation_events ENABLE ROW LEVEL SECURITY;

CREATE POLICY isolate_rotation_events_by_tenant ON credential_rotation_events
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', TRUE), '')::UUID);
