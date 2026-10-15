-- Sentry Gateway isolated schema
-- These tables are strictly owned by the Sentry Gateway and live in the 'sentry' schema.

CREATE TABLE IF NOT EXISTS mobile_devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id TEXT NOT NULL,
    ed25519_pub TEXT NOT NULL,
    x25519_pub TEXT NOT NULL,
    push_token TEXT,
    push_platform TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    last_heartbeat_at TIMESTAMPTZ,
    paired_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    device_model TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ml_dsa65_pub TEXT NOT NULL DEFAULT '',
    ml_kem768_pub TEXT NOT NULL DEFAULT '',
    UNIQUE (ed25519_pub),
    CHECK (push_platform IN ('android', 'ios')),
    CHECK (status IN ('active', 'suspended', 'revoked'))
);
CREATE INDEX IF NOT EXISTS idx_mobile_devices_tenant ON mobile_devices(tenant_id);
CREATE INDEX IF NOT EXISTS idx_mobile_devices_heartbeat ON mobile_devices(last_heartbeat_at) WHERE status = 'active';

CREATE TABLE IF NOT EXISTS decision_nonces (
    nonce TEXT PRIMARY KEY,
    hold_ref TEXT NOT NULL,
    consumed_at TIMESTAMPTZ,
    consumed_by TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_decision_nonces_expires ON decision_nonces(expires_at) WHERE consumed_at IS NULL;

CREATE TABLE IF NOT EXISTS hold_payloads (
    hold_ref TEXT PRIMARY KEY,
    ciphertext TEXT NOT NULL,
    ephemeral_pub TEXT NOT NULL,
    nonce TEXT NOT NULL,
    target_device TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_hold_payloads_expires ON hold_payloads(expires_at);

CREATE TABLE IF NOT EXISTS quorum_votes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hold_ref TEXT NOT NULL,
    device_fingerprint TEXT NOT NULL,
    vote TEXT NOT NULL,
    signature TEXT NOT NULL,
    voted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (hold_ref, device_fingerprint),
    CHECK (vote IN ('approve', 'reject', 'modify'))
);
CREATE INDEX IF NOT EXISTS idx_quorum_votes_hold ON quorum_votes(hold_ref);

CREATE TABLE IF NOT EXISTS policy_versions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_name VARCHAR(255) NOT NULL,
    version INTEGER NOT NULL,
    rego_content TEXT NOT NULL,
    created_by VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    active BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_policy_versions_active ON policy_versions(policy_name) WHERE active = TRUE;

CREATE TABLE IF NOT EXISTS aegis_devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    operator_evar_id VARCHAR(255) NOT NULL,
    tenant_id UUID NOT NULL, -- references public.tenants
    gateway_node_id UUID NOT NULL, -- references public.gateway_instances
    device_id VARCHAR(255) UNIQUE NOT NULL,
    platform VARCHAR(50) NOT NULL CHECK (platform IN ('ios', 'android')),
    os_version VARCHAR(50),
    model VARCHAR(255),
    manufacturer VARCHAR(100),
    app_version VARCHAR(50),
    biometric_enrolled BOOLEAN DEFAULT FALSE,
    secure_enclave_available BOOLEAN DEFAULT FALSE,
    attestation_status VARCHAR(50),
    screen_lock_enabled BOOLEAN DEFAULT FALSE,
    pairing_ip INET,
    pairing_timestamp TIMESTAMPTZ DEFAULT NOW(),
    mtls_cert_fingerprint VARCHAR(255),
    last_seen_at TIMESTAMPTZ,
    is_active BOOLEAN DEFAULT TRUE,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    location JSONB
);
CREATE INDEX IF NOT EXISTS idx_aegis_devices_tenant ON aegis_devices(tenant_id);
CREATE INDEX IF NOT EXISTS idx_aegis_devices_device_id ON aegis_devices(device_id);
CREATE INDEX IF NOT EXISTS idx_aegis_devices_operator ON aegis_devices(operator_evar_id);

CREATE TABLE IF NOT EXISTS attestation_config (
    tenant_id TEXT PRIMARY KEY,
    enforced BOOLEAN NOT NULL DEFAULT FALSE,
    play_integrity_project_id TEXT,
    play_integrity_credentials_json TEXT,
    app_attest_app_id TEXT,
    app_attest_environment TEXT DEFAULT 'production'
        CHECK (app_attest_environment IN ('production', 'development')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS credential_rotation_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id UUID NOT NULL, -- references public.agents
    tenant_id UUID NOT NULL, -- references public.tenants
    event_type VARCHAR(50) NOT NULL
        CHECK (event_type IN ('rotation', 'notification', 'expiry', 'manual_rotation', 'suspension')),
    old_evar_hash TEXT,
    new_evar_hash TEXT,
    rotation_reason VARCHAR(255),
    notification_tier VARCHAR(20),
    notification_target VARCHAR(512),
    initiated_by VARCHAR(255),
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_rotation_events_agent ON credential_rotation_events(agent_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_rotation_events_tenant ON credential_rotation_events(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_rotation_events_type ON credential_rotation_events(event_type, created_at DESC);

CREATE OR REPLACE FUNCTION prevent_rotation_event_updates()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'UPDATE' OR TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'Immutable audit trail violation: credential_rotation_events cannot be altered.';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_rotation_events_immutable ON credential_rotation_events;
CREATE TRIGGER trg_rotation_events_immutable
BEFORE DELETE OR UPDATE ON credential_rotation_events
FOR EACH ROW EXECUTE FUNCTION prevent_rotation_event_updates();
