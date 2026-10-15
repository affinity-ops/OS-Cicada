-- 013_scim_operators.sql
-- S6.4: SCIM 2.0 Provisioning for Operator Lifecycle
--
-- Stores operator (human user) accounts that are provisioned via SCIM or
-- auto-created during federated login. This is the authoritative record of
-- who has access to the Operator Dashboard and Gateway Portal.

CREATE TABLE IF NOT EXISTS operators (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- SCIM Core attributes (RFC 7643 §4.1)
    external_id     TEXT,                      -- IdP's external identifier
    username        TEXT NOT NULL,              -- SCIM userName (typically email)
    email           TEXT NOT NULL,
    display_name    TEXT,
    given_name      TEXT,
    family_name     TEXT,

    -- Cicada-specific
    role            VARCHAR(50) NOT NULL DEFAULT 'viewer'
        CHECK (role IN ('guest', 'viewer', 'operator', 'admin', 'super_admin')),
    active          BOOLEAN NOT NULL DEFAULT true,

    -- Provisioning metadata
    provider_id     UUID REFERENCES federation_providers(id),  -- which IdP provisioned this user
    scim_id         TEXT,                       -- SCIM resource ID (returned to IdP)
    provisioned_at  TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deprovisioned_at TIMESTAMP WITH TIME ZONE,

    -- Standard timestamps
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT unique_tenant_username UNIQUE (tenant_id, username),
    CONSTRAINT unique_tenant_email UNIQUE (tenant_id, email)
);

CREATE INDEX IF NOT EXISTS idx_operators_tenant ON operators(tenant_id) WHERE active = true;
CREATE INDEX IF NOT EXISTS idx_operators_external_id ON operators(external_id) WHERE external_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_operators_scim_id ON operators(scim_id) WHERE scim_id IS NOT NULL;

-- SCIM provisioning audit trail
CREATE TABLE IF NOT EXISTS scim_audit_log (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    operator_id     UUID REFERENCES operators(id),

    event_type      VARCHAR(50) NOT NULL
        CHECK (event_type IN ('create', 'update', 'deactivate', 'reactivate', 'delete', 'patch')),
    scim_operation  TEXT,                       -- raw SCIM operation for forensics
    changed_fields  JSONB,                     -- which fields changed
    initiated_by    VARCHAR(255),              -- "scim/okta", "scim/azure-ad", "manual/admin@example.com"

    created_at      TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_scim_audit_tenant ON scim_audit_log(tenant_id, created_at DESC);

-- RLS
ALTER TABLE operators ENABLE ROW LEVEL SECURITY;
ALTER TABLE scim_audit_log ENABLE ROW LEVEL SECURITY;

CREATE POLICY isolate_operators ON operators
    FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', TRUE), '')::UUID);
CREATE POLICY isolate_scim_audit ON scim_audit_log
    FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', TRUE), '')::UUID);
