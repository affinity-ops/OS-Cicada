-- 012_role_mappings.sql
-- S6.3: IdP Group → Cicada Role Mapping
--
-- Stores configurable rules that translate IdP group memberships
-- into Cicada portal roles. Supports exact, prefix, suffix, and wildcard patterns.

CREATE TABLE IF NOT EXISTS role_mappings (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider_id     UUID NOT NULL REFERENCES federation_providers(id) ON DELETE CASCADE,
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Mapping rule
    idp_group       TEXT NOT NULL,              -- IdP group name or pattern ("engineering", "team-*", "*-readonly")
    cicada_role     VARCHAR(50) NOT NULL
        CHECK (cicada_role IN ('guest', 'viewer', 'operator', 'admin', 'super_admin')),
    priority        INTEGER NOT NULL DEFAULT 0, -- Higher = checked first. Use for tie-breaking.
    description     TEXT,                       -- Human-readable note ("Maps all engineering teams to operator")

    created_at      TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT unique_provider_group UNIQUE (provider_id, idp_group)
);

CREATE INDEX IF NOT EXISTS idx_role_mappings_provider
    ON role_mappings(provider_id, priority DESC);

-- RLS
ALTER TABLE role_mappings ENABLE ROW LEVEL SECURITY;

CREATE POLICY isolate_role_mappings ON role_mappings
    FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', TRUE), '')::UUID);
