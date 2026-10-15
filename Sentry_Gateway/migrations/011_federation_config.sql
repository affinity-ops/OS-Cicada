-- 011_federation_config.sql
-- S6.2: SAML 2.0 / OIDC Federation Configuration
--
-- Stores per-tenant Identity Provider (IdP) configuration for enterprise SSO.
-- Each tenant can configure one or more IdPs for operator authentication.
-- Supports both SAML 2.0 Service Provider (SP) and OIDC Relying Party (RP) modes.

CREATE TABLE IF NOT EXISTS federation_providers (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Provider identification
    name            VARCHAR(255) NOT NULL,         -- "Okta Production", "Azure AD"
    protocol        VARCHAR(10) NOT NULL CHECK (protocol IN ('saml', 'oidc')),
    enabled         BOOLEAN NOT NULL DEFAULT true,

    -- SAML 2.0 configuration (populated when protocol = 'saml')
    saml_entity_id       TEXT,             -- IdP entity ID (e.g., "https://idp.example.com/saml/metadata")
    saml_sso_url         TEXT,             -- IdP SSO login URL (HTTP-Redirect binding)
    saml_slo_url         TEXT,             -- IdP SLO URL (optional)
    saml_certificate     TEXT,             -- IdP signing certificate (PEM, base64)
    saml_name_id_format  VARCHAR(255) DEFAULT 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',

    -- OIDC configuration (populated when protocol = 'oidc')
    oidc_issuer_url      TEXT,             -- IdP issuer URL (discovery: /.well-known/openid-configuration)
    oidc_client_id       TEXT,             -- Client ID from IdP
    oidc_client_secret   TEXT,             -- Client secret (encrypted at rest in production)
    oidc_scopes          TEXT DEFAULT 'openid profile email',
    oidc_redirect_uri    TEXT,             -- Callback URL registered with IdP

    -- Common configuration
    default_role         VARCHAR(50) DEFAULT 'viewer', -- Role assigned to federated users
    allowed_domains      TEXT[],           -- Email domain allowlist (e.g., {"example.com", "corp.example.com"})
    auto_provision       BOOLEAN DEFAULT false,        -- Auto-create operator accounts on first login

    -- Metadata
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT unique_tenant_provider UNIQUE (tenant_id, name)
);

-- Index for quick lookup during login flow
CREATE INDEX IF NOT EXISTS idx_federation_tenant_protocol
    ON federation_providers(tenant_id, protocol) WHERE enabled = true;

-- Federated operator sessions — tracks who logged in via which IdP
CREATE TABLE IF NOT EXISTS federated_sessions (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    provider_id      UUID NOT NULL REFERENCES federation_providers(id) ON DELETE CASCADE,

    -- User identity from IdP
    subject          TEXT NOT NULL,          -- IdP subject identifier (SAML NameID or OIDC sub)
    email            TEXT,
    display_name     TEXT,
    groups           TEXT[],                 -- IdP group memberships (for S6.3 role mapping)
    raw_attributes   JSONB,                 -- Full set of IdP attributes/claims

    -- Session metadata
    session_token    TEXT NOT NULL,          -- Cicada-issued portal JWT
    expires_at       TIMESTAMP WITH TIME ZONE NOT NULL,
    ip_address       INET,
    user_agent       TEXT,

    created_at       TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_federated_sessions_token
    ON federated_sessions(session_token) WHERE expires_at > CURRENT_TIMESTAMP;
CREATE INDEX IF NOT EXISTS idx_federated_sessions_subject
    ON federated_sessions(tenant_id, subject);

-- Federated login audit trail
CREATE TABLE IF NOT EXISTS federation_audit_log (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    provider_id     UUID REFERENCES federation_providers(id),

    event_type      VARCHAR(50) NOT NULL
        CHECK (event_type IN ('login_success', 'login_failure', 'logout', 'token_refresh',
                               'provider_created', 'provider_updated', 'provider_disabled')),

    subject         TEXT,
    email           TEXT,
    ip_address      INET,
    user_agent      TEXT,
    error_detail    TEXT,

    created_at      TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_federation_audit_tenant
    ON federation_audit_log(tenant_id, created_at DESC);

-- RLS
ALTER TABLE federation_providers ENABLE ROW LEVEL SECURITY;
ALTER TABLE federated_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE federation_audit_log ENABLE ROW LEVEL SECURITY;

CREATE POLICY isolate_federation_providers ON federation_providers
    FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', TRUE), '')::UUID);
CREATE POLICY isolate_federated_sessions ON federated_sessions
    FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', TRUE), '')::UUID);
CREATE POLICY isolate_federation_audit ON federation_audit_log
    FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', TRUE), '')::UUID);
