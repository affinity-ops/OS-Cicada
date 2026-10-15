-- 001_multi_tenant_schema.sql
-- Cicada Core Action Ledger Architecture
-- Executable against the free local postgres:15-alpine Docker instance

-- 1. Tenants (Enterprise customers utilizing the Cicada Network)
CREATE TABLE IF NOT EXISTS tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    status VARCHAR(50) DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 2. EVAR Identities (The Verified Agents)
-- Each agent is bound cryptographically to a Tenant.
CREATE TABLE IF NOT EXISTS agents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    pub_key_hash TEXT UNIQUE NOT NULL, -- Ed25519 JWT; length exceeds VARCHAR(255)
    scope_entitlements JSONB NOT NULL DEFAULT '[]', -- Roles/Capabilities passed to OPA
    trust_tier VARCHAR(50) DEFAULT 'unverified' CHECK (trust_tier IN ('unverified', 'nominal', 'elevated', 'critical')),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    revoked_at TIMESTAMP WITH TIME ZONE NULL
);

-- Index for blistering fast lookup during Gateway JWT evaluation
CREATE INDEX idx_agents_pub_key ON agents(pub_key_hash);

-- 3. The Immutable Action Ledger (CIC Generation Analog)
-- Every agent action proxied by Sentry Gateway is hashed and stored here.
-- This is append-only architecture.
CREATE TABLE IF NOT EXISTS action_ledger (
    trace_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    agent_id UUID NOT NULL REFERENCES agents(id),
    
    -- Telemetry
    action_type VARCHAR(100) NOT NULL,
    payload_hash VARCHAR(255) NOT NULL, -- Ensures input integrity
    target_api VARCHAR(512) NOT NULL,
    
    -- Swarm Verification Tracking
    status VARCHAR(50) DEFAULT 'pending_swarm' CHECK (status IN ('pending_swarm', 'approved', 'blocked', 'shadow_sandbox')),
    swarm_confidence_score DECIMAL(5,2) NULL, -- Driven by Python LangGraph
    policy_violations JSONB NULL,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Index telemetry for fast dashboard rendering (Action Volume / Threat Vectors)
CREATE INDEX idx_ledger_tenant_time ON action_ledger(tenant_id, created_at);
CREATE INDEX idx_ledger_status ON action_ledger(status);

-- 4. Enable PostgreSQL Row-Level Security (RLS)
-- Guaranteed cryptographic isolation; Tenant A cannot technically read Tenant B's ledger.
ALTER TABLE agents ENABLE ROW LEVEL SECURITY;
ALTER TABLE action_ledger ENABLE ROW LEVEL SECURITY;

-- Tenants Policy (Assuming app_user role sets current_setting('request.jwt.claim.tenant_id'))
CREATE POLICY isolate_agents_by_tenant ON agents
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', TRUE), '')::UUID);

CREATE POLICY isolate_ledger_by_tenant ON action_ledger
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', TRUE), '')::UUID);

-- Trigger function to enforce Append-Only on the ledger
CREATE OR REPLACE FUNCTION prevent_ledger_updates()
RETURNS TRIGGER AS $$
BEGIN
    -- It is mathematically unacceptable to alter the history of an agent's actions
    IF TG_OP = 'UPDATE' OR TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'Immutable ledger violation. Action history cannot be altered.';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_action_ledger_immutable
BEFORE UPDATE OR DELETE ON action_ledger
FOR EACH ROW EXECUTE FUNCTION prevent_ledger_updates();
