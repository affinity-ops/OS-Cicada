-- 003_policy_governance.sql
-- Cicada Policy Store Architecture

CREATE TABLE IF NOT EXISTS policy_versions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_name VARCHAR(255) NOT NULL,
    version INT NOT NULL,
    rego_content TEXT NOT NULL,
    created_by VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    active BOOLEAN NOT NULL DEFAULT FALSE
);

-- Ensure only one active version per policy name
CREATE UNIQUE INDEX idx_policy_versions_active ON policy_versions (policy_name) WHERE active = TRUE;

-- Insert the initial default policy as version 1
INSERT INTO policy_versions (policy_name, version, rego_content, created_by, active)
VALUES (
    'authz.rego',
    1,
    'package cicada.agent.authz

default allow = false

# Allow if the target action matches the agent''s EVAR allowed scopes
allow {
    some i
    input.evar_scopes[i] == input.action_scope
    not is_blacklisted
    not is_over_budget
}

is_blacklisted {
    input.agent_status == "revoked"
}

is_over_budget {
    input.action_cost + input.current_spend > input.spend_limit
}',
    'system_bootstrap',
    TRUE
) ON CONFLICT DO NOTHING;
