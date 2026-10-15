-- Migration 005: Gateway instances heartbeat registry
--
-- Every Sentry Gateway installation calls home on a configurable interval
-- (default 3 hours via CICADA_HEARTBEAT_INTERVAL). This table is the
-- authoritative record of every gateway in the world — who owns it, where
-- it is, whether it is healthy, and how many agents it is protecting.
--
-- Status logic (computed by the Core API heartbeat endpoint):
--   ONLINE   — last_seen_at within 1× the gateway's reported interval
--   DEGRADED — last_seen_at between 1× and 3× the interval
--   OFFLINE  — last_seen_at beyond 3× the interval or never seen

CREATE TABLE IF NOT EXISTS gateway_instances (
    id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    gateway_id                  VARCHAR(255) UNIQUE NOT NULL,
    tenant_id                   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Version and location
    gateway_version             VARCHAR(50) NOT NULL DEFAULT 'unknown',
    region                      VARCHAR(100) NULL,
    country                     VARCHAR(100) NULL,
    ip_address                  VARCHAR(45) NULL,       -- IPv4 or IPv6

    -- Current snapshot metrics
    agents_registered           INT NOT NULL DEFAULT 0,
    calls_last_window           BIGINT NOT NULL DEFAULT 0,
    calls_blocked_last_window   BIGINT NOT NULL DEFAULT 0,

    -- Security posture
    tls_enabled                 BOOL NOT NULL DEFAULT FALSE,
    mtls_enabled                BOOL NOT NULL DEFAULT FALSE,
    canary_tokens_active        INT NOT NULL DEFAULT 0,
    quarantined_agents          INT NOT NULL DEFAULT 0,

    -- Health
    status                      VARCHAR(20) NOT NULL DEFAULT 'pending'
                                    CHECK (status IN ('pending', 'online', 'degraded', 'offline')),
    last_seen_at                TIMESTAMP WITH TIME ZONE NULL,
    first_registered_at         TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,

    -- Arbitrary gateway-reported metadata (uptime, Redis/Postgres health, etc.)
    metadata                    JSONB NULL
);

CREATE INDEX IF NOT EXISTS idx_gateway_tenant  ON gateway_instances(tenant_id);
CREATE INDEX IF NOT EXISTS idx_gateway_status  ON gateway_instances(status);
CREATE INDEX IF NOT EXISTS idx_gateway_country ON gateway_instances(country);
CREATE INDEX IF NOT EXISTS idx_gateway_seen    ON gateway_instances(last_seen_at);
