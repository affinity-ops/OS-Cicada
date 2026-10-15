<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

/**
 * Creates the revocation_webhooks table for cross-system revocation (H2.3).
 *
 * When Cicada quarantines an agent, the agent may still hold independent OAuth
 * tokens for external services (Slack, Stripe, GitHub, etc.). This table stores
 * the outbound webhook endpoints that Cicada fires when a quarantine event occurs,
 * allowing external IdPs and SIEM platforms to revoke the agent's sessions.
 *
 * Each tenant can configure multiple webhook endpoints, each scoped to a specific
 * event type (agent_quarantined, circuit_breaker_trip, operator_quarantine).
 *
 * Wire format follows the IETF Shared Signals Framework (SSF) / CAEP standard
 * so that IdPs supporting CAEP (Okta, Microsoft Entra, Google) can consume the
 * events natively.
 */
return new class extends Migration
{
    public function up(): void
    {
        if (!Schema::hasTable('revocation_webhooks')) {
            DB::statement("
                CREATE TABLE revocation_webhooks (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
                    
                    -- Human-readable label for the dashboard (e.g. 'Okta Universal Logout')
                    name VARCHAR(255) NOT NULL,
                    
                    -- HTTPS webhook URL to POST the revocation event to.
                    -- Must be HTTPS and resolve to a public IP (SSRF protection enforced at runtime).
                    endpoint_url TEXT NOT NULL,
                    
                    -- Event types this webhook subscribes to. JSONB array.
                    -- Supported: 'agent_quarantined', 'circuit_breaker_trip', 'operator_quarantine',
                    --            'attestation_failed', 'canary_triggered'
                    event_types JSONB NOT NULL DEFAULT '[\"agent_quarantined\"]'::jsonb,
                    
                    -- Authentication method for outbound calls.
                    -- 'bearer_token': sends Authorization: Bearer <secret>
                    -- 'hmac_sha256':  signs the payload body with HMAC-SHA256
                    -- 'none':         no authentication (not recommended)
                    auth_method VARCHAR(50) NOT NULL DEFAULT 'bearer_token',
                    
                    -- The secret used for authentication (encrypted at rest via Laravel Crypt).
                    -- For bearer_token: the token value.
                    -- For hmac_sha256:  the HMAC secret key.
                    auth_secret TEXT,
                    
                    -- Whether this webhook is active. Disabled webhooks are skipped.
                    enabled BOOLEAN NOT NULL DEFAULT true,
                    
                    -- Last successful delivery timestamp (for health monitoring).
                    last_success_at TIMESTAMP NULL,
                    
                    -- Last failure message (for debugging in the dashboard).
                    last_failure_reason TEXT NULL,
                    
                    -- Consecutive failure count. After 5 consecutive failures, the webhook
                    -- is automatically disabled and an alert is raised.
                    consecutive_failures INTEGER NOT NULL DEFAULT 0,
                    
                    created_at TIMESTAMP DEFAULT NOW(),
                    updated_at TIMESTAMP DEFAULT NOW()
                )
            ");

            DB::statement("CREATE INDEX idx_revocation_webhooks_tenant ON revocation_webhooks(tenant_id)");
            DB::statement("CREATE INDEX idx_revocation_webhooks_enabled ON revocation_webhooks(tenant_id, enabled) WHERE enabled = true");
        }
    }

    public function down(): void
    {
        Schema::dropIfExists('revocation_webhooks');
    }
};
