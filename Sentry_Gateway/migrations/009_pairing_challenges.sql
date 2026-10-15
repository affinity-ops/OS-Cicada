-- ============================================================================
-- Migration 009: Mobile Pairing Challenges
-- ============================================================================
--
-- Stores single-use, time-bounded challenge nonces for QR-based device
-- pairing. The portal generates a challenge via POST /v1/portal/pair/generate,
-- which inserts a row here. The device scans the QR code containing the nonce,
-- signs it, and sends it to POST /v1/mobile/pair/handshake, which looks up and
-- consumes the nonce from this table.
--
-- Nonces are deleted on successful handshake or expire after 5 minutes.
--
-- Attestation:
--   The attestation_required column controls whether the gateway enforces
--   device attestation (Google Play Integrity / Apple App Attest) during
--   handshake. Set to TRUE in production once credentials are configured.
--   When FALSE, the gateway accepts any device (development/testing mode).
--
-- Safe to re-run: all statements use IF NOT EXISTS.
-- ============================================================================

-- ── Pairing Challenges ─────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS mobile_pairing_challenges (
    -- The challenge nonce — a cryptographically random string.
    -- This is what appears in the QR code and what the device signs.
    nonce TEXT PRIMARY KEY,

    -- Which tenant this challenge was generated for.
    -- Determines which tenant the device will be bound to on handshake.
    tenant_id TEXT NOT NULL,

    -- When this challenge expires. Default 5 minutes from creation.
    -- The gateway rejects handshakes for expired challenges.
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,

    -- When this challenge was created.
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Index for periodic cleanup of expired challenges.
CREATE INDEX IF NOT EXISTS idx_pairing_challenges_expires
    ON mobile_pairing_challenges(expires_at);

-- ── Attestation Configuration ──────────────────────────────────────────────
-- This table stores per-tenant attestation configuration.
-- When attestation is enforced, the gateway validates the device's
-- attestation token (Play Integrity / App Attest) during handshake.
-- Credentials (API keys, bundle IDs) are stored here so they can be
-- configured via the portal without redeploying the gateway.

CREATE TABLE IF NOT EXISTS attestation_config (
    tenant_id TEXT PRIMARY KEY,

    -- Whether attestation is enforced for this tenant.
    -- FALSE = development mode (any device accepted).
    -- TRUE  = production mode (valid attestation token required).
    enforced BOOLEAN NOT NULL DEFAULT FALSE,

    -- Google Play Integrity API credentials (Android).
    -- Store the decryption key and verification key from Google Cloud Console.
    -- NULL when not configured.
    play_integrity_project_id TEXT,
    play_integrity_credentials_json TEXT,

    -- Apple App Attest configuration (iOS).
    -- The App ID (team ID + bundle ID) used to verify attestation objects.
    -- NULL when not configured.
    app_attest_app_id TEXT,
    app_attest_environment TEXT DEFAULT 'production'
        CHECK (app_attest_environment IN ('production', 'development')),

    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
