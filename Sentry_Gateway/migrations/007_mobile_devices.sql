-- ============================================================================
-- Migration 007: Mobile Device Registry & Decision Nonces
-- ============================================================================
--
-- Phase 1 (Device Binding):
--   - mobile_devices: Stores enrolled device Ed25519/X25519 public keys,
--     FCM/APNs push tokens, and device lifecycle status.
--   - Each device is bound to a tenant via the ed25519_pub fingerprint.
--   - Status lifecycle: active → suspended → revoked.
--   - The Gateway uses this table to:
--     a) Verify challenge signatures during QR pairing.
--     b) Route push notifications to the correct FCM/APNs token.
--     c) Verify Ed25519 decision signatures against enrolled public keys.
--     d) Track heartbeat recency for extended-offline detection.
--
-- Phase 4 (Non-Repudiable Decisions):
--   - decision_nonces: Single-use nonce tracking for anti-replay protection.
--   - The Gateway issues a unique nonce per HITL hold. When the device
--     submits a signed decision, the Gateway marks the nonce as consumed.
--   - Any attempt to replay a consumed nonce is rejected.
--
-- Phase 7 (Multi-Approval):
--   - quorum_votes: Tracks individual operator votes for M-of-N holds.
--   - The Gateway is authoritative for quorum state. The app reads this
--     via GET /v1/hitl/hold/{ref}/quorum.
--
-- Safe to re-run: all statements use IF NOT EXISTS.
-- ============================================================================

-- ── Mobile Device Registry ─────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS mobile_devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Tenant binding — which organisation this device belongs to.
    tenant_id TEXT NOT NULL,

    -- Ed25519 public key (hex-encoded). This is the device's cryptographic
    -- identity. Used to verify decision signatures. UNIQUE constraint
    -- ensures one device per key — re-pairing generates new keys.
    ed25519_pub TEXT NOT NULL UNIQUE,

    -- X25519 public key (hex-encoded). Used by the Gateway to encrypt
    -- hold payloads for this specific device (Phase 2 hybrid encryption).
    x25519_pub TEXT NOT NULL,

    -- FCM/APNs push token. Updated on every token refresh.
    -- NULL if push has not been registered yet (heartbeat-only mode).
    push_token TEXT,

    -- Platform identifier: 'android' or 'ios'.
    push_platform TEXT CHECK (push_platform IN ('android', 'ios')),

    -- Device lifecycle status.
    --   active:    Normal operation — can receive holds and submit decisions.
    --   suspended: Temporarily blocked — heartbeat returns 'suspended'.
    --              Operator must re-authenticate via Dashboard MFA.
    --   revoked:   Permanently blocked — device must re-pair from scratch.
    status TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'suspended', 'revoked')),

    -- Last successful heartbeat timestamp. Used to detect extended offline
    -- (>72 hours) which triggers auto-suspension per Phase 6 spec.
    last_heartbeat_at TIMESTAMP WITH TIME ZONE,

    -- Pairing timestamp — when the QR handshake completed.
    paired_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    -- Device metadata (model name only — no IMEI, no serial, per Phase 5).
    device_model TEXT,

    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Index for looking up devices by tenant (dashboard device management).
CREATE INDEX IF NOT EXISTS idx_mobile_devices_tenant
    ON mobile_devices(tenant_id);

-- Index for heartbeat recency queries (find extended-offline devices).
CREATE INDEX IF NOT EXISTS idx_mobile_devices_heartbeat
    ON mobile_devices(last_heartbeat_at)
    WHERE status = 'active';

-- ── Decision Nonces (Anti-Replay) ──────────────────────────────────────────

CREATE TABLE IF NOT EXISTS decision_nonces (
    -- The nonce itself — UUID issued by the Gateway when the hold is created.
    nonce TEXT PRIMARY KEY,

    -- The hold this nonce belongs to.
    hold_ref TEXT NOT NULL,

    -- When this nonce was consumed by a signed decision submission.
    -- NULL means the nonce is still valid (unused).
    consumed_at TIMESTAMP WITH TIME ZONE,

    -- Which device consumed it (ed25519_pub fingerprint).
    consumed_by TEXT,

    -- When the nonce was issued.
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    -- Nonces expire with their hold. The Gateway should reject decisions
    -- for expired nonces even if they haven't been consumed.
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL
);

-- Index for cleanup of expired nonces (periodic maintenance job).
CREATE INDEX IF NOT EXISTS idx_decision_nonces_expires
    ON decision_nonces(expires_at)
    WHERE consumed_at IS NULL;

-- ── Quorum Votes (M-of-N Multi-Approval) ──────────────────────────────────

CREATE TABLE IF NOT EXISTS quorum_votes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- The hold this vote applies to.
    hold_ref TEXT NOT NULL,

    -- The device that cast this vote (ed25519_pub fingerprint).
    device_fingerprint TEXT NOT NULL,

    -- The vote: 'approve', 'reject', or 'modify'.
    vote TEXT NOT NULL CHECK (vote IN ('approve', 'reject', 'modify')),

    -- The Ed25519 signature of the decision payload.
    signature TEXT NOT NULL,

    -- When this vote was cast.
    voted_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    -- Prevent duplicate votes from the same device on the same hold.
    UNIQUE (hold_ref, device_fingerprint)
);

-- Index for quorum status lookups (count votes per hold).
CREATE INDEX IF NOT EXISTS idx_quorum_votes_hold
    ON quorum_votes(hold_ref);

-- ── Hold Payloads (Encrypted, Phase 2) ─────────────────────────────────────
-- Stores the encrypted hold payload that the device fetches after biometric
-- wake. The Gateway generates a fresh ephemeral X25519 keypair per payload
-- and encrypts with the device's enrolled X25519 public key.

CREATE TABLE IF NOT EXISTS hold_payloads (
    hold_ref TEXT PRIMARY KEY,

    -- The full hold payload, encrypted with AES-256-GCM.
    -- Base64-encoded ciphertext.
    ciphertext TEXT NOT NULL,

    -- The ephemeral X25519 public key used for this encryption.
    -- Base64-encoded.
    ephemeral_pub TEXT NOT NULL,

    -- The nonce/IV used for AES-256-GCM.
    -- Base64-encoded.
    nonce TEXT NOT NULL,

    -- Which device this payload is encrypted for (ed25519_pub fingerprint).
    target_device TEXT NOT NULL,

    -- When this payload was created.
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    -- When this payload expires (same as the hold's timeout_at).
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL
);

-- Index for cleanup of expired payloads.
CREATE INDEX IF NOT EXISTS idx_hold_payloads_expires
    ON hold_payloads(expires_at);
