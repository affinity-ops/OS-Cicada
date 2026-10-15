-- ============================================================================
-- Migration 014: Add PQC Public Key Columns to Mobile Devices
-- ============================================================================
--
-- The handlers_pairing.go HandleHandshake function inserts ml_dsa65_pub and
-- ml_kem768_pub when registering a device, but these columns were never added
-- to the mobile_devices table created in migration 007.
--
-- ML-DSA-65:  Post-quantum digital signature (NIST FIPS 204). Used by the
--             device to dual-sign HITL decisions alongside Ed25519.
-- ML-KEM-768: Post-quantum key encapsulation (NIST FIPS 203). Used by the
--             Gateway to encrypt hold payloads with hybrid classical+PQC.
--
-- Both columns default to empty string because PQC key generation is optional
-- (depends on liboqs availability on the device). The HandshakeRequest struct
-- uses `omitempty`, so the app sends empty strings when PQC is unavailable.
--
-- Safe to re-run: uses IF NOT EXISTS.
-- ============================================================================

ALTER TABLE mobile_devices ADD COLUMN IF NOT EXISTS ml_dsa65_pub TEXT NOT NULL DEFAULT '';
ALTER TABLE mobile_devices ADD COLUMN IF NOT EXISTS ml_kem768_pub TEXT NOT NULL DEFAULT '';
