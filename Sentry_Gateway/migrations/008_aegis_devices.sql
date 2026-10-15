-- Migration 008: Aegis Mobile Device Telemetry Capture
--
-- This table stores device telemetry captured immediately after QR pairing.
-- Used to verify device posture (secure enclave, biometric enrollment, jailbreak status).

CREATE TABLE IF NOT EXISTS aegis_devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    operator_evar_id VARCHAR(255) NOT NULL,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    gateway_node_id UUID NOT NULL REFERENCES gateway_instances(id) ON DELETE CASCADE,
    device_id VARCHAR(255) UNIQUE NOT NULL,
    platform VARCHAR(50) NOT NULL CHECK (platform IN ('ios', 'android')),
    os_version VARCHAR(50),
    model VARCHAR(255),
    manufacturer VARCHAR(100),
    app_version VARCHAR(50),
    biometric_enrolled BOOLEAN DEFAULT false,
    secure_enclave_available BOOLEAN DEFAULT false,
    attestation_status VARCHAR(50),
    screen_lock_enabled BOOLEAN DEFAULT false,
    pairing_ip INET,
    pairing_timestamp TIMESTAMPTZ DEFAULT NOW(),
    mtls_cert_fingerprint VARCHAR(255),
    last_seen_at TIMESTAMPTZ,
    is_active BOOLEAN DEFAULT true,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_aegis_devices_tenant ON aegis_devices(tenant_id);
CREATE INDEX IF NOT EXISTS idx_aegis_devices_device_id ON aegis_devices(device_id);
CREATE INDEX IF NOT EXISTS idx_aegis_devices_operator ON aegis_devices(operator_evar_id);
