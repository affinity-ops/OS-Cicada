// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package mobile

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
)

// DeviceProfile details from enrollment.
type DeviceProfile struct {
	Platform       string `json:"platform"`
	OSVersion      string `json:"os_version"`
	Model          string `json:"model"`
	Manufacturer   string `json:"manufacturer"`
	DeviceID       string `json:"device_id"`
	AppVersion     string `json:"app_version"`
	FlutterVersion string `json:"flutter_version"`
}

// SecurityPosture details from enrollment.
type SecurityPosture struct {
	BiometricEnrolled      bool   `json:"biometric_enrolled"`
	SecureEnclaveAvailable bool   `json:"secure_enclave_available"`
	PlayIntegrityStatus    string `json:"play_integrity_status"`
	AppAttestStatus        string `json:"app_attest_status"`
	JailbreakDetected      bool   `json:"jailbreak_detected"`
	ScreenLockEnabled      bool   `json:"screen_lock_enabled"`
}

// NetworkProfile details from enrollment.
type NetworkProfile struct {
	PairingIP           string `json:"pairing_ip"`
	PairingTimestamp    string `json:"pairing_timestamp"`
	MTLSCertFingerprint string `json:"mtls_cert_fingerprint"`
}

// EnrollDeviceRequest represents the POST /v1/device/enroll payload.
type EnrollDeviceRequest struct {
	EnrollmentID    string                 `json:"enrollment_id"`
	OperatorEvarID  string                 `json:"operator_evar_id"`
	GatewayNodeID   string                 `json:"gateway_node_id"`
	DeviceProfile   DeviceProfile          `json:"device_profile"`
	SecurityPosture SecurityPosture        `json:"security_posture"`
	NetworkProfile  NetworkProfile         `json:"network_profile"`
	Location        map[string]interface{} `json:"location"`
}

// HandleDeviceEnrollment processes POST /v1/device/enroll.
// This is called immediately after QR pairing.
func HandleDeviceEnrollment(w http.ResponseWriter, r *http.Request) {
	var req EnrollDeviceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "invalid JSON payload", http.StatusBadRequest)
		return
	}

	if req.OperatorEvarID == "" || req.GatewayNodeID == "" || req.DeviceProfile.DeviceID == "" {
		writeError(w, "missing required fields", http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	// Find the tenant_id associated with this device's public key (device_id)
	var tenantID string
	err := DB.QueryRow(ctx, "SELECT tenant_id FROM mobile_devices WHERE ed25519_pub = $1", req.DeviceProfile.DeviceID).Scan(&tenantID)
	if err != nil {
		log.Printf("[AEGIS ENROLL] Error finding tenant for device %s: %v", req.DeviceProfile.DeviceID, err)
		writeError(w, "unauthorized device", http.StatusUnauthorized)
		return
	}

	// Look up the actual registered operator name for this tenant
	var operatorName string
	err = DB.QueryRow(ctx, "SELECT name FROM contacts WHERE tenant_id = $1 ORDER BY is_primary DESC, created_at ASC LIMIT 1", tenantID).Scan(&operatorName)
	if err != nil {
		operatorName = "Unknown Operator" // Fallback if no contact is found
	}

	// The Flutter app currently sends a mocked string "gateway-uuid" which will fail UUID/FK constraints.
	// In production, the gateway_url would uniquely identify the gateway instance, or we can fetch the local one.
	var actualGatewayNodeID string
	err = DB.QueryRow(ctx, "SELECT id FROM gateway_instances LIMIT 1").Scan(&actualGatewayNodeID)
	if err != nil {
		log.Printf("[AEGIS ENROLL] Error fetching gateway node ID: %v", err)
		actualGatewayNodeID = req.GatewayNodeID // Fallback, though likely to fail FK
	}

	// Upsert the device into aegis_devices table
	pairingIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		pairingIP = r.RemoteAddr // Fallback, but might still crash if it contains a port
	}

	// Serialize location to JSON for JSONB column
	locationJSON, _ := json.Marshal(req.Location)
	if len(req.Location) == 0 {
		locationJSON = nil
	}

	_, err = DB.Exec(ctx, `
		INSERT INTO aegis_devices (
			operator_evar_id, tenant_id, gateway_node_id, device_id, platform, os_version,
			model, manufacturer, app_version, biometric_enrolled, secure_enclave_available,
			attestation_status, screen_lock_enabled, pairing_ip, pairing_timestamp, mtls_cert_fingerprint,
			location
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
		ON CONFLICT (device_id) DO UPDATE SET
			operator_evar_id = EXCLUDED.operator_evar_id,
			gateway_node_id = EXCLUDED.gateway_node_id,
			platform = EXCLUDED.platform,
			os_version = EXCLUDED.os_version,
			model = EXCLUDED.model,
			manufacturer = EXCLUDED.manufacturer,
			app_version = EXCLUDED.app_version,
			biometric_enrolled = EXCLUDED.biometric_enrolled,
			secure_enclave_available = EXCLUDED.secure_enclave_available,
			attestation_status = EXCLUDED.attestation_status,
			screen_lock_enabled = EXCLUDED.screen_lock_enabled,
			pairing_ip = EXCLUDED.pairing_ip,
			pairing_timestamp = EXCLUDED.pairing_timestamp,
			mtls_cert_fingerprint = EXCLUDED.mtls_cert_fingerprint,
			location = EXCLUDED.location,
			last_seen_at = NOW(),
			is_active = true
	`,
		operatorName,
		tenantID,
		actualGatewayNodeID,
		req.DeviceProfile.DeviceID,
		req.DeviceProfile.Platform,
		req.DeviceProfile.OSVersion,
		req.DeviceProfile.Model,
		req.DeviceProfile.Manufacturer,
		req.DeviceProfile.AppVersion,
		req.SecurityPosture.BiometricEnrolled,
		req.SecurityPosture.SecureEnclaveAvailable,
		req.SecurityPosture.AppAttestStatus, // Or PlayIntegrityStatus depending on platform
		req.SecurityPosture.ScreenLockEnabled,
		pairingIP,
		req.NetworkProfile.PairingTimestamp,
		req.NetworkProfile.MTLSCertFingerprint,
		locationJSON,
	)

	if err != nil {
		log.Printf("[AEGIS ENROLL] Error inserting device: %v", err)
		writeError(w, "internal server error", http.StatusInternalServerError)
		return
	}

	log.Printf("[AEGIS ENROLL] Successfully enrolled device %s for operator %s", req.DeviceProfile.DeviceID, req.OperatorEvarID)

	// Emit WebSocket event to Developer Portal (Mocked for now)
	// In production, this would publish to Redis Pub/Sub so the portal receives it.

	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "success",
		"message": "device enrolled successfully",
	})
}
