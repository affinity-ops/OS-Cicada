// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package mobile

// handlers_pairing.go — Phase 1: Zero-Secret QR Handshake
//                       Phase 2: Push Token Registration

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"time"
)

func HandleHandshake(w http.ResponseWriter, r *http.Request) {
	// Read raw body for debugging
	bodyBytes, readErr := io.ReadAll(r.Body)
	if readErr != nil {
		writeError(w, "failed to read body", http.StatusBadRequest)
		return
	}
	// Log truncated raw body (max 500 chars for readability)
	rawStr := string(bodyBytes)
	if len(rawStr) > 500 {
		rawStr = rawStr[:500] + "...(truncated)"
	}
	log.Printf("[MOBILE] Handshake RAW body (%d bytes): %s", len(bodyBytes), rawStr)

	var req HandshakeRequest
	if err := json.Unmarshal(bodyBytes, &req); err != nil {
		writeError(w, "invalid JSON payload", http.StatusBadRequest)
		return
	}

	// Debug: log PQC key lengths and diagnostic info from the app
	log.Printf("[MOBILE] Handshake received: ed25519=%d chars, x25519=%d chars, ml_dsa65=%d chars, ml_kem768=%d chars, pqc_diag=%q",
		len(req.Ed25519Pub), len(req.X25519Pub), len(req.MlDsa65Pub), len(req.MlKem768Pub), req.PqcDiag)

	// ── Validate required fields ──────────────────────────────────────────
	if req.Ed25519Pub == "" || req.X25519Pub == "" ||
		req.Nonce == "" || req.ChallengeSignature == "" {
		writeError(w, "missing required fields: ed25519_pub, x25519_pub, nonce, challenge_signature", http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	// ── Lookup the challenge nonce to find the TenantID ───────────────────
	// QR carries base64; DB stores hex — convert before lookup.
	nonceBytes, err := base64.StdEncoding.DecodeString(req.Nonce)
	if err != nil {
		writeError(w, "invalid nonce encoding", http.StatusBadRequest)
		return
	}
	hexNonce := hex.EncodeToString(nonceBytes)

	var tenantID string
	var expiresAt time.Time
	err = DB.QueryRow(ctx,
		`SELECT tenant_id, expires_at FROM mobile_pairing_challenges WHERE nonce = $1`,
		hexNonce,
	).Scan(&tenantID, &expiresAt)
	if err != nil {
		log.Printf("[MOBILE] Handshake failed: challenge nonce not found %s", req.Nonce)
		writeError(w, "challenge not found or already consumed", http.StatusUnauthorized)
		return
	}
	if time.Now().After(expiresAt) {
		log.Printf("[MOBILE] Handshake failed: challenge expired for nonce %s", req.Nonce)
		writeError(w, "challenge expired", http.StatusUnauthorized)
		return
	}

	// ── Decode the Ed25519 public key ─────────────────────────────────────
	pubKeyBytes, err := base64.StdEncoding.DecodeString(req.Ed25519Pub)
	if err != nil || len(pubKeyBytes) != ed25519.PublicKeySize {
		writeError(w, "invalid ed25519_pub: must be valid base64 (32 bytes)", http.StatusBadRequest)
		return
	}
	pubKey := ed25519.PublicKey(pubKeyBytes)

	// ── Decode and verify the signature ───────────────────────────────────
	// The device signed the nonce from the QR payload's 'n' field.
	// The nonce is the sole signing payload — it's unique per challenge,
	// cryptographically random (32 bytes), and bound to this specific
	// pairing session via the database record.
	//
	// The device's newly-generated Ed25519 private key signs this nonce
	// to prove possession of the corresponding public key.
	expectedPayload := req.Nonce

	sigBytes, err := base64.StdEncoding.DecodeString(req.ChallengeSignature)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		writeError(w, "invalid signature: must be valid base64 (64 bytes)", http.StatusBadRequest)
		return
	}

	if !ed25519.Verify(pubKey, []byte(expectedPayload), sigBytes) {
		log.Printf("[MOBILE] Handshake signature verification FAILED for tenant=%s (nonce=%s)", tenantID, req.Nonce)
		writeError(w, "signature verification failed — challenge response invalid", http.StatusUnauthorized)
		return
	}

	// ── Consume the challenge ─────────────────────────────────────────────
	_, _ = DB.Exec(ctx, `DELETE FROM mobile_pairing_challenges WHERE nonce = $1`, hexNonce)

	// ── Revoke ALL existing devices for this tenant (security) ───────────
	// When a new device pairs, ALL old devices for the same tenant are
	// revoked. This prevents a scenario where an attacker with an
	// extracted key from an old device can still sign decisions while
	// the operator believes they've re-paired on a new device.
	revokeResult, err := DB.Exec(ctx,
		`UPDATE mobile_devices SET status = 'revoked', updated_at = $1
		 WHERE tenant_id = $2 AND status = 'active'`,
		time.Now().UTC(), tenantID,
	)
	if err != nil {
		log.Printf("[MOBILE] Failed to revoke old devices for tenant=%s: %v", tenantID, err)
	} else if revokeResult.RowsAffected() > 0 {
		log.Printf("[MOBILE] Revoked %d existing device(s) for tenant=%s on re-pairing",
			revokeResult.RowsAffected(), tenantID)
	}

	// ── Insert the new device record ──────────────────────────────────────
	// Store both classical (Ed25519, X25519) and post-quantum (ML-DSA-65,
	// ML-KEM-768) public keys. The PQC keys are optional during rollout
	// (omitempty in HandshakeRequest) — they'll be empty strings if the
	// app hasn't implemented PQC signing yet. The ml_dsa65_pub column is
	// read by HandleBatchDecisions to verify hybrid PQC signatures.
	now := time.Now().UTC()
	_, err = DB.Exec(ctx,
		`INSERT INTO mobile_devices
			(tenant_id, ed25519_pub, x25519_pub, ml_dsa65_pub, ml_kem768_pub,
			 status, paired_at, last_heartbeat_at, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, 'active', $6, $6, $6, $6)
		 ON CONFLICT (ed25519_pub) DO UPDATE SET
			ml_dsa65_pub = EXCLUDED.ml_dsa65_pub,
			ml_kem768_pub = EXCLUDED.ml_kem768_pub,
			status = 'active',
			paired_at = EXCLUDED.paired_at,
			updated_at = EXCLUDED.updated_at`,
		tenantID, req.Ed25519Pub, req.X25519Pub,
		req.MlDsa65Pub, req.MlKem768Pub, now,
	)
	if err != nil {
		log.Printf("[MOBILE] Failed to insert device: %v", err)
		writeError(w, "device registration failed", http.StatusInternalServerError)
		return
	}

	log.Printf("[MOBILE] Device paired: tenant=%s fingerprint=%s...%s",
		tenantID, req.Ed25519Pub[:8], req.Ed25519Pub[len(req.Ed25519Pub)-8:])

	// ── Bootstrap aegis_devices record ───────────────────────────────────────
	// Insert a minimal record so the portal shows the device immediately.
	// The app's /v1/device/enroll call will upsert richer info (model, OS, etc.)
	// once it fires. This ensures the device always appears in the portal even
	// if enrollment fails.
	var gatewayNodeID string
	_ = DB.QueryRow(ctx, `SELECT id FROM gateway_instances LIMIT 1`).Scan(&gatewayNodeID)
	if gatewayNodeID != "" {
		_, _ = DB.Exec(ctx, `
			INSERT INTO aegis_devices
				(operator_evar_id, tenant_id, gateway_node_id, device_id, platform,
				 os_version, model, app_version, is_active, pairing_timestamp, last_seen_at)
			VALUES ('', $1, $2, $3, 'android', '', 'Unknown Device', '', true, NOW(), NOW())
			ON CONFLICT (device_id) DO UPDATE SET
				tenant_id        = EXCLUDED.tenant_id,
				gateway_node_id  = EXCLUDED.gateway_node_id,
				is_active        = true,
				pairing_timestamp = NOW(),
				last_seen_at     = NOW()`,
			tenantID, gatewayNodeID, req.Ed25519Pub,
		)
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"status": "success",
		"data": map[string]any{
			"token": req.Ed25519Pub,
		},
	})
}

// HandlePushToken processes POST /v1/mobile/push-token.
//
// Called by the app on boot and whenever the FCM/APNs token refreshes.
// The Gateway uses this token to send minimal push alerts (hold_ref only).
func HandlePushToken(w http.ResponseWriter, r *http.Request) {
	var req PushTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "invalid JSON payload", http.StatusBadRequest)
		return
	}

	if req.PushToken == "" || req.Ed25519PubFingerprint == "" {
		writeError(w, "push_token and ed25519_pub_fingerprint are required", http.StatusBadRequest)
		return
	}

	if req.Platform != "android" && req.Platform != "ios" {
		writeError(w, "platform must be 'android' or 'ios'", http.StatusBadRequest)
		return
	}

	// ── Update the device's push token ────────────────────────────────────
	ctx := r.Context()
	result, err := DB.Exec(ctx,
		`UPDATE mobile_devices
		 SET push_token = $1, push_platform = $2, updated_at = NOW()
		 WHERE ed25519_pub = $3 AND status = 'active'`,
		req.PushToken, req.Platform, req.Ed25519PubFingerprint,
	)
	if err != nil {
		log.Printf("[MOBILE] Push token update failed: %v", err)
		writeError(w, "push token update failed", http.StatusInternalServerError)
		return
	}

	if result.RowsAffected() == 0 {
		writeError(w, "device not found or not active", http.StatusNotFound)
		return
	}

	log.Printf("[MOBILE] Push token registered: device=%s...%s platform=%s",
		req.Ed25519PubFingerprint[:8], req.Ed25519PubFingerprint[len(req.Ed25519PubFingerprint)-4:],
		req.Platform)

	writeJSON(w, http.StatusOK, map[string]string{"status": "registered"})
}
