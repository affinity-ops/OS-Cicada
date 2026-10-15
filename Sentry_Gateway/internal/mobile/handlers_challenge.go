// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package mobile

// handlers_challenge.go — Portal-facing endpoints for QR pairing and device management.
//
// SECURITY: Both endpoints in this file are gated behind authenticatePortalRequest(),
// which validates the caller's bearer token against the Core API's /api/v1/auth/me
// endpoint. This is the same authentication mechanism used by every other page in
// the Developer Portal. The tenant_id is extracted from the authenticated session,
// never from user-supplied input — preventing cross-tenant pairing attacks.
//
// POST /v1/portal/pair/generate
//   - Requires: Authorization: Bearer <portal_session_token>
//   - Creates a single-use, time-bounded nonce in mobile_pairing_challenges
//   - Returns the nonce + gateway URL + expiry as a QR payload string
//
// GET /v1/portal/devices
//   - Requires: Authorization: Bearer <portal_session_token>
//   - Returns all enrolled devices for the authenticated tenant

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/asai/cicada/sentry/internal/auth"
	"github.com/go-chi/chi/v5"
)

// authCache caches validated portal session tokens for 30 seconds to avoid
// hammering Core API's /auth/me on every 5-second device poll.
var authCache sync.Map // map[token]cachedIdentity

type cachedIdentity struct {
	identity  *portalIdentity
	expiresAt time.Time
}

// ChallengeExpirySeconds is how long a pairing QR code remains valid.
// 5 minutes is the industry standard for device-binding challenges
// (matches Microsoft Authenticator, Duo, and FIDO2 registration flows).
const ChallengeExpirySeconds = 300

// portalIdentity holds the authenticated caller's identity, extracted from the
// Core API's /api/v1/auth/me response. Both tenant_id and contact_id are
// server-derived — the caller cannot spoof them.
type portalIdentity struct {
	TenantID  string
	ContactID string
}

// authenticatePortalRequest validates the bearer token against the Core API.
// This is the single authentication gate for all portal-facing endpoints in
// this file. It returns the authenticated identity (tenant + contact) or an
// error. The token is the same Laravel Sanctum token stored in the portal's
// localStorage — issued at login, validated here on every request.
//
// Why call Core API instead of verifying locally?
// The portal session token is a Laravel Sanctum token (opaque, DB-backed),
// not a JWT. It cannot be verified cryptographically without access to the
// Laravel database. The canonical way to validate it is to call /api/v1/auth/me
// which returns the authenticated user's tenant and contact if the token is valid.
func authenticatePortalRequest(r *http.Request) (*portalIdentity, error) {
	authHeader := r.Header.Get("Authorization")
	token := strings.TrimPrefix(authHeader, "Bearer ")
	if token == "" || token == authHeader {
		return nil, fmt.Errorf("missing Authorization header — present your portal session token")
	}

	// Check cache first — avoids calling Core API on every 5-second poll
	if cached, ok := authCache.Load(token); ok {
		c := cached.(cachedIdentity)
		if time.Now().Before(c.expiresAt) {
			return c.identity, nil
		}
		authCache.Delete(token)
	}

	// Validate against Core API
	coreAPI := os.Getenv("CICADA_CORE_API_URL")
	if coreAPI == "" {
		coreAPI = "http://localhost:8000"
	}

	ctx := r.Context()
	req, err := http.NewRequestWithContext(ctx, "GET", coreAPI+"/api/v1/auth/me", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create auth verification request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[MOBILE] Core API auth check failed: %v", err)
		return nil, fmt.Errorf("authentication service unreachable")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("invalid or expired session token (status %d)", resp.StatusCode)
	}

	// Parse the /auth/me response to extract tenant_id and contact_id
	var authResp struct {
		Data struct {
			Tenant struct {
				ID string `json:"id"`
			} `json:"tenant"`
			Contact struct {
				ID string `json:"id"`
			} `json:"contact"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return nil, fmt.Errorf("failed to parse auth response: %w", err)
	}

	if authResp.Data.Tenant.ID == "" {
		return nil, fmt.Errorf("authenticated session has no tenant association")
	}

	identity := &portalIdentity{
		TenantID:  authResp.Data.Tenant.ID,
		ContactID: authResp.Data.Contact.ID,
	}
	authCache.Store(token, cachedIdentity{
		identity:  identity,
		expiresAt: time.Now().Add(30 * time.Second),
	})
	return identity, nil
}

// HandleGenerateChallenge creates a new pairing challenge nonce.
//
// Request:  POST /v1/portal/pair/generate
//           Headers: Authorization: Bearer <portal_session_token>
//
// Response: 201 Created
//           {
//             "data": {
//               "qr_payload": "<base64-encoded JSON>",
//               "qr_payload_legacy": "nonce|gatewayUrl/v1/mobile/pair/handshake|300",
//               "nonce": "...",
//               "expires_at": "2026-05-01T20:15:00Z",
//               "attestation_enforced": false
//             }
//           }
//
// The qr_payload is a base64-encoded JSON object containing:
//   {"nonce": "...", "gateway": "http://host:8080/v1/mobile/pair/handshake",
//    "expires_in": 300, "version": 2}
//
// The Flutter app decodes base64 → JSON and extracts the fields.
// Base64 encoding avoids pipe-character encoding issues in QR code chains.
// The legacy pipe-delimited format is kept in qr_payload_legacy for manual entry.
func HandleGenerateChallenge(w http.ResponseWriter, r *http.Request) {
	// ── Authentication gate ───────────────────────────────────────────────
	// The tenant_id and contact_id come from the authenticated session,
	// not from user input. This prevents a malicious actor from generating
	// pairing challenges for a tenant they don't belong to.
	identity, err := authenticatePortalRequest(r)
	if err != nil {
		log.Printf("[MOBILE] Challenge auth failed: %v", err)
		writeError(w, "unauthorized: "+err.Error(), http.StatusUnauthorized)
		return
	}

	// ── Generate a cryptographically random nonce ─────────────────────────
	// 32 bytes = 256 bits of entropy — same strength as the Ed25519 keys.
	nonceBytes := make([]byte, 32)
	if _, err := rand.Read(nonceBytes); err != nil {
		log.Printf("[MOBILE] Failed to generate challenge nonce: %v", err)
		writeError(w, "nonce generation failed", http.StatusInternalServerError)
		return
	}
	nonce := hex.EncodeToString(nonceBytes)

	// ── Calculate expiry ──────────────────────────────────────────────────
	now := time.Now().UTC()
	expiresAt := now.Add(ChallengeExpirySeconds * time.Second)

	// ── Insert into database ──────────────────────────────────────────────
	// The existing schema uses UUID columns for tenant_id and contact_id,
	// and timestamp(0) without time zone for timestamps.
	ctx := r.Context()
	_, err = DB.Exec(ctx,
		`INSERT INTO mobile_pairing_challenges (nonce, tenant_id, contact_id, expires_at, created_at, updated_at)
		 VALUES ($1, $2::uuid, $3::uuid, $4, $5, $5)`,
		nonce, identity.TenantID, identity.ContactID, expiresAt, now,
	)
	if err != nil {
		log.Printf("[MOBILE] Failed to insert pairing challenge: %v", err)
		writeError(w, "challenge creation failed", http.StatusInternalServerError)
		return
	}

	// ── Clean up expired challenges (housekeeping) ────────────────────────
	// Use explicit UTC comparison — expires_at is stored as UTC without timezone.
	// NOW() returns local time (BST on this host), causing false positives that
	// delete freshly inserted challenges before the phone can claim them.
	go func() {
		_, _ = DB.Exec(context.Background(),
			`DELETE FROM mobile_pairing_challenges WHERE expires_at < NOW() AT TIME ZONE 'UTC'`,
		)
	}()

	// ── Build the structured, signed QR payload ──────────────────────────
	// The QR code contains a compact JSON payload with an Ed25519 signature
	// from the Gateway's persistent signing key (sentry_ed25519.key).
	//
	// This is NOT a secret. Anyone can read the QR — the security comes
	// from the signature (tamper-proof) and the nonce (replay-proof).
	// The device's Ed25519 private key never appears in the QR and never
	// leaves the Secure Enclave.
	//
	// Fields:
	//   v   — payload version
	//   tid — tenant UUID (scope binding)
	//   n   — cryptographic nonce (base64, 32 bytes of entropy)
	//   exp — unix timestamp (5 minutes from now)
	//   gw  — reachable Gateway URL (the phone connects to this)
	//   sig — Ed25519 signature of the canonical JSON of {v, tid, n, exp, gw}

	nonceB64 := base64.StdEncoding.EncodeToString(nonceBytes)

	expUnix := expiresAt.Unix()

	// Determine the Gateway's reachable URL.
	// GATEWAY_PUBLIC_URL should be set to the iMac's LAN IP in the start
	// script or .env. The phone connects to this URL — NOT localhost.
	gatewayURL := os.Getenv("GATEWAY_PUBLIC_URL")
	if gatewayURL == "" {
		// Auto-detect: use the request's Host header as a best-effort fallback.
		// In dev, the Portal calls the Gateway from the same machine, so the
		// Host header contains the LAN IP the browser used to reach it.
		host := r.Host
		if host != "" && !strings.HasPrefix(host, "localhost") && !strings.HasPrefix(host, "127.0.0.1") {
			gatewayURL = "http://" + host
		} else {
			gatewayURL = "http://localhost:8080"
		}
		log.Printf("[MOBILE] WARNING: GATEWAY_PUBLIC_URL not set, using %s", gatewayURL)
	}

	// Build the canonical payload with ALPHABETICAL key ordering.
	// Both Go (struct field order) and Dart (map insertion order) must
	// produce identical JSON. Alphabetical is deterministic and safe
	// against future reordering bugs.
	type canonicalPayload struct {
		Exp int64  `json:"exp"`
		GW  string `json:"gw"`
		N   string `json:"n"`
		TID string `json:"tid"`
		V   int    `json:"v"`
	}
	canonical := canonicalPayload{
		Exp: expUnix,
		GW:  gatewayURL,
		N:   nonceB64,
		TID: identity.TenantID,
		V:   1,
	}
	canonicalJSON, err := json.Marshal(canonical)
	if err != nil {
		log.Printf("[MOBILE] Failed to marshal QR canonical payload: %v", err)
		writeError(w, "payload generation failed", http.StatusInternalServerError)
		return
	}

	// Sign with the Gateway's persistent Ed25519 key (same key that signs EVARs)
	sig := ed25519.Sign(auth.GlobalSentryPrivateKey, canonicalJSON)
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	// Embed the gateway's public key in the QR so the app can verify the
	// signature offline — no network call needed before the handshake.
	// This allows pairing from anywhere in the world; the phone only needs
	// to reach the gateway URL for the final handshake POST.
	pubKeyB64 := base64.StdEncoding.EncodeToString(auth.GlobalSentryPrivateKey.Public().(ed25519.PublicKey))

	// Build the complete QR payload (canonical fields + signature + pubkey)
	qrPayload := map[string]interface{}{
		"v":   1,
		"tid": identity.TenantID,
		"n":   nonceB64,
		"exp": expUnix,
		"gw":  gatewayURL,
		"sig": sigB64,
		"pk":  pubKeyB64,
	}
	qrJSON, _ := json.Marshal(qrPayload)

	// ── Check attestation status for this tenant ──────────────────────────
	attestationEnforced := false
	_ = DB.QueryRow(ctx,
		`SELECT enforced FROM attestation_config WHERE tenant_id = $1::uuid`,
		identity.TenantID,
	).Scan(&attestationEnforced)
	// If no row exists, attestation is not enforced (development mode).

	log.Printf("[MOBILE] Challenge generated: tenant=%s contact=%s nonce=%s...%s expires=%s attestation=%v",
		identity.TenantID, identity.ContactID, nonce[:8], nonce[len(nonce)-8:],
		expiresAt.Format(time.RFC3339), attestationEnforced)

	writeJSON(w, http.StatusCreated, map[string]any{
		"data": map[string]any{
			"qr_payload":           string(qrJSON),
			"nonce":                nonce,
			"expires_at":           expiresAt.Format(time.RFC3339),
			"attestation_enforced": attestationEnforced,
		},
	})
}

// HandleGetDevices returns all devices for the authenticated tenant.
//
// Request:  GET /v1/portal/devices
//           Headers: Authorization: Bearer <portal_session_token>
//
// Response: { "data": { "devices": [...] } }
func HandleGetDevices(w http.ResponseWriter, r *http.Request) {
	// ── Authentication gate ───────────────────────────────────────────────
	identity, err := authenticatePortalRequest(r)
	if err != nil {
		log.Printf("[MOBILE] Devices auth failed: %v", err)
		writeError(w, "unauthorized: "+err.Error(), http.StatusUnauthorized)
		return
	}

	ctx := r.Context()
	rows, err := DB.Query(ctx,
		`SELECT md.id, md.ed25519_pub, md.status,
		        md.last_heartbeat_at, md.paired_at, md.created_at,
		        COALESCE(ad.model, 'Unknown Device') AS model,
		        COALESCE(ad.platform, md.push_platform, 'unknown') AS platform,
		        COALESCE(NULLIF(ad.operator_evar_id,''), c.name, '') AS operator,
		        COALESCE(ad.os_version, '') AS os_version,
		        COALESCE(ad.app_version, '') AS app_version,
		        COALESCE(ad.biometric_enrolled, false) AS biometric_enrolled,
		        COALESCE(ad.secure_enclave_available, false) AS secure_enclave_available
		   FROM mobile_devices md
		   LEFT JOIN aegis_devices ad ON ad.device_id = md.ed25519_pub
		   LEFT JOIN contacts c ON c.tenant_id = md.tenant_id::uuid
		  WHERE md.tenant_id = $1
		  ORDER BY md.paired_at DESC`,
		identity.TenantID,
	)
	if err != nil {
		log.Printf("[MOBILE] Failed to fetch devices for tenant=%s: %v", identity.TenantID, err)
		writeError(w, "failed to fetch devices", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var devices []map[string]any
	for rows.Next() {
		var (
			id, ed25519Pub, status              string
			model, platform, operator_          string
			osVersion, appVersion               string
			biometricEnrolled, secureEnclave    bool
			lastHeartbeat, pairedAt             *time.Time
			createdAt                           time.Time
		)
		if err := rows.Scan(&id, &ed25519Pub, &status,
			&lastHeartbeat, &pairedAt, &createdAt,
			&model, &platform, &operator_,
			&osVersion, &appVersion,
			&biometricEnrolled, &secureEnclave); err != nil {
			continue
		}

		device := map[string]any{
			"id":                       id,
			"device_id":                ed25519Pub,
			"status":                   status,
			"model":                    model,
			"platform":                 platform,
			"operator":                 operator_,
			"os_version":               osVersion,
			"app_version":              appVersion,
			"biometric_enrolled":       biometricEnrolled,
			"secure_enclave_available": secureEnclave,
			"paired_at":                formatTime(pairedAt),
			"last_seen":                formatTime(lastHeartbeat),
			"created_at":               createdAt.Format(time.RFC3339),
		}
		devices = append(devices, device)
	}

	if devices == nil {
		devices = []map[string]any{}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"data": map[string]any{
			"devices": devices,
		},
	})
}

// HandleRevokeDevice marks a device as revoked.
//
// Request:  POST /v1/portal/devices/{deviceID}/revoke
//           Headers: Authorization: Bearer <portal_session_token>
//
// Response: 200 { "status": "revoked" }
func HandleRevokeDevice(w http.ResponseWriter, r *http.Request) {
	identity, err := authenticatePortalRequest(r)
	if err != nil {
		log.Printf("[MOBILE] Revoke auth failed: %v", err)
		writeError(w, "unauthorized: "+err.Error(), http.StatusUnauthorized)
		return
	}

	deviceID := chi.URLParam(r, "deviceID")
	if deviceID == "" {
		writeError(w, "deviceID is required", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	result, err := DB.Exec(ctx,
		`UPDATE mobile_devices SET status = 'revoked', updated_at = NOW()
		 WHERE id = $1 AND tenant_id = $2`,
		deviceID, identity.TenantID,
	)
	if err != nil {
		log.Printf("[MOBILE] Revoke failed for device=%s tenant=%s: %v", deviceID, identity.TenantID, err)
		writeError(w, "revoke failed", http.StatusInternalServerError)
		return
	}
	if result.RowsAffected() == 0 {
		writeError(w, "device not found", http.StatusNotFound)
		return
	}

	log.Printf("[MOBILE] Device revoked: id=%s tenant=%s", deviceID, identity.TenantID)
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

// deref returns the value of a string pointer, or a default if nil.
func deref(s *string, def string) string {
	if s != nil {
		return *s
	}
	return def
}

// formatTime formats a nullable time pointer for JSON output.
func formatTime(t *time.Time) string {
	if t != nil {
		return t.Format(time.RFC3339)
	}
	return ""
}
