// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package mobile implements the Sentry Gateway's mobile device management
// endpoints for the Aegis HITL companion app.
//
// Endpoints registered:
//
//	POST /v1/mobile/pair/handshake  — Zero-secret QR device binding (Phase 1)
//	POST /v1/mobile/push-token     — FCM/APNs token registration (Phase 2)
//	POST /v1/mobile/heartbeat      — 5-min device heartbeat (Phase 6)
//	POST /v1/mobile/decisions/batch — Offline decision batch sync (Phase 3)
//	POST /v1/mobile/telemetry      — Weekly anonymised telemetry (Phase 5)
//	GET  /v1/hitl/hold/{ref}/payload — Encrypted hold payload fetch (Phase 2)
//	GET  /v1/hitl/hold/{ref}/quorum  — M-of-N quorum status (Phase 7)
package mobile

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// DB is the PostgreSQL connection pool, injected by main.go at startup.
var DB *pgxpool.Pool

// ─────────────────────────────────────────────────────────────────────────────
// Route Registration
// ─────────────────────────────────────────────────────────────────────────────

// RegisterRoutes mounts all mobile device endpoints on the provided chi router.
func RegisterRoutes(r chi.Router) {
	// Phase 1: Device pairing
	r.Post("/v1/mobile/pair/handshake", HandleHandshake)

	// Phase 2: Push token + encrypted payload
	r.Post("/v1/mobile/push-token", HandlePushToken)
	r.Get("/v1/hitl/hold/{holdRef}/payload", HandleHoldPayload)

	// Phase 3/6: Heartbeat + batch sync
	r.Post("/v1/mobile/heartbeat", HandleHeartbeat)
	r.Post("/v1/mobile/decisions/batch", HandleBatchDecisions)

	// Phase 5: Telemetry
	r.Post("/v1/mobile/telemetry", HandleTelemetry)

	// Phase 7: Multi-approval quorum
	r.Get("/v1/hitl/hold/{holdRef}/quorum", HandleQuorumStatus)

	// Phase 1.8: Device Telemetry Enrollment
	r.Post("/v1/device/enroll", HandleDeviceEnrollment)

	// ── Portal-facing endpoints ───────────────────────────────────────────
	// These are called by the Developer Portal (browser), not the mobile app.
	// They manage pairing challenge generation and device inventory.
	r.Post("/v1/portal/pair/generate", HandleGenerateChallenge)
	r.Get("/v1/portal/devices", HandleGetDevices)
	r.Post("/v1/portal/devices/{deviceID}/revoke", HandleRevokeDevice)

	// ── Public endpoints ──────────────────────────────────────────────────
	// Unauthenticated — the public key is not a secret.
	r.Get("/v1/gateway/pubkey", HandleGetPublicKey)
}

// ─────────────────────────────────────────────────────────────────────────────
// JSON Request/Response Types
// ─────────────────────────────────────────────────────────────────────────────

// HandshakeRequest is the body of POST /v1/mobile/pair/handshake.
// The device sends its public keys and a signed challenge to prove
// possession of the corresponding private keys.
type HandshakeRequest struct {
	Ed25519Pub         string `json:"ed25519_pub"`         // hex-encoded
	X25519Pub          string `json:"x25519_pub"`          // hex-encoded
	MlDsa65Pub         string `json:"ml_dsa65_pub,omitempty"`
	MlKem768Pub        string `json:"ml_kem768_pub,omitempty"`
	ChallengeSignature string `json:"challenge_signature"` // Ed25519 sig over the nonce
	Nonce              string `json:"nonce"`               // the nonce from the QR code
	PqcDiag            string `json:"pqc_diag,omitempty"`  // diagnostic info from app
}

// PushTokenRequest is the body of POST /v1/mobile/push-token.
type PushTokenRequest struct {
	PushToken             string `json:"push_token"`
	Platform              string `json:"platform"`                // "android" or "ios"
	Ed25519PubFingerprint string `json:"ed25519_pub_fingerprint"` // hex-encoded pub key
}

// HeartbeatRequest is the body of POST /v1/mobile/heartbeat.
type HeartbeatRequest struct {
	Ed25519Pub   string `json:"ed25519_pub"`
	PendingCount int    `json:"offline_queue_count"`
}

// HeartbeatResponse is returned from POST /v1/mobile/heartbeat.
type HeartbeatResponse struct {
	Status         string `json:"status"`        // "active", "suspended", "revoked"
	PendingHolds   int    `json:"pending_holds"` // holds awaiting this device
	ServerTime     string `json:"server_time"`   // authoritative UTC timestamp
	KeyRotationDue bool   `json:"key_rotation_due"`
}

// BatchDecision is one signed decision in a batch sync.
type BatchDecision struct {
	HoldRef          string `json:"hold_ref"`
	Decision         string `json:"decision"` // "APPROVE", "REJECT", "MODIFY"
	DecisionNonce    string `json:"decision_nonce"`
	GatewayTimestamp string `json:"gateway_timestamp"`
	HoldPayloadHash  string `json:"hold_payload_hash"`
	SignatureEd25519 string `json:"signature_ed25519"`
	SignatureMlDsa65 string `json:"signature_ml_dsa65,omitempty"`
	Ed25519Pub       string `json:"ed25519_pub"`
	AttestationToken string `json:"attestation_token"`
}

// QuorumResponse is returned from GET /v1/hitl/hold/{ref}/quorum.
type QuorumResponse struct {
	HoldRef           string   `json:"hold_ref"`
	RequiredVotes     int      `json:"required_votes"`
	TotalVoters       int      `json:"total_voters"`
	CurrentApprovals  int      `json:"current_approvals"`
	CurrentRejects    int      `json:"current_rejections"`
	VoterFingerprints []string `json:"voter_fingerprints"`
	Resolved          bool     `json:"resolved"`
	Outcome           string   `json:"outcome,omitempty"` // "approved", "rejected", ""
}

// ─────────────────────────────────────────────────────────────────────────────
// Utility
// ─────────────────────────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v) //nolint:errcheck
}

func writeError(w http.ResponseWriter, msg string, code int) {
	writeJSON(w, code, map[string]string{"error": msg})
}
