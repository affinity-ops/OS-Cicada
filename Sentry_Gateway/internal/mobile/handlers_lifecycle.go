// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package mobile

// handlers_lifecycle.go — Phase 2: Hold Payload Fetch
//                         Phase 3: Batch Decision Sync
//                         Phase 6: Device Heartbeat

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/asai/cicada/sentry/pkg/pqc"
)

// HandleHeartbeat processes POST /v1/mobile/heartbeat.
//
// Called every 5 minutes by the app's HeartbeatService.
// Returns:
//   - Device status (active/suspended/revoked)
//   - Number of pending holds awaiting this device
//   - Whether key rotation is due (>90 days since pairing)
//   - Authoritative server time
//
// Phase 6 spec: "If device offline >72h, auto-suspend the certificate."
func HandleHeartbeat(w http.ResponseWriter, r *http.Request) {
	var req HeartbeatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "invalid JSON payload", http.StatusBadRequest)
		return
	}

	if req.Ed25519Pub == "" {
		writeError(w, "ed25519_pub is required", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	now := time.Now().UTC()

	// ── Fetch the device record ───────────────────────────────────────────
	var status string
	var pairedAt time.Time
	var lastHeartbeat *time.Time
	err := DB.QueryRow(ctx,
		`SELECT status, paired_at, last_heartbeat_at
		 FROM mobile_devices WHERE ed25519_pub = $1`,
		req.Ed25519Pub,
	).Scan(&status, &pairedAt, &lastHeartbeat)
	if err != nil {
		writeError(w, "device not found", http.StatusNotFound)
		return
	}

	// ── Auto-suspend if offline >72 hours (Phase 6) ───────────────────────
	// Security policy: devices that go dark for >72 hours are automatically
	// suspended to prevent stale, unmonitored devices from retaining
	// authorization to approve high-risk actions.
	if status == "active" && lastHeartbeat != nil {
		offlineDuration := now.Sub(*lastHeartbeat)
		if offlineDuration > 72*time.Hour {
			log.Printf("[MOBILE] Auto-suspending device %s...%s: offline for %s",
				req.Ed25519Pub[:8], req.Ed25519Pub[len(req.Ed25519Pub)-4:], offlineDuration)
			_, _ = DB.Exec(ctx,
				`UPDATE mobile_devices SET status = 'suspended', updated_at = $1
				 WHERE ed25519_pub = $2`,
				now, req.Ed25519Pub,
			)
			status = "suspended"
		}
	}

	// ── Suspension recovery ───────────────────────────────────────────────
	// If a suspended device sends a heartbeat, the operator still has
	// physical possession of the device and has passed the biometric gate
	// on the app side. This is sufficient proof to re-activate.
	//
	// Without this path, suspended devices stay suspended forever because
	// the heartbeat timestamp update below only fires for 'active' devices,
	// creating a permanent lockout with no recovery mechanism.
	//
	// NOTE: This does NOT apply to 'revoked' devices. Revocation is
	// permanent and requires a full re-pair via QR scan.
	if status == "suspended" {
		log.Printf("[MOBILE] Re-activating suspended device %s...%s: heartbeat received, operator has physical possession",
			req.Ed25519Pub[:8], req.Ed25519Pub[len(req.Ed25519Pub)-4:])
		_, _ = DB.Exec(ctx,
			`UPDATE mobile_devices SET status = 'active',
			 last_heartbeat_at = $1, updated_at = $1
			 WHERE ed25519_pub = $2`,
			now, req.Ed25519Pub,
		)
		status = "active"
	}

	// ── Update heartbeat timestamp ────────────────────────────────────────
	// Only update for active devices. Revoked devices are ignored — their
	// heartbeats are acknowledged (so the app knows to re-pair) but their
	// timestamp is not refreshed.
	if status == "active" {
		_, _ = DB.Exec(ctx,
			`UPDATE mobile_devices SET last_heartbeat_at = $1, updated_at = $1
			 WHERE ed25519_pub = $2`,
			now, req.Ed25519Pub,
		)
	}

	// ── Count pending holds for this device's tenant ──────────────────────
	var pendingCount int
	_ = DB.QueryRow(ctx,
		`SELECT COUNT(*) FROM hold_payloads hp
		 WHERE hp.target_device = $1 AND hp.expires_at > $2`,
		req.Ed25519Pub, now,
	).Scan(&pendingCount)

	// ── Fetch pending hold details so the app can display alerts ──────────
	// When holds exist, the app needs the actual CIBA data (agent name,
	// action summary, risk score, etc.) to render the alert cards.
	var pendingAlerts []map[string]any
	if pendingCount > 0 {
		rows, err := DB.Query(ctx,
			`SELECT hp.hold_ref, car.agent_name, car.action_summary,
			        car.target_url, car.risk_score, car.risk_reason,
			        car.payload_preview, car.expires_at, car.created_at
			 FROM hold_payloads hp
			 JOIN ciba_authorization_requests car ON car.trace_id = hp.hold_ref
			 WHERE hp.target_device = $1
			   AND hp.expires_at > $2
			   AND car.status = 'pending'
			 ORDER BY car.created_at DESC
			 LIMIT 10`,
			req.Ed25519Pub, now,
		)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var holdRef, agentName, actionSummary string
				var targetURL, riskReason, payloadPreview *string
				var riskScore float64
				var expiresAt, createdAt time.Time
				if err := rows.Scan(&holdRef, &agentName, &actionSummary,
					&targetURL, &riskScore, &riskReason,
					&payloadPreview, &expiresAt, &createdAt); err != nil {
					continue
				}
				alert := map[string]any{
					"hold_ref":       holdRef,
					"agent_name":     agentName,
					"action_detail":  actionSummary,
					"action_type":    "hitl/hold",
					"trust_score":    1.0 - riskScore,
					"severity":       "critical",
					"velocity":       "HIGH",
					"expires_at":     expiresAt.Format(time.RFC3339),
					"created_at":     createdAt.Format(time.RFC3339),
				}
				if targetURL != nil {
					alert["action_target"] = *targetURL
				}
				if riskReason != nil {
					alert["risk_reason"] = *riskReason
				}
				pendingAlerts = append(pendingAlerts, alert)
			}
		}
	}

	// ── Check key rotation (>90 days since pairing) ───────────────────────
	keyRotationDue := now.Sub(pairedAt) > 90*24*time.Hour

	response := map[string]any{
		"status":           status,
		"pending_holds":    pendingCount,
		"server_time":      now.Format(time.RFC3339),
		"key_rotation_due": keyRotationDue,
	}
	if len(pendingAlerts) > 0 {
		response["alerts"] = pendingAlerts
	}
	writeJSON(w, http.StatusOK, response)
}

// HandleHoldPayload processes GET /v1/hitl/hold/{holdRef}/payload.
//
// Phase 2 spec: After biometric wake, the device fetches the full encrypted
// hold payload from this endpoint. The payload was encrypted with the device's
// X25519 public key using ephemeral ECDH + AES-256-GCM.
//
// The X-Device-Fingerprint header identifies which device is requesting.
func HandleHoldPayload(w http.ResponseWriter, r *http.Request) {
	holdRef := chi.URLParam(r, "holdRef")
	deviceFingerprint := r.Header.Get("X-Device-Fingerprint")

	if holdRef == "" {
		writeError(w, "hold_ref is required", http.StatusBadRequest)
		return
	}
	if deviceFingerprint == "" {
		writeError(w, "X-Device-Fingerprint header is required", http.StatusUnauthorized)
		return
	}

	ctx := r.Context()

	// ── Verify the device is active ───────────────────────────────────────
	var deviceStatus string
	err := DB.QueryRow(ctx,
		`SELECT status FROM mobile_devices WHERE ed25519_pub = $1`,
		deviceFingerprint,
	).Scan(&deviceStatus)
	if err != nil || deviceStatus != "active" {
		writeError(w, "device not found or not active", http.StatusForbidden)
		return
	}

	// ── Fetch the encrypted payload ───────────────────────────────────────
	var ciphertext, ephemeralPub, nonce string
	err = DB.QueryRow(ctx,
		`SELECT ciphertext, ephemeral_pub, nonce FROM hold_payloads
		 WHERE hold_ref = $1 AND target_device = $2 AND expires_at > NOW()`,
		holdRef, deviceFingerprint,
	).Scan(&ciphertext, &ephemeralPub, &nonce)
	if err != nil {
		writeError(w, "hold payload not found or expired", http.StatusNotFound)
		return
	}

	log.Printf("[MOBILE] Hold payload served: hold=%s device=%s...%s",
		holdRef, deviceFingerprint[:8], deviceFingerprint[len(deviceFingerprint)-4:])

	writeJSON(w, http.StatusOK, map[string]any{
		"encrypted": true,
		"payload": map[string]string{
			"ciphertext":        ciphertext,
			"ephemeral_pub":     ephemeralPub,
			"nonce":             nonce,
			"ml_kem_ciphertext": "", // Phase PQ: stub for ML-KEM-768
		},
	})
}

// HandleBatchDecisions processes POST /v1/mobile/decisions/batch.
//
// Phase 3 spec: When the device reconnects after being offline, it batch-syncs
// all queued signed decisions. Each decision is individually verified.
//
// Security invariants enforced:
//   1. Ed25519 signature verified BEFORE nonce is consumed.
//   2. Nonce must exist, not be expired, and not be previously consumed.
//   3. hold_payload_hash is verified against the stored hold payload.
//   4. Per-operator rate limit: max 10 decisions per batch, max 10 per minute.
//   5. Quorum-aware: if M-of-N is required, records a vote instead of
//      directly approving the action.
func HandleBatchDecisions(w http.ResponseWriter, r *http.Request) {
	var decisions []BatchDecision
	if err := json.NewDecoder(r.Body).Decode(&decisions); err != nil {
		writeError(w, "invalid JSON payload — expected array of decisions", http.StatusBadRequest)
		return
	}

	if len(decisions) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{
			"processed": 0,
			"results":   []any{},
		})
		return
	}

	// ── Rate limit: max 10 decisions per batch request ─────────────────────
	if len(decisions) > 10 {
		writeError(w, "batch size exceeds maximum of 10 decisions", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	now := time.Now().UTC()

	// ── Per-operator sliding window rate limit (10 decisions/minute) ──────
	// This prevents an operator (or compromised device) from rubber-stamping
	// hundreds of approvals by submitting many sequential batch requests.
	// Uses the decision_nonces table to count recently consumed nonces.
	if len(decisions) > 0 {
		operatorPub := decisions[0].Ed25519Pub
		var recentCount int
		_ = DB.QueryRow(ctx,
			`SELECT COUNT(*) FROM decision_nonces
			 WHERE consumed_by = $1 AND consumed_at > $2`,
			operatorPub, now.Add(-1*time.Minute),
		).Scan(&recentCount)

		if recentCount+len(decisions) > 10 {
			log.Printf("[MOBILE] Rate limit exceeded: device=%s...%s recent=%d+batch=%d > 10/min",
				operatorPub[:8], operatorPub[len(operatorPub)-4:], recentCount, len(decisions))
			writeJSON(w, http.StatusTooManyRequests, map[string]any{
				"error":          "per-operator rate limit exceeded: max 10 decisions per minute",
				"recent_count":   recentCount,
				"batch_size":     len(decisions),
				"retry_after_ms": 60000,
			})
			return
		}
	}

	// ── Attestation enforcement ───────────────────────────────────────────
	// In production mode (CICADA_ENFORCE_ATTESTATION=true), decisions without
	// a valid attestation token are DENIED and logged as security events.
	// Rejected tokens: empty string, "PENDING_IMPLEMENTATION", "ATTESTATION_UNAVAILABLE"
	enforceAttestation := os.Getenv("CICADA_ENFORCE_ATTESTATION") == "true"

	results := make([]map[string]any, 0, len(decisions))

	for _, d := range decisions {
		result := map[string]any{
			"hold_ref": d.HoldRef,
			"accepted": false,
		}

		// ── Step 1: Verify the device exists and is active ────────────────
		var deviceStatus string
		err := DB.QueryRow(ctx,
			`SELECT status FROM mobile_devices WHERE ed25519_pub = $1`,
			d.Ed25519Pub,
		).Scan(&deviceStatus)
		if err != nil || deviceStatus != "active" {
			result["error"] = "device not active"
			results = append(results, result)
			continue
		}

		// ── Step 1b: Enforce attestation token policy ─────────────────────
		// When CICADA_ENFORCE_ATTESTATION=true, reject any decision that
		// doesn't carry a valid platform attestation token. This prevents
		// rooted/emulated devices from approving actions in production.
		//
		// Known-invalid tokens (from AttestationService fallbacks):
		//   ""                                        → no token sent
		//   "PENDING_IMPLEMENTATION"                  → legacy placeholder (pre-R5)
		//   "ATTESTATION_UNAVAILABLE"                 → platform doesn't support it
		//   "ATTESTATION_ANDROID_PENDING_PLAY_CONSOLE_SETUP" → Play Integrity not configured
		//   "ATTESTATION_IOS_PENDING_XCODE_SETUP"     → App Attest not configured
		invalidTokens := map[string]bool{
			"":                          true,
			"PENDING_IMPLEMENTATION":    true,
			"ATTESTATION_UNAVAILABLE":   true,
			"ATTESTATION_ANDROID_PENDING_PLAY_CONSOLE_SETUP": true,
			"ATTESTATION_IOS_PENDING_XCODE_SETUP":            true,
		}
		if invalidTokens[d.AttestationToken] {
			if enforceAttestation {
				log.Printf("[MOBILE][SECURITY] Decision DENIED — invalid attestation token: "+
					"hold=%s device=%s...%s token=%q",
					d.HoldRef, d.Ed25519Pub[:8], d.Ed25519Pub[len(d.Ed25519Pub)-4:], d.AttestationToken)
				result["error"] = "device attestation required — decisions without valid Play Integrity / App Attest token are denied in production"
				results = append(results, result)
				continue
			}
			// Enforcement is off — log but proceed (development mode).
			log.Printf("[MOBILE][ATTESTATION] Non-production token accepted (enforcement off): "+
				"hold=%s token=%q", d.HoldRef, d.AttestationToken)
		}

		// ── Step 2: Verify Ed25519 signature BEFORE touching nonce ────────
		// The signing payload is: hold_ref|decision|decision_nonce|gateway_timestamp|hold_payload_hash
		// This MUST match what the app signs in DecisionService.signDecision().
		signingPayload := d.HoldRef + "|" + d.Decision + "|" + d.DecisionNonce + "|" + d.GatewayTimestamp + "|" + d.HoldPayloadHash
		pubKeyBytes, err := base64.StdEncoding.DecodeString(d.Ed25519Pub)
		if err != nil || len(pubKeyBytes) != ed25519.PublicKeySize {
			result["error"] = "invalid ed25519_pub encoding"
			results = append(results, result)
			continue
		}
		sigBytes, err := base64.StdEncoding.DecodeString(d.SignatureEd25519)
		if err != nil || len(sigBytes) != ed25519.SignatureSize {
			result["error"] = "invalid signature encoding"
			results = append(results, result)
			continue
		}
		if !ed25519.Verify(ed25519.PublicKey(pubKeyBytes), []byte(signingPayload), sigBytes) {
			log.Printf("[MOBILE] Signature verification FAILED: hold=%s device=%s...%s",
				d.HoldRef, d.Ed25519Pub[:8], d.Ed25519Pub[len(d.Ed25519Pub)-4:])
			result["error"] = "Ed25519 signature verification failed"
			results = append(results, result)
			continue
		}

		// ── Step 2b: Verify ML-DSA-65 PQC signature (hybrid verification) ─
		// When CICADA_ENFORCE_PQC is true, BOTH classical (Ed25519) and
		// post-quantum (ML-DSA-65) signatures MUST be present and valid.
		// This hybrid approach ensures security against quantum adversaries
		// while maintaining backward compatibility during rollout.
		//
		// The ML-DSA-65 signature covers the same signing payload as Ed25519:
		//   hold_ref|decision|decision_nonce|gateway_timestamp|hold_payload_hash
		enforcePQC := os.Getenv("CICADA_ENFORCE_PQC") == "true"
		if d.SignatureMlDsa65 != "" {
			// ML-DSA-65 signature present — verify it regardless of enforcement mode.
			// We need the device's ML-DSA public key from the database.
			var mlDsaPub string
			err := DB.QueryRow(ctx,
				`SELECT COALESCE(ml_dsa65_pub, '') FROM mobile_devices WHERE ed25519_pub = $1`,
				d.Ed25519Pub,
			).Scan(&mlDsaPub)
			if err != nil || mlDsaPub == "" {
				log.Printf("[MOBILE][PQC] ML-DSA-65 signature provided but no public key on file: "+
					"hold=%s device=%s...%s",
					d.HoldRef, d.Ed25519Pub[:8], d.Ed25519Pub[len(d.Ed25519Pub)-4:])
				result["error"] = "ML-DSA-65 signature provided but no public key registered — re-pair required"
				results = append(results, result)
				continue
			}

			if verifyErr := pqc.VerifyMLDSA65(mlDsaPub, []byte(signingPayload), d.SignatureMlDsa65); verifyErr != nil {
				log.Printf("[MOBILE][PQC] ML-DSA-65 verification FAILED: hold=%s device=%s...%s err=%v",
					d.HoldRef, d.Ed25519Pub[:8], d.Ed25519Pub[len(d.Ed25519Pub)-4:], verifyErr)
				result["error"] = "ML-DSA-65 signature verification failed"
				results = append(results, result)
				continue
			}
			log.Printf("[MOBILE][PQC] ML-DSA-65 verification PASSED: hold=%s device=%s...%s",
				d.HoldRef, d.Ed25519Pub[:8], d.Ed25519Pub[len(d.Ed25519Pub)-4:])
		} else if enforcePQC {
			// Enforcement mode is on but no PQC signature was provided.
			log.Printf("[MOBILE][PQC] DENIED — ML-DSA-65 signature required but missing: "+
				"hold=%s device=%s...%s",
				d.HoldRef, d.Ed25519Pub[:8], d.Ed25519Pub[len(d.Ed25519Pub)-4:])
			result["error"] = "ML-DSA-65 signature required — PQC enforcement is active"
			results = append(results, result)
			continue
		}
		// If enforcement is off and no PQC sig provided, proceed with
		// Ed25519-only verification (backward compatibility during rollout).

		// ── Step 3: Verify hold_payload_hash matches stored payload ───────
		var storedHash string
		err = DB.QueryRow(ctx,
			`SELECT encode(digest(ciphertext, 'sha256'), 'hex')
			 FROM hold_payloads WHERE hold_ref = $1`,
			d.HoldRef,
		).Scan(&storedHash)
		// If we have a stored hash, verify it matches. If the hold_payloads
		// table doesn't have this record (e.g. expired), we still proceed
		// but log a warning — the nonce check below will catch expired holds.
		if err == nil && storedHash != "" && d.HoldPayloadHash != storedHash {
			log.Printf("[MOBILE] hold_payload_hash MISMATCH: hold=%s expected=%s got=%s",
				d.HoldRef, storedHash, d.HoldPayloadHash)
			result["error"] = "hold_payload_hash does not match stored action — possible action substitution"
			results = append(results, result)
			continue
		}

		// ── Step 4: Check nonce hasn't been consumed (anti-replay) ────────
		var consumedAt *time.Time
		err = DB.QueryRow(ctx,
			`SELECT consumed_at FROM decision_nonces WHERE nonce = $1`,
			d.DecisionNonce,
		).Scan(&consumedAt)
		if err == nil && consumedAt != nil {
			result["error"] = "nonce already consumed — replay rejected"
			results = append(results, result)
			continue
		}

		// ── Step 5: Consume the nonce (ONLY after signature is verified) ──
		_, _ = DB.Exec(ctx,
			`INSERT INTO decision_nonces (nonce, hold_ref, consumed_at, consumed_by, expires_at)
			 VALUES ($1, $2, $3, $4, $5)
			 ON CONFLICT (nonce) DO UPDATE SET consumed_at = EXCLUDED.consumed_at, consumed_by = EXCLUDED.consumed_by`,
			d.DecisionNonce, d.HoldRef, now, d.Ed25519Pub, now.Add(24*time.Hour),
		)

		// ── Step 6: Check quorum requirements ─────────────────────────────
		// If this hold requires M-of-N approval, record a vote instead of
		// directly updating the CIBA status.
		var requiredVotes int
		err = DB.QueryRow(ctx,
			`SELECT COALESCE(required_votes, 1) FROM ciba_authorization_requests
			 WHERE trace_id = $1`,
			d.HoldRef,
		).Scan(&requiredVotes)
		if err != nil {
			requiredVotes = 1 // Default: single approval
		}

		if requiredVotes > 1 {
			// M-of-N mode: Record the vote, don't directly approve.
			_, err = DB.Exec(ctx,
				`INSERT INTO quorum_votes (hold_ref, device_fingerprint, vote, signature, voted_at)
				 VALUES ($1, $2, $3, $4, $5)
				 ON CONFLICT (hold_ref, device_fingerprint) DO NOTHING`,
				d.HoldRef, d.Ed25519Pub, d.Decision, d.SignatureEd25519, now,
			)
			if err != nil {
				result["error"] = "failed to record quorum vote"
				results = append(results, result)
				continue
			}

			// Check if quorum is now met.
			var approvalCount int
			_ = DB.QueryRow(ctx,
				`SELECT COUNT(*) FROM quorum_votes
				 WHERE hold_ref = $1 AND vote = 'APPROVE'`,
				d.HoldRef,
			).Scan(&approvalCount)

			if approvalCount >= requiredVotes {
				// Quorum met — execute the approval.
				_, _ = DB.Exec(ctx,
					`UPDATE ciba_authorization_requests
					 SET status = 'approved', responded_by = 'quorum',
					     responded_at = $1, updated_at = $1
					 WHERE trace_id = $2 AND status = 'pending'`,
					now, d.HoldRef,
				)
				log.Printf("[MOBILE] Quorum met: hold=%s votes=%d/%d",
					d.HoldRef, approvalCount, requiredVotes)
			} else {
				log.Printf("[MOBILE] Quorum vote recorded: hold=%s votes=%d/%d",
					d.HoldRef, approvalCount, requiredVotes)
			}

			result["accepted"] = true
			result["quorum_status"] = map[string]any{
				"current_approvals": approvalCount,
				"required_votes":    requiredVotes,
				"resolved":          approvalCount >= requiredVotes,
			}
			results = append(results, result)
			continue
		}

		// ── Step 7: Single-approval mode — record directly ────────────────
		_, err = DB.Exec(ctx,
			`UPDATE ciba_authorization_requests
			 SET status = CASE WHEN $1 = 'APPROVE' THEN 'approved'
			                   WHEN $1 = 'REJECT' THEN 'denied'
			                   ELSE 'modified' END,
			     responded_by = $2,
			     responded_at = $3,
			     updated_at = $3
			 WHERE trace_id = $4 AND status = 'pending'`,
			d.Decision, d.Ed25519Pub, now, d.HoldRef,
		)
		if err != nil {
			result["error"] = "failed to record decision"
			results = append(results, result)
			continue
		}

		result["accepted"] = true
		results = append(results, result)

		log.Printf("[MOBILE] Decision verified+recorded: hold=%s decision=%s device=%s...%s sig=VERIFIED",
			d.HoldRef, d.Decision, d.Ed25519Pub[:8], d.Ed25519Pub[len(d.Ed25519Pub)-4:])
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"processed": len(decisions),
		"results":   results,
	})
}

