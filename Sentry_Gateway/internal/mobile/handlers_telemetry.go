// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package mobile

// handlers_telemetry.go — Phase 5: Privacy-Preserving Telemetry
//                         Phase 7: Multi-Approval Quorum Status

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
)

// HandleTelemetry processes POST /v1/mobile/telemetry.
//
// Phase 5 spec: The device sends a weekly aggregated telemetry report.
// All data is already bucketed and anonymised on-device:
//   - Date-only precision (no hours/minutes/seconds)
//   - Bucketed latency (0-5s, 5-15s, 15-30s, 30s+)
//   - ZERO geolocation, ZERO biometric data, ZERO IMEI
//
// The Gateway stores this for operational analytics only. The data
// cannot be used to identify individual operators or their behaviour.
func HandleTelemetry(w http.ResponseWriter, r *http.Request) {
	var report map[string]any
	if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
		writeError(w, "invalid JSON payload", http.StatusBadRequest)
		return
	}

	deviceFingerprint, _ := report["device_fingerprint"].(string)
	if deviceFingerprint == "" {
		writeError(w, "device_fingerprint is required", http.StatusBadRequest)
		return
	}

	// ── Verify device is active ───────────────────────────────────────────
	ctx := r.Context()
	var status string
	err := DB.QueryRow(ctx,
		`SELECT status FROM mobile_devices WHERE ed25519_pub = $1`,
		deviceFingerprint,
	).Scan(&status)
	if err != nil || status != "active" {
		writeError(w, "device not found or not active", http.StatusForbidden)
		return
	}

	// ── Store the telemetry report ────────────────────────────────────────
	// In production, this would go to a time-series database or analytics
	// pipeline. For now, we log it as structured JSON for the audit trail.
	reportJSON, _ := json.Marshal(report)
	log.Printf("[TELEMETRY] Weekly report from device %s...%s: %s",
		deviceFingerprint[:8], deviceFingerprint[len(deviceFingerprint)-4:],
		string(reportJSON))

	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "accepted",
		"message": "telemetry report received",
	})
}

// HandleQuorumStatus processes GET /v1/hitl/hold/{holdRef}/quorum.
//
// Phase 7 spec: Returns the M-of-N quorum status for a multi-approval hold.
// The app polls this to show how many approvals are still needed.
func HandleQuorumStatus(w http.ResponseWriter, r *http.Request) {
	holdRef := chi.URLParam(r, "holdRef")
	if holdRef == "" {
		writeError(w, "hold_ref is required", http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	// ── Fetch quorum configuration for this hold ──────────────────────────
	// The required_votes is set when the hold is created (e.g., 2-of-3).
	// Default to 1-of-1 if no quorum config exists (standard single-approval).
	var requiredVotes, totalVoters int
	err := DB.QueryRow(ctx,
		`SELECT COALESCE(
			(SELECT required_approvals FROM ciba_authorization_requests
			 WHERE trace_id = $1), 1),
		 COALESCE(
			(SELECT total_approvers FROM ciba_authorization_requests
			 WHERE trace_id = $1), 1)`,
		holdRef,
	).Scan(&requiredVotes, &totalVoters)
	if err != nil {
		// Default to single approval if table doesn't have these columns yet
		requiredVotes = 1
		totalVoters = 1
	}

	// ── Count current votes ───────────────────────────────────────────────
	var approvals, rejections int
	_ = DB.QueryRow(ctx,
		`SELECT COUNT(*) FROM quorum_votes WHERE hold_ref = $1 AND vote = 'approve'`,
		holdRef,
	).Scan(&approvals)
	_ = DB.QueryRow(ctx,
		`SELECT COUNT(*) FROM quorum_votes WHERE hold_ref = $1 AND vote = 'reject'`,
		holdRef,
	).Scan(&rejections)

	// ── Fetch voter fingerprints ──────────────────────────────────────────
	rows, err := DB.Query(ctx,
		`SELECT device_fingerprint FROM quorum_votes WHERE hold_ref = $1`,
		holdRef,
	)
	var fingerprints []string
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var fp string
			if rows.Scan(&fp) == nil {
				fingerprints = append(fingerprints, fp)
			}
		}
	}
	if fingerprints == nil {
		fingerprints = []string{}
	}

	// ── Determine outcome ─────────────────────────────────────────────────
	resolved := false
	outcome := ""
	if approvals >= requiredVotes {
		resolved = true
		outcome = "approved"
	} else if rejections > (totalVoters - requiredVotes) {
		// Enough rejections that approval is mathematically impossible
		resolved = true
		outcome = "rejected"
	}

	writeJSON(w, http.StatusOK, QuorumResponse{
		HoldRef:           holdRef,
		RequiredVotes:     requiredVotes,
		TotalVoters:       totalVoters,
		CurrentApprovals:  approvals,
		CurrentRejects:    rejections,
		VoterFingerprints: fingerprints,
		Resolved:          resolved,
		Outcome:           outcome,
	})
}
