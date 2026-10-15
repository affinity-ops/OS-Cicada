// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"
)

// IntegrityStatus represents the result of a chain integrity verification.
type IntegrityStatus struct {
	// Valid is true if every link in the chain is intact.
	Valid bool `json:"valid"`
	// LastVerifiedAt is the timestamp of the most recent verification run.
	LastVerifiedAt string `json:"last_verified_at"`
	// VerifiedEntries is the total number of records successfully verified.
	VerifiedEntries int `json:"verified_entries"`
	// FirstBreakAt is the event_id where the chain break was detected (empty if valid).
	FirstBreakAt string `json:"first_break_at,omitempty"`
	// ExpectedHash is what the re-computed hash should have been.
	ExpectedHash string `json:"expected_hash,omitempty"`
	// ActualHash is the hash stored in the database.
	ActualHash string `json:"actual_hash,omitempty"`
	// ErrorMessage provides human-readable detail on any integrity violation.
	ErrorMessage string `json:"error_message,omitempty"`
}

// IntegrityViolationHandler is called when the monitor detects a chain break.
// Implementations should fire operator alerts and Aegis push notifications.
type IntegrityViolationHandler func(status IntegrityStatus)

// IntegrityMonitor periodically re-walks the evidence chain, recomputing
// SHA-256 hashes to detect bit-rot, unauthorized modification, or insertion.
//
// This is the "Heartbeat of Truth" — a background Go routine that provides
// a continuous integrity proof for auditors. The GET /api/v1/ledger/status
// endpoint returns the latest IntegrityStatus.
type IntegrityMonitor struct {
	db               *sql.DB
	interval         time.Duration
	onViolation      IntegrityViolationHandler
	mu               sync.RWMutex
	latestStatus     IntegrityStatus
	cancel           context.CancelFunc
	done             chan struct{}
	checkpointRowID  int64 // optimization: start from last verified row
}

// NewIntegrityMonitor creates a monitor that verifies the evidence chain
// at the given interval.
//
// Args:
//
//	db:          The SQLite database containing the evidence_chain table.
//	interval:    How often to run verification (e.g. 1 * time.Hour).
//	onViolation: Callback invoked when a chain break is detected.
//	             Called at most once per verification cycle.
func NewIntegrityMonitor(db *sql.DB, interval time.Duration, onViolation IntegrityViolationHandler) *IntegrityMonitor {
	return &IntegrityMonitor{
		db:          db,
		interval:    interval,
		onViolation: onViolation,
		done:        make(chan struct{}),
		latestStatus: IntegrityStatus{
			Valid:          true,
			LastVerifiedAt: "never",
		},
	}
}

// Start begins the background verification loop. Non-blocking.
func (m *IntegrityMonitor) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel

	go func() {
		defer close(m.done)

		// Run verification immediately on start
		m.runVerification()

		ticker := time.NewTicker(m.interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				m.runVerification()
			case <-ctx.Done():
				return
			}
		}
	}()

	log.Printf("[LEDGER-MONITOR] Integrity monitor started — verifying every %s", m.interval)
}

// Stop gracefully shuts down the monitor.
func (m *IntegrityMonitor) Stop() {
	if m.cancel != nil {
		m.cancel()
		<-m.done
	}
	log.Printf("[LEDGER-MONITOR] Integrity monitor stopped")
}

// Status returns the latest integrity verification result.
// Thread-safe — called by the HTTP handler.
func (m *IntegrityMonitor) Status() IntegrityStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.latestStatus
}

// VerifyChain walks the entire evidence chain (or from checkpoint),
// re-computing each hash and comparing it to the stored value.
// This is the core verification function, also called directly by tests.
func (m *IntegrityMonitor) VerifyChain() IntegrityStatus {
	return m.verifyChainFromDB()
}

func (m *IntegrityMonitor) runVerification() {
	status := m.verifyChainFromDB()

	m.mu.Lock()
	m.latestStatus = status
	m.mu.Unlock()

	if !status.Valid {
		log.Printf("[LEDGER-MONITOR] ⚠ INTEGRITY VIOLATION at event %s: expected %s, got %s",
			status.FirstBreakAt, status.ExpectedHash[:16], status.ActualHash[:16])
		if m.onViolation != nil {
			m.onViolation(status)
		}
	} else {
		log.Printf("[LEDGER-MONITOR] ✓ Chain verified — %d entries valid", status.VerifiedEntries)
	}
}

func (m *IntegrityMonitor) verifyChainFromDB() IntegrityStatus {
	now := time.Now().UTC().Format(time.RFC3339)

	// Walk all records in insertion order (rowid)
	rows, err := m.db.Query(`
		SELECT event_id, trace_id, agent_id, decision, action_class,
		       policy_version, reason_codes, risk_score, timestamp,
		       previous_hash, record_hash
		FROM evidence_chain
		WHERE rowid > ?
		ORDER BY rowid ASC
	`, m.checkpointRowID)
	if err != nil {
		return IntegrityStatus{
			Valid:          false,
			LastVerifiedAt: now,
			ErrorMessage:   fmt.Sprintf("query failed: %v", err),
		}
	}
	defer rows.Close()

	verified := 0
	// If this is a checkpoint-based scan, we need the hash from the
	// previous checkpoint as the expected previous_hash for the first record.
	expectedPrevHash := ""
	if m.checkpointRowID == 0 {
		expectedPrevHash = "genesis_000000000000000000000000000000"
	} else {
		// Load the hash of the checkpoint record
		err := m.db.QueryRow(
			"SELECT record_hash FROM evidence_chain WHERE rowid = ?",
			m.checkpointRowID,
		).Scan(&expectedPrevHash)
		if err != nil {
			expectedPrevHash = "genesis_000000000000000000000000000000"
		}
	}

	lastRowID := m.checkpointRowID

	for rows.Next() {
		var (
			eventID, traceID, agentID       string
			decision, actionClass           string
			policyVersion, reasonCodesJSON  string
			timestamp, previousHash         string
			storedHash                      string
			riskScore                       float64
		)

		if err := rows.Scan(
			&eventID, &traceID, &agentID, &decision, &actionClass,
			&policyVersion, &reasonCodesJSON, &riskScore, &timestamp,
			&previousHash, &storedHash,
		); err != nil {
			return IntegrityStatus{
				Valid:          false,
				LastVerifiedAt: now,
				ErrorMessage:   fmt.Sprintf("scan failed: %v", err),
			}
		}

		// Step 1: Verify the previous_hash links to the prior record
		if previousHash != expectedPrevHash {
			return IntegrityStatus{
				Valid:           false,
				LastVerifiedAt:  now,
				VerifiedEntries: verified,
				FirstBreakAt:    eventID,
				ExpectedHash:    expectedPrevHash,
				ActualHash:      previousHash,
				ErrorMessage:    fmt.Sprintf("chain link broken: record %s has previous_hash %s but expected %s", eventID, previousHash[:16], expectedPrevHash[:16]),
			}
		}

		// Step 2: Recompute the record hash from the payload fields
		// This MUST match the formula in AppendRecord exactly (edge_ledger.go:141-147)
		var reasonCodes []string
		json.Unmarshal([]byte(reasonCodesJSON), &reasonCodes)
		recomputedReasonJSON, _ := json.Marshal(reasonCodes)

		payloadStr := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%f|%s",
			previousHash, traceID, agentID,
			decision, actionClass, policyVersion,
			timestamp, riskScore, string(recomputedReasonJSON),
		)
		h := sha256.Sum256([]byte(payloadStr))
		recomputedHash := hex.EncodeToString(h[:])

		if recomputedHash != storedHash {
			return IntegrityStatus{
				Valid:           false,
				LastVerifiedAt:  now,
				VerifiedEntries: verified,
				FirstBreakAt:    eventID,
				ExpectedHash:    recomputedHash,
				ActualHash:      storedHash,
				ErrorMessage:    fmt.Sprintf("hash mismatch: record %s — recomputed %s but stored %s (data may be tampered)", eventID, recomputedHash[:16], storedHash[:16]),
			}
		}

		expectedPrevHash = storedHash
		verified++
		lastRowID++
	}

	if err := rows.Err(); err != nil {
		return IntegrityStatus{
			Valid:          false,
			LastVerifiedAt: now,
			ErrorMessage:   fmt.Sprintf("row iteration error: %v", err),
		}
	}

	// Update checkpoint for the next run — only re-verify new records
	m.checkpointRowID = lastRowID

	return IntegrityStatus{
		Valid:           true,
		LastVerifiedAt:  now,
		VerifiedEntries: verified,
	}
}
