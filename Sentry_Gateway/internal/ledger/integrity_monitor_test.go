// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// ── Test Helpers ──────────────────────────────────────────────────

func setupTestDB(t *testing.T) *sql.DB {
	t.Helper()
	f, err := os.CreateTemp("", "ledger_monitor_test_*.db")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	t.Cleanup(func() { os.Remove(f.Name()) })

	db, err := sql.Open("sqlite", f.Name())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	// Create evidence_chain table (matches edge_ledger.go schema)
	_, err = db.Exec(`
		CREATE TABLE evidence_chain (
			event_id       TEXT PRIMARY KEY,
			trace_id       TEXT NOT NULL,
			tenant_id      TEXT,
			agent_id       TEXT,
			decision       TEXT NOT NULL,
			action_class   TEXT,
			policy_version TEXT,
			reason_codes   TEXT,
			risk_score     REAL,
			timestamp      TEXT NOT NULL,
			previous_hash  TEXT NOT NULL,
			record_hash    TEXT NOT NULL,
			signature_ref  TEXT,
			synced         INTEGER DEFAULT 0,
			context_fingerprint TEXT DEFAULT '',
			reasoning_trace TEXT DEFAULT '',
			shadow_violation INTEGER DEFAULT 0,
			human_context TEXT DEFAULT ''
		)
	`)
	if err != nil {
		t.Fatal(err)
	}

	return db
}

// computeHash replicates the exact hashing logic from edge_ledger.go:141-147
func computeHash(prevHash, traceID, agentID, decision, actionClass, policyVersion, timestamp string, riskScore float64, reasonCodes []string) string {
	reasonJSON, _ := json.Marshal(reasonCodes)
	payloadStr := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%f|%s",
		prevHash, traceID, agentID,
		decision, actionClass, policyVersion,
		timestamp, riskScore, string(reasonJSON),
	)
	h := sha256.Sum256([]byte(payloadStr))
	return hex.EncodeToString(h[:])
}

// insertValidRecord inserts a properly hashed record into the test DB
func insertValidRecord(t *testing.T, db *sql.DB, eventID, prevHash, traceID, agentID, decision string) string {
	t.Helper()
	actionClass := "proxy"
	policyVersion := "v1"
	timestamp := time.Now().UTC().Format(time.RFC3339Nano)
	riskScore := 0.42
	reasonCodes := []string{"test_reason"}
	reasonJSON, _ := json.Marshal(reasonCodes)

	recordHash := computeHash(prevHash, traceID, agentID, decision, actionClass, policyVersion, timestamp, riskScore, reasonCodes)

	_, err := db.Exec(`
		INSERT INTO evidence_chain
			(event_id, trace_id, tenant_id, agent_id, decision, action_class,
			 policy_version, reason_codes, risk_score, timestamp, previous_hash, record_hash)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		eventID, traceID, "tenant-1", agentID, decision, actionClass,
		policyVersion, string(reasonJSON), riskScore, timestamp, prevHash, recordHash,
	)
	if err != nil {
		t.Fatal(err)
	}
	return recordHash
}

// ── IntegrityMonitor Tests ───────────────────────────────────────

func TestIntegrityMonitor_EmptyChain(t *testing.T) {
	db := setupTestDB(t)
	monitor := NewIntegrityMonitor(db, time.Hour, nil)

	status := monitor.VerifyChain()

	if !status.Valid {
		t.Errorf("empty chain should be valid, got: %+v", status)
	}
	if status.VerifiedEntries != 0 {
		t.Errorf("expected 0 verified entries, got %d", status.VerifiedEntries)
	}
}

func TestIntegrityMonitor_SingleValidRecord(t *testing.T) {
	db := setupTestDB(t)
	genesis := "genesis_000000000000000000000000000000"
	insertValidRecord(t, db, "evt-001", genesis, "trace-001", "agent-001", "allow")

	monitor := NewIntegrityMonitor(db, time.Hour, nil)
	status := monitor.VerifyChain()

	if !status.Valid {
		t.Errorf("single valid record should pass, got: %+v", status)
	}
	if status.VerifiedEntries != 1 {
		t.Errorf("expected 1 verified entry, got %d", status.VerifiedEntries)
	}
}

func TestIntegrityMonitor_ValidChainMultipleRecords(t *testing.T) {
	db := setupTestDB(t)
	genesis := "genesis_000000000000000000000000000000"

	hash1 := insertValidRecord(t, db, "evt-001", genesis, "trace-001", "agent-001", "allow")
	hash2 := insertValidRecord(t, db, "evt-002", hash1, "trace-002", "agent-001", "deny")
	_ = insertValidRecord(t, db, "evt-003", hash2, "trace-003", "agent-002", "allow")

	monitor := NewIntegrityMonitor(db, time.Hour, nil)
	status := monitor.VerifyChain()

	if !status.Valid {
		t.Errorf("valid 3-record chain should pass, got: %+v", status)
	}
	if status.VerifiedEntries != 3 {
		t.Errorf("expected 3 verified entries, got %d", status.VerifiedEntries)
	}
}

func TestIntegrityMonitor_TamperedRecordHash(t *testing.T) {
	db := setupTestDB(t)
	genesis := "genesis_000000000000000000000000000000"

	hash1 := insertValidRecord(t, db, "evt-001", genesis, "trace-001", "agent-001", "allow")
	insertValidRecord(t, db, "evt-002", hash1, "trace-002", "agent-001", "deny")

	// Tamper with the second record's stored hash
	_, err := db.Exec("UPDATE evidence_chain SET record_hash = 'TAMPERED_HASH_VALUE_000000000000000000' WHERE event_id = 'evt-002'")
	if err != nil {
		t.Fatal(err)
	}

	monitor := NewIntegrityMonitor(db, time.Hour, nil)
	status := monitor.VerifyChain()

	if status.Valid {
		t.Error("tampered hash should be detected as invalid")
	}
	if status.FirstBreakAt != "evt-002" {
		t.Errorf("expected break at evt-002, got %s", status.FirstBreakAt)
	}
	if status.ErrorMessage == "" {
		t.Error("expected an error message describing the tampering")
	}
}

func TestIntegrityMonitor_BrokenChainLink(t *testing.T) {
	db := setupTestDB(t)
	genesis := "genesis_000000000000000000000000000000"

	hash1 := insertValidRecord(t, db, "evt-001", genesis, "trace-001", "agent-001", "allow")
	insertValidRecord(t, db, "evt-002", hash1, "trace-002", "agent-001", "deny")

	// Break the chain by changing previous_hash of the second record
	_, err := db.Exec("UPDATE evidence_chain SET previous_hash = 'wrong_previous_hash' WHERE event_id = 'evt-002'")
	if err != nil {
		t.Fatal(err)
	}

	monitor := NewIntegrityMonitor(db, time.Hour, nil)
	status := monitor.VerifyChain()

	if status.Valid {
		t.Error("broken chain link should be detected")
	}
	if status.FirstBreakAt != "evt-002" {
		t.Errorf("expected break at evt-002, got %s", status.FirstBreakAt)
	}
	if status.VerifiedEntries != 1 {
		t.Errorf("expected 1 verified entry before break, got %d", status.VerifiedEntries)
	}
}

func TestIntegrityMonitor_TamperedField(t *testing.T) {
	db := setupTestDB(t)
	genesis := "genesis_000000000000000000000000000000"

	insertValidRecord(t, db, "evt-001", genesis, "trace-001", "agent-001", "allow")

	// Tamper with a payload field — change the decision from "allow" to "deny"
	// The stored hash was computed with "allow", so the recomputed hash will differ
	_, err := db.Exec("UPDATE evidence_chain SET decision = 'deny' WHERE event_id = 'evt-001'")
	if err != nil {
		t.Fatal(err)
	}

	monitor := NewIntegrityMonitor(db, time.Hour, nil)
	status := monitor.VerifyChain()

	if status.Valid {
		t.Error("tampered decision field should cause hash mismatch")
	}
	if status.FirstBreakAt != "evt-001" {
		t.Errorf("expected break at evt-001, got %s", status.FirstBreakAt)
	}
}

func TestIntegrityMonitor_ViolationHandlerCalled(t *testing.T) {
	db := setupTestDB(t)
	genesis := "genesis_000000000000000000000000000000"

	insertValidRecord(t, db, "evt-001", genesis, "trace-001", "agent-001", "allow")

	// Tamper
	db.Exec("UPDATE evidence_chain SET decision = 'deny' WHERE event_id = 'evt-001'")

	handlerCalled := false
	var capturedStatus IntegrityStatus

	handler := func(status IntegrityStatus) {
		handlerCalled = true
		capturedStatus = status
	}

	monitor := NewIntegrityMonitor(db, time.Hour, handler)
	monitor.runVerification()

	if !handlerCalled {
		t.Error("violation handler should have been called")
	}
	if capturedStatus.Valid {
		t.Error("captured status should be invalid")
	}
}

func TestIntegrityMonitor_ViolationHandlerNotCalledOnValid(t *testing.T) {
	db := setupTestDB(t)
	genesis := "genesis_000000000000000000000000000000"
	insertValidRecord(t, db, "evt-001", genesis, "trace-001", "agent-001", "allow")

	handlerCalled := false
	handler := func(status IntegrityStatus) {
		handlerCalled = true
	}

	monitor := NewIntegrityMonitor(db, time.Hour, handler)
	monitor.runVerification()

	if handlerCalled {
		t.Error("violation handler should NOT be called when chain is valid")
	}
}

func TestIntegrityMonitor_StatusThreadSafe(t *testing.T) {
	db := setupTestDB(t)
	monitor := NewIntegrityMonitor(db, time.Hour, nil)

	// Start and stop should not panic
	monitor.Start()

	// Read status concurrently
	for i := 0; i < 10; i++ {
		go func() {
			_ = monitor.Status()
		}()
	}

	time.Sleep(100 * time.Millisecond)
	monitor.Stop()

	status := monitor.Status()
	if !status.Valid {
		t.Errorf("empty chain should be valid, got: %+v", status)
	}
}

func TestIntegrityMonitor_CheckpointOptimization(t *testing.T) {
	db := setupTestDB(t)
	genesis := "genesis_000000000000000000000000000000"

	hash1 := insertValidRecord(t, db, "evt-001", genesis, "trace-001", "agent-001", "allow")
	monitor := NewIntegrityMonitor(db, time.Hour, nil)

	// First verification — processes 1 record
	status1 := monitor.VerifyChain()
	if status1.VerifiedEntries != 1 {
		t.Errorf("first run: expected 1, got %d", status1.VerifiedEntries)
	}

	// Add more records
	hash2 := insertValidRecord(t, db, "evt-002", hash1, "trace-002", "agent-001", "deny")
	_ = insertValidRecord(t, db, "evt-003", hash2, "trace-003", "agent-002", "allow")

	// Second verification — should only process 2 new records (checkpoint optimization)
	status2 := monitor.VerifyChain()
	if status2.VerifiedEntries != 2 {
		t.Errorf("second run: expected 2 new entries, got %d", status2.VerifiedEntries)
	}
	if !status2.Valid {
		t.Error("second run should still be valid")
	}
}

func TestIntegrityMonitor_LargeChain(t *testing.T) {
	db := setupTestDB(t)
	prevHash := "genesis_000000000000000000000000000000"

	// Build a 100-record chain
	for i := 0; i < 100; i++ {
		eventID := fmt.Sprintf("evt-%04d", i)
		traceID := fmt.Sprintf("trace-%04d", i)
		prevHash = insertValidRecord(t, db, eventID, prevHash, traceID, "agent-bulk", "allow")
	}

	monitor := NewIntegrityMonitor(db, time.Hour, nil)
	status := monitor.VerifyChain()

	if !status.Valid {
		t.Errorf("100-record chain should be valid, got: %+v", status)
	}
	if status.VerifiedEntries != 100 {
		t.Errorf("expected 100, got %d", status.VerifiedEntries)
	}
}

func TestIntegrityMonitor_TamperInMiddleOfLargeChain(t *testing.T) {
	db := setupTestDB(t)
	prevHash := "genesis_000000000000000000000000000000"

	for i := 0; i < 20; i++ {
		eventID := fmt.Sprintf("evt-%04d", i)
		traceID := fmt.Sprintf("trace-%04d", i)
		prevHash = insertValidRecord(t, db, eventID, prevHash, traceID, "agent-bulk", "allow")
	}

	// Tamper with record 10 (middle of chain)
	db.Exec("UPDATE evidence_chain SET risk_score = 0.99 WHERE event_id = 'evt-0010'")

	monitor := NewIntegrityMonitor(db, time.Hour, nil)
	status := monitor.VerifyChain()

	if status.Valid {
		t.Error("tampered record in middle should be caught")
	}
	if status.FirstBreakAt != "evt-0010" {
		t.Errorf("expected break at evt-0010, got %s", status.FirstBreakAt)
	}
	if status.VerifiedEntries != 10 {
		t.Errorf("expected 10 verified before break, got %d", status.VerifiedEntries)
	}
}

func TestIntegrityStatus_JSON(t *testing.T) {
	status := IntegrityStatus{
		Valid:           true,
		LastVerifiedAt:  "2026-05-11T10:00:00Z",
		VerifiedEntries: 42000,
	}

	data, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}

	var decoded IntegrityStatus
	json.Unmarshal(data, &decoded)

	if decoded.VerifiedEntries != 42000 {
		t.Errorf("expected 42000, got %d", decoded.VerifiedEntries)
	}
	if decoded.FirstBreakAt != "" {
		t.Error("omitempty should exclude empty FirstBreakAt")
	}
}
