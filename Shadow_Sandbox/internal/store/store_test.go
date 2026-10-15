// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package store — test suite for the Shadow Sandbox SQLite persistence layer.
//
// Tests use in-memory SQLite databases (`:memory:`) to avoid filesystem
// side-effects. Each test creates a fresh database to ensure isolation.
package store

import (
	"testing"
)

// setupTestDB creates an in-memory SQLite database for a single test.
// Returns a cleanup function that must be deferred by the caller.
func setupTestDB(t *testing.T) func() {
	t.Helper()
	if err := Open(":memory:"); err != nil {
		t.Fatalf("failed to open in-memory db: %v", err)
	}
	return func() {
		if db != nil {
			db.Close()
			db = nil
		}
	}
}

// ─── Schema & Migration ─────────────────────────────────────────────────────

func TestOpen_CreatesSchema(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	// Verify the sandbox_events table exists by querying it.
	rows, err := db.Query("SELECT COUNT(*) FROM sandbox_events")
	if err != nil {
		t.Fatalf("schema should create sandbox_events table: %v", err)
	}
	defer rows.Close()

	if !rows.Next() {
		t.Fatal("expected at least one row from COUNT(*)")
	}
	var count int
	if err := rows.Scan(&count); err != nil {
		t.Fatalf("failed to scan count: %v", err)
	}
	if count != 0 {
		t.Errorf("fresh database should have 0 events, got %d", count)
	}
}

// ─── Append ──────────────────────────────────────────────────────────────────

func TestAppend_WritesRecord(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	Append(Event{
		AgentID:      "agent-001",
		TenantID:     "tenant-001",
		TraceID:      "trace-001",
		Method:       "POST",
		TargetURL:    "https://api.stripe.com/v1/charges",
		BodySnapshot: `{"amount":2000}`,
		AnomalyScore: 0.42,
		Findings:     `[{"rule":"destructive_method","score":0.40,"hit":"DELETE"}]`,
		SentToGossip: false,
	})

	events, err := Recent(10)
	if err != nil {
		t.Fatalf("Recent() failed: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	e := events[0]
	if e.AgentID != "agent-001" {
		t.Errorf("agent_id: want 'agent-001', got %q", e.AgentID)
	}
	if e.TenantID != "tenant-001" {
		t.Errorf("tenant_id: want 'tenant-001', got %q", e.TenantID)
	}
	if e.Method != "POST" {
		t.Errorf("method: want 'POST', got %q", e.Method)
	}
	if e.TargetURL != "https://api.stripe.com/v1/charges" {
		t.Errorf("target_url mismatch: got %q", e.TargetURL)
	}
	if e.BodySnapshot != `{"amount":2000}` {
		t.Errorf("body_snapshot mismatch: got %q", e.BodySnapshot)
	}
	if e.AnomalyScore < 0.41 || e.AnomalyScore > 0.43 {
		t.Errorf("anomaly_score: want ~0.42, got %.2f", e.AnomalyScore)
	}
	if e.RecordedAt == "" {
		t.Error("recorded_at should be set automatically")
	}
}

// ─── Recent ──────────────────────────────────────────────────────────────────

func TestRecent_NewestFirst(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	// Insert 3 events in sequence.
	for i := 0; i < 3; i++ {
		Append(Event{
			AgentID:   "agent-order",
			Method:    "GET",
			TargetURL: "https://example.com/" + string(rune('a'+i)),
		})
	}

	events, err := Recent(10)
	if err != nil {
		t.Fatalf("Recent() failed: %v", err)
	}
	if len(events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(events))
	}

	// Newest first = highest ID first (auto-increment).
	if events[0].ID <= events[1].ID || events[1].ID <= events[2].ID {
		t.Errorf("events should be newest-first: IDs %d, %d, %d",
			events[0].ID, events[1].ID, events[2].ID)
	}
}

func TestRecent_RespectsLimit(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	// Insert 5 events, request only 2.
	for i := 0; i < 5; i++ {
		Append(Event{
			AgentID:   "agent-limit",
			Method:    "GET",
			TargetURL: "https://example.com/",
		})
	}

	events, err := Recent(2)
	if err != nil {
		t.Fatalf("Recent() failed: %v", err)
	}
	if len(events) != 2 {
		t.Errorf("expected 2 events with limit=2, got %d", len(events))
	}
}

func TestRecent_EmptyDB(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	events, err := Recent(10)
	if err != nil {
		t.Fatalf("Recent() on empty DB failed: %v", err)
	}
	// Go SQLite returns nil for empty result sets, which is acceptable.
	if events != nil && len(events) != 0 {
		t.Errorf("expected nil or empty slice, got %d events", len(events))
	}
}

// ─── Nil DB Safety ───────────────────────────────────────────────────────────

func TestAppend_NilDB_NoPanic(t *testing.T) {
	// Ensure db is nil — this simulates the sandbox starting before
	// the database is opened. Append must be a no-op, not a crash.
	oldDB := db
	db = nil
	defer func() { db = oldDB }()

	// This must not panic.
	Append(Event{AgentID: "should-not-crash"})
}

func TestRecent_NilDB_ReturnsNil(t *testing.T) {
	oldDB := db
	db = nil
	defer func() { db = oldDB }()

	events, err := Recent(10)
	if err != nil {
		t.Errorf("nil DB should not return an error, got %v", err)
	}
	if events != nil {
		t.Errorf("nil DB should return nil events, got %v", events)
	}
}

// ─── SentToGossip Boolean Mapping ────────────────────────────────────────────

func TestAppend_SentToGossip_True(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	Append(Event{
		AgentID:      "agent-gossip",
		Method:       "POST",
		TargetURL:    "https://example.com",
		SentToGossip: true,
	})

	events, _ := Recent(1)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if !events[0].SentToGossip {
		t.Error("SentToGossip should be true after round-trip")
	}
}

// ─── FindingsSummary ─────────────────────────────────────────────────────────

func TestFindingsSummary_ValidJSON(t *testing.T) {
	input := `[{"rule":"destructive_sql","score":0.90,"hit":"DROP TABLE"},{"rule":"credential_in_body","score":0.80,"hit":"sk-abc..."}]`
	result := FindingsSummary(input)
	if result != "destructive_sql, credential_in_body" {
		t.Errorf("expected 'destructive_sql, credential_in_body', got %q", result)
	}
}

func TestFindingsSummary_EmptyArray(t *testing.T) {
	result := FindingsSummary("[]")
	if result != "none" {
		t.Errorf("empty findings should return 'none', got %q", result)
	}
}

func TestFindingsSummary_InvalidJSON(t *testing.T) {
	result := FindingsSummary("not json at all")
	if result != "none" {
		t.Errorf("invalid JSON should return 'none', got %q", result)
	}
}

func TestFindingsSummary_NullString(t *testing.T) {
	result := FindingsSummary("null")
	if result != "none" {
		t.Errorf("null findings should return 'none', got %q", result)
	}
}
