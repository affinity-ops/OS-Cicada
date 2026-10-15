// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package store persists every intercepted ghost-mode request to SQLite.
// This is append-only — records are never updated or deleted. The operator
// can query the database directly or via the /sandbox/events endpoint to
// review what a ghost-mode agent was attempting to do.
package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// Event is one intercepted agent request with its analysis result.
type Event struct {
	ID           int64   `json:"id"`
	RecordedAt   string  `json:"recorded_at"`
	AgentID      string  `json:"agent_id"`
	TenantID     string  `json:"tenant_id"`
	TraceID      string  `json:"trace_id"`
	Method       string  `json:"method"`
	TargetURL    string  `json:"target_url"`
	BodySnapshot string  `json:"body_snapshot"` // first 1024 bytes only
	AnomalyScore float64 `json:"anomaly_score"`
	Findings     string  `json:"findings"` // JSON-encoded []Finding
	SentToGossip bool    `json:"sent_to_gossip"`
}

var db *sql.DB

// Open initialises (or opens) the SQLite database at dbPath.
// Schema is created if the file does not yet exist.
func Open(dbPath string) error {
	var err error
	db, err = sql.Open("sqlite3", dbPath)
	if err != nil {
		return fmt.Errorf("open sqlite: %w", err)
	}
	return migrate()
}

// OpenDefault opens the database at the path set in SANDBOX_DB_PATH,
// falling back to /data/sandbox.db (the container's mounted volume path).
func OpenDefault() error {
	path := os.Getenv("SANDBOX_DB_PATH")
	if path == "" {
		path = "/data/sandbox.db"
	}
	return Open(path)
}

func migrate() error {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS sandbox_events (
		id            INTEGER PRIMARY KEY AUTOINCREMENT,
		recorded_at   TEXT    NOT NULL,
		agent_id      TEXT    NOT NULL,
		tenant_id     TEXT    NOT NULL DEFAULT '',
		trace_id      TEXT    NOT NULL DEFAULT '',
		method        TEXT    NOT NULL,
		target_url    TEXT    NOT NULL,
		body_snapshot TEXT    NOT NULL DEFAULT '',
		anomaly_score REAL    NOT NULL DEFAULT 0,
		findings      TEXT    NOT NULL DEFAULT '[]',
		sent_to_gossip INTEGER NOT NULL DEFAULT 0
	)`)
	return err
}

// Append writes a new event record. Non-fatal on error — sandbox recording
// must not block the response path.
func Append(e Event) {
	if db == nil {
		return
	}
	_, err := db.Exec(`INSERT INTO sandbox_events
		(recorded_at, agent_id, tenant_id, trace_id, method, target_url, body_snapshot, anomaly_score, findings, sent_to_gossip)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		time.Now().UTC().Format(time.RFC3339),
		e.AgentID, e.TenantID, e.TraceID, e.Method, e.TargetURL,
		e.BodySnapshot, e.AnomalyScore, e.Findings, boolInt(e.SentToGossip),
	)
	if err != nil {
		log.Printf("[STORE] append error: %v", err)
	}
}

// Recent returns the most recent n events ordered newest-first.
func Recent(n int) ([]Event, error) {
	if db == nil {
		return nil, nil
	}
	rows, err := db.Query(`SELECT id, recorded_at, agent_id, tenant_id, trace_id,
		method, target_url, body_snapshot, anomaly_score, findings, sent_to_gossip
		FROM sandbox_events ORDER BY id DESC LIMIT ?`, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []Event
	for rows.Next() {
		var e Event
		var gossipInt int
		if err := rows.Scan(&e.ID, &e.RecordedAt, &e.AgentID, &e.TenantID, &e.TraceID,
			&e.Method, &e.TargetURL, &e.BodySnapshot, &e.AnomalyScore, &e.Findings, &gossipInt); err != nil {
			continue
		}
		e.SentToGossip = gossipInt == 1
		events = append(events, e)
	}
	return events, nil
}

// FindingsSummary returns a human-readable summary for an event's findings JSON.
func FindingsSummary(findingsJSON string) string {
	var findings []struct {
		Rule string `json:"rule"`
	}
	if err := json.Unmarshal([]byte(findingsJSON), &findings); err != nil || len(findings) == 0 {
		return "none"
	}
	names := make([]string, len(findings))
	for i, f := range findings {
		names[i] = f.Rule
	}
	result := ""
	for i, n := range names {
		if i > 0 {
			result += ", "
		}
		result += n
	}
	return result
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
