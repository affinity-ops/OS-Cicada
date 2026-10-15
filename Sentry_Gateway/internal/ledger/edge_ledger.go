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
	"os"
	"strings"
	"sync"
	"time"

	"github.com/asai/cicada/sentry/internal/store"
	_ "modernc.org/sqlite"
)

// EventRecord represents a single immutable entry in the evidence chain.
type EventRecord struct {
	EventID       string   `json:"event_id"`
	TraceID       string   `json:"trace_id"`
	TenantID      string   `json:"tenant_id"`
	AgentID       string   `json:"agent_id"`
	EvarID        string   `json:"evar_id"`
	Decision      string   `json:"decision"`
	ActionClass   string   `json:"action_class"`
	TargetURL     string   `json:"target_url,omitempty"` // real target API URL for PG mirror
	PolicyVersion string   `json:"policy_version"`
	ReasonCodes   []string `json:"reason_codes"`
	RiskScore     float64  `json:"risk_score"`
	Timestamp     string   `json:"timestamp"`
	PreviousHash  string   `json:"previous_hash"`
	RecordHash      string   `json:"record_hash"`
	SignatureRef    string   `json:"signature_ref"`
	ShadowViolation bool     `json:"shadow_violation"`

	// LLM audit fields — populated only for ActionClass="llm_proxy" records.
	// ContextFingerprint is the SHA-256 of the agent's sorted message content
	// hashes at the time of the call. Used for memory isolation: two records with
	// the same fingerprint have identical context windows.
	// ReasoningTrace stores the chain-of-thought tokens extracted from the LLM
	// response (Claude <thinking> blocks, OpenAI reasoning_content). Empty for
	// standard non-thinking responses and non-LLM proxy calls.
	ContextFingerprint string `json:"context_fingerprint,omitempty"`
	ReasoningTrace     string `json:"reasoning_trace,omitempty"`
	HumanContext       string `json:"human_context,omitempty"`

	// Model is the LLM model identifier (e.g. "gpt-4o", "claude-3-5-sonnet-20241022").
	// Extracted from the top-level "model" field of the LLM proxy request body.
	// Empty for non-LLM actions.
	Model string `json:"model,omitempty"`
}

// EdgeLedger manages the local append-only SQLite evidence chain.
type EdgeLedger struct {
	db         *sql.DB
	mu         sync.Mutex
	latestHash string
	syncWorker *CentralSyncWorker
	pgMirrorCh chan EventRecord // bounded buffer for async PG mirror writes
}

// NewEdgeLedger opens the SQLite database at the given path, creates the
// evidence_chain table if needed, and loads the latest chain hash.
func NewEdgeLedger(syncWorker *CentralSyncWorker) (*EdgeLedger, error) {
	dsn := os.Getenv("CICADA_LEDGER_PATH")
	if dsn == "" {
		dsn = "cicada_edge_ledger.db"
	}

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	// Enable WAL mode for concurrent read/write performance
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		return nil, fmt.Errorf("set WAL mode: %w", err)
	}

	// Create the evidence chain table
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS evidence_chain (
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
			synced         INTEGER DEFAULT 0
		)
	`); err != nil {
		return nil, fmt.Errorf("create evidence_chain table: %w", err)
	}

	// Add LLM audit columns to existing databases that predate them.
	// SQLite returns "duplicate column name" when the column already exists —
	// that is expected on fresh databases and is not an error.
	for _, ddl := range []string{
		"ALTER TABLE evidence_chain ADD COLUMN context_fingerprint TEXT DEFAULT ''",
		"ALTER TABLE evidence_chain ADD COLUMN reasoning_trace TEXT DEFAULT ''",
		"ALTER TABLE evidence_chain ADD COLUMN shadow_violation INTEGER DEFAULT 0",
		"ALTER TABLE evidence_chain ADD COLUMN human_context TEXT DEFAULT ''",
	} {
		if _, err := db.Exec(ddl); err != nil && !strings.Contains(err.Error(), "duplicate column") {
			return nil, fmt.Errorf("migrate evidence_chain: %w", err)
		}
	}

	// Load the latest hash for chain continuity
	var latestHash string
	err = db.QueryRow("SELECT record_hash FROM evidence_chain ORDER BY rowid DESC LIMIT 1").Scan(&latestHash)
	if err == sql.ErrNoRows {
		latestHash = "genesis_000000000000000000000000000000"
	} else if err != nil {
		return nil, fmt.Errorf("load latest hash: %w", err)
	}

	log.Printf("[LEDGER] Edge SQLite ledger initialized at %s (chain tail: %s...)", dsn, latestHash[:16])

	// PG mirror channel: bounded buffer prevents goroutine explosion under load.
	// Capacity 4096 absorbs burst traffic; a single background worker drains it.
	pgCh := make(chan EventRecord, 4096)

	ledger := &EdgeLedger{
		db:         db,
		latestHash: latestHash,
		syncWorker: syncWorker,
		pgMirrorCh: pgCh,
	}

	// Start a single background worker that drains the PG mirror channel.
	// This replaces the previous per-record `go func()` that spawned 8,000+
	// concurrent goroutines under 200 VUs, exhausting file descriptors.
	go ledger.pgMirrorWorker()

	return ledger, nil
}

// AppendRecord computes the chain hash and inserts a new immutable record.
func (l *EdgeLedger) AppendRecord(record EventRecord) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	record.PreviousHash = l.latestHash
	record.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)

	// Compute cryptographic chain hash
	reasonJSON, _ := json.Marshal(record.ReasonCodes)
	payloadStr := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%f|%s",
		record.PreviousHash, record.TraceID, record.AgentID,
		record.Decision, record.ActionClass, record.PolicyVersion,
		record.Timestamp, record.RiskScore, string(reasonJSON),
	)
	h := sha256.Sum256([]byte(payloadStr))
	record.RecordHash = hex.EncodeToString(h[:])

	// Persist to SQLite
	_, err := l.db.Exec(`
		INSERT INTO evidence_chain
			(event_id, trace_id, tenant_id, agent_id, decision, action_class,
			 policy_version, reason_codes, risk_score, timestamp, previous_hash, record_hash,
			 context_fingerprint, reasoning_trace, shadow_violation, human_context)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		record.EventID, record.TraceID, record.TenantID, record.AgentID,
		record.Decision, record.ActionClass, record.PolicyVersion,
		string(reasonJSON), record.RiskScore, record.Timestamp,
		record.PreviousHash, record.RecordHash,
		record.ContextFingerprint, record.ReasoningTrace, record.ShadowViolation, record.HumanContext,
	)
	if err != nil {
		return fmt.Errorf("sqlite insert: %w", err)
	}

	l.latestHash = record.RecordHash
	log.Printf("[LEDGER] Trace %s -> [%s] -> Chain: %s...", record.TraceID, record.Decision, record.RecordHash[:16])

	// Enqueue for PG mirror — non-blocking. If the buffer is full (sustained
	// load exceeding drain rate), drop the mirror write rather than blocking
	// the proxy path. SQLite is the primary store; PG is for dashboard visibility.
	if store.DB != nil {
		select {
		case l.pgMirrorCh <- record:
			// Enqueued successfully
		default:
			log.Printf("[LEDGER] PG mirror buffer full — dropping mirror for trace %s", record.TraceID)
		}
	}

	// Notify sync worker for central replication
	if l.syncWorker != nil {
		l.syncWorker.Enqueue(record)
	}

	return nil
}

// pgMirrorWorker is a single long-lived goroutine that drains the PG mirror
// channel using a batch accumulation strategy. Records are buffered in memory
// and flushed to PostgreSQL in bulk when either:
//   - The batch reaches maxBatchSize (500 records), or
//   - The flushInterval ticker fires (every 100ms)
//
// This replaces the previous per-record `go func()` pattern that spawned
// 8,000+ concurrent goroutines under 200 VUs, each holding a Postgres
// connection and exhausting file descriptors.
//
// Architecture: the proxy hot path enqueues records to pgMirrorCh (O(1)
// non-blocking channel push). This worker accumulates them and executes
// a single multi-valued INSERT per flush, reducing Postgres IOPS by 500x.
func (l *EdgeLedger) pgMirrorWorker() {
	const maxBatchSize = 500
	const flushInterval = 100 * time.Millisecond

	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()

	batch := make([]EventRecord, 0, maxBatchSize)

	for {
		select {
		case record, ok := <-l.pgMirrorCh:
			if !ok {
				// Channel closed — flush remaining and exit
				if len(batch) > 0 {
					l.flushPGBatch(batch)
				}
				return
			}
			batch = append(batch, record)
			if len(batch) >= maxBatchSize {
				l.flushPGBatch(batch)
				batch = make([]EventRecord, 0, maxBatchSize)
			}

		case <-ticker.C:
			if len(batch) > 0 {
				l.flushPGBatch(batch)
				batch = make([]EventRecord, 0, maxBatchSize)
			}
		}
	}
}

// flushPGBatch writes a batch of records to PostgreSQL's action_ledger using
// a single multi-valued INSERT statement. This is O(1) database round-trips
// regardless of batch size, compared to the previous O(N) approach.
func (l *EdgeLedger) flushPGBatch(batch []EventRecord) {
	if len(batch) == 0 || store.DB == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Build multi-valued INSERT: INSERT INTO action_ledger (...) VALUES ($1,...,$12), ($13,...,$24), ...
	query := `INSERT INTO action_ledger
		(tenant_id, agent_id, action_type, payload_hash, target_api,
		 status, swarm_confidence_score, policy_violations, shadow_violation, trace_id, human_user_context, model)
		VALUES `

	args := make([]interface{}, 0, len(batch)*12)
	for i, r := range batch {
		if i > 0 {
			query += ", "
		}
		base := i * 12
		query += fmt.Sprintf("($%d, $%d::uuid, $%d, $%d, $%d, $%d, $%d, $%d::jsonb, $%d, $%d, $%d, $%d)",
			base+1, base+2, base+3, base+4, base+5, base+6,
			base+7, base+8, base+9, base+10, base+11, base+12)

		status := decisionToStatus(r.Decision)
		reasonJSON, _ := json.Marshal(r.ReasonCodes)
		targetAPI := r.TargetURL
		if targetAPI == "" {
			targetAPI = r.ActionClass
		}
		actionType := r.ActionClass
		if actionType == "" {
			actionType = r.Decision
		}

		args = append(args,
			r.TenantID, r.AgentID, actionType, r.RecordHash,
			targetAPI, status, r.RiskScore, string(reasonJSON),
			r.ShadowViolation, r.TraceID, r.HumanContext, r.Model,
		)
	}

	_, err := store.DB.Exec(ctx, query, args...)
	if err != nil {
		// Log but never block — dashboard visibility is best-effort.
		// Common error: "invalid input syntax for type uuid" from k6 test IDs.
		log.Printf("[LEDGER] PG batch mirror failed (%d records): %v", len(batch), err)
	}
}

// decisionToStatus maps Gateway decision strings to the action_ledger status enum.
func decisionToStatus(decision string) string {
	switch decision {
	case "deny", "contamination_detected":
		return "blocked"
	case "allow":
		return "approved"
	case "ghost_proxied":
		return "shadow_sandbox"
	case "shadow_allowed":
		return "shadow_allowed"
	default:
		return "pending_swarm"
	}
}

// DB returns the underlying SQLite database handle. Used by the IntegrityMonitor
// to walk the evidence chain without going through the mutex-protected write path.
func (l *EdgeLedger) DB() *sql.DB {
	return l.db
}

// Close cleanly shuts down the SQLite database.
func (l *EdgeLedger) Close() error {
	return l.db.Close()
}

// UnsyncedRecords fetches records that haven't been replicated to the central vault.
func (l *EdgeLedger) UnsyncedRecords(limit int) ([]EventRecord, error) {
	rows, err := l.db.Query(
		"SELECT event_id, trace_id, tenant_id, agent_id, decision, action_class, policy_version, reason_codes, risk_score, timestamp, previous_hash, record_hash, human_context FROM evidence_chain WHERE synced = 0 ORDER BY rowid ASC LIMIT ?",
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []EventRecord
	for rows.Next() {
		var r EventRecord
		var reasonJSON string
		if err := rows.Scan(&r.EventID, &r.TraceID, &r.TenantID, &r.AgentID, &r.Decision, &r.ActionClass, &r.PolicyVersion, &reasonJSON, &r.RiskScore, &r.Timestamp, &r.PreviousHash, &r.RecordHash, &r.HumanContext); err != nil {
			return nil, err
		}
		json.Unmarshal([]byte(reasonJSON), &r.ReasonCodes)
		records = append(records, r)
	}
	return records, nil
}

// MarkSynced marks a batch of records as replicated to the central vault.
func (l *EdgeLedger) MarkSynced(eventIDs []string) error {
	tx, err := l.db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare("UPDATE evidence_chain SET synced = 1 WHERE event_id = ?")
	if err != nil {
		tx.Rollback()
		return err
	}
	defer stmt.Close()
	for _, id := range eventIDs {
		stmt.Exec(id)
	}
	return tx.Commit()
}
