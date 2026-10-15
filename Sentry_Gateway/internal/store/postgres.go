// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
)

// DB holds the production PostgreSQL connection pool.
var DB *pgxpool.Pool

// InitPostgres creates a connection pool from the CICADA_POSTGRES_URL
// environment variable and verifies connectivity.
func InitPostgres(ctx context.Context) error {
	dsn := os.Getenv("CICADA_POSTGRES_URL")
	if dsn == "" {
		return fmt.Errorf("CICADA_POSTGRES_URL environment variable is required")
	}

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return fmt.Errorf("failed to create postgres pool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return fmt.Errorf("failed to ping postgres: %w", err)
	}

	// STRICT API BOUNDARY: Ensure Sentry uses its own schema to prevent Laravel 
	// RefreshDatabase from dropping Go-managed tables.
	_, err = pool.Exec(ctx, "CREATE SCHEMA IF NOT EXISTS sentry; SET search_path TO sentry, public;")
	if err != nil {
		pool.Close()
		return fmt.Errorf("failed to configure schema search path: %w", err)
	}

	DB = pool
	log.Printf("[STORE] PostgreSQL connection pool established with search_path=sentry,public")
	return nil
}

// Close gracefully shuts down the connection pool.
func Close() {
	if DB != nil {
		DB.Close()
		log.Println("[STORE] PostgreSQL pool closed")
	}
}

// AgentRecord maps to the agents table defined in 001_multi_tenant_schema.sql.
type AgentRecord struct {
	ID                string
	TenantID          string
	PubKeyHash        string
	ScopeEntitlements string // JSONB
	ReversalMap       string // JSONB
	TrustTier         string
}

// InsertAgent persists a new agent record and returns the generated UUID.
func InsertAgent(ctx context.Context, tenantID, pubKeyHash, scopes, reversalRoutes string) (string, error) {
	var agentID string
	err := DB.QueryRow(ctx,
		`INSERT INTO agents (tenant_id, pub_key_hash, scope_entitlements, trust_tier)
		 VALUES ($1, $2, $3::jsonb, 'nominal')
		 RETURNING id`,
		tenantID, pubKeyHash, scopes,
	).Scan(&agentID)
	if err != nil {
		return "", fmt.Errorf("insert agent: %w", err)
	}
	return agentID, nil
}

// LookupAgentByHash finds an agent by its public key hash.
func LookupAgentByHash(ctx context.Context, pubKeyHash string) (*AgentRecord, error) {
	rec := &AgentRecord{}
	err := DB.QueryRow(ctx,
		`SELECT id, tenant_id, pub_key_hash, scope_entitlements, trust_tier
		 FROM agents WHERE pub_key_hash = $1 AND revoked_at IS NULL`,
		pubKeyHash,
	).Scan(&rec.ID, &rec.TenantID, &rec.PubKeyHash, &rec.ScopeEntitlements, &rec.TrustTier)
	if err != nil {
		return nil, fmt.Errorf("lookup agent: %w", err)
	}
	return rec, nil
}

// RecordAction appends an immutable entry to the action_ledger.
// reasoningTrace is the chain-of-thought captured at the edge (Claude <thinking> /
// OpenAI reasoning_content). Pass nil when no trace is available.
// model is the LLM model identifier (e.g. "gpt-4o"). Pass nil for non-LLM actions.
func RecordAction(ctx context.Context, tenantID, agentID, actionType, payloadHash, targetAPI, status string, confidence *float64, reasoningTrace *string, model *string) error {
	_, err := DB.Exec(ctx,
		`INSERT INTO action_ledger (tenant_id, agent_id, action_type, payload_hash, target_api, status, swarm_confidence_score, reasoning_trace, model)
		 VALUES ($1, $2::uuid, $3, $4, $5, $6, $7, $8, $9)`,
		tenantID, agentID, actionType, payloadHash, targetAPI, status, confidence, reasoningTrace, model,
	)
	if err != nil {
		return fmt.Errorf("record action: %w", err)
	}
	return nil
}

// RunMigrations executes the SQL migration file against the database.
func RunMigrations(ctx context.Context, migrationPath string) error {
	sql, err := os.ReadFile(migrationPath)
	if err != nil {
		return fmt.Errorf("read migration file: %w", err)
	}
	if _, err := DB.Exec(ctx, string(sql)); err != nil {
		return fmt.Errorf("execute migration: %w", err)
	}
	log.Printf("[STORE] Migrations applied from %s", migrationPath)
	return nil
}
