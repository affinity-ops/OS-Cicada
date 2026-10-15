// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package policystore

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// GetActivePolicy returns the currently active Rego content for a given policy name.
func GetActivePolicy(ctx context.Context, pool *pgxpool.Pool, policyName string) (string, error) {
	var regoContent string
	query := `
		SELECT rego_content 
		FROM policy_versions 
		WHERE policy_name = $1 AND active = TRUE
	`
	err := pool.QueryRow(ctx, query, policyName).Scan(&regoContent)
	if err != nil {
		return "", fmt.Errorf("failed to fetch active policy for %s: %w", policyName, err)
	}
	return regoContent, nil
}

// SubmitPolicyRevision inserts a new inactive version of a policy, auto-incrementing the version number.
func SubmitPolicyRevision(ctx context.Context, pool *pgxpool.Pool, policyName, content, author string) (int, error) {
	// Execute in a transaction to safely compute the next version number
	tx, err := pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to start transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	var currentMax int
	err = tx.QueryRow(ctx, "SELECT COALESCE(MAX(version), 0) FROM policy_versions WHERE policy_name = $1", policyName).Scan(&currentMax)
	if err != nil {
		return 0, fmt.Errorf("failed to get max version: %w", err)
	}

	nextVersion := currentMax + 1

	insertQuery := `
		INSERT INTO policy_versions (policy_name, version, rego_content, created_by, active)
		VALUES ($1, $2, $3, $4, FALSE)
		RETURNING version
	`
	var insertedVersion int
	err = tx.QueryRow(ctx, insertQuery, policyName, nextVersion, content, author).Scan(&insertedVersion)
	if err != nil {
		return 0, fmt.Errorf("failed to insert policy revision: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("failed to commit policy revision: %w", err)
	}

	return insertedVersion, nil
}

// ActivatePolicy makes a specific version of a policy active, demoting all others.
func ActivatePolicy(ctx context.Context, pool *pgxpool.Pool, policyName string, version int) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	// Demote currently active
	_, err = tx.Exec(ctx, "UPDATE policy_versions SET active = FALSE WHERE policy_name = $1 AND active = TRUE", policyName)
	if err != nil {
		return fmt.Errorf("failed to demote active policies: %w", err)
	}

	// Promote new version
	tag, err := tx.Exec(ctx, "UPDATE policy_versions SET active = TRUE WHERE policy_name = $1 AND version = $2", policyName, version)
	if err != nil {
		return fmt.Errorf("failed to activate target policy version: %w", err)
	}

	if tag.RowsAffected() == 0 {
		return fmt.Errorf("policy version %d for %s not found", version, policyName)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit policy activation: %w", err)
	}

	return nil
}
