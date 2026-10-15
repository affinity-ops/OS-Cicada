// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package rolemapping implements IdP group → Cicada role translation (S6.3).
//
// Enterprise IdPs (Okta, Azure AD, Google Workspace) organize users into groups.
// Cicada needs to translate those group memberships into portal roles so that
// operators get the correct permissions without manual provisioning.
//
// The mapping engine supports:
//   - Exact match:   "engineering"        → "admin"
//   - Prefix match:  "team-*"             → "operator"
//   - Suffix match:  "*-readonly"         → "viewer"
//   - Wildcard:      "*"                  → "viewer" (catch-all)
//   - Priority:      highest-privilege wins when multiple groups match
//
// Role hierarchy (highest to lowest):
//   super_admin > admin > operator > viewer > guest
//
// Configuration is stored per-provider in the role_mappings table.
package rolemapping

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ── Role Hierarchy ───────────────────────────────────────────────────────────

// RolePriority defines the privilege ranking. Higher number = more privilege.
var RolePriority = map[string]int{
	"guest":       0,
	"viewer":      1,
	"operator":    2,
	"admin":       3,
	"super_admin": 4,
}

// ValidRoles is the set of recognized Cicada portal roles.
var ValidRoles = map[string]bool{
	"guest":       true,
	"viewer":      true,
	"operator":    true,
	"admin":       true,
	"super_admin": true,
}

// ── Data Types ───────────────────────────────────────────────────────────────

// Mapping represents a single IdP group → Cicada role rule.
type Mapping struct {
	ID           string `json:"id"`
	ProviderID   string `json:"provider_id"`
	TenantID     string `json:"tenant_id"`
	IdPGroup     string `json:"idp_group"`     // IdP group name or pattern ("engineering", "team-*")
	CicadaRole   string `json:"cicada_role"`   // Cicada role to assign
	Priority     int    `json:"priority"`      // explicit ordering (higher = checked first)
	Description  string `json:"description,omitempty"`
}

// ResolveResult contains the outcome of a role resolution.
type ResolveResult struct {
	ResolvedRole   string   `json:"resolved_role"`
	MatchedGroups  []string `json:"matched_groups"`     // which IdP groups triggered the match
	MatchedRules   []string `json:"matched_rules"`      // which mapping rules were hit
	DefaultApplied bool     `json:"default_applied"`    // true if no rules matched, default used
}

// ── Core Resolution Engine ───────────────────────────────────────────────────

// ResolveRole determines the highest-privilege Cicada role for a set of IdP groups.
// It evaluates all mappings for the provider and returns the highest-priority match.
//
// If no mappings match, it falls back to defaultRole (typically from the Provider).
func ResolveRole(mappings []Mapping, userGroups []string, defaultRole string) ResolveResult {
	if len(userGroups) == 0 || len(mappings) == 0 {
		return ResolveResult{
			ResolvedRole:   normalizeRole(defaultRole),
			DefaultApplied: true,
		}
	}

	bestRole := ""
	bestPriority := -1
	var matchedGroups []string
	var matchedRules []string

	for _, m := range mappings {
		for _, group := range userGroups {
			if matchesPattern(m.IdPGroup, group) {
				rolePriority := RolePriority[m.CicadaRole]
				if rolePriority > bestPriority {
					bestPriority = rolePriority
					bestRole = m.CicadaRole
					matchedGroups = []string{group}
					matchedRules = []string{m.ID}
				} else if rolePriority == bestPriority {
					// Same priority — track all matches for audit
					matchedGroups = append(matchedGroups, group)
					matchedRules = append(matchedRules, m.ID)
				}
			}
		}
	}

	if bestRole == "" {
		return ResolveResult{
			ResolvedRole:   normalizeRole(defaultRole),
			DefaultApplied: true,
		}
	}

	return ResolveResult{
		ResolvedRole:  bestRole,
		MatchedGroups: matchedGroups,
		MatchedRules:  matchedRules,
	}
}

// matchesPattern checks if an IdP group matches a mapping pattern.
// Supports exact match, prefix wildcard ("team-*"), suffix wildcard ("*-readonly"),
// and full wildcard ("*").
func matchesPattern(pattern, group string) bool {
	if pattern == "*" {
		return true
	}
	if pattern == group {
		return true
	}
	// Prefix match: "team-*" matches "team-backend", "team-frontend"
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(group, prefix)
	}
	// Suffix match: "*-readonly" matches "eng-readonly", "ops-readonly"
	if strings.HasPrefix(pattern, "*") {
		suffix := strings.TrimPrefix(pattern, "*")
		return strings.HasSuffix(group, suffix)
	}
	// Case-insensitive exact match
	return strings.EqualFold(pattern, group)
}

// normalizeRole ensures a role string is valid; defaults to "viewer" if unknown.
func normalizeRole(role string) string {
	if role == "" {
		return "viewer"
	}
	r := strings.ToLower(strings.TrimSpace(role))
	if ValidRoles[r] {
		return r
	}
	return "viewer"
}

// ── Database Operations ──────────────────────────────────────────────────────

// LoadMappings fetches all role mappings for a provider, ordered by priority DESC.
func LoadMappings(ctx context.Context, db *pgxpool.Pool, providerID string) ([]Mapping, error) {
	rows, err := db.Query(ctx, `
		SELECT id, provider_id, tenant_id, idp_group, cicada_role, priority,
		       COALESCE(description, '')
		FROM role_mappings
		WHERE provider_id = $1::UUID
		ORDER BY priority DESC, cicada_role ASC
	`, providerID)
	if err != nil {
		return nil, fmt.Errorf("load mappings: %w", err)
	}
	defer rows.Close()

	var mappings []Mapping
	for rows.Next() {
		var m Mapping
		if err := rows.Scan(&m.ID, &m.ProviderID, &m.TenantID,
			&m.IdPGroup, &m.CicadaRole, &m.Priority, &m.Description); err != nil {
			continue
		}
		mappings = append(mappings, m)
	}
	return mappings, nil
}

// CreateMapping persists a new role mapping rule.
func CreateMapping(ctx context.Context, db *pgxpool.Pool, m Mapping) (string, error) {
	if !ValidRoles[m.CicadaRole] {
		return "", fmt.Errorf("invalid Cicada role: %q (valid: guest, viewer, operator, admin, super_admin)", m.CicadaRole)
	}
	if m.IdPGroup == "" {
		return "", fmt.Errorf("idp_group is required")
	}

	var id string
	err := db.QueryRow(ctx, `
		INSERT INTO role_mappings (provider_id, tenant_id, idp_group, cicada_role, priority, description)
		VALUES ($1::UUID, $2::UUID, $3, $4, $5, NULLIF($6, ''))
		RETURNING id
	`, m.ProviderID, m.TenantID, m.IdPGroup, m.CicadaRole, m.Priority, m.Description).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("create mapping: %w", err)
	}

	log.Printf("[ROLE-MAPPING] Created rule: %q → %q (provider=%s, priority=%d)",
		m.IdPGroup, m.CicadaRole, m.ProviderID, m.Priority)
	return id, nil
}

// DeleteMapping removes a role mapping rule.
func DeleteMapping(ctx context.Context, db *pgxpool.Pool, mappingID string) error {
	tag, err := db.Exec(ctx, `DELETE FROM role_mappings WHERE id = $1::UUID`, mappingID)
	if err != nil {
		return fmt.Errorf("delete mapping: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("mapping %s not found", mappingID)
	}
	return nil
}

// ResolveForProvider loads mappings from the DB and resolves the role.
// This is the primary entry point used by the federation login flow.
func ResolveForProvider(ctx context.Context, db *pgxpool.Pool, providerID string, userGroups []string, defaultRole string) (ResolveResult, error) {
	mappings, err := LoadMappings(ctx, db, providerID)
	if err != nil {
		return ResolveResult{
			ResolvedRole:   normalizeRole(defaultRole),
			DefaultApplied: true,
		}, fmt.Errorf("load mappings: %w", err)
	}

	result := ResolveRole(mappings, userGroups, defaultRole)
	return result, nil
}
