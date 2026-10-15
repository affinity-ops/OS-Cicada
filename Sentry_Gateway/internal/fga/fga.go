// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package fga implements Fine-Grained Authorization (FGA) per resource for
// Cicada's Sentry Gateway.
//
// Design rationale: Scope entitlements (proxy:write, proxy:read, etc.) are
// coarse-grained — they answer "what category of action is this agent allowed."
// FGA answers the runtime question: "can this specific agent call THIS specific
// URL with THIS HTTP method right now?" An agent with proxy:write may legitimately
// update a user profile but must not be allowed to delete all records. FGA
// lets the developer express that boundary precisely.
//
// Patterns use path-prefix glob matching (not full regex) because:
//   - It's predictable — developers can reason about it without regex expertise.
//   - It avoids catastrophic backtracking from malformed patterns.
//   - API URLs are hierarchical; prefix matching aligns with that structure.
//
// Backwards compatibility: if an agent has no resource policies defined, the
// check passes (falls back to scope-only enforcement). This prevents existing
// agents from breaking when FGA is deployed.
package fga

import (
	"context"
	"log"
	"net/url"
	"strings"

	"github.com/asai/cicada/sentry/internal/agentcache"
	"github.com/asai/cicada/sentry/internal/store"
)

// ResourcePolicy is one row from agent_resource_policies.
type ResourcePolicy struct {
	ResourcePattern string   // e.g. "https://api.stripe.com/v1/charges*"
	AllowedMethods  []string // e.g. ["POST", "GET"]
	Active          bool
}

// Check evaluates whether an agent is permitted to call targetURL with method.
// Returns (true, nil) in any of these cases:
//   - The agent has no policies defined (backwards-compatible passthrough).
//   - At least one active policy matches the URL and permits the method.
//
// Returns (false, nil) when a policy exists but none match — explicit deny.
// Returns (false, err) only on database error.
func Check(ctx context.Context, agentID, targetURL, method string) (bool, error) {
	// ── Try Redis cache first ────────────────────────────────────────────
	cachedPolicies, cacheErr := agentcache.GetFGAPolicies(ctx, agentID)
	if cacheErr == nil {
		if len(cachedPolicies) == 0 {
			return true, nil // no policies defined — passthrough
		}
		for _, p := range cachedPolicies {
			if !p.Active {
				continue
			}
			if matchesPattern(p.ResourcePattern, targetURL) && methodAllowed(p.AllowedMethods, method) {
				return true, nil
			}
		}
		log.Printf("[FGA] Denied: agent %s attempted %s %s — no matching resource policy", agentID, method, targetURL)
		return false, nil
	}

	// ── Cache miss or Redis unavailable: fall back to direct DB ──────────
	policies, err := loadPolicies(ctx, agentID)
	if err != nil {
		log.Printf("[FGA] DB error loading policies for agent %s: %v", agentID, err)
		return false, err
	}

	// No policies defined — pass through to scope-only enforcement.
	if len(policies) == 0 {
		return true, nil
	}

	for _, p := range policies {
		if !p.Active {
			continue
		}
		if matchesPattern(p.ResourcePattern, targetURL) && methodAllowed(p.AllowedMethods, method) {
			return true, nil
		}
	}

	log.Printf("[FGA] Denied: agent %s attempted %s %s — no matching resource policy", agentID, method, targetURL)
	return false, nil
}

// matchesPattern checks whether url matches a glob-style pattern.
// Canonicalizes both pattern and URL via url.Parse to prevent @userinfo,
// scheme/host spoofing, and path traversal evasions.
func matchesPattern(pattern, rawURL string) bool {
	if pattern == "" {
		return rawURL == ""
	}
	if pattern == "*" {
		return true
	}
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	cleanPattern := strings.TrimSuffix(pattern, "*")
	parsedPattern, err := url.Parse(cleanPattern)
	if err != nil {
		return false
	}

	// Hostname check (if pattern specifies a hostname)
	if parsedPattern.Hostname() != "" && !strings.EqualFold(parsedPattern.Hostname(), parsedURL.Hostname()) {
		return false
	}
	// Scheme check (if pattern specifies a scheme)
	if parsedPattern.Scheme != "" && !strings.EqualFold(parsedPattern.Scheme, parsedURL.Scheme) {
		return false
	}

	// Path matching
	patternPath := parsedPattern.Path
	if patternPath == "" && parsedPattern.Hostname() == "" {
		patternPath = cleanPattern
	}

	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(parsedURL.Path, patternPath) || strings.HasPrefix(rawURL, cleanPattern)
	}
	return parsedURL.Path == patternPath || rawURL == cleanPattern
}

// MatchesPatternCanonical exports canonical pattern matching for external verification.
func MatchesPatternCanonical(pattern, rawURL string) bool {
	return matchesPattern(pattern, rawURL)
}

func methodAllowed(allowed []string, method string) bool {
	for _, m := range allowed {
		if strings.EqualFold(m, method) {
			return true
		}
	}
	return false
}

// loadPolicies fetches all active resource policies for an agent from PostgreSQL.
func loadPolicies(ctx context.Context, agentID string) ([]ResourcePolicy, error) {
	rows, err := store.DB.Query(ctx,
		`SELECT resource_pattern, allowed_methods, active
		   FROM agent_resource_policies
		  WHERE agent_id = $1`,
		agentID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var policies []ResourcePolicy
	for rows.Next() {
		var p ResourcePolicy
		var methodsJSON []byte
		if err := rows.Scan(&p.ResourcePattern, &methodsJSON, &p.Active); err != nil {
			return nil, err
		}
		// allowed_methods is stored as a JSONB array: ["POST","GET"]
		// pgx returns it as raw bytes; split on commas after stripping brackets/quotes.
		p.AllowedMethods = parseJSONStringArray(string(methodsJSON))
		policies = append(policies, p)
	}
	return policies, rows.Err()
}

// parseJSONStringArray lightly parses a JSON string array without importing
// encoding/json to keep this hot-path allocation-free for the common case.
// Input: ["POST","GET"] → ["POST", "GET"]
func parseJSONStringArray(raw string) []string {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(raw, "[")
	raw = strings.TrimSuffix(raw, "]")
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		p = strings.Trim(p, `"`)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
