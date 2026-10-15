// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package velocity — impact.go
//
// Semantic Impact Multipliers for velocity limiting.
//
// Standard velocity counting treats every request as cost=1. This is incorrect
// for bulk operations: a DELETE to /api/v1/users/123 (1 record) and a DELETE
// to /api/v1/users/bulk (5,000 records) both count as "1 delete."
//
// Impact multipliers solve this by inspecting the URL path and request body
// for bulk indicators and multiplying the velocity cost accordingly. A single
// bulk-delete call that would wipe 5,000 records costs 100x in the velocity
// window, causing it to hit the z-score anomaly threshold immediately — even
// if it's the agent's first call of the hour.
//
// This is Pillar 4 of the Multi-Faceted Agent Governance model:
// "Limit impact per hour, not just call count."
package velocity

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"
)

// Default multiplier for bulk operations — configurable via env var.
// 100x means a single bulk call costs the same as 100 individual calls
// in the velocity window. This is intentionally aggressive: bulk operations
// are the highest-risk vector for data destruction.
const defaultBulkMultiplier = 100

// Default multiplier for operations targeting many records — e.g., a payload
// containing an array of 50+ items. Less aggressive than bulk endpoint hits
// because array payloads could be legitimate batch processing.
const defaultArrayMultiplier = 10

// ImpactWeight contains the computed multiplier and the reason it was assigned.
type ImpactWeight struct {
	Multiplier int64  // How many "calls" this request counts as
	Reason     string // Human-readable reason for the multiplier (for audit log)
	Indicator  string // Which indicator triggered: "bulk_url", "array_payload", "none"
}

// bulkPathSegments are URL path segments that indicate bulk/batch operations.
// If any of these appear in the URL path, the request is treated as a bulk op.
var bulkPathSegments = []string{
	"/bulk",
	"/batch",
	"/mass-",
	"/mass_",
	"/all",
	"/purge",
	"/truncate",
	"/wipe",
}

// ComputeImpact inspects the target URL and request body for bulk indicators
// and returns an impact weight multiplier.
//
// Detection layers (evaluated in order, first match wins):
//  1. URL path contains a bulk indicator segment → bulkMultiplier (default 100x)
//  2. Request body is a JSON array with >arrayThreshold items → arrayMultiplier (default 10x)
//  3. Neither → multiplier = 1 (normal request)
//
// This function is intentionally conservative: it only looks at structural
// indicators (URL segments and JSON shape), never at the content of individual
// records. This keeps it fast (no deep payload inspection) and deterministic
// (no ML or heuristics).
func ComputeImpact(targetURL, body, httpMethod string) ImpactWeight {
	method := strings.ToUpper(httpMethod)

	// GET/HEAD/OPTIONS are not velocity-limited at all — no impact to compute.
	if method == "GET" || method == "HEAD" || method == "OPTIONS" {
		return ImpactWeight{Multiplier: 1, Reason: "read method — not impact-weighted", Indicator: "none"}
	}

	// ── Layer 1: Bulk URL path detection ──────────────────────────────────
	urlLower := strings.ToLower(targetURL)
	for _, seg := range bulkPathSegments {
		if strings.Contains(urlLower, seg) {
			mult := bulkMultiplier()
			return ImpactWeight{
				Multiplier: mult,
				Reason:     "URL contains bulk indicator: " + seg,
				Indicator:  "bulk_url",
			}
		}
	}

	// ── Layer 2: Array payload detection ──────────────────────────────────
	// Only inspect body if it's non-empty and starts with '[' (JSON array).
	// This avoids parsing large single-object payloads unnecessarily.
	trimmed := strings.TrimSpace(body)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		arrayLen := countJSONArrayElements(trimmed)
		threshold := arrayThreshold()
		if arrayLen > threshold {
			mult := arrayMultiplier()
			return ImpactWeight{
				Multiplier: mult,
				Reason:     "payload is JSON array with " + strconv.Itoa(arrayLen) + " elements (threshold: " + strconv.Itoa(threshold) + ")",
				Indicator:  "array_payload",
			}
		}
	}

	// ── No bulk indicators — normal request ──────────────────────────────
	return ImpactWeight{Multiplier: 1, Reason: "no bulk indicators detected", Indicator: "none"}
}

// countJSONArrayElements does a fast, allocation-light count of top-level
// elements in a JSON array. It unmarshals into []json.RawMessage to avoid
// parsing each element's contents.
//
// Returns 0 if the body is not a valid JSON array.
func countJSONArrayElements(body string) int {
	var arr []json.RawMessage
	if err := json.Unmarshal([]byte(body), &arr); err != nil {
		return 0
	}
	return len(arr)
}

// ── Configurable thresholds ───────────────────────────────────────────────────

func bulkMultiplier() int64 {
	return int64(envInt("VELOCITY_BULK_MULTIPLIER", defaultBulkMultiplier))
}

func arrayMultiplier() int64 {
	return int64(envInt("VELOCITY_ARRAY_MULTIPLIER", defaultArrayMultiplier))
}

func arrayThreshold() int {
	if v := os.Getenv("VELOCITY_ARRAY_THRESHOLD"); v != "" {
		if i, err := strconv.Atoi(v); err == nil && i > 0 {
			return i
		}
	}
	// Default: arrays with >10 elements trigger the multiplier.
	// Single-record POSTs wrapped in an array (common pattern) won't trigger.
	return 10
}
