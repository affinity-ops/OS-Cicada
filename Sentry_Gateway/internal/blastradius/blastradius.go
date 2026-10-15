// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package blastradius implements pre-execution impact analysis for destructive
// operations in Cicada's Sentry Gateway.
//
// The problem this solves:
// A single-shot destructive command to an allowlisted endpoint can cause
// catastrophic damage if the payload has a high blast radius. DELETE /users/123
// is low-risk; DELETE /users with WHERE 1=1 is catastrophic. Velocity limiting
// (Layer 5) catches REPEATED destructive calls but not a SINGLE unbounded one.
// CIBA is mandatory for write/transact SCOPES but doesn't inspect the PAYLOAD.
//
// This module bridges the gap by estimating how much damage a destructive
// request would cause BEFORE it's forwarded to the target API.
//
// Detection tiers:
//   1. Endpoint criticality tagging — CRITICAL/HIGH/MEDIUM/LOW per resource
//      policy. CRITICAL endpoints force mandatory HITL regardless of agent config.
//   2. SQL/query blast-radius estimation — detects unbounded DELETE/DROP/UPDATE.
//   3. Shell command analysis — detects rm -rf, chmod -R 777, wildcard root ops.
//   4. Structured API heuristics — detects bulk Stripe refunds, mass deletions.
//
// Integration point:
//   Called in the pipeline AFTER toolscope (Layer 7) and BEFORE the Swarm.
//   Returns an Estimate that the pipeline uses to force CIBA escalation on
//   high blast-radius operations.
package blastradius

import (
	"encoding/json"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// Criticality levels for endpoint classification.
const (
	CriticalityCRITICAL = "CRITICAL" // Mandatory HITL — cannot be overridden
	CriticalityHIGH     = "HIGH"     // Blast-radius check required
	CriticalityMEDIUM   = "MEDIUM"   // Standard CIBA for write/transact
	CriticalityLOW      = "LOW"      // Proceed normally
)

// Estimate is the result of blast-radius analysis for a single request.
type Estimate struct {
	// ForceCIBA is true when this request MUST go through CIBA regardless
	// of the agent's HITL configuration. This is the key output.
	ForceCIBA bool `json:"force_ciba"`

	// Score is a 0.0–1.0 blast-radius score. 0 = no detected risk.
	// 0.8+ triggers ForceCIBA when combined with a destructive method.
	Score float64 `json:"score"`

	// Criticality is the endpoint's criticality tag from the resource policy.
	Criticality string `json:"criticality"`

	// Indicators are human-readable descriptions of detected risks.
	Indicators []string `json:"indicators"`

	// EstimatedRecords is the estimated number of records affected.
	// -1 means "unbounded / all records" (e.g., WHERE 1=1).
	// 0 means "could not estimate".
	EstimatedRecords int `json:"estimated_records"`

	// Summary is a one-line human-readable summary for the CIBA approval prompt.
	Summary string `json:"summary"`
}

// ── SQL/Query blast-radius patterns ──────────────────────────────────────────

// sqlUnboundedPatterns detect SQL operations that affect all records.
// Note: Go's regexp does not support negative lookaheads, so we use separate
// patterns for keyword detection and check for WHERE clause absence in code.
var sqlUnboundedPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bWHERE\s+1\s*=\s*1\b`),
	regexp.MustCompile(`(?i)\bWHERE\s+TRUE\b`),
	regexp.MustCompile(`(?i)\bDROP\s+(?:TABLE|DATABASE|SCHEMA)\b`),
	regexp.MustCompile(`(?i)\bTRUNCATE\s+(?:TABLE\s+)?\w+`),
}

// sqlDestructiveWithoutWhere detects DELETE FROM or UPDATE...SET without a WHERE clause.
// We match the destructive keyword first, then check programmatically that no
// WHERE clause follows (since Go regexp lacks negative lookahead).
var sqlDeletePattern = regexp.MustCompile(`(?i)\bDELETE\s+FROM\b`)
var sqlUpdatePattern = regexp.MustCompile(`(?i)\bUPDATE\b.*\bSET\b`)
var sqlWherePattern = regexp.MustCompile(`(?i)\bWHERE\b`)

// sqlTargetedPatterns detect SQL operations with a bounded WHERE clause.
var sqlTargetedPattern = regexp.MustCompile(`(?i)\bWHERE\s+\w+\s*=\s*(?:\d+|'[^']*'|"[^"]*")`)

// ── Shell command blast-radius patterns ──────────────────────────────────────

// shellDestructivePatterns detect shell commands that are catastrophically
// destructive regardless of context.
var shellDestructivePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f|(-[a-zA-Z]*f[a-zA-Z]*r))\b`), // rm -rf, rm -fr
	regexp.MustCompile(`(?i)\brm\s+-[a-zA-Z]*\s+/\b`),                                    // rm anything starting at root
	regexp.MustCompile(`(?i)\bchmod\s+-R\s+777\b`),                                        // chmod -R 777
	regexp.MustCompile(`(?i)\bchown\s+-R\b.*\s+/\b`),                                      // chown -R at root
	regexp.MustCompile(`(?i)\bmkfs\b`),                                                     // format filesystem
	regexp.MustCompile(`(?i)\bdd\s+if=.*\s+of=\s*/dev/`),                                   // dd to device
	regexp.MustCompile(`(?i)\b>\s*/dev/sd[a-z]`),                                           // redirect to disk device
	regexp.MustCompile(`(?i)\bformat\s+[a-zA-Z]:\b`),                                       // Windows format
}

// shellCriticalPaths are filesystem paths that should never be targets of
// destructive operations without human review.
var shellCriticalPaths = []string{
	"/etc", "/var", "/usr", "/boot", "/sys", "/proc",
	"/data", "/home", "/root", "/srv", "/opt",
	"C:\\Windows", "C:\\System32",
}

// ── Structured API bulk indicators ───────────────────────────────────────────

// bulkAPIIndicators detect bulk operations in structured API request bodies.
var bulkAPIIndicators = []string{
	"\"all\":", "\"all_customers\":", "\"all_subscriptions\":",
	"\"bulk\":", "\"batch\":", "\"mass_action\":",
	"\"limit\": 0", "\"limit\":0",
	"\"confirm_all\":", "\"force_all\":",
}

// Analyze inspects a request payload for blast-radius indicators and returns
// an Estimate. The caller provides the endpoint criticality tag (from the
// resource policy), the HTTP method, the request body, and the target URL.
//
// Decision logic:
//   1. CRITICAL endpoints → ForceCIBA always (regardless of payload)
//   2. HIGH endpoints + destructive method → payload inspection required
//   3. Any endpoint + high blast-radius payload → ForceCIBA
//   4. MEDIUM/LOW + normal payload → pass through
func Analyze(criticality, httpMethod, body, targetURL string) Estimate {
	method := strings.ToUpper(httpMethod)
	crit := strings.ToUpper(criticality)

	// Default to MEDIUM if no criticality is set (backwards compatible).
	if crit == "" {
		crit = CriticalityMEDIUM
	}

	est := Estimate{
		Criticality: crit,
	}

	// ── CRITICAL endpoints: always force CIBA ──────────────────────────────
	if crit == CriticalityCRITICAL {
		est.ForceCIBA = true
		est.Score = 1.0
		est.Indicators = append(est.Indicators, "endpoint tagged CRITICAL — mandatory human review")
		est.Summary = "CRITICAL endpoint: all operations require human approval"
		return est
	}

	// Read methods are never high blast-radius.
	if method == "GET" || method == "HEAD" || method == "OPTIONS" {
		est.Score = 0.0
		est.Summary = "read method — no blast-radius risk"
		return est
	}

	// ── Payload inspection for destructive methods ─────────────────────────
	var score float64

	// SQL/query analysis
	sqlScore, sqlIndicators, sqlRecords := analyzeSQLBlastRadius(body)
	score += sqlScore
	est.Indicators = append(est.Indicators, sqlIndicators...)
	if sqlRecords != 0 {
		est.EstimatedRecords = sqlRecords
	}

	// Shell command analysis
	shellScore, shellIndicators := analyzeShellBlastRadius(body, targetURL)
	score += shellScore
	est.Indicators = append(est.Indicators, shellIndicators...)

	// Structured API analysis
	apiScore, apiIndicators := analyzeAPIBlastRadius(body)
	score += apiScore
	est.Indicators = append(est.Indicators, apiIndicators...)

	// JSON array batch detection (reuse from velocity/impact.go logic)
	arrayScore, arrayIndicators := analyzeArrayPayload(body)
	score += arrayScore
	est.Indicators = append(est.Indicators, arrayIndicators...)

	// Normalize score to 0.0–1.0
	if score > 1.0 {
		score = 1.0
	}
	est.Score = score

	// ── Force CIBA decision ────────────────────────────────────────────────
	threshold := blastRadiusThreshold()

	if score >= threshold {
		est.ForceCIBA = true
	}

	// HIGH endpoints with any blast-radius signal → force CIBA
	if crit == CriticalityHIGH && score > 0.0 && isDestructive(method) {
		est.ForceCIBA = true
	}

	// Build summary
	if est.ForceCIBA {
		if est.EstimatedRecords == -1 {
			est.Summary = "HIGH BLAST RADIUS: operation targets ALL records — mandatory human review"
		} else if est.EstimatedRecords > 0 {
			est.Summary = strings.Join(est.Indicators, "; ")
		} else {
			est.Summary = "destructive operation with elevated risk indicators — mandatory human review"
		}
	} else {
		est.Summary = "blast-radius within acceptable bounds"
	}

	return est
}

// ── Internal analysis functions ──────────────────────────────────────────────

func analyzeSQLBlastRadius(body string) (float64, []string, int) {
	if body == "" {
		return 0, nil, 0
	}

	var score float64
	var indicators []string
	estimatedRecords := 0

	// Check for explicit unbounded patterns (WHERE 1=1, WHERE TRUE, DROP, TRUNCATE)
	for _, pattern := range sqlUnboundedPatterns {
		if pattern.MatchString(body) {
			score = 1.0
			estimatedRecords = -1 // unbounded
			indicators = append(indicators, "UNBOUNDED SQL: "+pattern.String())
		}
	}

	// Check for DELETE FROM without WHERE clause
	if score == 0 && sqlDeletePattern.MatchString(body) && !sqlWherePattern.MatchString(body) {
		score = 1.0
		estimatedRecords = -1
		indicators = append(indicators, "UNBOUNDED SQL: DELETE FROM without WHERE clause")
	}

	// Check for UPDATE...SET without WHERE clause
	if score == 0 && sqlUpdatePattern.MatchString(body) && !sqlWherePattern.MatchString(body) {
		score = 1.0
		estimatedRecords = -1
		indicators = append(indicators, "UNBOUNDED SQL: UPDATE SET without WHERE clause")
	}

	// Check for targeted operations (lower risk)
	if score == 0 && sqlTargetedPattern.MatchString(body) {
		score = 0.1
		estimatedRecords = 1
		indicators = append(indicators, "targeted SQL operation with WHERE clause")
	}

	return score, indicators, estimatedRecords
}

func analyzeShellBlastRadius(body string, targetURL string) (float64, []string) {
	// Only inspect if target URL looks like a shell/exec endpoint
	urlLower := strings.ToLower(targetURL)
	isShellEndpoint := strings.Contains(urlLower, "shell") ||
		strings.Contains(urlLower, "exec") ||
		strings.Contains(urlLower, "command") ||
		strings.Contains(urlLower, "terminal") ||
		strings.Contains(urlLower, "run")

	if !isShellEndpoint && body == "" {
		return 0, nil
	}

	var score float64
	var indicators []string

	// Check for catastrophically destructive commands
	for _, pattern := range shellDestructivePatterns {
		if pattern.MatchString(body) {
			score = 1.0
			indicators = append(indicators, "DESTRUCTIVE SHELL: "+pattern.String())
		}
	}

	// Check for operations targeting critical paths
	bodyLower := strings.ToLower(body)
	for _, path := range shellCriticalPaths {
		if strings.Contains(bodyLower, strings.ToLower(path)) {
			if score < 0.6 {
				score = 0.6
			}
			indicators = append(indicators, "targets critical path: "+path)
		}
	}

	// Wildcard operations at broad scopes
	if regexp.MustCompile(`\*\s`).MatchString(body) || strings.Contains(body, "/*") {
		if score < 0.5 {
			score = 0.5
		}
		indicators = append(indicators, "wildcard operation detected")
	}

	return score, indicators
}

func analyzeAPIBlastRadius(body string) (float64, []string) {
	if body == "" {
		return 0, nil
	}

	var score float64
	var indicators []string
	bodyLower := strings.ToLower(body)

	for _, indicator := range bulkAPIIndicators {
		if strings.Contains(bodyLower, strings.ToLower(indicator)) {
			if score < 0.7 {
				score = 0.7
			}
			indicators = append(indicators, "bulk API indicator: "+indicator)
		}
	}

	return score, indicators
}

func analyzeArrayPayload(body string) (float64, []string) {
	trimmed := strings.TrimSpace(body)
	if len(trimmed) == 0 || trimmed[0] != '[' {
		return 0, nil
	}

	var arr []json.RawMessage
	if err := json.Unmarshal([]byte(trimmed), &arr); err != nil {
		return 0, nil
	}

	count := len(arr)
	if count > 100 {
		return 0.8, []string{"JSON array with " + strings.TrimSpace(string(rune(count))) + " elements (>100 threshold)"}
	}
	if count > 50 {
		return 0.5, []string{"JSON array with batch payload (>50 elements)"}
	}

	return 0, nil
}

func isDestructive(method string) bool {
	return method == "DELETE" || method == "POST" || method == "PUT" || method == "PATCH"
}

// blastRadiusThreshold returns the score above which ForceCIBA is triggered.
// Default: 0.7. Configurable via CICADA_BLAST_RADIUS_THRESHOLD.
func blastRadiusThreshold() float64 {
	if v := os.Getenv("CICADA_BLAST_RADIUS_THRESHOLD"); v != "" {
		if f, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil && f > 0 && f <= 1.0 {
			return f
		}
	}
	return 0.7
}
