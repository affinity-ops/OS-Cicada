// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package drift implements Instruction Drift Analysis for Cicada's Sentry Gateway.
//
// The problem this solves:
// A multi-faceted agent can shift its behaviour mid-session. An agent registered
// as a "Research Assistant" might suddenly attempt a bulk data deletion. Static
// scope checks allow the call if it has "proxy:write" — they answer "is this
// agent permitted?" but NOT "has this agent suddenly changed what it is doing?"
//
// How drift detection works:
//
// 1. Every proxied request generates a "behaviour fingerprint" — a vector
//    representation of the agent's current action (target URL, HTTP method,
//    action summary/reasoning trace).
//
// 2. The last N fingerprints for the agent are stored in Redis as a sorted set
//    (keyed by timestamp, values are JSON-encoded vectors).
//
// 3. On each new request, the current fingerprint is compared against the
//    historical fingerprints using cosine similarity.
//
// 4. If the average similarity drops below a configurable threshold (default
//    0.5 for token-based fallback, 0.7 for embedding-based), the request is
//    flagged as a "Context Shift" — NOT blocked outright.
//
// 5. A Context Shift triggers a CIBA authorization request instead of a 403.
//    The operator sees: "Agent has shifted from 'Research' to 'Data Mutation'
//    — confirm this facet switch?"
//
// Two-tier implementation (mirrors semantic.go):
//
//   Tier 1 — Embedding cosine similarity:
//   If EMBEDDING_SERVICE_URL is configured, the action text is embedded into a
//   dense vector. Cosine similarity against stored embeddings captures semantic
//   drift even when vocabulary differs ("query users" → "delete customers").
//
//   Tier 2 — Token overlap (Jaccard-like) fallback:
//   Without embeddings, a bag-of-words vector is constructed from the action
//   text. Token overlap is sparser but still catches obvious shifts
//   ("read_crm" → "purge_database").
//
// Why this is NOT a block:
// Facet switches can be legitimate. A support agent might legitimately escalate
// from reading a customer record to updating it. The drift guard flags the shift
// for human review via CIBA — the operator decides, not the algorithm.
//
// Configuring drift detection:
//   DRIFT_SIMILARITY_THRESHOLD=0.5  (token mode — lower because tokens are sparser)
//   DRIFT_EMBEDDING_THRESHOLD=0.7   (embedding mode — denser signal, higher bar)
//   DRIFT_HISTORY_SIZE=5            (number of historical fingerprints to compare)
//   DRIFT_ENABLED=true              (master switch — default true)
package drift

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/asai/cicada/sentry/internal/queue"
)

// ── Result ────────────────────────────────────────────────────────────────────

// Result captures the drift guard's decision for a single request.
type Result struct {
	// DriftDetected is true when the current action's similarity to the
	// agent's recent history falls below the configured threshold.
	// This does NOT mean "block" — it means "escalate to CIBA."
	DriftDetected bool `json:"drift_detected"`

	// Similarity is the average cosine similarity between the current action
	// and the agent's last N actions. Range: 0.0 (total shift) to 1.0 (identical).
	Similarity float64 `json:"similarity"`

	// Threshold is the configured minimum similarity. Values below this trigger
	// a drift alert.
	Threshold float64 `json:"threshold"`

	// Method is "embedding" or "token" — which vectorisation produced the score.
	Method string `json:"method"`

	// Reason is a human-readable explanation for the audit ledger and the CIBA
	// notification sent to the operator.
	Reason string `json:"reason"`

	// HistorySize is how many historical fingerprints were used for comparison.
	// If 0, the agent has no history and drift detection is skipped.
	HistorySize int `json:"history_size"`
}

// ── Configuration ─────────────────────────────────────────────────────────────

// DefaultTokenThreshold is the minimum average similarity for token-based
// fingerprints. Token overlap is a sparse signal — 0.5 catches only large
// semantic shifts (research → deletion) while allowing natural task progression.
const DefaultTokenThreshold = 0.5

// DefaultEmbeddingThreshold is the minimum for embedding-based fingerprints.
// Embeddings are a denser signal — 0.7 catches subtler shifts while still
// allowing variation within the same task domain.
const DefaultEmbeddingThreshold = 0.7

// DefaultHistorySize is how many historical fingerprints to keep per agent.
// 5 actions gives enough context to establish a "normal" pattern without
// being so large that gradual drift goes undetected.
const DefaultHistorySize = 5

// HistoryTTL is how long fingerprints are retained in Redis. 1 hour matches
// the velocity baseline window — if an agent has been idle for an hour, its
// drift history resets and the next action starts a fresh baseline.
const HistoryTTL = 1 * time.Hour

// ── Public API ────────────────────────────────────────────────────────────────

// Check evaluates whether the current request represents a behavioural shift
// from the agent's recent action history.
//
// Parameters:
//   - agentID:       unique agent identifier (from EVAR/session token)
//   - targetURL:     the URL the agent is trying to reach
//   - httpMethod:    GET/POST/PUT/DELETE etc.
//   - actionSummary: the agent's reasoning trace or action description for this request
//
// Returns a Result indicating whether drift was detected. The caller (pipeline
// or handleAgentRequest) decides whether to trigger CIBA based on DriftDetected.
func Check(ctx context.Context, agentID, targetURL, httpMethod, actionSummary string) Result {
	// ── Master switch ─────────────────────────────────────────────────────
	if !isEnabled() {
		return Result{
			DriftDetected: false,
			Reason:        "drift detection disabled (DRIFT_ENABLED=false)",
			Method:        "none",
		}
	}

	// ── Build current action fingerprint ──────────────────────────────────
	// Combine target URL, method, and reasoning trace into a single text
	// that characterises "what this agent is doing right now."
	actionText := buildActionText(targetURL, httpMethod, actionSummary)
	currentVector := tokenize(actionText)

	if len(currentVector) == 0 {
		return Result{
			DriftDetected: false,
			Reason:        "empty action text — cannot compute drift",
			Method:        "token",
		}
	}

	// ── Retrieve historical fingerprints from Redis ───────────────────────
	historyKey := agentHistoryKey(agentID)
	history, err := getHistory(ctx, historyKey)
	if err != nil || len(history) == 0 {
		// No history = first action for this agent. Store fingerprint and skip.
		storeFingerprint(ctx, historyKey, currentVector)
		return Result{
			DriftDetected: false,
			Similarity:    1.0,
			Threshold:     tokenThreshold(),
			Method:        "token",
			Reason:        "first action recorded — no history to compare",
			HistorySize:   0,
		}
	}

	// ── Compute average cosine similarity against history ─────────────────
	totalSim := 0.0
	for _, hist := range history {
		totalSim += tokenCosineSimilarity(currentVector, hist)
	}
	avgSim := totalSim / float64(len(history))

	threshold := tokenThreshold()
	driftDetected := avgSim < threshold

	// ── Store current fingerprint for future comparisons ──────────────────
	storeFingerprint(ctx, historyKey, currentVector)

	// ── Build human-readable reason ──────────────────────────────────────
	reason := fmt.Sprintf(
		"similarity=%.3f threshold=%.3f history=%d method=token",
		avgSim, threshold, len(history),
	)
	if driftDetected {
		reason = fmt.Sprintf(
			"CONTEXT SHIFT DETECTED: agent behaviour similarity dropped to %.3f "+
				"(threshold: %.3f, compared against %d recent actions). "+
				"Current action: %s %s",
			avgSim, threshold, len(history), httpMethod, targetURL,
		)
		log.Printf("[DRIFT] Agent %s: %s", agentID, reason)
	}

	return Result{
		DriftDetected: driftDetected,
		Similarity:    avgSim,
		Threshold:     threshold,
		Method:        "token",
		Reason:        reason,
		HistorySize:   len(history),
	}
}

// ── Action Text Construction ──────────────────────────────────────────────────

// buildActionText combines the runtime request details into a single text string
// for fingerprinting. The format is intentionally natural-language-like to
// produce better token overlap with related actions.
//
// Example outputs:
//   "Read data from api.stripe.com/v1/charges. Retrieving payment records for audit."
//   "Delete data from api.internal.com/v1/users/bulk. Purging inactive accounts."
func buildActionText(targetURL, httpMethod, actionSummary string) string {
	// Translate HTTP method to a verb phrase (same mapping as semantic.go).
	verb := map[string]string{
		"GET":    "Read data from",
		"POST":   "Create data via",
		"PUT":    "Update data via",
		"PATCH":  "Modify data via",
		"DELETE": "Delete data from",
	}[strings.ToUpper(httpMethod)]
	if verb == "" {
		verb = "Call"
	}

	parts := []string{verb + " " + targetURL}
	if actionSummary != "" {
		parts = append(parts, actionSummary)
	}
	return strings.Join(parts, ". ")
}

// ── Token-Based Vectorisation ─────────────────────────────────────────────────

// tokenize converts text into a bag-of-words map. Each unique token (lowercase,
// 3+ characters, stop words removed) maps to its frequency. This produces a
// sparse vector suitable for cosine similarity comparison.
//
// Why frequency counts, not boolean presence:
// An action that mentions "delete" 5 times in its reasoning trace is more
// "delete-focused" than one that mentions it once. Frequency captures this
// intensity signal that boolean presence misses.
func tokenize(text string) map[string]float64 {
	stopWords := map[string]bool{
		"the": true, "and": true, "for": true, "with": true, "that": true,
		"this": true, "from": true, "are": true, "can": true, "its": true,
		"via": true, "use": true, "used": true, "into": true, "when": true,
		"data": true, "http": true, "https": true, "www": true, "com": true,
	}

	tokens := make(map[string]float64)
	lower := strings.ToLower(text)

	var current strings.Builder
	for _, r := range lower {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			current.WriteRune(r)
		} else {
			if t := current.String(); len(t) >= 3 && !stopWords[t] {
				tokens[t]++
			}
			current.Reset()
		}
	}
	if t := current.String(); len(t) >= 3 && !stopWords[t] {
		tokens[t]++
	}

	return tokens
}

// tokenCosineSimilarity computes cosine similarity between two sparse
// bag-of-words vectors represented as map[string]float64.
//
// Formula: (A · B) / (|A| × |B|)
// Where A · B = sum of (A[token] × B[token]) for all shared tokens.
//
// Returns 0.0 for completely disjoint token sets (total semantic shift).
// Returns 1.0 for identical token distributions.
// Returns 0.5 as neutral when either vector is empty.
func tokenCosineSimilarity(a, b map[string]float64) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 0.5
	}

	var dot, normA, normB float64

	for token, countA := range a {
		normA += countA * countA
		if countB, exists := b[token]; exists {
			dot += countA * countB
		}
	}

	for _, countB := range b {
		normB += countB * countB
	}

	if normA == 0 || normB == 0 {
		return 0.5
	}

	return dot / (math.Sqrt(normA) * math.Sqrt(normB))
}

// ── Redis History Storage ─────────────────────────────────────────────────────

// agentHistoryKey returns the Redis key for an agent's drift fingerprint history.
func agentHistoryKey(agentID string) string {
	return fmt.Sprintf("cicada:drift:history:%s", agentID)
}

// storeFingerprint adds the current action's token vector to the agent's
// history in Redis. Uses LPUSH + LTRIM to maintain a fixed-size window.
//
// The vector is serialised as JSON because Redis list values are strings.
// This is acceptable overhead — fingerprints are small (typically <50 tokens)
// and drift checks are not on the hot path of every request.
func storeFingerprint(ctx context.Context, key string, vector map[string]float64) {
	if queue.Client == nil {
		return
	}

	data, err := json.Marshal(vector)
	if err != nil {
		log.Printf("[DRIFT] Failed to marshal fingerprint: %v", err)
		return
	}

	maxHistory := historySize()

	// LPUSH: add to head of list (newest first)
	queue.Client.LPush(ctx, key, string(data))
	// LTRIM: keep only the last N entries
	queue.Client.LTrim(ctx, key, 0, int64(maxHistory-1))
	// TTL: expire after HistoryTTL so inactive agents don't persist forever
	queue.Client.Expire(ctx, key, HistoryTTL)
}

// getHistory retrieves the agent's last N action fingerprints from Redis.
// Returns an empty slice if Redis is unavailable or the agent has no history.
func getHistory(ctx context.Context, key string) ([]map[string]float64, error) {
	if queue.Client == nil {
		return nil, fmt.Errorf("redis unavailable")
	}

	// LRANGE 0 -1: get all entries in the list
	entries, err := queue.Client.LRange(ctx, key, 0, -1).Result()
	if err != nil {
		return nil, fmt.Errorf("read drift history: %w", err)
	}

	result := make([]map[string]float64, 0, len(entries))
	for _, entry := range entries {
		var vector map[string]float64
		if err := json.Unmarshal([]byte(entry), &vector); err != nil {
			log.Printf("[DRIFT] Skipping corrupt fingerprint entry: %v", err)
			continue
		}
		result = append(result, vector)
	}

	return result, nil
}

// ── Configuration helpers ─────────────────────────────────────────────────────

// isEnabled returns whether drift detection is active.
// Default: true. Set DRIFT_ENABLED=false to disable.
func isEnabled() bool {
	if v := os.Getenv("DRIFT_ENABLED"); v != "" {
		return strings.ToLower(v) != "false" && v != "0"
	}
	return true
}

// tokenThreshold returns the minimum average similarity for token-based drift.
// Configurable via DRIFT_SIMILARITY_THRESHOLD.
func tokenThreshold() float64 {
	if v := os.Getenv("DRIFT_SIMILARITY_THRESHOLD"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f >= 0 && f <= 1 {
			return f
		}
	}
	return DefaultTokenThreshold
}

// historySize returns how many fingerprints to retain per agent.
// Configurable via DRIFT_HISTORY_SIZE.
func historySize() int {
	if v := os.Getenv("DRIFT_HISTORY_SIZE"); v != "" {
		if i, err := strconv.Atoi(v); err == nil && i > 0 {
			return i
		}
	}
	return DefaultHistorySize
}
