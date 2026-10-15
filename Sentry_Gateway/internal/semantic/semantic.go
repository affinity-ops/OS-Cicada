// © 2026 Affinity Ops Ltd. All rights reserved.
// Proprietary and confidential. Unauthorized copying or distribution prohibited.

// Package semantic implements intent alignment checking for Cicada's proxy layer.
//
// The problem this solves:
// An agent registered as "customer support assistant" should never call a payment
// deletion endpoint — yet its EVAR, scopes, and resource policies might technically
// permit the call. Those controls answer "is this agent allowed to do this?"
// This package answers "does this call make sense given what this agent IS?"
//
// Why NOT an LLM for this check:
// Using a second LLM to verify a first LLM's intent is circular — the verifier
// can hallucinate approval just as the agent can hallucinate the action. A 2026
// standards-compliant approach uses a lightweight, deterministic embedding model
// that cannot be prompt-injected and does not add LLM inference latency.
//
// Two-tier implementation:
//
// Tier 1 — Embedding cosine similarity (primary):
// If EMBEDDING_SERVICE_URL is configured, the agent description + type and the
// target URL text are each encoded into a sentence embedding vector (384 dimensions
// using nomic-embed-text or all-MiniLM-L6-v2). Cosine similarity between the two
// vectors captures semantic relatedness regardless of synonym variation — "payments",
// "billing", "charges", and "invoices" all produce similar embeddings near the
// Stripe domain vocabulary.
//
// Tier 2 — Jaccard + domain taxonomy (fallback):
// If the embedding service is unavailable (not yet deployed, cold start, network
// partition), the existing deterministic token overlap + domain category map runs
// instead. This ensures the semantic check never silently passes all traffic
// because the embedding service is down.
//
// Configuring the embedding service:
//   EMBEDDING_SERVICE_URL=http://localhost:11434   (Ollama — recommended)
//   EMBEDDING_MODEL=nomic-embed-text               (default)
//
// To start Ollama with the recommended model:
//   ollama pull nomic-embed-text && ollama serve
package semantic

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// embeddingClient is shared across calls. Timeout of 2 seconds is intentional:
// the semantic check is on the hot path — if the embedding service takes longer
// than 2 seconds to respond, we fall back to Jaccard rather than stalling the
// agent's request. Fast fallback is more important than waiting for the better check.
var embeddingClient = &http.Client{Timeout: 2 * time.Second}

// Result holds the outcome of a semantic intent check.
type Result struct {
	Score    float64 // 0.0 (total mismatch) – 1.0 (perfect alignment)
	Reason   string  // human-readable explanation written to the audit ledger
	Block    bool    // true when Score falls below the configured block threshold
	Method   string  // "embedding" or "jaccard" — which tier produced the score
}

// BlockThreshold returns the minimum acceptable alignment score.
// Scores below this value cause the proxy to deny the call.
//
// Default 0.35 for embedding mode — cosine similarity below 0.35 between an
// agent's description and a target URL indicates genuine semantic mismatch
// (e.g. a "document summarisation" agent calling Stripe's charges endpoint).
//
// Default 0.10 for Jaccard fallback mode — Jaccard is a much sparser signal
// so the threshold is lower to avoid false positives when synonyms are involved.
func BlockThreshold(method string) float64 {
	envKey := "SEMANTIC_BLOCK_THRESHOLD"
	if method == "jaccard" {
		envKey = "SEMANTIC_JACCARD_BLOCK_THRESHOLD"
	}
	if v := os.Getenv(envKey); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f >= 0 && f <= 1 {
			return f
		}
	}
	if method == "embedding" {
		return 0.35
	}
	return 0.10
}

// Check scores alignment between an agent's declared purpose and a runtime call.
// Tries embedding cosine similarity first; falls back to Jaccard if the embedding
// service is unavailable. The audit ledger records which method was used.
func Check(agentDescription, agentType, targetRawURL, httpMethod string) Result {
	if targetRawURL == "" {
		return Result{Score: 0.5, Reason: "no target URL declared; intent check skipped", Block: false, Method: "none"}
	}

	parsedURL, err := url.Parse(targetRawURL)
	if err != nil {
		return Result{Score: 0.5, Reason: "unparseable target URL; intent check skipped", Block: false, Method: "none"}
	}

	// ── Tier 1: Embedding cosine similarity ──────────────────────────────────────
	// Build natural-language representations of both the agent and the target,
	// then ask the embedding model whether they are semantically related.
	// Using natural language rather than raw tokens improves coverage for synonyms
	// and domain-specific vocabulary without manual taxonomy maintenance.
	agentText := buildAgentText(agentDescription, agentType)
	targetText := buildTargetText(parsedURL, httpMethod)

	agentVec, agentErr := getEmbedding(agentText)
	targetVec, targetErr := getEmbedding(targetText)

	if agentErr == nil && targetErr == nil && len(agentVec) > 0 && len(targetVec) == len(agentVec) {
		similarity := cosineSimilarity(agentVec, targetVec)

		// Apply method-class penalty on top of embedding score.
		// Embeddings capture semantic similarity but not the write/read direction —
		// a "read-only monitoring agent" and "delete endpoint" can have high similarity
		// (both relate to "data") while the action is clearly wrong.
		if methodPenalty := readOnlyMethodPenalty(agentDescription, httpMethod); methodPenalty > 0 {
			similarity -= methodPenalty
			if similarity < 0 {
				similarity = 0
			}
		}

		threshold := BlockThreshold("embedding")
		block := similarity < threshold && len(strings.TrimSpace(agentDescription)) > 0

		return Result{
			Score:  similarity,
			Reason: fmt.Sprintf("embedding cosine similarity=%.3f threshold=%.3f target=%s", similarity, threshold, parsedURL.Host),
			Block:  block,
			Method: "embedding",
		}
	}

	// Log the fallback reason once — not per-request (spam risk) — caller logs it.
	if agentErr != nil {
		log.Printf("[SEMANTIC] Embedding service unavailable (%v) — falling back to Jaccard", agentErr)
	}

	// ── Tier 2: Jaccard + domain taxonomy fallback ────────────────────────────────
	return jaccardCheck(agentDescription, agentType, parsedURL, httpMethod)
}

// ────────────────────────────────────────────────────────────────────────────
// Embedding helpers
// ────────────────────────────────────────────────────────────────────────────

// ollamaRequest is the JSON body sent to the Ollama embeddings endpoint.
// Ollama is the recommended local embedding service for self-hosted deployments.
// Format is also compatible with most OpenAI-compatible embedding services.
type ollamaRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
}

// ollamaResponse is the expected JSON response from the Ollama API.
type ollamaResponse struct {
	Embedding []float64 `json:"embedding"`
}

// getEmbedding calls the configured embedding service and returns a float64
// vector. Returns an error (without logging) if the service is unavailable —
// the caller decides whether to fall back or propagate.
//
// Supported service formats:
//   - Ollama: POST /api/embeddings {"model": "...", "prompt": "..."}
//   - Any service that returns {"embedding": [...]} for the same request body
func getEmbedding(text string) ([]float64, error) {
	serviceURL := os.Getenv("EMBEDDING_SERVICE_URL")
	if serviceURL == "" {
		return nil, fmt.Errorf("EMBEDDING_SERVICE_URL not configured")
	}

	model := os.Getenv("EMBEDDING_MODEL")
	if model == "" {
		model = "nomic-embed-text" // best open-weights model for semantic similarity as of 2026
	}

	body, err := json.Marshal(ollamaRequest{Model: model, Prompt: text})
	if err != nil {
		return nil, fmt.Errorf("marshal embedding request: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, serviceURL+"/api/embeddings", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build embedding request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := embeddingClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("embedding service unreachable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("embedding service returned HTTP %d", resp.StatusCode)
	}

	var result ollamaResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode embedding response: %w", err)
	}

	if len(result.Embedding) == 0 {
		return nil, fmt.Errorf("embedding service returned empty vector")
	}

	return result.Embedding, nil
}

// cosineSimilarity computes the cosine of the angle between two vectors.
// Returns 0.5 (neutral) for mismatched lengths or zero-magnitude vectors.
// Pre-normalised vectors are not assumed — the denominator is always computed.
//
// Formula: (A · B) / (|A| × |B|)
// Range: -1.0 (opposite) to 1.0 (identical). In practice, sentence embeddings
// from the same language space stay in [0.0, 1.0].
func cosineSimilarity(a, b []float64) float64 {
	if len(a) != len(b) || len(a) == 0 {
		return 0.5
	}

	var dot, normA, normB float64
	for i := range a {
		dot += a[i] * b[i]
		normA += a[i] * a[i]
		normB += b[i] * b[i]
	}

	if normA == 0 || normB == 0 {
		return 0.5
	}

	return dot / (math.Sqrt(normA) * math.Sqrt(normB))
}

// buildAgentText converts agent registration fields into a natural-language
// sentence suitable for embedding. Richer input improves embedding quality —
// the embedding model has better coverage when the input reads like a sentence
// rather than a raw token dump.
func buildAgentText(description, agentType string) string {
	parts := []string{}
	if description != "" {
		parts = append(parts, description)
	}
	if agentType != "" {
		parts = append(parts, "This is a "+strings.ReplaceAll(agentType, "_", " ")+" agent.")
	}
	if len(parts) == 0 {
		return "general purpose agent"
	}
	return strings.Join(parts, " ")
}

// buildTargetText converts a parsed URL and HTTP method into a natural-language
// sentence. This gives the embedding model context about what the call is doing,
// not just what domain it is hitting.
func buildTargetText(u *url.URL, method string) string {
	host := strings.ToLower(u.Host)
	path := strings.Trim(u.Path, "/")

	// Translate HTTP method to a verb phrase for the embedding model.
	// "Call DELETE /v1/charges on api.stripe.com" produces a more semantically
	// accurate embedding than "DELETE api.stripe.com v1 charges".
	verb := map[string]string{
		"GET":    "Read data from",
		"POST":   "Create data via",
		"PUT":    "Update data via",
		"PATCH":  "Modify data via",
		"DELETE": "Delete data from",
	}[strings.ToUpper(method)]
	if verb == "" {
		verb = "Call"
	}

	if path != "" {
		return fmt.Sprintf("%s %s/%s", verb, host, path)
	}
	return fmt.Sprintf("%s %s", verb, host)
}

// ────────────────────────────────────────────────────────────────────────────
// Jaccard fallback (Tier 2)
// ────────────────────────────────────────────────────────────────────────────

// readOnlyMethodPenalty returns a score penalty when a read-only agent description
// is paired with a destructive HTTP method. Applied in both embedding and Jaccard
// paths — embeddings capture semantic similarity but not write/read directionality.
func readOnlyMethodPenalty(agentDescription, httpMethod string) float64 {
	destructive := map[string]bool{"POST": true, "PUT": true, "PATCH": true, "DELETE": true}
	if !destructive[strings.ToUpper(httpMethod)] {
		return 0
	}
	readOnlyKeywords := []string{
		"read", "readonly", "read-only", "view", "fetch", "retrieve", "query",
		"monitor", "observe", "inspect", "report", "list", "get", "lookup",
	}
	lower := strings.ToLower(agentDescription)
	for _, kw := range readOnlyKeywords {
		if strings.Contains(lower, kw) {
			return 0.35
		}
	}
	return 0
}

// domainCategories maps well-known API domains to semantic category tags.
// Used by the Jaccard fallback to bridge the lexical gap between an agent's
// description vocabulary ("payments") and the literal URL tokens ("stripe.com").
var domainCategories = map[string][]string{
	"stripe.com":          {"payment", "billing", "charge", "invoice", "subscription", "finance", "refund"},
	"api.stripe.com":      {"payment", "billing", "charge", "invoice", "subscription", "finance", "refund"},
	"sendgrid.com":        {"email", "mail", "message", "notify", "notification", "communication"},
	"api.sendgrid.com":    {"email", "mail", "message", "notify", "notification", "communication"},
	"api.openai.com":      {"llm", "ai", "completion", "embedding", "chat", "model", "inference", "assistant"},
	"api.anthropic.com":   {"llm", "ai", "completion", "embedding", "chat", "model", "inference", "assistant"},
	"graph.microsoft.com": {"calendar", "email", "office", "mail", "teams", "user", "identity"},
	"api.github.com":      {"code", "repo", "git", "deploy", "release", "developer", "ci", "issue", "pull"},
	"hooks.slack.com":     {"notification", "message", "alert", "chat", "communicate", "slack"},
	"api.twilio.com":      {"sms", "phone", "voice", "message", "notification", "communicate"},
	"api.hubspot.com":     {"crm", "contact", "lead", "sales", "marketing", "customer"},
	"api.salesforce.com":  {"crm", "contact", "lead", "sales", "opportunity", "customer"},
	"api.linear.app":      {"issue", "ticket", "project", "sprint", "bug", "engineering", "task"},
	"api.notion.com":      {"document", "wiki", "knowledge", "note", "page", "workspace"},
	"api.pagerduty.com":   {"incident", "alert", "oncall", "monitor", "escalate", "ops"},
	"api.datadoghq.com":   {"metric", "log", "monitor", "trace", "observability", "telemetry", "alert"},
}

// semanticExfilSinks lists known data-exfiltration and webhook-capture domains
// that no legitimate production agent should align with.
var semanticExfilSinks = []string{
	"webhook.site",
	"pastebin.com",
	"paste.ee",
	"hastebin.com",
	"requestbin.com",
	"hookbin.com",
	"beeceptor.com",
	"requestcatcher.com",
	"burpcollaborator.net",
	"oastify.com",
	"interact.sh",
	"ngrok.io",
	"ngrok-free.app",
	"localtunnel.me",
	"serveo.net",
	"transfer.sh",
	"0x0.st",
}

func isExfiltrationSinkHost(host string) bool {
	h := strings.ToLower(host)
	for _, sink := range semanticExfilSinks {
		if h == sink || strings.HasSuffix(h, "."+sink) {
			return true
		}
	}
	return false
}

func jaccardCheck(agentDescription, agentType string, parsedURL *url.URL, httpMethod string) Result {
	agentTokens := extractTokens(agentDescription + " " + agentType)
	urlTokens := extractURLTokens(parsedURL)

	host := strings.ToLower(parsedURL.Host)
	if isExfiltrationSinkHost(host) && len(agentTokens) > 0 {
		return Result{
			Score:  0.0,
			Reason: fmt.Sprintf("[jaccard fallback — embedding service unavailable]; target host %s is a known data exfiltration sink", host),
			Block:  true,
			Method: "jaccard",
		}
	}

	overlapScore := jaccardScore(agentTokens, urlTokens)

	methodPenalty := readOnlyMethodPenalty(agentDescription, httpMethod)

	domainAdjustment := 0.0
	if categories, known := domainCategories[host]; known {
		matched := false
		for _, cat := range categories {
			if agentTokens[cat] || agentTokens[stemToken(cat)] {
				matched = true
				break
			}
		}
		if matched {
			domainAdjustment = 0.40
		} else if len(agentTokens) > 0 {
			domainAdjustment = -0.25
		}
	}

	rawScore := overlapScore + domainAdjustment - methodPenalty
	if rawScore < 0 {
		rawScore = 0
	}
	if rawScore > 1 {
		rawScore = 1
	}

	threshold := BlockThreshold("jaccard")
	block := rawScore < threshold && len(agentTokens) > 0

	return Result{
		Score:  rawScore,
		Reason: buildJaccardReason(overlapScore, domainAdjustment, methodPenalty, httpMethod, host),
		Block:  block,
		Method: "jaccard",
	}
}

// stemToken applies fast, deterministic morphological suffix stripping so
// plural/inflected forms ("payments", "charges", "processing", "orders")
// match their root tokens ("payment", "charge", "process", "order") without
// requiring an external NLP runtime.
func stemToken(word string) string {
	if len(word) <= 4 {
		return word
	}
	switch {
	case strings.HasSuffix(word, "ies") && len(word) > 5:
		return word[:len(word)-3] + "y"
	case strings.HasSuffix(word, "ing") && len(word) > 5:
		base := word[:len(word)-3]
		if len(base) >= 3 {
			return base
		}
	case strings.HasSuffix(word, "es") && len(word) > 4:
		// e.g. "processes" -> "process", "charges" -> "charge"
		if strings.HasSuffix(word, "sses") || strings.HasSuffix(word, "ches") || strings.HasSuffix(word, "shes") || strings.HasSuffix(word, "xes") {
			return word[:len(word)-2]
		}
		return word[:len(word)-1]
	case strings.HasSuffix(word, "s") && !strings.HasSuffix(word, "ss") && !strings.HasSuffix(word, "us") && !strings.HasSuffix(word, "is"):
		return word[:len(word)-1]
	case strings.HasSuffix(word, "ed") && len(word) > 5:
		return word[:len(word)-2]
	}
	return word
}

func addTokenWithStem(tokens map[string]bool, t string) {
	tokens[t] = true
	if stem := stemToken(t); stem != t && len(stem) >= 3 {
		tokens[stem] = true
	}
}

func extractTokens(text string) map[string]bool {
	stopWords := map[string]bool{
		"the": true, "and": true, "for": true, "with": true, "that": true,
		"this": true, "from": true, "are": true, "can": true, "its": true,
		"via": true, "use": true, "used": true, "into": true, "when": true,
	}
	tokens := make(map[string]bool)
	text = strings.ToLower(text)
	var current strings.Builder
	for _, r := range text {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			current.WriteRune(r)
		} else {
			if t := current.String(); len(t) >= 3 && !stopWords[t] {
				addTokenWithStem(tokens, t)
			}
			current.Reset()
		}
	}
	if t := current.String(); len(t) >= 3 && !stopWords[t] {
		addTokenWithStem(tokens, t)
	}
	return tokens
}

func extractURLTokens(u *url.URL) map[string]bool {
	tokens := make(map[string]bool)
	for _, seg := range strings.Split(u.Host, ".") {
		if len(seg) >= 3 {
			addTokenWithStem(tokens, strings.ToLower(seg))
		}
	}
	path := strings.Trim(u.Path, "/")
	for _, seg := range strings.FieldsFunc(path, func(r rune) bool {
		return r == '/' || r == '-' || r == '_'
	}) {
		lower := strings.ToLower(seg)
		if len(lower) >= 3 && !isVersionOrID(lower) {
			addTokenWithStem(tokens, lower)
		}
	}
	return tokens
}

func isVersionOrID(s string) bool {
	if len(s) > 8 {
		allHexOrDash := true
		for _, r := range s {
			if !unicode.IsDigit(r) && (r < 'a' || r > 'f') && r != '-' {
				allHexOrDash = false
				break
			}
		}
		if allHexOrDash {
			return true
		}
	}
	if len(s) <= 3 && s[0] == 'v' {
		allDigits := true
		for _, r := range s[1:] {
			if !unicode.IsDigit(r) {
				allDigits = false
				break
			}
		}
		if allDigits {
			return true
		}
	}
	return false
}

func jaccardScore(a, b map[string]bool) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 0.5
	}
	intersection := 0
	for k := range a {
		if b[k] {
			intersection++
		}
	}
	union := len(a) + len(b) - intersection
	if union == 0 {
		return 0.5
	}
	return float64(intersection) / float64(union)
}

func buildJaccardReason(overlap, domainAdj, methodPenalty float64, method, host string) string {
	parts := []string{"[jaccard fallback — embedding service unavailable]"}
	if overlap < 0.05 {
		parts = append(parts, "near-zero token overlap between agent description and target URL")
	} else if overlap > 0.4 {
		parts = append(parts, "strong token alignment")
	}
	if domainAdj > 0 {
		parts = append(parts, "agent category matches known domain "+host)
	} else if domainAdj < 0 {
		parts = append(parts, "agent tokens do not match known category for "+host)
	}
	if methodPenalty > 0 {
		parts = append(parts, "read-only agent description conflicts with "+method+" method")
	}
	return strings.Join(parts, "; ")
}

