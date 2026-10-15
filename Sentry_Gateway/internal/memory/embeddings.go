// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package memory implements Phase 8 of the Cicada security roadmap:
// semantic memory isolation for the LLM proxy pipeline.
//
// # The problem this solves
//
// The existing hash-based contamination check (llmproxy.CheckContamination)
// detects verbatim repetition: if the exact bytes of a message from Agent A
// appear in Agent B's context, the SHA-256 hash matches and contamination is
// flagged. This covers the simple case.
//
// It does not cover the default operating pattern of every production
// multi-agent system (LangGraph, AutoGen, CrewAI): an orchestrator receives
// Agent A's output, summarises or paraphrases it, and passes it to Agent B.
// The content is semantically identical but lexically different. The hashes
// do not match. The contamination is invisible to the existing check.
//
// This package closes that gap using two complementary tiers.
//
// # Tier 1 — Embedding cosine similarity
//
// When EMBEDDING_SERVICE_URL is configured (pointing at an Ollama or
// compatible embedding service), each message is encoded as a dense vector
// (default: nomic-embed-text, 768-dim). Two texts that convey the same
// information produce vectors with cosine similarity > 0.65 regardless of
// lexical differences. This is the definitive 2026 approach to semantic
// contamination detection.
//
// The embedding service is the same Ollama instance used by the semantic
// intent checker, reused here to avoid additional deployment dependencies.
//
// Block threshold: 0.65 (configurable via EMBEDDING_CONTAMINATION_THRESHOLD).
// Chosen to be above the noise floor (~0.4–0.55 for unrelated texts on the
// same topic) and below perfect paraphrase (~0.85–0.95).
//
// # Tier 2 — SimHash + Named Entity Recall (fallback)
//
// When the embedding service is unavailable or not configured, two
// complementary signals are combined into a single similarity score:
//
//  1. SimHash fingerprinting
//     A 64-bit locality-sensitive hash computed by tallying per-bit votes
//     across all tokens. Two texts that share most of their vocabulary
//     produce similar SimHashes. Hamming distance between SimHashes is a
//     proxy for cosine similarity between the bag-of-words vectors.
//     Catches: near-verbatim paraphrases, reorderings, synonym substitutions.
//
//  2. Named entity recall
//     Numeric entities (account numbers, sort codes, card suffixes) are
//     extracted from both texts as normalised digit n-grams. The fraction
//     of the incoming text's entities that previously appeared in another
//     agent's context is computed as a recall score.
//     Catches: paraphrases where numbers are preserved but wording changes
//     entirely (e.g. "£47,230.00" vs "forty-seven thousand pounds" —
//     the sort code "20-44-53" / "204453" and account suffix "6819" both
//     appear in the paraphrase and match the original).
//
// Tier 2 block threshold: 0.40 (configurable via SEMANTIC_SIMILARITY_THRESHOLD).
//
// # Storage schema (Redis)
//
//	cicada:semctx:{tenantID}          — hash: field={simhash|efp}  value={agentID}
//	cicada:semctx:emb:{tenantID}      — hash: field={simhash|efp}  value=JSON{AgentID,Embedding}
//	cicada:semctx:entities:{t}:{efp}  — set: entity strings for Tier 2 recall
//
// All keys TTL: 24 hours (refreshed on each write).
package memory

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"math/bits"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/asai/cicada/sentry/internal/queue"
)

// ── Configuration ─────────────────────────────────────────────────────────────

// defaultThreshold is the Tier 2 (SimHash+NER) similarity threshold.
const defaultThreshold = 0.40

// defaultEmbeddingThreshold is the Tier 1 (cosine similarity) block threshold.
// Higher than Tier 2 because embedding similarity is more precise — a score of
// 0.65 represents clear semantic equivalence, not superficial token overlap.
const defaultEmbeddingThreshold = 0.65

const entityWeight = 1.5
const minEntitiesForRecall = 2

// SimilarityThreshold returns the Tier 2 block threshold from env.
func SimilarityThreshold() float64 {
	if v := os.Getenv("SEMANTIC_SIMILARITY_THRESHOLD"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 && f <= 1.0 {
			return f
		}
	}
	return defaultThreshold
}

// embeddingThreshold returns the Tier 1 cosine similarity block threshold.
func embeddingThreshold() float64 {
	if v := os.Getenv("EMBEDDING_CONTAMINATION_THRESHOLD"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 && f <= 1.0 {
			return f
		}
	}
	return defaultEmbeddingThreshold
}

// ── Tier 1: Embedding cosine similarity ───────────────────────────────────────

// embeddingRequest is the JSON payload sent to the Ollama /api/embeddings endpoint.
type embeddingRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
}

// embeddingResponse is the JSON response from Ollama.
type embeddingResponse struct {
	Embedding []float64 `json:"embedding"`
}

// embeddingRecord is stored in Redis to pair an embedding vector with its agent.
// Compact JSON field names keep storage size manageable (384–768 floats ≈ 3–6 KB).
type embeddingRecord struct {
	AgentID   string    `json:"a"`
	Embedding []float64 `json:"e"`
}

var embHTTPClient = &http.Client{Timeout: 2 * time.Second}

// getEmbedding calls the embedding service and returns the vector for text.
// Returns an error if the service is not configured or unreachable — the
// caller falls back to Tier 2 (SimHash+NER) on any error.
func getEmbedding(ctx context.Context, text string) ([]float64, error) {
	serviceURL := os.Getenv("EMBEDDING_SERVICE_URL")
	if serviceURL == "" {
		return nil, fmt.Errorf("EMBEDDING_SERVICE_URL not set")
	}
	model := os.Getenv("EMBEDDING_MODEL")
	if model == "" {
		model = "nomic-embed-text"
	}

	body, err := json.Marshal(embeddingRequest{Model: model, Prompt: text})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, serviceURL+"/api/embeddings", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := embHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("embedding service unreachable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("embedding service returned %d", resp.StatusCode)
	}

	var result embeddingResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode embedding response: %w", err)
	}
	if len(result.Embedding) == 0 {
		return nil, fmt.Errorf("embedding service returned empty vector")
	}
	return result.Embedding, nil
}

// cosineSimilarity computes the cosine similarity between two float64 vectors.
// Returns 0 if either vector is zero-magnitude (avoids division by zero).
// Values range from -1 (opposite) to 1 (identical direction). Semantic text
// similarity is always non-negative in practice — two texts about unrelated
// topics score ~0.4, same topic ~0.5–0.6, paraphrase ~0.65–0.95.
func cosineSimilarity(a, b []float64) float64 {
	if len(a) != len(b) || len(a) == 0 {
		return 0
	}
	var dot, magA, magB float64
	for i := range a {
		dot += a[i] * b[i]
		magA += a[i] * a[i]
		magB += b[i] * b[i]
	}
	magA = math.Sqrt(magA)
	magB = math.Sqrt(magB)
	if magA == 0 || magB == 0 {
		return 0
	}
	return dot / (magA * magB)
}

// embeddingRedisKey returns the Redis key for the embedding store of a tenant.
func embeddingRedisKey(tenantID string) string {
	return fmt.Sprintf("cicada:semctx:emb:%s", tenantID)
}

// ── Tier 2: SimHash + Named Entity Recall ─────────────────────────────────────

// SimHash computes a 64-bit locality-sensitive hash of the input text.
//
// Algorithm (Charikar 2002):
//  1. Tokenise the text into lowercase word tokens.
//  2. For each token, compute a 64-bit hash (SHA-256 truncated to 8 bytes).
//  3. For each bit position 0–63, accumulate a weight: +1 if the bit is set
//     in the token hash, -1 if the bit is unset.
//  4. The final bit at position i is 1 if its accumulated weight is positive.
func SimHash(text string) uint64 {
	tokens := tokenise(text)
	if len(tokens) == 0 {
		return 0
	}

	var weights [64]float64
	for _, tok := range tokens {
		raw := sha256.Sum256([]byte(tok))
		h := binary.LittleEndian.Uint64(raw[:8])
		for i := 0; i < 64; i++ {
			if (h>>uint(i))&1 == 1 {
				weights[i]++
			} else {
				weights[i]--
			}
		}
	}

	var result uint64
	for i := 0; i < 64; i++ {
		if weights[i] > 0 {
			result |= 1 << uint(i)
		}
	}
	return result
}

// HammingDistance returns the number of differing bits between two uint64 values.
func HammingDistance(a, b uint64) int {
	return bits.OnesCount64(a ^ b)
}

// SimHashSimilarity converts Hamming distance to a [0, 1] similarity score.
func SimHashSimilarity(a, b uint64) float64 {
	return 1.0 - float64(HammingDistance(a, b))/64.0
}

// ── Named entity extraction ───────────────────────────────────────────────────

var (
	reDigitRun = regexp.MustCompile(`\d+`)
	reSortCode = regexp.MustCompile(`\b(\d{2})[-\s](\d{2})[-\s](\d{2})\b`)
)

func extractEntities(text string) map[string]struct{} {
	entities := make(map[string]struct{})

	for _, m := range reSortCode.FindAllStringSubmatch(text, -1) {
		entities[m[1]+m[2]+m[3]] = struct{}{}
	}

	cleaned := reSortCode.ReplaceAllStringFunc(text, func(s string) string {
		return strings.ReplaceAll(strings.ReplaceAll(s, "-", ""), " ", "")
	})

	for _, run := range reDigitRun.FindAllString(cleaned, -1) {
		if len(run) < 4 {
			continue
		}
		if len(run) == 6 {
			entities[run] = struct{}{}
		}
		for i := 0; i+4 <= len(run); i++ {
			entities[run[i:i+4]] = struct{}{}
		}
	}

	words := strings.Fields(text)
	for i, w := range words {
		stripped := strings.Trim(w, `.,;:!?"'()`)
		if i > 0 && len(stripped) >= 2 && unicode.IsUpper(rune(stripped[0])) && unicode.IsLower(rune(stripped[1])) {
			entities[strings.ToLower(stripped)] = struct{}{}
		}
	}

	return entities
}

func entityRecall(incoming, stored map[string]struct{}) float64 {
	if len(incoming) < minEntitiesForRecall {
		return 0
	}
	var matched int
	for e := range incoming {
		if _, ok := stored[e]; ok {
			matched++
		}
	}
	return float64(matched) / float64(len(incoming))
}

func entityFingerprint(entities map[string]struct{}) string {
	keys := make([]string, 0, len(entities))
	for k := range entities {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	joined := strings.Join(keys, ",")
	h := sha256.Sum256([]byte(joined))
	return hex.EncodeToString(h[:8])
}

// ── Tokenisation ──────────────────────────────────────────────────────────────

var stopWords = map[string]struct{}{
	"a": {}, "an": {}, "the": {}, "and": {}, "or": {}, "but": {},
	"in": {}, "on": {}, "at": {}, "to": {}, "for": {}, "of": {},
	"with": {}, "by": {}, "from": {}, "is": {}, "are": {}, "was": {},
	"were": {}, "be": {}, "been": {}, "has": {}, "have": {}, "had": {},
	"it": {}, "its": {}, "that": {}, "this": {}, "these": {}, "those": {},
}

func tokenise(text string) []string {
	text = strings.ToLower(text)
	var tokens []string
	for _, word := range strings.FieldsFunc(text, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	}) {
		if _, isStop := stopWords[word]; !isStop && len(word) > 1 {
			tokens = append(tokens, word)
		}
	}
	return tokens
}

// ── Redis storage ─────────────────────────────────────────────────────────────

// SemanticRecord is the value stored in Redis for each message fingerprint.
type SemanticRecord struct {
	AgentID           string
	EntityFingerprint string
	StoredEntities    map[string]struct{}
}

func redisKey(tenantID string) string {
	return fmt.Sprintf("cicada:semctx:%s", tenantID)
}

func fieldKey(simhash uint64, efp string) string {
	return fmt.Sprintf("%016x|%s", simhash, efp)
}

// ── CheckSemanticContamination ────────────────────────────────────────────────

// CheckSemanticContamination determines whether the incoming message content
// is semantically similar to content registered by a different agent in this
// tenant's context. Two tiers run in order — the first positive result wins:
//
// Tier 1 (embedding cosine similarity): only runs when EMBEDDING_SERVICE_URL
// is set. A cosine similarity above EMBEDDING_CONTAMINATION_THRESHOLD (0.65)
// with a different agent's content is a definitive contamination signal. This
// tier catches complete semantic paraphrases where no tokens are shared at all.
//
// Tier 2 (SimHash + NER): always available, no external dependency. Uses a
// combination of locality-sensitive hashing and numeric entity recall to catch
// near-verbatim paraphrases and cases where numeric identifiers (sort codes,
// account numbers) are preserved across rewordings.
//
// Fail-open: Redis unavailability or embedding service unavailability each return
// (false, "", 0, nil) — neither blocks the LLM call. The security value of
// contamination detection is telemetry for Aegis-0 to investigate; blocking
// on a check failure would create a denial-of-service attack vector.
func CheckSemanticContamination(
	ctx context.Context,
	tenantID, agentID, messageContent string,
) (contaminated bool, originAgentID string, score float64, err error) {
	if queue.Client == nil {
		return false, "", 0, nil
	}

	// Pre-compute SimHash and entities (needed for both tiers and for registration).
	incoming := SimHash(messageContent)
	incomingEntities := extractEntities(messageContent)
	incomingEFP := entityFingerprint(incomingEntities)
	fk := fieldKey(incoming, incomingEFP)

	// ── Tier 1: Embedding cosine similarity ───────────────────────────────────
	// An embedding encodes the meaning of text as a dense vector. Two texts
	// with different words but the same meaning produce vectors with cosine
	// similarity > 0.65. This tier runs first because it catches the case that
	// Tier 2 cannot: complete semantic paraphrase with no shared tokens or numbers.
	//
	// We call the embedding service with the same 2-second timeout used by the
	// semantic intent checker so this check does not meaningfully add latency to
	// the LLM proxy hot path. On service unavailability, fall through immediately.
	incomingEmb, embErr := getEmbedding(ctx, messageContent)
	if embErr == nil && len(incomingEmb) > 0 {
		embKey := embeddingRedisKey(tenantID)
		storedEmbs, getErr := queue.Client.HGetAll(ctx, embKey).Result()
		if getErr == nil {
			threshold := embeddingThreshold()
			for _, rawRecord := range storedEmbs {
				var rec embeddingRecord
				if jsonErr := json.Unmarshal([]byte(rawRecord), &rec); jsonErr != nil {
					continue
				}
				if rec.AgentID == agentID {
					continue
				}
				sim := cosineSimilarity(incomingEmb, rec.Embedding)
				if sim > threshold {
					log.Printf("[MEMISO-EMB] Tier 1 contamination: agent=%s sim=%.3f source=%s tenant=%s",
						agentID, sim, rec.AgentID, tenantID)
					// Register before returning so future checks include this content.
					registerContent(ctx, tenantID, agentID, fk, incomingEFP, incomingEntities, incomingEmb)
					return true, rec.AgentID, sim, nil
				}
			}
		}
	} else if embErr != nil && os.Getenv("EMBEDDING_SERVICE_URL") != "" {
		// Service is configured but unreachable — log so operators know Tier 1 is degraded.
		log.Printf("[MEMISO-EMB] Embedding service unavailable, falling back to Tier 2: %v", embErr)
	}

	// ── Tier 2: SimHash + Named Entity Recall ─────────────────────────────────
	// Always runs. Catches near-verbatim paraphrases and numeric entity reuse even
	// when the embedding service is unavailable. Lower precision than Tier 1 but
	// zero external dependency.
	t2Threshold := SimilarityThreshold()
	stored, getErr := queue.Client.HGetAll(ctx, redisKey(tenantID)).Result()
	if getErr != nil {
		log.Printf("[MEMISO-SEM] Redis unavailable for tenant %s: %v", tenantID, getErr)
		return false, "", 0, nil
	}

	for field, storedAgentID := range stored {
		if storedAgentID == agentID {
			continue
		}

		parts := strings.SplitN(field, "|", 2)
		if len(parts) != 2 {
			continue
		}
		var storedSimHash uint64
		if _, parseErr := fmt.Sscanf(parts[0], "%016x", &storedSimHash); parseErr != nil {
			continue
		}

		simSim := SimHashSimilarity(incoming, storedSimHash)

		storedEntityKey := fmt.Sprintf("cicada:semctx:entities:%s:%s", tenantID, parts[1])
		rawEntities, _ := queue.Client.SMembers(ctx, storedEntityKey).Result()
		storedEntities := make(map[string]struct{}, len(rawEntities))
		for _, e := range rawEntities {
			storedEntities[e] = struct{}{}
		}

		recall := entityRecall(incomingEntities, storedEntities)
		entitySim := recall * entityWeight
		if entitySim > 1.0 {
			entitySim = 1.0
		}

		combined := simSim
		if entitySim > combined {
			combined = entitySim
		}

		if combined > t2Threshold {
			log.Printf("[MEMISO-SEM] Tier 2 contamination: agent=%s sim=%.3f (simhash=%.3f entity_recall=%.3f) source=%s",
				agentID, combined, simSim, recall, storedAgentID)
			registerContent(ctx, tenantID, agentID, fk, incomingEFP, incomingEntities, incomingEmb)
			return true, storedAgentID, combined, nil
		}
	}

	// No contamination found — register the incoming content for future checks.
	registerContent(ctx, tenantID, agentID, fk, incomingEFP, incomingEntities, incomingEmb)
	return false, "", 0, nil
}

// registerContent stores the incoming content's fingerprints and embedding in
// Redis so that future calls from other agents can be compared against it.
// Both Tier 1 (embedding) and Tier 2 (SimHash+entities) data are written in
// a single pipeline to minimise round trips.
func registerContent(
	ctx context.Context,
	tenantID, agentID, fk, efp string,
	entities map[string]struct{},
	embedding []float64,
) {
	if queue.Client == nil {
		return
	}

	pipe := queue.Client.Pipeline()

	// Tier 2 registration: SimHash field → agentID
	pipe.HSet(ctx, redisKey(tenantID), fk, agentID)
	pipe.Expire(ctx, redisKey(tenantID), 24*time.Hour)

	// Tier 2 entity set
	entityKey := fmt.Sprintf("cicada:semctx:entities:%s:%s", tenantID, efp)
	if len(entities) > 0 {
		entitySlice := make([]interface{}, 0, len(entities))
		for e := range entities {
			entitySlice = append(entitySlice, e)
		}
		pipe.SAdd(ctx, entityKey, entitySlice...)
		pipe.Expire(ctx, entityKey, 24*time.Hour)
	}

	// Tier 1 registration: same field key → JSON{agentID, embedding}
	// Only stored when we actually have an embedding (service was reachable).
	if len(embedding) > 0 {
		rec, jsonErr := json.Marshal(embeddingRecord{AgentID: agentID, Embedding: embedding})
		if jsonErr == nil {
			pipe.HSet(ctx, embeddingRedisKey(tenantID), fk, string(rec))
			pipe.Expire(ctx, embeddingRedisKey(tenantID), 24*time.Hour)
		}
	}

	if _, pipeErr := pipe.Exec(ctx); pipeErr != nil {
		log.Printf("[MEMISO] Redis write error for tenant %s: %v", tenantID, pipeErr)
	}
}
