// © 2026 Affinity Ops Ltd. All rights reserved.
// Proprietary and confidential. Unauthorized copying or distribution prohibited.

// Package canary implements honeytoken deception for Cicada's threat hunting layer.
//
// What are canary tokens (honeytokens)?
// A canary token is a fake credential or identifier that looks real but is
// never used in legitimate operations. It is injected into an agent's context
// (as a fake API key, a fake database record, or a fake bearer token). If that
// token subsequently appears in an outbound call — meaning the agent attempted
// to use or exfiltrate it — that is definitive proof of:
//   (a) data exfiltration (agent relayed the credential to an external system)
//   (b) credential misuse (agent attempted to authenticate using a stolen token)
//   (c) prompt injection success (injected instructions directed the agent to use the canary)
//
// Why this is categorically different from other detection methods:
// Rate limits, semantic checks, and anomaly detection all produce probabilistic
// signals — they fire with some false positive rate. A canary token trigger is a
// zero-false-positive signal: a real API key never starts with CICADA_CANARY_.
// There is no legitimate reason for an agent to present a canary token to any
// external API. When it happens, it IS an incident, not a suspicion.
//
// How canary tokens reach the agent:
// The verification swarm injects a canary into selected agent responses as a
// metadata field. The agent's system prompt typically includes instructions to
// store and use API credentials it encounters — a prompt-injected agent will
// attempt to use the canary. The gateway intercepts the outbound call and fires
// the alert before it reaches the external API.
//
// Token format:
// CICADA_CANARY_{type}_{tenant_prefix}_{random_16_hex}
// Example: CICADA_CANARY_APIKEY_acme_a3f7b9c2d1e4f508
// The format is realistic enough to look like a real key to an LLM but unique
// enough that it cannot be confused with any real credential.
package canary

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/asai/cicada/sentry/internal/queue"
)

var (
	canaryPatternRe    = regexp.MustCompile(`CICADA_CANARY_[A-Za-z0-9_]+`)
	canaryBase64CandRe = regexp.MustCompile(`[A-Za-z0-9+/_\-]{20,}={0,2}`)
)

// ContainsCanaryToken performs a deterministic, zero-dependency scan of outbound
// content (including Base64-encoded and URL-encoded payloads) for any Cicada
// honeytoken matching CICADA_CANARY_*. Returns true and the matched token value
// if found.
func ContainsCanaryToken(content string) (bool, string) {
	if content == "" {
		return false, ""
	}
	if m := canaryPatternRe.FindString(content); m != "" {
		return true, m
	}
	for _, decoded := range unwrapCanaryEncodings(content) {
		if m := canaryPatternRe.FindString(decoded); m != "" {
			return true, m
		}
	}
	return false, ""
}

func unwrapCanaryEncodings(content string) []string {
	var out []string
	if strings.Contains(content, "%") {
		if unescaped, err := url.QueryUnescape(content); err == nil && unescaped != content {
			out = append(out, unescaped)
		}
	}
	for _, m := range canaryBase64CandRe.FindAllString(content, 20) {
		cleaned := strings.TrimRight(m, "=")
		for _, enc := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding, base64.StdEncoding, base64.URLEncoding} {
			target := m
			if enc == base64.RawStdEncoding || enc == base64.RawURLEncoding {
				target = cleaned
			}
			if raw, err := enc.DecodeString(target); err == nil && len(raw) >= 14 {
				out = append(out, string(raw))
				break
			}
		}
	}
	return out
}

// TokenType classifies what kind of credential the canary impersonates.
// Different types are injected in contexts where that credential type would
// naturally appear to a model (e.g. APIKEY in a tool configuration response).
type TokenType string

const (
	TokenTypeAPIKey  TokenType = "APIKEY"
	TokenTypeJWT     TokenType = "JWT"
	TokenTypeSecret  TokenType = "SECRET"
	TokenTypeDBCreds TokenType = "DBCREDS"
)

// Token is a generated canary credential.
type Token struct {
	Value      string    // the full canary string to inject
	Type       TokenType
	AgentID    string
	TenantID   string
	CreatedAt  time.Time
}

// TriggerResult is returned when a canary token is detected in outbound content.
type TriggerResult struct {
	TokenValue string
	AgentID    string
	TenantID   string
	InjectedAt time.Time
}

// redisKey returns the Redis key where a canary token's metadata is stored.
// Keyed by the token value so detection is O(1) — just check if the key exists.
func redisKey(tokenValue string) string {
	return fmt.Sprintf("cicada:canary:%s", tokenValue)
}

// tenantSetKey returns the Redis set key listing all active canaries for a tenant.
// Used to retrieve the full token list for scanning outbound content.
func tenantSetKey(tenantID string) string {
	return fmt.Sprintf("cicada:canary:tenant:%s", tenantID)
}

// Issue generates a new canary token and registers it in Redis.
// The token is scoped to a specific agent and tenant so that when it triggers,
// we know precisely which agent exfiltrated it.
//
// TTL of 72 hours: long enough to be used in multiple agent sessions (agents
// can cache context), short enough to prevent the Redis key store from growing
// unbounded if tokens are never triggered.
func Issue(ctx context.Context, agentID, tenantID string, tokenType TokenType) (Token, error) {
	if queue.Client == nil {
		return Token{}, fmt.Errorf("Redis not available — cannot issue canary token")
	}

	// Generate 16 bytes of cryptographic randomness for the token suffix.
	// crypto/rand rather than math/rand — the token must be unguessable.
	rawBytes := make([]byte, 16)
	if _, err := rand.Read(rawBytes); err != nil {
		return Token{}, fmt.Errorf("generate canary randomness: %w", err)
	}

	// Build a token that looks realistic to an LLM (provider:format:random)
	// but is unmistakably a canary in our detection scan.
	tenantPrefix := tenantID
	if len(tenantPrefix) > 6 {
		tenantPrefix = tenantPrefix[:6] // first 6 chars of tenant UUID
	}
	tokenValue := fmt.Sprintf("CICADA_CANARY_%s_%s_%s",
		string(tokenType), tenantPrefix, hex.EncodeToString(rawBytes))

	token := Token{
		Value:     tokenValue,
		Type:      tokenType,
		AgentID:   agentID,
		TenantID:  tenantID,
		CreatedAt: time.Now(),
	}

	// Store in Redis: key=token value, value=metadata JSON, TTL=72h
	pipe := queue.Client.Pipeline()
	pipe.HSet(ctx, redisKey(tokenValue),
		"agent_id", agentID,
		"tenant_id", tenantID,
		"token_type", string(tokenType),
		"created_at", token.CreatedAt.Unix(),
	)
	pipe.Expire(ctx, redisKey(tokenValue), 72*time.Hour)
	pipe.SAdd(ctx, tenantSetKey(tenantID), tokenValue)
	pipe.Expire(ctx, tenantSetKey(tenantID), 72*time.Hour)
	if _, err := pipe.Exec(ctx); err != nil {
		return Token{}, fmt.Errorf("store canary in Redis: %w", err)
	}

	log.Printf("[CANARY] Issued token type=%s agent=%s tenant=%s", tokenType, agentID, tenantID)
	return token, nil
}

// CheckOutbound scans outbound request content for canary tokens belonging to
// the given tenant. If a match is found, the token's metadata is returned so
// the caller can write a critical ledger event and alert Aegis-0.
//
// This is called on the hot path (every proxied request) but is O(n) on the
// number of active canary tokens for the tenant — kept low by the 72h TTL and
// by only issuing one canary per agent session rather than per-request.
//
// Returns nil if no canary was found (the common case).
func CheckOutbound(ctx context.Context, tenantID, content string) *TriggerResult {
	if queue.Client == nil {
		return nil
	}

	// Retrieve all active canary token values for this tenant
	tokenValues, err := queue.Client.SMembers(ctx, tenantSetKey(tenantID)).Result()
	if err != nil || len(tokenValues) == 0 {
		return nil
	}

	decodedSegments := unwrapCanaryEncodings(content)

	// Scan the outbound content (raw + decoded) for each token value.
	// O(n*m) where n=canaries (small, typically 1–5) and m=content length.
	// Acceptable on the hot path because n is bounded and the string scan is fast.
	for _, tv := range tokenValues {
		matched := strings.Contains(content, tv)
		if !matched {
			for _, seg := range decodedSegments {
				if strings.Contains(seg, tv) {
					matched = true
					break
				}
			}
		}
		if matched {
			// Canary triggered — retrieve metadata for the incident report
			meta, err := queue.Client.HGetAll(ctx, redisKey(tv)).Result()
			if err != nil || len(meta) == 0 {
				// Token was found in content but metadata expired — still report it
				log.Printf("[CANARY] TRIGGER: token=%s tenant=%s (metadata expired)", tv, tenantID)
				return &TriggerResult{TokenValue: tv, TenantID: tenantID}
			}

			var injectedAt time.Time
			if ts, ok := meta["created_at"]; ok {
				if unix, err := fmt.Sscan(ts); err == nil {
					_ = unix // parsed but stored as time.Time below
				}
				injectedAt = time.Now() // fallback if parse fails
			}

			result := &TriggerResult{
				TokenValue: tv,
				AgentID:    meta["agent_id"],
				TenantID:   tenantID,
				InjectedAt: injectedAt,
			}

			log.Printf("[CANARY] TRIGGER: token=%s agent=%s tenant=%s — CRITICAL INCIDENT",
				tv, result.AgentID, tenantID)

			// Mark the canary as triggered in Redis so duplicate triggers from
			// the same agent session do not generate duplicate incident reports.
			queue.Client.HSet(ctx, redisKey(tv), "triggered", "1", "triggered_at", time.Now().Unix())

			return result
		}
	}

	return nil
}

// Revoke removes a canary token from active monitoring. Called after the
// incident response is complete so the token no longer appears in future scans.
func Revoke(ctx context.Context, tenantID, tokenValue string) error {
	if queue.Client == nil {
		return fmt.Errorf("Redis not available")
	}
	pipe := queue.Client.Pipeline()
	pipe.Del(ctx, redisKey(tokenValue))
	pipe.SRem(ctx, tenantSetKey(tenantID), tokenValue)
	_, err := pipe.Exec(ctx)
	return err
}

