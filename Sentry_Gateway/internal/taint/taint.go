// © 2026 Affinity Ops Ltd.
// SPDX-License-Identifier: Apache-2.0

// Package taint implements CaMeL-inspired capability taint tracking
// (Debenedetti et al., "Defeating Prompt Injections by Design", arXiv:2503.18813)
// for Cicada's Sentry Gateway.
//
// Core architectural invariant:
// Prompt injection classifiers (regex, TF-IDF, cosine similarity, SLMs) can be
// bypassed by adaptive attackers using business-aligned language ("The Attacker
// Moves Second"). Capability taint tracking enforces control-flow and data-flow
// security deterministically:
//
//  1. When an agent session ingests untrusted data — such as external GET
//     responses, tool_result messages in /v1/llm/proxy, RAG-retrieved context,
//     or cross-agent memory — the session is marked TAINTED.
//  2. While a session is tainted, it loses autonomous capability to mutate
//     state (POST, PUT, PATCH, DELETE) or exfiltrate data externally without
//     explicit human-in-the-loop (CIBA) approval.
//  3. Taint is cleared only when the agent performs a verified context flush
//     (X-Cicada-Memory-Action: flush) or receives operator CIBA sign-off.
package taint

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/asai/cicada/sentry/internal/queue"
	"github.com/redis/go-redis/v9"
)

// DefaultTTL is how long a session remains tainted without a context flush.
const DefaultTTL = 30 * time.Minute

// TaintRecord describes when and why an agent session became tainted.
type TaintRecord struct {
	AgentID   string    `json:"agent_id"`
	Source    string    `json:"source"`
	Reason    string    `json:"reason"`
	TaintedAt time.Time `json:"tainted_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// CapabilityResult captures the outcome of evaluating an action against the
// agent's current taint state.
type CapabilityResult struct {
	Tainted   bool   `json:"tainted"`
	ForceCIBA bool   `json:"force_ciba"`
	Source    string `json:"source,omitempty"`
	Reason    string `json:"reason"`
}

// localStore provides an in-memory fallback when Redis is unavailable (e.g.,
// unit tests, simulation mode, or degraded infrastructure) so taint enforcement
// never silently fails open.
var localStore sync.Map // map[string]TaintRecord

func redisKey(agentID string) string {
	return fmt.Sprintf("cicada:taint:%s", agentID)
}

// MarkTainted records that an agent session has ingested untrusted content.
func MarkTainted(ctx context.Context, agentID, source, reason string) {
	if agentID == "" || !isEnabled() {
		return
	}
	ttl := getTTL()
	now := time.Now().UTC()
	rec := TaintRecord{
		AgentID:   agentID,
		Source:    source,
		Reason:    reason,
		TaintedAt: now,
		ExpiresAt: now.Add(ttl),
	}

	localStore.Store(agentID, rec)

	if queue.Client != nil {
		if data, err := json.Marshal(rec); err == nil {
			_ = queue.Client.Set(ctx, redisKey(agentID), string(data), ttl).Err()
		}
	}
}

// ClearTaint removes taint state for an agent (called on explicit context flush
// or after an operator approves the tainted action via CIBA).
func ClearTaint(ctx context.Context, agentID string) {
	if agentID == "" {
		return
	}
	localStore.Delete(agentID)
	if queue.Client != nil {
		_ = queue.Client.Del(ctx, redisKey(agentID)).Err()
	}
}

// IsTainted checks whether the agent session is currently tainted.
// When Redis is connected, Redis is queried first so that a ClearTaint flush on
// another gateway node immediately invalidates any local cache entry on this node.
func IsTainted(ctx context.Context, agentID string) (TaintRecord, bool) {
	if agentID == "" || !isEnabled() {
		return TaintRecord{}, false
	}

	now := time.Now().UTC()

	if queue.Client != nil {
		data, err := queue.Client.Get(ctx, redisKey(agentID)).Result()
		if err == nil && data != "" {
			var rec TaintRecord
			if json.Unmarshal([]byte(data), &rec) == nil {
				if now.Before(rec.ExpiresAt) {
					localStore.Store(agentID, rec)
					return rec, true
				}
				_ = queue.Client.Del(ctx, redisKey(agentID)).Err()
				localStore.Delete(agentID)
				return TaintRecord{}, false
			}
		} else if errors.Is(err, redis.Nil) {
			// Taint was cleared or expired in Redis — evict any stale local copy.
			localStore.Delete(agentID)
			return TaintRecord{}, false
		}
		// On transient Redis error, fall through to localStore.
	}

	if v, ok := localStore.Load(agentID); ok {
		rec := v.(TaintRecord)
		if now.Before(rec.ExpiresAt) {
			return rec, true
		}
		localStore.Delete(agentID)
	}

	return TaintRecord{}, false
}

// IsUntrustedProvenance returns true if the provenance label indicates content
// originating outside the trusted system/operator control plane.
func IsUntrustedProvenance(provenance string) bool {
	switch strings.ToLower(strings.TrimSpace(provenance)) {
	case "retrieved", "untrusted", "external", "rag", "tool_result", "web", "webhook", "user_upload", "email", "scrape", "third_party":
		return true
	default:
		return false
	}
}

// IsTrustedProvenance returns true if the provenance label explicitly asserts
// a trusted internal or operator-verified source.
func IsTrustedProvenance(provenance string) bool {
	switch strings.ToLower(strings.TrimSpace(provenance)) {
	case "internal", "system", "trusted", "verified", "operator":
		return true
	default:
		return false
	}
}

// IsTrustedDomain returns true if targetURL points to a trusted internal network
// domain (*.internal, *.internal.*, *.local, *.corp, *.svc.cluster.local, localhost)
// or a domain explicitly listed in CICADA_TRUSTED_DOMAINS.
func IsTrustedDomain(targetURL string) bool {
	trimmed := strings.TrimSpace(targetURL)
	if trimmed == "" {
		return true
	}
	parsed, err := url.Parse(trimmed)
	if err != nil || parsed.Hostname() == "" {
		return false
	}
	host := strings.ToLower(parsed.Hostname())

	if host == "localhost" ||
		strings.HasSuffix(host, ".internal") ||
		strings.Contains(host, ".internal.") ||
		strings.HasSuffix(host, ".local") ||
		strings.HasSuffix(host, ".corp") ||
		strings.HasSuffix(host, ".lan") ||
		strings.HasSuffix(host, ".svc.cluster.local") {
		return true
	}

	if rawAllow := os.Getenv("CICADA_TRUSTED_DOMAINS"); rawAllow != "" {
		for _, entry := range strings.Split(rawAllow, ",") {
			d := strings.ToLower(strings.TrimSpace(entry))
			if d == "" {
				continue
			}
			if strings.HasPrefix(d, "*.") {
				suffix := d[1:] // ".example.com"
				if strings.HasSuffix(host, suffix) || host == d[2:] {
					return true
				}
			} else if host == d || strings.HasSuffix(host, "."+d) {
				return true
			}
		}
	}

	return false
}

// ShouldTaintOnRead determines whether a read-only GET request to targetURL with
// the given provenance header should mark the agent session as tainted.
//
// Rules:
//  1. Explicit untrusted provenance ("external", "rag", "web", etc.) -> ALWAYS taints.
//  2. Explicit trusted provenance ("internal", "system", "trusted") -> NEVER taints.
//  3. Trusted internal/operator-allowlisted domains (*.internal*, *.corp, *.local,
//     CICADA_TRUSTED_DOMAINS) -> do NOT taint on ordinary GET workflows.
//  4. External non-allowlisted domains -> taint on GET.
func ShouldTaintOnRead(targetURL, provenance string) bool {
	if IsUntrustedProvenance(provenance) {
		return true
	}
	if IsTrustedProvenance(provenance) {
		return false
	}
	if strings.TrimSpace(targetURL) == "" {
		return false
	}
	return !IsTrustedDomain(targetURL)
}

// CheckCapability evaluates whether an agent's outbound action is permitted
// under CaMeL capability restrictions.
//
// If the session is tainted (or the current request carries untrusted provenance)
// AND the request attempts state mutation (POST, PUT, PATCH, DELETE), it forces
// CIBA human approval regardless of how benign the payload looks semantically.
func CheckCapability(ctx context.Context, agentID, httpMethod, targetURL, provenance string) CapabilityResult {
	if !isEnabled() {
		return CapabilityResult{
			Tainted:   false,
			ForceCIBA: false,
			Reason:    "taint tracking disabled",
		}
	}

	method := strings.ToUpper(strings.TrimSpace(httpMethod))
	isMutating := method == "POST" || method == "PUT" || method == "PATCH" || method == "DELETE"

	// If the current request explicitly declares untrusted provenance, taint the session immediately.
	if IsUntrustedProvenance(provenance) {
		MarkTainted(ctx, agentID, "provenance:"+provenance,
			fmt.Sprintf("request carried untrusted provenance '%s' targeting %s", provenance, targetURL))
	}

	rec, tainted := IsTainted(ctx, agentID)
	if !tainted {
		return CapabilityResult{
			Tainted:   false,
			ForceCIBA: false,
			Reason:    "session untainted — full capability retained",
		}
	}

	if !isMutating {
		return CapabilityResult{
			Tainted:   true,
			ForceCIBA: false,
			Source:    rec.Source,
			Reason:    fmt.Sprintf("session tainted by %s, but %s is read-only", rec.Source, method),
		}
	}

	return CapabilityResult{
		Tainted:   true,
		ForceCIBA: true,
		Source:    rec.Source,
		Reason: fmt.Sprintf(
			"CAMEL TAINT ESCALATION: session previously ingested untrusted content [%s: %s] — "+
				"state-mutating %s to %s requires mandatory human approval",
			rec.Source, rec.Reason, method, targetURL,
		),
	}
}

func isEnabled() bool {
	if v := os.Getenv("CICADA_TAINT_ENABLED"); v != "" {
		return strings.ToLower(v) != "false" && v != "0"
	}
	return true
}

func getTTL() time.Duration {
	if v := os.Getenv("CICADA_TAINT_TTL_MINUTES"); v != "" {
		if mins, err := strconv.Atoi(v); err == nil && mins > 0 {
			return time.Duration(mins) * time.Minute
		}
	}
	return DefaultTTL
}
