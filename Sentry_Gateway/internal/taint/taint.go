// © 2026 Affinity Ops Ltd. All rights reserved.
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
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/asai/cicada/sentry/internal/queue"
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
func IsTainted(ctx context.Context, agentID string) (TaintRecord, bool) {
	if agentID == "" || !isEnabled() {
		return TaintRecord{}, false
	}

	if v, ok := localStore.Load(agentID); ok {
		rec := v.(TaintRecord)
		if time.Now().UTC().Before(rec.ExpiresAt) {
			return rec, true
		}
		localStore.Delete(agentID)
	}

	if queue.Client != nil {
		data, err := queue.Client.Get(ctx, redisKey(agentID)).Result()
		if err == nil && data != "" {
			var rec TaintRecord
			if json.Unmarshal([]byte(data), &rec) == nil {
				localStore.Store(agentID, rec)
				return rec, true
			}
		}
	}

	return TaintRecord{}, false
}

// IsUntrustedProvenance returns true if the provenance label indicates content
// originating outside the trusted system/operator control plane.
func IsUntrustedProvenance(provenance string) bool {
	switch strings.ToLower(strings.TrimSpace(provenance)) {
	case "retrieved", "untrusted", "external", "rag", "tool_result", "web", "webhook":
		return true
	default:
		return false
	}
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
