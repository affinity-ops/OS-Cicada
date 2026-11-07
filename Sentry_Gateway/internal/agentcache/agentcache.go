// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package agentcache provides a Redis-backed read-through cache for agent
// metadata and FGA policies. It replaces the 6–8 synchronous PostgreSQL
// queries that the proxy hot path previously executed per request with a
// single Redis HGETALL (sub-millisecond).
//
// Cache key layout:
//
//	cicada:agent:{agent_id}  — hash with all agent metadata fields
//	cicada:fga:{agent_id}    — string containing JSON-serialised FGA policies
//	cicada:skills:{agent_id} — string containing JSON-serialised skill contracts
//
// Cache behaviour:
//   - TTL: 60 seconds (configurable via AGENT_CACHE_TTL_SECONDS)
//   - Read-through: cache miss → single batched SQL → populate Redis → return
//   - Fail-open: if Redis is unavailable, callers fall back to direct SQL
//   - Invalidation: call Invalidate(agentID) after any agent mutation
//
// This package was introduced to resolve the PostgreSQL connection pool
// exhaustion documented in Security Audit Iteration 21 (k6 load test baseline).
package agentcache

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/rand/v2"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/asai/cicada/sentry/internal/queue"
	"github.com/asai/cicada/sentry/internal/store"
	"github.com/redis/go-redis/v9"
	"golang.org/x/sync/singleflight"
)

// ── Performance Counters (lock-free, atomic) ────────────────────────────────
// These counters track real cache hit/miss ratios and request latency for
// operational observability. They are exposed via the /metrics API endpoint.
var (
	agentCacheHits   atomic.Int64
	agentCacheMisses atomic.Int64
	fgaCacheHits     atomic.Int64
	fgaCacheMisses   atomic.Int64
	totalRequests    atomic.Int64
	totalLatencyNs   atomic.Int64 // cumulative nanoseconds for p-approx
	latencyMax       atomic.Int64 // max latency in nanoseconds
	latencySamples   atomic.Int64
)

// agentFlight coalesces concurrent cache-miss DB queries for the same agent.
// Under 200 VUs with a cold cache (post-FLUSHALL), the first request queries
// Postgres; all others wait for the result. This prevents thundering herd
// on the PostgreSQL connection pool.
var agentFlight singleflight.Group
var fgaFlight singleflight.Group
var skillsFlight singleflight.Group
var toolsFlight singleflight.Group

// CacheStats holds a point-in-time snapshot of cache performance counters.
type CacheStats struct {
	AgentHits      int64   `json:"agent_cache_hits"`
	AgentMisses    int64   `json:"agent_cache_misses"`
	AgentHitRate   float64 `json:"agent_hit_rate_pct"`
	FGAHits        int64   `json:"fga_cache_hits"`
	FGAMisses      int64   `json:"fga_cache_misses"`
	FGAHitRate     float64 `json:"fga_hit_rate_pct"`
	TotalRequests  int64   `json:"total_requests"`
	AvgLatencyMs   float64 `json:"avg_latency_ms"`
	MaxLatencyMs   float64 `json:"max_latency_ms"`
}

// Stats returns a point-in-time snapshot of cache performance.
func Stats() CacheStats {
	ah := agentCacheHits.Load()
	am := agentCacheMisses.Load()
	fh := fgaCacheHits.Load()
	fm := fgaCacheMisses.Load()

	agentTotal := ah + am
	fgaTotal := fh + fm

	var agentRate, fgaRate float64
	if agentTotal > 0 {
		agentRate = float64(ah) / float64(agentTotal) * 100
	}
	if fgaTotal > 0 {
		fgaRate = float64(fh) / float64(fgaTotal) * 100
	}

	samples := latencySamples.Load()
	var avgMs float64
	if samples > 0 {
		avgMs = float64(totalLatencyNs.Load()) / float64(samples) / 1e6
	}

	return CacheStats{
		AgentHits:     ah,
		AgentMisses:   am,
		AgentHitRate:  agentRate,
		FGAHits:       fh,
		FGAMisses:     fm,
		FGAHitRate:    fgaRate,
		TotalRequests: totalRequests.Load(),
		AvgLatencyMs:  avgMs,
		MaxLatencyMs:  float64(latencyMax.Load()) / 1e6,
	}
}

// recordLatency updates the cumulative latency counters.
func recordLatency(d time.Duration) {
	ns := d.Nanoseconds()
	totalLatencyNs.Add(ns)
	latencySamples.Add(1)
	// Atomic max update (CAS loop)
	for {
		cur := latencyMax.Load()
		if ns <= cur || latencyMax.CompareAndSwap(cur, ns) {
			break
		}
	}
}

// DefaultTTL is the cache entry lifetime. 60 seconds balances freshness
// (operator changes take at most 60s to propagate) against query reduction
// (each agent is queried from PostgreSQL at most once per minute, not once
// per request).
const DefaultTTL = 60 * time.Second

// AgentInfo holds all agent metadata fields that the proxy hot path needs.
// A single GetAgent call replaces the 6+ separate DB queries that previously
// ran on every proxied request. Fields added in Iteration 27 (AgentType,
// TenantID, Role) eliminate the standalone semantic intent DB query (L2099)
// that was the primary p95 latency bottleneck.
type AgentInfo struct {
	ApprovalStatus       string  `json:"approval_status"`
	HITLEnabled          bool    `json:"hitl_enabled"`
	HITLWebhookURL       string  `json:"hitl_webhook_url"`
	ObserveOnlyMode      bool    `json:"observe_only_mode"`
	SwarmConfidenceScore float64 `json:"swarm_confidence_score"`
	Description          string  `json:"description"`
	Name                 string  `json:"name"`
	AgentType            string  `json:"agent_type"`
	TenantID             string  `json:"tenant_id"`
	Role                 string  `json:"role"`
	DestructiveCapability bool   `json:"destructive_capability"`
	GhostModeAllowed     bool    `json:"ghost_mode_allowed"`
}

// SkillContract represents a per-tool capability contract declared in cicada.yaml.
// Each contract defines structural payload constraints, upstream delegation
// permissions, and per-skill criticality classification for Layer 1d enforcement.
type SkillContract struct {
	SkillName        string   `json:"skill_name"`
	InputSchema      string   `json:"input_schema"`       // JSON Schema as string (pre-compiled at validation time)
	AllowedUpstreams []string `json:"allowed_upstreams"`   // Agent IDs allowed to invoke this skill
	CriticalityLevel string   `json:"criticality_level"`   // "low", "medium", "high"
}

// FGAPolicy is a cached resource policy entry.
type FGAPolicy struct {
	ResourcePattern string   `json:"resource_pattern"`
	AllowedMethods  []string `json:"allowed_methods"`
	Active          bool     `json:"active"`
}

// ToolManifestEntry represents a registered tool from the agent_tools table,
// providing server-side tool scope and Forward-Saga prerequisite bindings.
type ToolManifestEntry struct {
	ToolID               string `json:"tool_id"`
	ToolName             string `json:"tool_name"`
	ToolScope            string `json:"tool_scope"`
	RequiresPreviousTool string `json:"requires_previous_tool"`
}

// cacheKeyAgent returns the Redis key for an agent's metadata hash.
func cacheKeyAgent(agentID string) string {
	return fmt.Sprintf("cicada:agent:%s", agentID)
}

// cacheKeyFGA returns the Redis key for an agent's FGA policy cache.
func cacheKeyFGA(agentID string) string {
	return fmt.Sprintf("cicada:fga:%s", agentID)
}

// cacheKeySkills returns the Redis key for an agent's skill contracts cache.
func cacheKeySkills(agentID string) string {
	return fmt.Sprintf("cicada:skills:%s", agentID)
}

// cacheKeyTools returns the Redis key for an agent's tool manifest cache.
func cacheKeyTools(agentID string) string {
	return fmt.Sprintf("cicada:tools:%s", agentID)
}

// ttl returns the configured base cache TTL (without jitter).
func ttl() time.Duration {
	if v := os.Getenv("AGENT_CACHE_TTL_SECONDS"); v != "" {
		if secs, err := strconv.Atoi(v); err == nil && secs > 0 {
			return time.Duration(secs) * time.Second
		}
	}
	return DefaultTTL
}

// jitteredTTL returns the base TTL plus a random offset in [-15s, +15s].
// This prevents synchronous cache expiration under high-VU load:
// without jitter, all entries for the same agent expire at exactly 60s,
// causing a brief stampede even with singleflight (the single coalesced
// DB query under 200-VU contention takes longer). Jitter distributes
// refreshes stochastically across a 45–75 second window.
func jitteredTTL() time.Duration {
	base := ttl()
	// rand.IntN is concurrency-safe in Go 1.22+ (math/rand/v2)
	jitter := time.Duration(rand.IntN(31)-15) * time.Second // [-15s, +15s]
	result := base + jitter
	if result < 10*time.Second {
		result = 10 * time.Second // floor: never expire faster than 10s
	}
	return result
}

// GetAgent retrieves agent metadata from Redis. On cache miss, it queries
// PostgreSQL, populates the cache, and returns the result.
//
// Returns an error only if both Redis and PostgreSQL fail. Callers should
// treat errors as "unknown agent" and apply fail-closed logic.
func GetAgent(ctx context.Context, agentID string) (AgentInfo, error) {
	var info AgentInfo
	start := time.Now()
	totalRequests.Add(1)

	// ── Try Redis first ──────────────────────────────────────────────────
	if queue.Client != nil {
		key := cacheKeyAgent(agentID)
		data, err := queue.Client.HGetAll(ctx, key).Result()
		if err == nil && len(data) > 0 {
			// Cache hit — unmarshal from hash fields
			agentCacheHits.Add(1)
			info.ApprovalStatus = data["approval_status"]
			info.HITLEnabled = data["hitl_enabled"] == "true"
			info.HITLWebhookURL = data["hitl_webhook_url"]
			info.ObserveOnlyMode = data["observe_only_mode"] == "true"
			info.Description = data["description"]
			info.Name = data["name"]
			info.AgentType = data["agent_type"]
			info.TenantID = data["tenant_id"]
			info.Role = data["role"]
			info.DestructiveCapability = data["destructive_capability"] == "true"
			info.GhostModeAllowed = data["ghost_mode_allowed"] == "true"
			if v, err := strconv.ParseFloat(data["swarm_confidence_score"], 64); err == nil {
				info.SwarmConfidenceScore = v
			} else {
				info.SwarmConfidenceScore = -1.0
			}
			recordLatency(time.Since(start))
			return info, nil
		}
	}

	// ── Cache miss: use singleflight to coalesce concurrent DB queries ──
	// Under 200 VUs with a cold cache (post-FLUSHALL), the first request
	// queries Postgres; all concurrent requests for the same agentID wait
	// for that single query to complete and share the result. This prevents
	// thundering herd on the PostgreSQL connection pool.
	agentCacheMisses.Add(1)
	v, err, _ := agentFlight.Do(agentID, func() (interface{}, error) {
		return fetchAgentFromPostgres(ctx, agentID)
	})
	if err != nil {
		return AgentInfo{}, err
	}

	// Explicit value copy — AgentInfo contains only primitives (strings,
	// bools, float64), so this is a safe deep copy. Multiple goroutines
	// reading the singleflight result cannot mutate each other's data.
	info = v.(AgentInfo)

	recordLatency(time.Since(start))
	return info, nil
}

// fetchAgentFromPostgres executes the single batched SQL query that loads
// all agent metadata fields. Called by GetAgent on cache miss (via singleflight).
// The result is asynchronously populated into the Redis cache.
func fetchAgentFromPostgres(ctx context.Context, agentID string) (AgentInfo, error) {
	var info AgentInfo
	if store.DB == nil {
		return info, fmt.Errorf("both Redis and PostgreSQL unavailable")
	}

	err := store.DB.QueryRow(ctx, `
		SELECT
			COALESCE(a.approval_status, 'pending_review'),
			COALESCE(a.hitl_enabled, false),
			COALESCE(a.hitl_webhook_url, ''),
			COALESCE(arp.observe_only_mode, false),
			COALESCE(a.swarm_confidence_score, -1.0),
			COALESCE(a.description, a.name, ''),
			COALESCE(a.name, ''),
			COALESCE(a.agent_type, ''),
			COALESCE(a.tenant_id::text, ''),
			COALESCE(a.role, ''),
			COALESCE(a.destructive_capability, false),
			COALESCE(a.ghost_mode_allowed, false)
		FROM agents a
		LEFT JOIN agent_resource_policies arp ON arp.agent_id = a.id AND arp.active = true
		WHERE a.id = $1
		LIMIT 1
	`, agentID).Scan(
		&info.ApprovalStatus,
		&info.HITLEnabled,
		&info.HITLWebhookURL,
		&info.ObserveOnlyMode,
		&info.SwarmConfidenceScore,
		&info.Description,
		&info.Name,
		&info.AgentType,
		&info.TenantID,
		&info.Role,
		&info.DestructiveCapability,
		&info.GhostModeAllowed,
	)
	if err != nil {
		return info, fmt.Errorf("agent query failed: %w", err)
	}

	// Asynchronously populate Redis cache — caller does not wait.
	// Uses context.Background() so the cache write survives request cancellation.
	if queue.Client != nil {
		go populateAgentCache(agentID, info)
	}

	return info, nil
}

// populateAgentCache writes agent metadata into a Redis hash with TTL.
// Called asynchronously after a cache miss — the caller does not wait.
func populateAgentCache(agentID string, info AgentInfo) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	key := cacheKeyAgent(agentID)
	fields := map[string]interface{}{
		"approval_status":        info.ApprovalStatus,
		"hitl_enabled":           strconv.FormatBool(info.HITLEnabled),
		"hitl_webhook_url":       info.HITLWebhookURL,
		"observe_only_mode":      strconv.FormatBool(info.ObserveOnlyMode),
		"swarm_confidence_score": strconv.FormatFloat(info.SwarmConfidenceScore, 'f', 6, 64),
		"description":            info.Description,
		"name":                   info.Name,
		"agent_type":             info.AgentType,
		"tenant_id":              info.TenantID,
		"role":                   info.Role,
		"destructive_capability": strconv.FormatBool(info.DestructiveCapability),
		"ghost_mode_allowed":     strconv.FormatBool(info.GhostModeAllowed),
	}

	if err := queue.Client.HSet(ctx, key, fields).Err(); err != nil {
		log.Printf("[AGENTCACHE] Failed to populate cache for agent %s: %v", agentID, err)
		return
	}
	queue.Client.Expire(ctx, key, jitteredTTL())
}

// GetFGAPolicies retrieves FGA policies from Redis. On cache miss, it queries
// PostgreSQL, populates the cache, and returns the result.
//
// IMPORTANT: Empty policy sets ARE cached (as "[]") to prevent the negative
// cache miss loop — agents without FGA policies would otherwise query Postgres
// on every single request, producing 48,000+ misses under load.
func GetFGAPolicies(ctx context.Context, agentID string) ([]FGAPolicy, error) {
	// ── Try Redis first ──────────────────────────────────────────────────
	if queue.Client != nil {
		key := cacheKeyFGA(agentID)
		data, err := queue.Client.Get(ctx, key).Result()
		if err == nil && data != "" {
			var policies []FGAPolicy
			if err := json.Unmarshal([]byte(data), &policies); err == nil {
				fgaCacheHits.Add(1)
				return policies, nil
			}
		} else if err != nil && err != redis.Nil {
			log.Printf("[AGENTCACHE] Redis FGA read error for agent %s: %v", agentID, err)
		}
	}

	// ── Cache miss: use singleflight to coalesce concurrent queries ─────
	fgaCacheMisses.Add(1)
	v, err, _ := fgaFlight.Do(agentID, func() (interface{}, error) {
		return fetchFGAFromPostgres(ctx, agentID)
	})
	if err != nil {
		return nil, err
	}

	// Safe type assertion — returns a copy of the slice header
	return v.([]FGAPolicy), nil
}

// fetchFGAFromPostgres loads FGA policies from PostgreSQL and caches the result
// (including empty policy sets). Called via singleflight on cache miss.
func fetchFGAFromPostgres(ctx context.Context, agentID string) ([]FGAPolicy, error) {
	if store.DB == nil {
		return nil, fmt.Errorf("both Redis and PostgreSQL unavailable")
	}

	rows, err := store.DB.Query(ctx,
		`SELECT resource_pattern, allowed_methods, active
		   FROM agent_resource_policies
		  WHERE agent_id = $1`,
		agentID,
	)
	if err != nil {
		return nil, fmt.Errorf("FGA query failed: %w", err)
	}
	defer rows.Close()

	var policies []FGAPolicy
	for rows.Next() {
		var p FGAPolicy
		var methodsJSON []byte
		if err := rows.Scan(&p.ResourcePattern, &methodsJSON, &p.Active); err != nil {
			return nil, fmt.Errorf("FGA row scan failed: %w", err)
		}
		p.AllowedMethods = parseJSONStringArray(string(methodsJSON))
		policies = append(policies, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// ── Populate Redis cache — INCLUDING empty results ──────────────────
	// Caching the empty array "[]" is critical: without it, agents that
	// have no FGA policies generate a Postgres query on every request
	// (the negative cache miss loop that produced 48,928 misses).
	if queue.Client != nil {
		if policies == nil {
			policies = []FGAPolicy{} // ensure JSON marshal produces "[]"
		}
		go populateFGACache(agentID, policies)
	}

	return policies, nil
}

// populateFGACache writes FGA policies into Redis as a JSON string with TTL.
func populateFGACache(agentID string, policies []FGAPolicy) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	data, err := json.Marshal(policies)
	if err != nil {
		log.Printf("[AGENTCACHE] Failed to marshal FGA policies for agent %s: %v", agentID, err)
		return
	}

	key := cacheKeyFGA(agentID)
	if err := queue.Client.Set(ctx, key, string(data), jitteredTTL()).Err(); err != nil {
		log.Printf("[AGENTCACHE] Failed to populate FGA cache for agent %s: %v", agentID, err)
	}
}

// Invalidate removes both agent metadata and FGA policy caches for an agent.
// Call this after any mutation to the agent's record (certification, policy
// change, suspension, etc.). The next GetAgent/GetFGAPolicies call will
// trigger a fresh read-through from PostgreSQL.
func Invalidate(ctx context.Context, agentID string) {
	if queue.Client == nil {
		return
	}
	queue.Client.Del(ctx, cacheKeyAgent(agentID), cacheKeyFGA(agentID), cacheKeySkills(agentID), cacheKeyTools(agentID))
	log.Printf("[AGENTCACHE] Cache invalidated for agent %s", agentID)
}

// ── Skills Cache ────────────────────────────────────────────────────────────
// GetSkills retrieves per-tool skill contracts from Redis. On cache miss, it
// queries the agent_skills table in PostgreSQL and populates the cache.
// Returns a map keyed by skill_name for O(1) lookups in Layer 1d.
//
// Like FGA, empty skill sets ARE cached (as "{}") to prevent negative cache
// miss loops for agents that have no skill contracts declared.
func GetSkills(ctx context.Context, agentID string) (map[string]SkillContract, error) {
	// ── Try Redis first ──────────────────────────────────────────────────
	if queue.Client != nil {
		key := cacheKeySkills(agentID)
		data, err := queue.Client.Get(ctx, key).Result()
		if err == nil && data != "" {
			var skills map[string]SkillContract
			if err := json.Unmarshal([]byte(data), &skills); err == nil {
				return skills, nil
			}
		}
	}

	// ── Cache miss: singleflight ─────────────────────────────────────────
	v, err, _ := skillsFlight.Do(agentID, func() (interface{}, error) {
		return fetchSkillsFromPostgres(ctx, agentID)
	})
	if err != nil {
		return nil, err
	}

	return v.(map[string]SkillContract), nil
}

// fetchSkillsFromPostgres loads skill contracts from the agent_skills table
// and caches the result (including empty maps). Called via singleflight.
func fetchSkillsFromPostgres(ctx context.Context, agentID string) (map[string]SkillContract, error) {
	if store.DB == nil {
		return nil, fmt.Errorf("both Redis and PostgreSQL unavailable")
	}

	rows, err := store.DB.Query(ctx,
		`SELECT skill_name, COALESCE(input_schema::text, '{}'),
		        COALESCE(allowed_upstreams::text, '[]'), criticality_level
		   FROM agent_skills
		  WHERE agent_id = $1`,
		agentID,
	)
	if err != nil {
		return nil, fmt.Errorf("skills query failed: %w", err)
	}
	defer rows.Close()

	skills := make(map[string]SkillContract)
	for rows.Next() {
		var sc SkillContract
		var upstreamsJSON string
		if err := rows.Scan(&sc.SkillName, &sc.InputSchema, &upstreamsJSON, &sc.CriticalityLevel); err != nil {
			return nil, fmt.Errorf("skills row scan failed: %w", err)
		}
		sc.AllowedUpstreams = parseJSONStringArray(upstreamsJSON)
		skills[sc.SkillName] = sc
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Populate Redis cache — including empty results to prevent negative miss loop
	if queue.Client != nil {
		go populateSkillsCache(agentID, skills)
	}

	return skills, nil
}

// populateSkillsCache writes skill contracts into Redis as a JSON string with TTL.
func populateSkillsCache(agentID string, skills map[string]SkillContract) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	data, err := json.Marshal(skills)
	if err != nil {
		log.Printf("[AGENTCACHE] Failed to marshal skills for agent %s: %v", agentID, err)
		return
	}

	key := cacheKeySkills(agentID)
	if err := queue.Client.Set(ctx, key, string(data), jitteredTTL()).Err(); err != nil {
		log.Printf("[AGENTCACHE] Failed to populate skills cache for agent %s: %v", agentID, err)
	}
}

// ── Tools Manifest Cache (Server-Side Prerequisite & Atomic Scope Resolver) ──

var memTools sync.Map // map[string][]ToolManifestEntry

// SetTools seeds an in-memory tool manifest for an agent (used in standalone
// mode and handler-level integration tests when Redis/PostgreSQL are absent).
func SetTools(agentID string, tools []ToolManifestEntry) {
	cp := make([]ToolManifestEntry, len(tools))
	copy(cp, tools)
	memTools.Store(agentID, cp)
}

// ClearTools removes an in-memory tool manifest entry for an agent.
func ClearTools(agentID string) {
	memTools.Delete(agentID)
}

// GetTools retrieves the agent's active registered tools from in-memory override
// or Redis, falling back to PostgreSQL (agent_tools table) via singleflight on cache miss.
func GetTools(ctx context.Context, agentID string) ([]ToolManifestEntry, error) {
	if v, ok := memTools.Load(agentID); ok {
		return v.([]ToolManifestEntry), nil
	}

	if queue.Client != nil {
		key := cacheKeyTools(agentID)
		data, err := queue.Client.Get(ctx, key).Result()
		if err == nil && data != "" {
			var tools []ToolManifestEntry
			if err := json.Unmarshal([]byte(data), &tools); err == nil {
				return tools, nil
			}
		}
	}

	v, err, _ := toolsFlight.Do(agentID, func() (interface{}, error) {
		return fetchToolsFromPostgres(ctx, agentID)
	})
	if err != nil {
		return nil, err
	}

	return v.([]ToolManifestEntry), nil
}

func fetchToolsFromPostgres(ctx context.Context, agentID string) ([]ToolManifestEntry, error) {
	if store.DB == nil {
		return nil, fmt.Errorf("both Redis and PostgreSQL unavailable")
	}

	rows, err := store.DB.Query(ctx,
		`SELECT tool_id, COALESCE(tool_name, ''), COALESCE(tool_scope, ''), COALESCE(requires_previous_tool, '')
		   FROM agent_tools
		  WHERE agent_id = $1 AND is_active = true`,
		agentID,
	)
	if err != nil {
		return nil, fmt.Errorf("tools query failed: %w", err)
	}
	defer rows.Close()

	var tools []ToolManifestEntry
	for rows.Next() {
		var t ToolManifestEntry
		if err := rows.Scan(&t.ToolID, &t.ToolName, &t.ToolScope, &t.RequiresPreviousTool); err != nil {
			return nil, fmt.Errorf("tools row scan failed: %w", err)
		}
		tools = append(tools, t)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	if queue.Client != nil {
		if tools == nil {
			tools = []ToolManifestEntry{}
		}
		go populateToolsCache(agentID, tools)
	}

	return tools, nil
}

func populateToolsCache(agentID string, tools []ToolManifestEntry) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	data, err := json.Marshal(tools)
	if err != nil {
		log.Printf("[AGENTCACHE] Failed to marshal tools for agent %s: %v", agentID, err)
		return
	}

	key := cacheKeyTools(agentID)
	if err := queue.Client.Set(ctx, key, string(data), jitteredTTL()).Err(); err != nil {
		log.Printf("[AGENTCACHE] Failed to populate tools cache for agent %s: %v", agentID, err)
	}
}

// ResolveToolForRequest derives the authoritative tool identity, prerequisite
// map, and atomic tool scope map from the server-side tool manifest rather
// than trusting client-controlled headers alone.
//
// Security properties:
//  1. Query parameters (?foo=bar) and fragments (#baz) are stripped before URL
//     matching so an agent cannot stuff a harmless tool keyword into a query string.
//  2. Only canonical URL path segments are matched against tool IDs (never prose
//     descriptions), and method-compatible tools with prerequisites take precedence.
//  3. If the agent has a non-empty manifest and either claims an unknown tool ID
//     or calls a URL that matches no declared tool, resolvedToolID is returned as ""
//      alongside the non-empty maps so pipeline.Evaluate denies the request fail-closed.
func ResolveToolForRequest(tools []ToolManifestEntry, clientToolID, targetURL, httpMethod string) (string, map[string]string, map[string]string) {
	if len(tools) == 0 {
		return strings.TrimSpace(clientToolID), nil, nil
	}

	prereqMap := make(map[string]string, len(tools))
	scopeMap := make(map[string]string, len(tools))
	for _, t := range tools {
		prereqMap[t.ToolID] = t.RequiresPreviousTool
		scopeMap[t.ToolID] = t.ToolScope
	}

	pathSegs := extractCanonicalPathSegments(targetURL)
	methodUpper := strings.ToUpper(strings.TrimSpace(httpMethod))

	bestCompatibleID := ""
	bestCompatibleScore := 0
	bestCompatibleHasPrereq := false

	bestAnyID := ""
	bestAnyScore := 0

	for _, t := range tools {
		score := scoreToolAgainstPathSegments(t.ToolID, pathSegs)
		if score <= 0 {
			continue
		}
		if score > bestAnyScore {
			bestAnyScore = score
			bestAnyID = t.ToolID
		}
		if isScopeCompatibleWithMethod(t.ToolScope, methodUpper) {
			hasPrereq := t.RequiresPreviousTool != ""
			if score > bestCompatibleScore || (score == bestCompatibleScore && hasPrereq && !bestCompatibleHasPrereq) {
				bestCompatibleScore = score
				bestCompatibleID = t.ToolID
				bestCompatibleHasPrereq = hasPrereq
			}
		}
	}

	trimmedClient := strings.TrimSpace(clientToolID)
	if trimmedClient != "" {
		// Reject unknown client tool IDs immediately (fail-closed in pipeline).
		if _, exists := prereqMap[trimmedClient]; !exists {
			return "", prereqMap, scopeMap
		}
		// Prevent header spoofing: if the client header claims a tool whose scope is
		// incompatible with the HTTP method, or if a method-compatible tool with a
		// prerequisite matches the URL at least as well as the client header, enforce
		// the server-inferred method-compatible tool.
		if bestCompatibleID != "" && bestCompatibleID != trimmedClient {
			clientCompatible := isScopeCompatibleWithMethod(scopeMap[trimmedClient], methodUpper)
			clientScore := scoreToolAgainstPathSegments(trimmedClient, pathSegs)
			if !clientCompatible || (bestCompatibleHasPrereq && clientScore <= bestCompatibleScore) {
				return bestCompatibleID, prereqMap, scopeMap
			}
		}
		return trimmedClient, prereqMap, scopeMap
	}

	if bestCompatibleID != "" {
		return bestCompatibleID, prereqMap, scopeMap
	}
	if bestAnyID != "" {
		return bestAnyID, prereqMap, scopeMap
	}

	// Only bind automatically to a single tool when no URL is present (e.g. internal call).
	if len(tools) == 1 && strings.TrimSpace(targetURL) == "" {
		return tools[0].ToolID, prereqMap, scopeMap
	}

	// No tool resolved from manifest -> pipeline.Evaluate will deny fail-closed.
	return "", prereqMap, scopeMap
}

func extractCanonicalPathSegments(rawURL string) map[string]bool {
	segs := make(map[string]bool)
	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		return segs
	}
	parsed, err := url.Parse(trimmed)
	pathPart := trimmed
	if err == nil && parsed.Path != "" {
		pathPart = parsed.Path
	} else if idx := strings.IndexAny(pathPart, "?#"); idx >= 0 {
		pathPart = pathPart[:idx]
	}

	tokens := strings.FieldsFunc(strings.ToLower(pathPart), func(r rune) bool {
		return r == '/' || r == '_' || r == '-' || r == '.' || r == ':'
	})
	for _, tok := range tokens {
		if len(tok) < 3 || tok == "api" || tok == "rest" {
			continue
		}
		segs[tok] = true
		if strings.HasSuffix(tok, "s") && len(tok) > 3 {
			segs[strings.TrimSuffix(tok, "s")] = true
		} else {
			segs[tok+"s"] = true
		}
	}
	return segs
}

func scoreToolAgainstPathSegments(toolID string, pathSegs map[string]bool) int {
	if len(pathSegs) == 0 {
		return 0
	}
	// If toolID has a namespace prefix (e.g. "storage:delete_volume"), focus on
	// the action/resource tokens so generic namespace prefixes cannot be abused.
	targetPart := strings.ToLower(toolID)
	if idx := strings.IndexByte(targetPart, ':'); idx >= 0 && idx+1 < len(targetPart) {
		targetPart = targetPart[idx+1:]
	}
	tokens := strings.FieldsFunc(targetPart, func(r rune) bool {
		return r == '_' || r == '-' || r == '/' || r == ':'
	})
	score := 0
	for _, tok := range tokens {
		if len(tok) < 3 {
			continue
		}
		// Skip generic verb prefixes so matching anchors on resource nouns or specific actions
		if tok == "get" || tok == "create" || tok == "update" || tok == "delete" || tok == "read" || tok == "write" || tok == "list" {
			continue
		}
		if pathSegs[tok] {
			score += 2
		}
	}
	return score
}

func isScopeCompatibleWithMethod(scope, methodUpper string) bool {
	switch strings.ToLower(strings.TrimSpace(scope)) {
	case "", "unrestricted":
		return true
	case "read":
		return methodUpper == "GET" || methodUpper == "HEAD" || methodUpper == "OPTIONS"
	case "write":
		return methodUpper == "POST" || methodUpper == "PUT" || methodUpper == "PATCH"
	case "delete":
		return methodUpper == "DELETE"
	case "transact":
		return methodUpper == "POST"
	default:
		return true
	}
}

// parseJSONStringArray lightly parses a JSON string array without importing
// encoding/json to keep the hot-path allocation-free for the common case.
// Duplicated from fga.go to avoid a circular import.
func parseJSONStringArray(raw string) []string {
	raw = trimBrackets(raw)
	if raw == "" {
		return nil
	}
	parts := splitComma(raw)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = trimQuotes(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func trimBrackets(s string) string {
	if len(s) >= 2 && s[0] == '[' && s[len(s)-1] == ']' {
		return s[1 : len(s)-1]
	}
	return s
}

func trimQuotes(s string) string {
	s = trimSpace(s)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

func trimSpace(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}

func splitComma(s string) []string {
	var result []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			result = append(result, s[start:i])
			start = i + 1
		}
	}
	result = append(result, s[start:])
	return result
}
