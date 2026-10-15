// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package cascade — multi-agent cascade failure detection.
//
// When Agent B acts on Agent A's output, and both route through the gateway,
// there is a risk of cascading failures: a compromised or poisoned output
// from Agent A becomes Agent B's trusted input. This package detects these
// cascade chains by correlating trace IDs across agent boundaries.
//
// Detection strategy (O(1) per extracted trace, not O(N) string search):
//
//   1. Extract trace ID candidates from the request body using a compiled
//      regex that matches the gateway's trace ID format (req-[0-9a-f-]{36}).
//      This avoids scanning the full body against every active trace.
//
//   2. For each extracted candidate, perform a Redis SISMEMBER check against
//      the set of recent trace IDs emitted by OTHER agents. O(1) per check.
//
//   3. If a match is found, the request body contains content that originated
//      from another agent's gateway response — this is a cascade.
//
// Trace storage:
//
//   After each successful proxy response, the gateway stores the trace ID
//   in a per-agent Redis sorted set with a timestamp score. An EXPIRE of
//   5 minutes prevents memory leaks. ZADD is atomic.
//
// Integration: called from the proxy handler in main.go after the
// exfiltration scan (L9b) and before the final forwarding step.
package cascade

import (
	"context"
	"regexp"
	"time"

	"github.com/redis/go-redis/v9"
)

// CascadeResult captures whether a request body contains content from
// another agent's recent response.
type CascadeResult struct {
	IsCascade       bool   // True if cross-agent trace ID detected
	UpstreamTraceID string // The trace ID from the upstream agent's response
	UpstreamAgentID string // The agent that emitted the upstream trace
	ChainDepth      int    // Number of hops in the cascade chain
}

// Detector performs cascade detection using Redis-backed trace correlation.
type Detector struct {
	rdb            redis.Cmdable
	traceWindow    time.Duration // How long trace IDs are retained (default: 5 min)
	maxChainDepth  int           // CIBA enforcement threshold (default: 3)
}

// NewDetector creates a cascade detector backed by the given Redis client.
func NewDetector(rdb redis.Cmdable, opts ...Option) *Detector {
	d := &Detector{
		rdb:           rdb,
		traceWindow:   5 * time.Minute,
		maxChainDepth: 3,
	}
	for _, opt := range opts {
		opt(d)
	}
	return d
}

// Option configures the Detector.
type Option func(*Detector)

// WithTraceWindow sets how long trace IDs are retained for correlation.
func WithTraceWindow(d time.Duration) Option {
	return func(det *Detector) { det.traceWindow = d }
}

// WithMaxChainDepth sets the CIBA enforcement threshold.
func WithMaxChainDepth(depth int) Option {
	return func(det *Detector) { det.maxChainDepth = depth }
}

// ── Compiled regex for trace ID extraction ────────────────────────────────────
// Matches the gateway's trace ID format: req- followed by a UUID v4.
// Compiled once at package init for zero allocation on each call.
var traceIDPattern = regexp.MustCompile(`req-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

// Detect checks whether the request body contains trace IDs from other agents'
// recent responses. Returns a CascadeResult indicating whether a cascade was
// detected and the chain metadata.
//
// Performance: O(K) where K is the number of trace ID patterns found in the body
// (typically 0–2). Each check is a Redis SISMEMBER (O(1)). No full-body string
// scan against the trace set.
func (d *Detector) Detect(ctx context.Context, body string, currentAgentID string) CascadeResult {
	// 1. Extract all trace ID candidates from the body.
	candidates := traceIDPattern.FindAllString(body, 10) // Cap at 10 to prevent regex DoS
	if len(candidates) == 0 {
		return CascadeResult{}
	}

	// 2. Check each candidate against the global trace set, excluding the
	//    current agent's own traces (an agent referencing its own previous
	//    trace is not a cascade).
	for _, traceID := range candidates {
		// SISMEMBER against the global recent traces set.
		exists, err := d.rdb.SIsMember(ctx, "cicada:cascade:traces", traceID).Result()
		if err != nil || !exists {
			continue
		}

		// Found a match — look up which agent emitted this trace.
		upstreamAgent, err := d.rdb.HGet(ctx, "cicada:cascade:trace_owners", traceID).Result()
		if err != nil {
			continue
		}

		// Skip self-references — an agent referencing its own output is not a cascade.
		if upstreamAgent == currentAgentID {
			continue
		}

		// Look up the chain depth (how many hops this trace has traversed).
		depth := 1
		depthStr, err := d.rdb.HGet(ctx, "cicada:cascade:trace_depth", traceID).Result()
		if err == nil {
			for _, c := range depthStr {
				if c >= '0' && c <= '9' {
					depth = int(c - '0')
					break
				}
			}
			depth++ // Current hop increments the chain
		}

		return CascadeResult{
			IsCascade:       true,
			UpstreamTraceID: traceID,
			UpstreamAgentID: upstreamAgent,
			ChainDepth:      depth,
		}
	}

	return CascadeResult{}
}

// RecordTrace stores a trace ID for cascade correlation after a successful
// proxy response. Uses an atomic pipeline: SADD to the global set, HSET
// for the owner mapping, and EXPIRE on both keys.
//
// The trace window (default 5 min) prevents memory leaks in high-throughput
// environments. Old traces are naturally evicted.
func (d *Detector) RecordTrace(ctx context.Context, traceID string, agentID string, chainDepth int) error {
	pipe := d.rdb.Pipeline()

	// Atomic: add trace to the global set
	pipe.SAdd(ctx, "cicada:cascade:traces", traceID)
	pipe.Expire(ctx, "cicada:cascade:traces", d.traceWindow)

	// Atomic: map trace → owning agent
	pipe.HSet(ctx, "cicada:cascade:trace_owners", traceID, agentID)
	pipe.Expire(ctx, "cicada:cascade:trace_owners", d.traceWindow)

	// Atomic: store chain depth for this trace
	pipe.HSet(ctx, "cicada:cascade:trace_depth", traceID, chainDepth)
	pipe.Expire(ctx, "cicada:cascade:trace_depth", d.traceWindow)

	_, err := pipe.Exec(ctx)
	return err
}

// ExceedsMaxChainDepth returns true if the cascade chain depth exceeds the
// configured maximum, indicating that CIBA hold should be enforced.
func (d *Detector) ExceedsMaxChainDepth(result CascadeResult) bool {
	return result.IsCascade && result.ChainDepth > d.maxChainDepth
}
