// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package velocity implements adaptive per-agent rate limiting for destructive
// (write/delete) calls in Cicada's Sentry Gateway.
//
// Why adaptive, not static:
// Static thresholds ("block after 30 writes/min") fail in both directions for
// agent workloads. A bulk-import agent legitimately making 200 write calls per
// minute trips a static limit. A rogue agent making exactly 29 calls per minute
// indefinitely sails through. The correct question is not "how many calls?" but
// "how many calls relative to what is normal for THIS agent?"
//
// Algorithm — z-score anomaly detection over a rolling baseline:
//  1. Every call increments a per-minute Redis counter for the agent.
//  2. After each increment, the last BaselineWindowCount per-minute counts are
//     read from a Redis sorted set (one entry per completed minute).
//  3. Mean and standard deviation are computed over the baseline window.
//  4. Current rate is converted to a z-score: (current - mean) / stddev.
//  5. If z-score > ZScoreBlockThreshold (default 3.0 sigma), the call is blocked.
//     Three sigma means the current rate is statistically anomalous — it would
//     occur by chance less than 0.3% of the time in a normal distribution.
//
// Fallback to static threshold:
// For new agents with fewer than BaselineMinWindows completed minutes of history,
// there is insufficient data for z-score computation. The static threshold applies
// during this "cold start" period. This is intentional — new agents are less trusted
// and the static limit is conservative.
//
// Why Redis sorted sets for history:
// Sorted sets (ZADD score=timestamp member=count) allow efficient range queries
// for the last N minutes with a single ZRANGEBYSCORE call. TTL is set to
// BaselineWindowCount minutes so the history automatically prunes itself.
package velocity

import (
	"context"
	"fmt"
	"log"
	"math"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/asai/cicada/sentry/internal/queue"
	"github.com/redis/go-redis/v9"
)

// WindowSeconds is the per-window duration — one window = one minute.
// This is the unit over which calls are counted and stored historically.
const WindowSeconds = 60

// BaselineWindowCount is how many historical windows to use for mean/stddev.
// 60 windows = 1 hour of history. Enough to capture normal agent behaviour
// cycles (e.g. a scheduler that fires every 10 minutes) without being so long
// that a slow-escalating attack pattern blends into the baseline.
const BaselineWindowCount = 60

// BaselineMinWindows is the minimum completed windows before adaptive mode
// activates. Below this, the static threshold applies (cold-start protection).
// 5 minutes of history is the minimum for a reliable baseline — fewer data
// points produce unreliable stddev values that could either block legitimate
// agents or allow rogue ones.
const BaselineMinWindows = 5

// ZScoreBlockThreshold is the number of standard deviations above baseline
// that triggers a block. 3.0 sigma = ~0.3% false positive rate on a normal
// distribution. Configurable via VELOCITY_ZSCORE_THRESHOLD env var so operators
// can tighten (lower) or loosen (higher) based on their agent population.
const ZScoreBlockThreshold = 3.0

// Default static thresholds — apply during cold start and when Redis is unavailable.
const defaultWriteThreshold = 30
const defaultDeleteThreshold = 10

// Result is returned by Check for every proxied call.
type Result struct {
	Exceeded         bool    // true → caller should deny the request
	CurrentRate      int64   // current counter value in this window
	Threshold        int64   // static threshold (meaningful even in adaptive mode)
	ZScore           float64 // z-score vs baseline (0 if baseline insufficient)
	WindowSecs       int     // window length in seconds
	CounterType      string  // "write" or "delete"
	Mode             string  // "adaptive" or "static" — which path triggered the decision
	ImpactMultiplier int64   // semantic impact multiplier applied (1 = normal, 100 = bulk)
	ImpactReason     string  // why the multiplier was applied (for audit log)
	ImpactIndicator  string  // which indicator triggered: "bulk_url", "array_payload", "none"
}

// CheckWithImpact is the impact-aware entry point for the velocity limiter.
// It computes the semantic impact weight of the request (based on URL and body)
// and increments the Redis counter by that weight instead of 1.
//
// Example: A DELETE to /api/v1/users/bulk increments the counter by 100,
// causing the z-score to spike immediately even if it's the first call.
//
// This function replaces direct calls to Check() in the pipeline for
// state-mutating requests. Read methods bypass impact computation entirely.
func CheckWithImpact(ctx context.Context, agentID, httpMethod, targetURL, body string) Result {
	impact := ComputeImpact(targetURL, body, httpMethod)

	// If multiplier is 1, fall through to standard Check (no overhead).
	if impact.Multiplier <= 1 {
		result := Check(ctx, agentID, httpMethod)
		result.ImpactMultiplier = 1
		result.ImpactReason = impact.Reason
		result.ImpactIndicator = impact.Indicator
		return result
	}

	// For impact > 1: increment the Redis counter by the multiplier instead of 1.
	// This is the core mechanism — a single bulk call "costs" N normal calls.
	result := checkWithWeight(ctx, agentID, httpMethod, impact.Multiplier)
	result.ImpactMultiplier = impact.Multiplier
	result.ImpactReason = impact.Reason
	result.ImpactIndicator = impact.Indicator

	if result.Exceeded {
		log.Printf("[VELOCITY] Impact-weighted block: agent=%s method=%s multiplier=%d indicator=%s reason=%s",
			agentID, httpMethod, impact.Multiplier, impact.Indicator, impact.Reason)
	}

	return result
}

// checkWithWeight is the internal weighted variant of Check.
// Instead of INCR (add 1), it uses INCRBY (add weight).
func checkWithWeight(ctx context.Context, agentID, httpMethod string, weight int64) Result {
	method := strings.ToUpper(httpMethod)

	counterType, applicable := classifyMethod(method)
	if !applicable {
		return Result{Exceeded: false, CounterType: "none"}
	}

	staticThreshold := thresholdForType(counterType)

	if queue.Client == nil {
		log.Printf("[VELOCITY] Redis not available for agent %s", agentID)
		failClosed := os.Getenv("CICADA_FAIL_CLOSED") != "false"
		return Result{Exceeded: failClosed, CurrentRate: 0, Threshold: staticThreshold, WindowSecs: WindowSeconds, CounterType: counterType, Mode: "static"}
	}

	// ── Increment by weight instead of 1 ─────────────────────────────────
	currentKey := currentWindowKey(agentID, counterType)
	count, err := queue.Client.IncrBy(ctx, currentKey, weight).Result()
	if err != nil {
		log.Printf("[VELOCITY] Redis INCRBY failed for agent %s: %v", agentID, err)
		return Result{Exceeded: false, CurrentRate: 0, Threshold: staticThreshold, WindowSecs: WindowSeconds, CounterType: counterType, Mode: "static"}
	}
	queue.Client.Expire(ctx, currentKey, time.Duration(WindowSeconds)*time.Second)

	go recordWindowSnapshot(ctx, agentID, counterType)

	// ── Same adaptive/static logic as Check ──────────────────────────────
	baseline, baselineErr := getHistoricalBaseline(ctx, agentID, counterType)
	if baselineErr == nil && baseline.count >= BaselineMinWindows {
		if baseline.stddev > 0 {
			zScore := (float64(count) - baseline.mean) / baseline.stddev
			zThreshold := zscoreThreshold()
			exceeded := zScore > zThreshold

			return Result{
				Exceeded:    exceeded,
				CurrentRate: count,
				Threshold:   staticThreshold,
				ZScore:      zScore,
				WindowSecs:  WindowSeconds,
				CounterType: counterType,
				Mode:        "adaptive",
			}
		}
		if count > int64(math.Round(baseline.mean)) {
			return Result{Exceeded: true, CurrentRate: count, Threshold: staticThreshold, ZScore: 999, WindowSecs: WindowSeconds, CounterType: counterType, Mode: "adaptive"}
		}
	}

	exceeded := count > staticThreshold
	return Result{
		Exceeded:    exceeded,
		CurrentRate: count,
		Threshold:   staticThreshold,
		ZScore:      0,
		WindowSecs:  WindowSeconds,
		CounterType: counterType,
		Mode:        "static",
	}
}

// Check increments the per-agent velocity counter and evaluates whether the
// agent's current call rate is anomalous relative to its historical baseline.
// Fails open (non-exceeded) if Redis is unavailable — velocity limiting is one
// of several defence-in-depth layers; failing closed would cause cascading
// outages if Redis experiences a brief hiccup.
func Check(ctx context.Context, agentID, httpMethod string) Result {
	method := strings.ToUpper(httpMethod)

	// Only count state-mutating calls; GET/HEAD/OPTIONS go through the billing
	// meter for volume tracking but are not velocity-limited here.
	counterType, applicable := classifyMethod(method)
	if !applicable {
		return Result{Exceeded: false, CounterType: "none"}
	}

	staticThreshold := thresholdForType(counterType)

	if queue.Client == nil {
		log.Printf("[VELOCITY] Redis not available for agent %s", agentID)
		failClosed := os.Getenv("CICADA_FAIL_CLOSED") != "false"
		return Result{Exceeded: failClosed, CurrentRate: 0, Threshold: staticThreshold, WindowSecs: WindowSeconds, CounterType: counterType, Mode: "static"}
	}

	// ── Increment current-window counter ──────────────────────────────────────
	currentKey := currentWindowKey(agentID, counterType)
	count, err := queue.Client.Incr(ctx, currentKey).Result()
	if err != nil {
		log.Printf("[VELOCITY] Redis INCR failed for agent %s: %v", agentID, err)
		return Result{Exceeded: false, CurrentRate: 0, Threshold: staticThreshold, WindowSecs: WindowSeconds, CounterType: counterType, Mode: "static"}
	}
	// Sliding window: always refresh the TTL so the window expires from the
	// last call, not the first. This prevents burst-at-boundary attacks where
	// an attacker times their calls to straddle two fixed 60-second windows.
	queue.Client.Expire(ctx, currentKey, time.Duration(WindowSeconds)*time.Second)

	// ── Record completed windows for baseline ────────────────────────────────
	// Asynchronously snapshot the previous window's count into the sorted set.
	// We do this on every call rather than on a timer to avoid requiring a
	// separate background goroutine — the gateway is already I/O-bound on Redis.
	go recordWindowSnapshot(ctx, agentID, counterType)

	// ── Adaptive mode: z-score against historical baseline ──────────────────
	baseline, baselineErr := getHistoricalBaseline(ctx, agentID, counterType)
	if baselineErr == nil && baseline.count >= BaselineMinWindows {
		if baseline.stddev > 0 {
			zScore := (float64(count) - baseline.mean) / baseline.stddev
			zThreshold := zscoreThreshold()
			exceeded := zScore > zThreshold

			if exceeded {
				log.Printf("[VELOCITY] Adaptive block: agent=%s type=%s count=%d mean=%.1f stddev=%.1f z=%.2f threshold=%.1f",
					agentID, counterType, count, baseline.mean, baseline.stddev, zScore, zThreshold)
			}

			return Result{
				Exceeded:    exceeded,
				CurrentRate: count,
				Threshold:   staticThreshold,
				ZScore:      zScore,
				WindowSecs:  WindowSeconds,
				CounterType: counterType,
				Mode:        "adaptive",
			}
		}
		// stddev == 0 means perfectly consistent behaviour — current rate matching
		// the mean exactly is fine; any deviation should be flagged.
		if count > int64(math.Round(baseline.mean)) {
			log.Printf("[VELOCITY] Adaptive block (zero-stddev): agent=%s type=%s count=%d mean=%.1f",
				agentID, counterType, count, baseline.mean)
			return Result{Exceeded: true, CurrentRate: count, Threshold: staticThreshold, ZScore: 999, WindowSecs: WindowSeconds, CounterType: counterType, Mode: "adaptive"}
		}
	}

	// ── Static fallback: cold-start or insufficient history ──────────────────
	exceeded := count > staticThreshold
	if exceeded {
		log.Printf("[VELOCITY] Static block: agent=%s type=%s count=%d threshold=%d (baseline windows: %d)",
			agentID, counterType, count, staticThreshold, baseline.count)
	}

	return Result{
		Exceeded:    exceeded,
		CurrentRate: count,
		Threshold:   staticThreshold,
		ZScore:      0,
		WindowSecs:  WindowSeconds,
		CounterType: counterType,
		Mode:        "static",
	}
}

// CurrentRate returns the live counter without incrementing. Used by monitoring
// and the threat signals endpoint to surface velocity telemetry to Aegis-0.
func CurrentRate(ctx context.Context, agentID, counterType string) int64 {
	if queue.Client == nil {
		return 0
	}
	key := currentWindowKey(agentID, counterType)
	val, err := queue.Client.Get(ctx, key).Int64()
	if err != nil {
		return 0
	}
	return val
}

// ────────────────────────────────────────────────────────────────────────────
// Baseline tracking
// ────────────────────────────────────────────────────────────────────────────

type baselineStats struct {
	mean   float64
	stddev float64
	count  int // number of completed windows available
}

// recordWindowSnapshot writes the count from the previous 60-second window into
// the agent's historical sorted set. Called asynchronously on every request so
// baseline data accumulates naturally without a dedicated scheduler.
//
// The previous window's key may have already expired by the time we read it;
// that is acceptable — expired windows simply contribute a 0 to the history,
// which is accurate (the agent made 0 calls in that window).
func recordWindowSnapshot(ctx context.Context, agentID, counterType string) {
	if queue.Client == nil {
		return
	}

	// Previous window = current bucket - 1
	prevBucket := time.Now().Unix()/int64(WindowSeconds) - 1
	prevKey := fmt.Sprintf("cicada:velocity:%s:%s:%d", agentID, counterType, prevBucket)

	count, err := queue.Client.Get(ctx, prevKey).Int64()
	if err != nil {
		count = 0 // key expired or never set — zero calls in that window
	}

	histKey := historyKey(agentID, counterType)
	ts := float64(prevBucket * int64(WindowSeconds))

	// ZADD NX: only add if this window has not been recorded yet.
	// Without NX, concurrent requests in the same window would add duplicate
	// entries for the same bucket, skewing the baseline mean upward.
	queue.Client.ZAddNX(ctx, histKey, redisZValue(ts, count))

	// Prune entries older than BaselineWindowCount windows to keep the sorted
	// set bounded. ZREMRANGEBYSCORE removes by score range — we remove anything
	// older than (now - BaselineWindowCount * WindowSeconds).
	cutoff := float64((time.Now().Unix() - int64(BaselineWindowCount*WindowSeconds)))
	queue.Client.ZRemRangeByScore(ctx, histKey, "-inf", fmt.Sprintf("%f", cutoff))

	// TTL on the history key keeps it from persisting forever for inactive agents.
	queue.Client.Expire(ctx, histKey, time.Duration(BaselineWindowCount*2)*time.Minute)
}

// getHistoricalBaseline reads the last BaselineWindowCount entries from the
// history sorted set and computes mean and population standard deviation.
func getHistoricalBaseline(ctx context.Context, agentID, counterType string) (baselineStats, error) {
	if queue.Client == nil {
		return baselineStats{}, fmt.Errorf("redis unavailable")
	}

	histKey := historyKey(agentID, counterType)
	// Read all members with their scores (scores = timestamps, members = counts)
	entries, err := queue.Client.ZRangeWithScores(ctx, histKey, 0, -1).Result()
	if err != nil {
		return baselineStats{}, err
	}
	if len(entries) == 0 {
		return baselineStats{count: 0}, nil
	}

	// Extract the float count values stored as member strings.
	values := make([]float64, 0, len(entries))
	for _, e := range entries {
		if v, ok := e.Member.(string); ok {
			if f, err := strconv.ParseFloat(v, 64); err == nil {
				values = append(values, f)
			}
		}
	}

	if len(values) == 0 {
		return baselineStats{count: 0}, nil
	}

	// Population mean
	sum := 0.0
	for _, v := range values {
		sum += v
	}
	mean := sum / float64(len(values))

	// Population standard deviation (not sample stddev — we are characterising
	// the agent's actual behaviour, not estimating a population parameter).
	varianceSum := 0.0
	for _, v := range values {
		diff := v - mean
		varianceSum += diff * diff
	}
	stddev := math.Sqrt(varianceSum / float64(len(values)))

	return baselineStats{mean: mean, stddev: stddev, count: len(values)}, nil
}

// redisZValue constructs a redis.Z value for the history sorted set.
// Member is the string representation of the count so it can be parsed back
// as a float64 when computing the baseline statistics.
func redisZValue(score float64, count int64) redis.Z {
	return redis.Z{Score: score, Member: fmt.Sprintf("%d", count)}
}

// ────────────────────────────────────────────────────────────────────────────
// Key helpers and config
// ────────────────────────────────────────────────────────────────────────────

func currentWindowKey(agentID, counterType string) string {
	bucket := time.Now().Unix() / int64(WindowSeconds)
	return fmt.Sprintf("cicada:velocity:%s:%s:%d", agentID, counterType, bucket)
}

func historyKey(agentID, counterType string) string {
	return fmt.Sprintf("cicada:velocity:history:%s:%s", agentID, counterType)
}

func classifyMethod(method string) (string, bool) {
	switch method {
	case "DELETE":
		return "delete", true
	case "POST", "PUT", "PATCH":
		return "write", true
	default:
		return "", false
	}
}

func thresholdForType(counterType string) int64 {
	switch counterType {
	case "delete":
		return int64(envInt("VELOCITY_DELETE_THRESHOLD", defaultDeleteThreshold))
	case "write":
		return int64(envInt("VELOCITY_WRITE_THRESHOLD", defaultWriteThreshold))
	default:
		return int64(defaultWriteThreshold)
	}
}

func zscoreThreshold() float64 {
	if v := os.Getenv("VELOCITY_ZSCORE_THRESHOLD"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 {
			return f
		}
	}
	return ZScoreBlockThreshold
}

func envInt(key string, defaultVal int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil && i > 0 {
			return i
		}
	}
	return defaultVal
}
