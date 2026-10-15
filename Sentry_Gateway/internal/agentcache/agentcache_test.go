// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package agentcache

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/asai/cicada/sentry/internal/queue"
	"github.com/redis/go-redis/v9"
)

func TestCacheCounters(t *testing.T) {
	// Connect to local Redis
	redisAddr := os.Getenv("REDIS_URL")
	if redisAddr == "" {
		redisAddr = "localhost:6379"
	}
	queue.Client = redis.NewClient(&redis.Options{Addr: redisAddr})
	ctx := context.Background()

	// Verify Redis is up
	if err := queue.Client.Ping(ctx).Err(); err != nil {
		t.Skipf("Redis unavailable: %v", err)
	}

	// Pre-seed a test agent in Redis
	testAgentID := "test-metrics-agent-001"
	key := cacheKeyAgent(testAgentID)
	queue.Client.HSet(ctx, key, map[string]interface{}{
		"approval_status":        "approved",
		"hitl_enabled":           "false",
		"hitl_webhook_url":       "",
		"observe_only_mode":      "false",
		"swarm_confidence_score": "0.950000",
		"description":            "Test agent for metrics validation",
		"name":                   "metrics_test_agent",
		"destructive_capability": "false",
		"ghost_mode_allowed":     "false",
	})
	queue.Client.Expire(ctx, key, 60*time.Second)

	// Pre-seed FGA policies
	fgaKey := cacheKeyFGA(testAgentID)
	queue.Client.Set(ctx, fgaKey, `[{"resource_pattern":"https://api.example.com/*","allowed_methods":["GET","POST"],"active":true}]`, 60*time.Second)

	// Read initial stats
	before := Stats()
	t.Logf("BEFORE: Agent hits=%d misses=%d | FGA hits=%d misses=%d | Requests=%d",
		before.AgentHits, before.AgentMisses, before.FGAHits, before.FGAMisses, before.TotalRequests)

	// Hit the cache 10 times (should all be hits since we seeded Redis)
	for i := 0; i < 10; i++ {
		info, err := GetAgent(ctx, testAgentID)
		if err != nil {
			t.Fatalf("GetAgent failed: %v", err)
		}
		if info.ApprovalStatus != "approved" {
			t.Errorf("Expected approved, got %s", info.ApprovalStatus)
		}
	}

	// Hit FGA cache 5 times
	for i := 0; i < 5; i++ {
		policies, err := GetFGAPolicies(ctx, testAgentID)
		if err != nil {
			t.Fatalf("GetFGAPolicies failed: %v", err)
		}
		if len(policies) != 1 {
			t.Errorf("Expected 1 policy, got %d", len(policies))
		}
	}

	// Force a cache miss by querying a non-existent agent (will fail at DB level)
	GetAgent(ctx, "non-existent-agent-will-miss")

	// Read stats after
	after := Stats()
	t.Logf("AFTER:  Agent hits=%d misses=%d | FGA hits=%d misses=%d | Requests=%d",
		after.AgentHits, after.AgentMisses, after.FGAHits, after.FGAMisses, after.TotalRequests)
	t.Logf("LATENCY: avg=%.4fms max=%.4fms", after.AvgLatencyMs, after.MaxLatencyMs)
	t.Logf("HIT RATES: agent=%.1f%% fga=%.1f%%", after.AgentHitRate, after.FGAHitRate)

	// Assertions
	agentHitDelta := after.AgentHits - before.AgentHits
	agentMissDelta := after.AgentMisses - before.AgentMisses
	fgaHitDelta := after.FGAHits - before.FGAHits

	if agentHitDelta != 10 {
		t.Errorf("Expected 10 agent cache hits, got %d", agentHitDelta)
	}
	if agentMissDelta < 1 {
		t.Errorf("Expected at least 1 agent cache miss, got %d", agentMissDelta)
	}
	if fgaHitDelta != 5 {
		t.Errorf("Expected 5 FGA cache hits, got %d", fgaHitDelta)
	}
	if after.TotalRequests < 11 {
		t.Errorf("Expected at least 11 total requests, got %d", after.TotalRequests)
	}
	if after.AvgLatencyMs <= 0 {
		t.Errorf("Expected positive avg latency, got %.4fms", after.AvgLatencyMs)
	}

	// Cleanup
	queue.Client.Del(ctx, key, fgaKey)
	t.Log("✅ All cache counter assertions passed.")
}
