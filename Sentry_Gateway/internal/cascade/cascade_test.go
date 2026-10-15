// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package cascade

import (
	"context"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// testRedis returns a Redis client connected to localhost.
// Tests are skipped if Redis is not available.
func testRedis(t *testing.T) *redis.Client {
	t.Helper()
	rdb := redis.NewClient(&redis.Options{Addr: "localhost:6379", DB: 15}) // Use DB 15 for tests
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		t.Skipf("Redis not available: %v", err)
	}
	rdb.FlushDB(context.Background()) // Clean slate
	return rdb
}

// ── Trace ID extraction tests ─────────────────────────────────────────────────

func TestTraceIDPattern_MatchesValidTraces(t *testing.T) {
	body := `{"result": "processed by req-a1b2c3d4-e5f6-7890-abcd-ef1234567890", "data": "ok"}`
	matches := traceIDPattern.FindAllString(body, 10)
	if len(matches) != 1 {
		t.Fatalf("expected 1 trace ID match, got %d", len(matches))
	}
	if matches[0] != "req-a1b2c3d4-e5f6-7890-abcd-ef1234567890" {
		t.Errorf("unexpected match: %s", matches[0])
	}
}

func TestTraceIDPattern_NoMatchOnCleanBody(t *testing.T) {
	body := `{"query": "SELECT * FROM accounts WHERE id = 42", "api_key": "sk-proj-abc123"}`
	matches := traceIDPattern.FindAllString(body, 10)
	if len(matches) != 0 {
		t.Errorf("clean body should not match trace ID pattern, got %d matches", len(matches))
	}
}

func TestTraceIDPattern_MultipleTraces(t *testing.T) {
	body := `{
		"upstream_trace": "req-11111111-2222-3333-4444-555555555555",
		"original_trace": "req-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
		"data": "normal content"
	}`
	matches := traceIDPattern.FindAllString(body, 10)
	if len(matches) != 2 {
		t.Fatalf("expected 2 trace ID matches, got %d", len(matches))
	}
}

// ── Cascade detection integration tests ───────────────────────────────────────

func TestDetect_NoCascade_CleanBody(t *testing.T) {
	rdb := testRedis(t)
	defer rdb.Close()

	d := NewDetector(rdb)
	result := d.Detect(context.Background(), `{"query": "normal data"}`, "agent-b")

	if result.IsCascade {
		t.Error("clean body should not trigger cascade detection")
	}
}

func TestDetect_NoCascade_SelfReference(t *testing.T) {
	rdb := testRedis(t)
	defer rdb.Close()

	ctx := context.Background()
	d := NewDetector(rdb)

	// Agent A stores its own trace
	err := d.RecordTrace(ctx, "req-a1b2c3d4-e5f6-7890-abcd-ef1234567890", "agent-a", 1)
	if err != nil {
		t.Fatalf("RecordTrace failed: %v", err)
	}

	// Agent A references its own trace — NOT a cascade
	body := `{"previous": "req-a1b2c3d4-e5f6-7890-abcd-ef1234567890"}`
	result := d.Detect(ctx, body, "agent-a")

	if result.IsCascade {
		t.Error("self-reference should not trigger cascade detection")
	}
}

func TestDetect_Cascade_CrossAgentTrace(t *testing.T) {
	rdb := testRedis(t)
	defer rdb.Close()

	ctx := context.Background()
	d := NewDetector(rdb)

	// Agent A stores a trace
	traceID := "req-a1b2c3d4-e5f6-7890-abcd-ef1234567890"
	err := d.RecordTrace(ctx, traceID, "agent-a", 1)
	if err != nil {
		t.Fatalf("RecordTrace failed: %v", err)
	}

	// Agent B's request body contains Agent A's trace ID — CASCADE
	body := `{"upstream_result": "Data from req-a1b2c3d4-e5f6-7890-abcd-ef1234567890"}`
	result := d.Detect(ctx, body, "agent-b")

	if !result.IsCascade {
		t.Fatal("cross-agent trace reference should trigger cascade detection")
	}
	if result.UpstreamAgentID != "agent-a" {
		t.Errorf("upstream agent should be agent-a, got %s", result.UpstreamAgentID)
	}
	if result.UpstreamTraceID != traceID {
		t.Errorf("upstream trace should be %s, got %s", traceID, result.UpstreamTraceID)
	}
	if result.ChainDepth != 2 {
		t.Errorf("chain depth should be 2 (agent-a=1, agent-b=2), got %d", result.ChainDepth)
	}
}

func TestDetect_ExceedsMaxChainDepth(t *testing.T) {
	rdb := testRedis(t)
	defer rdb.Close()

	ctx := context.Background()
	d := NewDetector(rdb, WithMaxChainDepth(2))

	// Simulate a 3-hop chain
	traceID := "req-a1b2c3d4-e5f6-7890-abcd-ef1234567890"
	err := d.RecordTrace(ctx, traceID, "agent-a", 3)
	if err != nil {
		t.Fatalf("RecordTrace failed: %v", err)
	}

	body := `{"data": "req-a1b2c3d4-e5f6-7890-abcd-ef1234567890"}`
	result := d.Detect(ctx, body, "agent-d")

	if !result.IsCascade {
		t.Fatal("should detect cascade")
	}
	if !d.ExceedsMaxChainDepth(result) {
		t.Error("chain depth 4 should exceed max of 2")
	}
}

func TestRecordTrace_Expiry(t *testing.T) {
	rdb := testRedis(t)
	defer rdb.Close()

	ctx := context.Background()
	d := NewDetector(rdb, WithTraceWindow(1*time.Second))

	traceID := "req-a1b2c3d4-e5f6-7890-abcd-ef1234567890"
	err := d.RecordTrace(ctx, traceID, "agent-a", 1)
	if err != nil {
		t.Fatalf("RecordTrace failed: %v", err)
	}

	// Immediately detectable
	body := `{"data": "req-a1b2c3d4-e5f6-7890-abcd-ef1234567890"}`
	result := d.Detect(ctx, body, "agent-b")
	if !result.IsCascade {
		t.Fatal("should detect cascade immediately after recording")
	}

	// Wait for expiry
	time.Sleep(2 * time.Second)

	result = d.Detect(ctx, body, "agent-b")
	if result.IsCascade {
		t.Error("cascade should not be detected after trace window expiry")
	}
}
