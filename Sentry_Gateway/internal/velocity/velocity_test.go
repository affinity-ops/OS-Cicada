// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package velocity

import (
	"context"
	"fmt"
	"testing"
)

// ── Method Classification ─────────────────────────────────────────────────────

func TestClassifyMethod(t *testing.T) {
	cases := []struct {
		method     string
		wantType   string
		wantApply  bool
	}{
		{"POST", "write", true},
		{"PUT", "write", true},
		{"PATCH", "write", true},
		{"DELETE", "delete", true},
		// Read methods are NOT velocity-limited
		{"GET", "", false},
		{"HEAD", "", false},
		{"OPTIONS", "", false},
	}
	for _, tc := range cases {
		gotType, gotApply := classifyMethod(tc.method)
		if gotType != tc.wantType || gotApply != tc.wantApply {
			t.Errorf("classifyMethod(%q) = (%q, %v), want (%q, %v)",
				tc.method, gotType, gotApply, tc.wantType, tc.wantApply)
		}
	}
}

// ── Threshold Defaults ────────────────────────────────────────────────────────

func TestThresholdForType_Defaults(t *testing.T) {
	writeThreshold := thresholdForType("write")
	if writeThreshold != int64(defaultWriteThreshold) {
		t.Errorf("write threshold = %d, want %d", writeThreshold, defaultWriteThreshold)
	}

	deleteThreshold := thresholdForType("delete")
	if deleteThreshold != int64(defaultDeleteThreshold) {
		t.Errorf("delete threshold = %d, want %d", deleteThreshold, defaultDeleteThreshold)
	}

	// Delete threshold should be stricter than write
	if deleteThreshold >= writeThreshold {
		t.Errorf("delete threshold (%d) should be stricter (lower) than write threshold (%d)",
			deleteThreshold, writeThreshold)
	}
}

// ── Z-Score Threshold ─────────────────────────────────────────────────────────

func TestZscoreThreshold_Default(t *testing.T) {
	threshold := zscoreThreshold()
	if threshold != ZScoreBlockThreshold {
		t.Errorf("default z-score threshold = %f, want %f", threshold, ZScoreBlockThreshold)
	}
	// 3 sigma is the statistical standard for anomaly detection
	if threshold < 2.0 || threshold > 5.0 {
		t.Errorf("z-score threshold %f is outside reasonable range [2.0, 5.0]", threshold)
	}
}

// ── Key Generation ────────────────────────────────────────────────────────────

func TestCurrentWindowKey_Format(t *testing.T) {
	key := currentWindowKey("agent-123", "write")
	if key == "" {
		t.Fatal("key should not be empty")
	}
	// Key should contain the agent ID, counter type, and bucket timestamp
	expected := fmt.Sprintf("cicada:velocity:agent-123:write:")
	if len(key) < len(expected) {
		t.Errorf("key %q is too short, expected prefix %q", key, expected)
	}
}

func TestHistoryKey_Format(t *testing.T) {
	key := historyKey("agent-456", "delete")
	expected := "cicada:velocity:history:agent-456:delete"
	if key != expected {
		t.Errorf("historyKey = %q, want %q", key, expected)
	}
}

// ── Redis Z Value ─────────────────────────────────────────────────────────────

func TestRedisZValue(t *testing.T) {
	z := redisZValue(1714200000.0, 42)
	if z.Score != 1714200000.0 {
		t.Errorf("z.Score = %f, want 1714200000.0", z.Score)
	}
	member, ok := z.Member.(string)
	if !ok {
		t.Fatal("z.Member should be a string")
	}
	if member != "42" {
		t.Errorf("z.Member = %q, want %q", member, "42")
	}
}

// ── envInt Helper ─────────────────────────────────────────────────────────────

func TestEnvInt_Default(t *testing.T) {
	val := envInt("VELOCITY_NONEXISTENT_KEY_FOR_TEST", 99)
	if val != 99 {
		t.Errorf("envInt with missing key = %d, want 99", val)
	}
}

// ── Constants ─────────────────────────────────────────────────────────────────

func TestConstants(t *testing.T) {
	if WindowSeconds != 60 {
		t.Errorf("WindowSeconds = %d, want 60", WindowSeconds)
	}
	if BaselineWindowCount != 60 {
		t.Errorf("BaselineWindowCount = %d, want 60 (1 hour)", BaselineWindowCount)
	}
	if BaselineMinWindows < 3 {
		t.Errorf("BaselineMinWindows = %d, should be at least 3 for reliable stddev", BaselineMinWindows)
	}
	if defaultWriteThreshold <= 0 || defaultDeleteThreshold <= 0 {
		t.Error("static thresholds must be positive")
	}
}

// ── Check with nil Redis (fail-closed when configured) ──────────────────────

func TestCheck_NilRedis_FailsClosedWhenConfigured(t *testing.T) {
	// With queue.Client == nil and CICADA_FAIL_CLOSED=true, Check should fail closed (Exceeded = true)
	t.Setenv("CICADA_FAIL_CLOSED", "true")
	resultClosed := Check(context.Background(), "agent-test", "POST")
	if !resultClosed.Exceeded {
		t.Error("velocity check should fail closed when CICADA_FAIL_CLOSED=true")
	}

	// When explicitly configured for fail-open (dev mode), Check should return Exceeded = false
	t.Setenv("CICADA_FAIL_CLOSED", "false")
	resultOpen := Check(context.Background(), "agent-test", "POST")
	if resultOpen.Exceeded {
		t.Error("velocity check should fail open when CICADA_FAIL_CLOSED=false")
	}
}

func TestCheck_GETMethod_NotLimited(t *testing.T) {
	result := Check(context.Background(), "agent-test", "GET")
	if result.Exceeded {
		t.Error("GET requests should never be velocity-limited")
	}
	if result.CounterType != "none" {
		t.Errorf("GET should have counterType 'none', got %q", result.CounterType)
	}
}
