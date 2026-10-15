// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package rotation

import (
	"os"
	"testing"
	"time"
)

// ── Configuration Tests ──────────────────────────────────────────────────────

func TestRotationPeriod_Default(t *testing.T) {
	os.Unsetenv("CICADA_ROTATION_PERIOD_DAYS")
	got := RotationPeriod()
	want := 90 * 24 * time.Hour
	if got != want {
		t.Errorf("RotationPeriod() = %v, want %v", got, want)
	}
}

func TestRotationPeriod_Custom(t *testing.T) {
	t.Setenv("CICADA_ROTATION_PERIOD_DAYS", "30")
	got := RotationPeriod()
	want := 30 * 24 * time.Hour
	if got != want {
		t.Errorf("RotationPeriod() = %v, want %v", got, want)
	}
}

func TestRotationPeriod_InvalidFallsBack(t *testing.T) {
	t.Setenv("CICADA_ROTATION_PERIOD_DAYS", "not_a_number")
	got := RotationPeriod()
	if got != DefaultRotationPeriod {
		t.Errorf("Expected default period for invalid input, got %v", got)
	}
}

func TestRotationPeriod_ZeroFallsBack(t *testing.T) {
	t.Setenv("CICADA_ROTATION_PERIOD_DAYS", "0")
	got := RotationPeriod()
	if got != DefaultRotationPeriod {
		t.Errorf("Expected default period for zero, got %v", got)
	}
}

func TestNotificationTiers_Default(t *testing.T) {
	os.Unsetenv("CICADA_ROTATION_NOTIFY_DAYS")
	tiers := NotificationTiers()
	if len(tiers) != 2 || tiers[0] != 7 || tiers[1] != 1 {
		t.Errorf("NotificationTiers() = %v, want [7, 1]", tiers)
	}
}

func TestNotificationTiers_Custom(t *testing.T) {
	t.Setenv("CICADA_ROTATION_NOTIFY_DAYS", "14,7,3,1")
	tiers := NotificationTiers()
	if len(tiers) != 4 {
		t.Errorf("Expected 4 tiers, got %d: %v", len(tiers), tiers)
	}
	if tiers[0] != 14 || tiers[3] != 1 {
		t.Errorf("Tiers = %v, want [14, 7, 3, 1]", tiers)
	}
}

func TestNotificationTiers_EmptyString(t *testing.T) {
	t.Setenv("CICADA_ROTATION_NOTIFY_DAYS", "")
	tiers := NotificationTiers()
	if len(tiers) != 2 {
		t.Errorf("Expected default tiers for empty string, got %v", tiers)
	}
}

func TestNotificationTiers_InvalidEntries(t *testing.T) {
	t.Setenv("CICADA_ROTATION_NOTIFY_DAYS", "abc,7,xyz,1")
	tiers := NotificationTiers()
	if len(tiers) != 2 || tiers[0] != 7 || tiers[1] != 1 {
		t.Errorf("Expected [7, 1] after filtering invalid, got %v", tiers)
	}
}

func TestCheckInterval_Default(t *testing.T) {
	os.Unsetenv("CICADA_ROTATION_CHECK_INTERVAL")
	got := CheckInterval()
	if got != DefaultCheckInterval {
		t.Errorf("CheckInterval() = %v, want %v", got, DefaultCheckInterval)
	}
}

func TestCheckInterval_Custom(t *testing.T) {
	t.Setenv("CICADA_ROTATION_CHECK_INTERVAL", "5m")
	got := CheckInterval()
	if got != 5*time.Minute {
		t.Errorf("CheckInterval() = %v, want 5m", got)
	}
}

func TestCheckInterval_TooShort(t *testing.T) {
	t.Setenv("CICADA_ROTATION_CHECK_INTERVAL", "10s")
	got := CheckInterval()
	if got != DefaultCheckInterval {
		t.Errorf("Expected default for too-short interval, got %v", got)
	}
}

// ── Hash Prefix Tests ────────────────────────────────────────────────────────

func TestHashPrefix_Length(t *testing.T) {
	h := hashPrefix("test-evar-token")
	if len(h) != 16 {
		t.Errorf("hashPrefix length = %d, want 16", len(h))
	}
}

func TestHashPrefix_Deterministic(t *testing.T) {
	a := hashPrefix("same-input")
	b := hashPrefix("same-input")
	if a != b {
		t.Errorf("hashPrefix not deterministic: %q != %q", a, b)
	}
}

func TestHashPrefix_DifferentInputs(t *testing.T) {
	a := hashPrefix("input-a")
	b := hashPrefix("input-b")
	if a == b {
		t.Errorf("Different inputs produced same hash prefix: %q", a)
	}
}

func TestHashPrefix_EmptyString(t *testing.T) {
	h := hashPrefix("")
	if len(h) != 16 {
		t.Errorf("hashPrefix of empty string: length = %d", len(h))
	}
}

// ── Monitor Construction Tests ───────────────────────────────────────────────

func TestNewMonitor_NilDB(t *testing.T) {
	m := NewMonitor(nil, 1*time.Hour)
	if m == nil {
		t.Fatal("NewMonitor returned nil")
	}
	status := m.Status()
	if status.LastRunAt != "never" {
		t.Errorf("initial LastRunAt = %q, want %q", status.LastRunAt, "never")
	}
}

func TestMonitorStatus_ThreadSafe(t *testing.T) {
	m := NewMonitor(nil, 1*time.Hour)

	// Simulate concurrent reads — should not panic
	done := make(chan struct{})
	for i := 0; i < 10; i++ {
		go func() {
			_ = m.Status()
			done <- struct{}{}
		}()
	}
	for i := 0; i < 10; i++ {
		<-done
	}
}

// ── Notification Payload Tests ───────────────────────────────────────────────

func TestNotificationPayload_Structure(t *testing.T) {
	p := NotificationPayload{
		Type:      "credential_rotation_warning",
		AgentID:   "agent-123",
		TenantID:  "tenant-456",
		ExpiresAt: "2026-08-10T00:00:00Z",
		DaysLeft:  7,
		Tier:      "7d",
		Action:    "rotate_evar",
		RotateURL: "/v1/agent/agent-123/rotate",
	}

	if p.Type != "credential_rotation_warning" {
		t.Errorf("Type = %q", p.Type)
	}
	if p.DaysLeft != 7 {
		t.Errorf("DaysLeft = %d, want 7", p.DaysLeft)
	}
}

// ── Rotation Event Structure Tests ───────────────────────────────────────────

func TestRotationEvent_Fields(t *testing.T) {
	evt := RotationEvent{
		AgentID:        "agent-abc",
		TenantID:       "tenant-xyz",
		EventType:      "rotation",
		OldEVARHash:    "abc123",
		NewEVARHash:    "def456",
		RotationReason: "scheduled_90day",
		InitiatedBy:    "system/rotation-monitor",
	}

	if evt.EventType != "rotation" {
		t.Errorf("EventType = %q, want %q", evt.EventType, "rotation")
	}
	if evt.InitiatedBy != "system/rotation-monitor" {
		t.Errorf("InitiatedBy = %q", evt.InitiatedBy)
	}
}

// ── Agent Credential State Tests ─────────────────────────────────────────────

func TestAgentCredentialState_ExpiryCheck(t *testing.T) {
	now := time.Now().UTC()
	agent := AgentCredentialState{
		AgentID:       "agent-test",
		EVARIssuedAt:  now.Add(-89 * 24 * time.Hour),
		EVARExpiresAt: now.Add(1 * 24 * time.Hour),
		RotationCount: 0,
	}

	timeUntilExpiry := agent.EVARExpiresAt.Sub(now)
	daysLeft := int(timeUntilExpiry.Hours() / 24)

	if daysLeft > 1 {
		t.Errorf("Expected 1 day left, got %d", daysLeft)
	}
	if daysLeft < 0 {
		t.Errorf("Expected positive days left, got %d", daysLeft)
	}
}

func TestAgentCredentialState_Expired(t *testing.T) {
	now := time.Now().UTC()
	agent := AgentCredentialState{
		AgentID:       "agent-expired",
		EVARIssuedAt:  now.Add(-91 * 24 * time.Hour),
		EVARExpiresAt: now.Add(-1 * 24 * time.Hour),
	}

	timeUntilExpiry := agent.EVARExpiresAt.Sub(now)
	if timeUntilExpiry > 0 {
		t.Errorf("Expected expired (negative duration), got %v", timeUntilExpiry)
	}
}
