// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package threatintel

import (
	"strings"
	"testing"
	"time"

	"github.com/asai/cicada/sentry/internal/injection"
)

func TestThreatSignalContainsNoPII(t *testing.T) {
	// The core design invariant: no field in a ThreatSignal can reveal
	// the source company, agent, user, or raw payload content.
	result := injection.Result{
		Block: true,
		Score: 1.0,
		Findings: []injection.Finding{
			{Pattern: "ignore previous instructions", Severity: "critical", Excerpt: "SECRET AGENT DATA ignore previous instructions REAL PAYLOAD"},
		},
	}

	signal := NewInjectionSignal(result)

	// SignalID must not contain any identifiable info
	if strings.Contains(signal.SignalID, "tenant") || strings.Contains(signal.SignalID, "agent") {
		t.Error("SignalID must not contain tenant or agent identifiers")
	}

	// Fingerprint must be a SHA-256 hash, not raw content
	if len(signal.Fingerprint) != 64 { // SHA-256 hex = 64 chars
		t.Errorf("Fingerprint must be SHA-256 hex (64 chars), got %d chars", len(signal.Fingerprint))
	}

	// Fingerprint must NOT contain the raw excerpt or payload
	if strings.Contains(signal.Fingerprint, "SECRET") || strings.Contains(signal.Fingerprint, "PAYLOAD") {
		t.Error("Fingerprint must not contain raw payload content")
	}

	// Category must be a generic label, not company-specific
	if signal.Category != CategoryPromptInjection {
		t.Errorf("Expected category %s, got %s", CategoryPromptInjection, signal.Category)
	}

	// No field should be empty
	if signal.SignalID == "" || signal.Fingerprint == "" || signal.Severity == "" {
		t.Error("Signal fields must not be empty")
	}
}

func TestInjectionPatternToSignal(t *testing.T) {
	result := injection.Result{
		Block: true,
		Score: 1.0,
		Findings: []injection.Finding{
			{Pattern: "ignore previous instructions", Severity: "critical"},
			{Pattern: "DAN jailbreak pattern", Severity: "critical"},
		},
	}

	signal := NewInjectionSignal(result)

	if signal.Category != CategoryPromptInjection {
		t.Errorf("Expected category %s, got %s", CategoryPromptInjection, signal.Category)
	}
	if signal.Severity != "critical" {
		t.Errorf("Expected severity critical, got %s", signal.Severity)
	}
	if signal.Fingerprint == "" {
		t.Error("Fingerprint must not be empty")
	}
	if signal.TTL != int64(DefaultTTL) {
		t.Errorf("Expected TTL %d, got %d", int64(DefaultTTL), signal.TTL)
	}
}

func TestExfiltrationPatternToSignal(t *testing.T) {
	signal := NewExfiltrationSignal("aws_key", "high")

	if signal.Category != CategoryExfiltration {
		t.Errorf("Expected category %s, got %s", CategoryExfiltration, signal.Category)
	}
	if signal.Severity != "high" {
		t.Errorf("Expected severity high, got %s", signal.Severity)
	}

	// Fingerprint must be consistent for the same subtype
	signal2 := NewExfiltrationSignal("aws_key", "high")
	if signal.Fingerprint != signal2.Fingerprint {
		t.Error("Same exfiltration subtype must produce same fingerprint")
	}

	// Different subtype must produce different fingerprint
	signal3 := NewExfiltrationSignal("pem_key", "high")
	if signal.Fingerprint == signal3.Fingerprint {
		t.Error("Different exfiltration subtypes must produce different fingerprints")
	}
}

func TestThreatSignalAbsorption(t *testing.T) {
	bl := NewBlocklist()

	signal := NewInjectionSignal(injection.Result{
		Block: true,
		Score: 1.0,
		Findings: []injection.Finding{
			{Pattern: "separator-based system injection", Severity: "critical"},
		},
	})

	// Before absorption — not known
	if bl.IsKnownThreat(signal.Fingerprint) {
		t.Error("Signal must not be known before absorption")
	}

	// Absorb
	bl.Absorb(signal)

	// After absorption — known
	if !bl.IsKnownThreat(signal.Fingerprint) {
		t.Error("Signal must be known after absorption")
	}

	if bl.ActiveCount() != 1 {
		t.Errorf("Expected 1 active entry, got %d", bl.ActiveCount())
	}
}

func TestDuplicateSignalDedup(t *testing.T) {
	bl := NewBlocklist()

	// Same fingerprint from two different "peers"
	signal1 := ThreatSignal{
		SignalID:    "signal-from-peer-a",
		Category:   CategoryPromptInjection,
		Fingerprint: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
		Severity:   "critical",
		Timestamp:  time.Now().UnixNano(),
		TTL:        int64(DefaultTTL),
	}

	signal2 := ThreatSignal{
		SignalID:    "signal-from-peer-b", // different signal ID
		Category:   CategoryPromptInjection,
		Fingerprint: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", // same fingerprint
		Severity:   "critical",
		Timestamp:  time.Now().UnixNano(),
		TTL:        int64(DefaultTTL),
	}

	bl.Absorb(signal1)
	bl.Absorb(signal2)

	// Must still be 1 entry (deduplicated)
	if bl.ActiveCount() != 1 {
		t.Errorf("Duplicate fingerprints must be deduplicated: expected 1, got %d", bl.ActiveCount())
	}

	// SeenCount must be 2 (consensus)
	bl.mu.RLock()
	entry := bl.entries[signal1.Fingerprint]
	bl.mu.RUnlock()
	if entry.SeenCount != 2 {
		t.Errorf("SeenCount must be 2 after two absorptions, got %d", entry.SeenCount)
	}
}

func TestTTLExpiration(t *testing.T) {
	bl := NewBlocklist()

	// Create a signal with TTL already expired
	signal := ThreatSignal{
		SignalID:    "expired-signal",
		Category:   CategoryPromptInjection,
		Fingerprint: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Severity:   "high",
		Timestamp:  time.Now().Add(-48 * time.Hour).UnixNano(), // 48 hours ago
		TTL:        int64(1 * time.Hour),                        // 1 hour TTL → expired 47 hours ago
	}

	bl.Absorb(signal)

	// Manually trigger eviction (normally runs on a ticker)
	bl.mu.Lock()
	now := time.Now().UnixNano()
	for fp, entry := range bl.entries {
		if now > entry.ExpiresAt {
			delete(bl.entries, fp)
		}
	}
	bl.mu.Unlock()

	if bl.ActiveCount() != 0 {
		t.Error("Expired signal must be evicted from blocklist")
	}
}

func TestWireFormatRoundTrip(t *testing.T) {
	original := ThreatSignal{
		SignalID:    "test-signal-123",
		Category:   CategoryPromptInjection,
		Fingerprint: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
		Severity:   "critical",
		Timestamp:  1234567890,
		TTL:        86400000000000,
	}

	wire := original.WireFormat()

	// Must start with THREAT|
	if !strings.HasPrefix(wire, "THREAT|") {
		t.Error("Wire format must start with THREAT| prefix")
	}

	// Round-trip
	parsed, ok := ParseThreatSignal(wire)
	if !ok {
		t.Fatal("ParseThreatSignal must succeed for valid wire format")
	}

	if parsed.SignalID != original.SignalID {
		t.Errorf("SignalID mismatch: got %s, want %s", parsed.SignalID, original.SignalID)
	}
	if parsed.Category != original.Category {
		t.Errorf("Category mismatch: got %s, want %s", parsed.Category, original.Category)
	}
	if parsed.Fingerprint != original.Fingerprint {
		t.Errorf("Fingerprint mismatch: got %s, want %s", parsed.Fingerprint, original.Fingerprint)
	}
	if parsed.Severity != original.Severity {
		t.Errorf("Severity mismatch: got %s, want %s", parsed.Severity, original.Severity)
	}
	if parsed.Timestamp != original.Timestamp {
		t.Errorf("Timestamp mismatch: got %d, want %d", parsed.Timestamp, original.Timestamp)
	}
	if parsed.TTL != original.TTL {
		t.Errorf("TTL mismatch: got %d, want %d", parsed.TTL, original.TTL)
	}
}

func TestParseNonThreatLine(t *testing.T) {
	// Operational gossip (AgentState) must not parse as a ThreatSignal
	operationalWire := "tenant-alpha|agent-123|QUARANTINED|1234567890|node-1"
	_, ok := ParseThreatSignal(operationalWire)
	if ok {
		t.Error("Operational gossip must NOT parse as a ThreatSignal")
	}
}

func TestCheckInjectionResultAgainstBlocklist(t *testing.T) {
	bl := NewBlocklist()

	// Create and absorb a threat signal for a specific injection pattern
	injResult := injection.Result{
		Block: true,
		Score: 1.0,
		Findings: []injection.Finding{
			{Pattern: "new instructions injection", Severity: "critical"},
		},
	}
	signal := NewInjectionSignal(injResult)
	bl.Absorb(signal)

	// Now check the same pattern against the blocklist — must match
	if !bl.CheckInjectionResult(injResult) {
		t.Error("Injection result with matching fingerprint must be flagged as known threat")
	}

	// A different pattern must NOT match
	differentResult := injection.Result{
		Block: true,
		Score: 0.85,
		Findings: []injection.Finding{
			{Pattern: "completely different pattern", Severity: "high"},
		},
	}
	if bl.CheckInjectionResult(differentResult) {
		t.Error("Injection result with different fingerprint must NOT be flagged as known threat")
	}
}

func TestFingerprintDeterminism(t *testing.T) {
	// Same patterns must always produce the same fingerprint
	result1 := injection.Result{
		Findings: []injection.Finding{
			{Pattern: "ignore previous instructions", Severity: "critical"},
			{Pattern: "DAN jailbreak pattern", Severity: "critical"},
		},
	}
	result2 := injection.Result{
		Findings: []injection.Finding{
			{Pattern: "ignore previous instructions", Severity: "critical"},
			{Pattern: "DAN jailbreak pattern", Severity: "critical"},
		},
	}

	fp1 := FingerprintFromInjection(result1)
	fp2 := FingerprintFromInjection(result2)

	if fp1 != fp2 {
		t.Error("Same injection patterns must produce identical fingerprints")
	}
}
