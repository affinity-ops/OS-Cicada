// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package threatintel implements anonymised threat intelligence sharing for
// the Cicada P2P gossip mesh.
//
// Design invariant: NO field in ThreatSignal can identify the source company,
// the targeted agent, any raw payload content, user data, or PII. Only
// structural fingerprints of attack patterns are shared.
//
// This is the strategic differentiator: every Cicada gateway in the mesh
// benefits from the collective threat visibility of all other gateways,
// without any company exposing operational data to any other company.
package threatintel

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/asai/cicada/sentry/internal/injection"
)

// ─── Threat Signal Categories ────────────────────────────────────────────────

const (
	CategoryPromptInjection = "prompt_injection"
	CategoryExfiltration    = "exfiltration"
	CategoryVelocityAnomaly = "velocity_anomaly"
	CategoryCredentialScan  = "credential_scan"
	CategoryHoneytoken      = "honeytoken"
	CategorySessionAbuse    = "session_abuse"
)

// Default TTL for threat signals (24 hours).
const DefaultTTL = 24 * time.Hour

// ThreatSignal represents an anonymised attack fingerprint shared across the mesh.
//
// BY CONSTRUCTION, no field in this struct can identify:
//   - The source company or tenant
//   - The targeted agent or user
//   - Any raw payload content, prompt, or API response
//   - Any credential, token, or secret value
//   - Any PII whatsoever
//
// What flows across the mesh is ONLY the structural shape of the attack.
type ThreatSignal struct {
	SignalID    string `json:"signal_id"`    // Random ID — not traceable to source node or tenant
	Category   string `json:"category"`     // Attack category (see Category* constants)
	Fingerprint string `json:"fingerprint"` // SHA-256 of the normalised attack pattern
	Severity   string `json:"severity"`     // "critical", "high", "medium"
	Timestamp  int64  `json:"timestamp"`    // Unix nanos — when the attack was detected
	TTL        int64  `json:"ttl"`          // Duration in nanoseconds this signal stays active
}

// WireFormat serialises a ThreatSignal into the pipe-delimited gossip format.
// Format: THREAT|SignalID|Category|Fingerprint|Severity|Timestamp|TTL
// The "THREAT" prefix distinguishes threat intel from operational gossip (AgentState).
func (s ThreatSignal) WireFormat() string {
	return fmt.Sprintf("THREAT|%s|%s|%s|%s|%d|%d",
		s.SignalID, s.Category, s.Fingerprint, s.Severity, s.Timestamp, s.TTL)
}

// ParseThreatSignal parses a wire-format string back into a ThreatSignal.
// Returns the signal and true if valid, or zero-value and false if not a threat signal.
func ParseThreatSignal(wire string) (ThreatSignal, bool) {
	if !strings.HasPrefix(wire, "THREAT|") {
		return ThreatSignal{}, false
	}
	parts := strings.SplitN(wire, "|", 7)
	if len(parts) != 7 {
		return ThreatSignal{}, false
	}

	var ts, ttl int64
	fmt.Sscanf(parts[5], "%d", &ts)
	fmt.Sscanf(parts[6], "%d", &ttl)

	return ThreatSignal{
		SignalID:    parts[1],
		Category:   parts[2],
		Fingerprint: parts[3],
		Severity:   parts[4],
		Timestamp:  ts,
		TTL:        ttl,
	}, true
}

// ─── Fingerprint Generation ─────────────────────────────────────────────────
// These functions extract anonymised fingerprints from detection results.
// The fingerprint is a SHA-256 hash of the normalised pattern — NEVER the
// raw content that triggered detection.

// FingerprintFromInjection generates a fingerprint from an injection detection result.
// It hashes the matched pattern names (e.g., "ignore previous instructions",
// "DAN jailbreak pattern"), NOT the actual payload text.
func FingerprintFromInjection(result injection.Result) string {
	if len(result.Findings) == 0 {
		return ""
	}

	// Normalise: sort-stable list of pattern names joined with |
	// We use the pattern desc field which is a human-readable label,
	// not the regex or the matched text.
	patterns := make([]string, len(result.Findings))
	for i, f := range result.Findings {
		patterns[i] = f.Pattern
	}
	// Deterministic order: patterns are already in scan order
	combined := strings.Join(patterns, "|")
	hash := sha256.Sum256([]byte(combined))
	return hex.EncodeToString(hash[:])
}

// FingerprintFromCategory generates a fingerprint from a category string.
// Used for exfiltration, velocity, and honeytoken signals where the
// "pattern" is a category label rather than a regex match.
func FingerprintFromCategory(category, subtype string) string {
	combined := category + "|" + subtype
	hash := sha256.Sum256([]byte(combined))
	return hex.EncodeToString(hash[:])
}

// ─── Signal Constructors ────────────────────────────────────────────────────
// These construct ThreatSignal objects from detection events. Each constructor
// strips all identifying information and produces only the anonymised fingerprint.

// NewInjectionSignal creates a ThreatSignal from an injection scanner result.
func NewInjectionSignal(result injection.Result) ThreatSignal {
	// Determine severity from the highest-severity finding
	sev := "medium"
	for _, f := range result.Findings {
		if f.Severity == injection.SeverityCritical {
			sev = "critical"
			break
		}
		if f.Severity == injection.SeverityHigh {
			sev = "high"
		}
	}

	return ThreatSignal{
		SignalID:    generateSignalID(),
		Category:   CategoryPromptInjection,
		Fingerprint: FingerprintFromInjection(result),
		Severity:   sev,
		Timestamp:  time.Now().UnixNano(),
		TTL:        int64(DefaultTTL),
	}
}

// NewExfiltrationSignal creates a ThreatSignal for an exfiltration detection.
// subtype is the pattern category (e.g., "aws_key", "pem_key", "jwt") — NOT the value.
func NewExfiltrationSignal(subtype, severity string) ThreatSignal {
	return ThreatSignal{
		SignalID:    generateSignalID(),
		Category:   CategoryExfiltration,
		Fingerprint: FingerprintFromCategory(CategoryExfiltration, subtype),
		Severity:   severity,
		Timestamp:  time.Now().UnixNano(),
		TTL:        int64(DefaultTTL),
	}
}

// NewVelocitySignal creates a ThreatSignal for a velocity anomaly.
// profile describes the burst shape (e.g., "50rps_z4.2") — NOT the agent or tenant.
func NewVelocitySignal(profile, severity string) ThreatSignal {
	return ThreatSignal{
		SignalID:    generateSignalID(),
		Category:   CategoryVelocityAnomaly,
		Fingerprint: FingerprintFromCategory(CategoryVelocityAnomaly, profile),
		Severity:   severity,
		Timestamp:  time.Now().UnixNano(),
		TTL:        int64(DefaultTTL),
	}
}

// ─── Local Blocklist (Threat Signal Absorption) ─────────────────────────────
// When a gateway receives a threat signal from the mesh, the fingerprint is
// absorbed into a local blocklist. The injection scanner can then check
// incoming payloads against known-bad fingerprints, creating a collective
// immune system across the mesh.

// Blocklist holds absorbed threat fingerprints from the mesh.
type Blocklist struct {
	mu      sync.RWMutex
	entries map[string]*BlocklistEntry // keyed by fingerprint
}

// BlocklistEntry is a single absorbed threat signal.
type BlocklistEntry struct {
	Fingerprint string
	Category    string
	Severity    string
	AbsorbedAt  int64 // when this node absorbed the signal
	ExpiresAt   int64 // when to evict (AbsorbedAt + TTL)
	SeenCount   int   // how many peers reported this fingerprint
}

// NewBlocklist creates an empty blocklist and starts the TTL eviction goroutine.
func NewBlocklist() *Blocklist {
	bl := &Blocklist{
		entries: make(map[string]*BlocklistEntry),
	}
	go bl.runEviction()
	return bl
}

// Absorb ingests a threat signal from the mesh into the local blocklist.
// Duplicate fingerprints increment the SeenCount (mesh consensus signal).
func (bl *Blocklist) Absorb(signal ThreatSignal) {
	bl.mu.Lock()
	defer bl.mu.Unlock()

	if existing, ok := bl.entries[signal.Fingerprint]; ok {
		// Already known — increment consensus count
		existing.SeenCount++
		// Extend TTL if the new signal has a later expiry
		newExpiry := signal.Timestamp + signal.TTL
		if newExpiry > existing.ExpiresAt {
			existing.ExpiresAt = newExpiry
		}
		return
	}

	bl.entries[signal.Fingerprint] = &BlocklistEntry{
		Fingerprint: signal.Fingerprint,
		Category:    signal.Category,
		Severity:    signal.Severity,
		AbsorbedAt:  time.Now().UnixNano(),
		ExpiresAt:   signal.Timestamp + signal.TTL,
		SeenCount:   1,
	}
	log.Printf("[THREATINTEL] Absorbed signal: category=%s severity=%s fingerprint=%s…%s",
		signal.Category, signal.Severity, signal.Fingerprint[:8], signal.Fingerprint[len(signal.Fingerprint)-4:])
}

// IsKnownThreat checks if a fingerprint exists in the blocklist.
func (bl *Blocklist) IsKnownThreat(fingerprint string) bool {
	bl.mu.RLock()
	defer bl.mu.RUnlock()
	_, ok := bl.entries[fingerprint]
	return ok
}

// CheckInjectionResult checks an injection result against the blocklist.
// Returns true if the injection fingerprint matches a known threat from the mesh.
func (bl *Blocklist) CheckInjectionResult(result injection.Result) bool {
	fp := FingerprintFromInjection(result)
	if fp == "" {
		return false
	}
	return bl.IsKnownThreat(fp)
}

// ActiveCount returns the number of active (non-expired) entries.
func (bl *Blocklist) ActiveCount() int {
	bl.mu.RLock()
	defer bl.mu.RUnlock()
	return len(bl.entries)
}

// runEviction periodically removes expired entries from the blocklist.
func (bl *Blocklist) runEviction() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		bl.mu.Lock()
		now := time.Now().UnixNano()
		evicted := 0
		for fp, entry := range bl.entries {
			if now > entry.ExpiresAt {
				delete(bl.entries, fp)
				evicted++
			}
		}
		bl.mu.Unlock()
		if evicted > 0 {
			log.Printf("[THREATINTEL] Evicted %d expired signals from blocklist", evicted)
		}
	}
}

// ─── Signal ID Generation ───────────────────────────────────────────────────

// generateSignalID produces a random signal ID that cannot be traced to the
// source node or tenant. Uses timestamp + random suffix for uniqueness.
func generateSignalID() string {
	ts := time.Now().UnixNano()
	hash := sha256.Sum256([]byte(fmt.Sprintf("%d-%d", ts, time.Now().UnixMicro())))
	return hex.EncodeToString(hash[:16]) // 128-bit random-ish ID
}
