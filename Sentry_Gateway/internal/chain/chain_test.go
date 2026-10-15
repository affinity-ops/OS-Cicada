// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package chain

import (
	"crypto/ed25519"
	"testing"
)

// testKeyPair generates a deterministic Ed25519 key pair for tests.
func testKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("key generation failed: %v", err)
	}
	return pub, priv
}

// ── Single hop (first agent in chain) ─────────────────────────────────────────

func TestVerifyAndExtend_FirstHop(t *testing.T) {
	pub, priv := testKeyPair(t)
	v := NewVerifier(pub, priv, 3)

	result := v.VerifyAndExtend("", "agent-alpha")

	if !result.Valid {
		t.Fatalf("first hop should be valid: %s", result.Error)
	}
	if result.CurrentDepth != 1 {
		t.Errorf("first hop depth should be 1, got %d", result.CurrentDepth)
	}
	if len(result.Chain) != 1 {
		t.Fatalf("chain should have 1 hop, got %d", len(result.Chain))
	}
	if result.Chain[0].AgentID != "agent-alpha" {
		t.Errorf("first hop agent should be agent-alpha, got %s", result.Chain[0].AgentID)
	}
	if result.ExceedsMax {
		t.Error("depth 1 should not exceed max of 3")
	}
}

// ── Two-hop chain ─────────────────────────────────────────────────────────────

func TestVerifyAndExtend_TwoHops(t *testing.T) {
	pub, priv := testKeyPair(t)
	v := NewVerifier(pub, priv, 3)

	// First hop
	r1 := v.VerifyAndExtend("", "agent-alpha")
	if !r1.Valid {
		t.Fatalf("first hop failed: %s", r1.Error)
	}

	// Encode and pass to second hop
	encoded, err := Encode(r1.Chain)
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}

	r2 := v.VerifyAndExtend(encoded, "agent-beta")
	if !r2.Valid {
		t.Fatalf("second hop failed: %s", r2.Error)
	}
	if r2.CurrentDepth != 2 {
		t.Errorf("second hop depth should be 2, got %d", r2.CurrentDepth)
	}
	if len(r2.Chain) != 2 {
		t.Fatalf("chain should have 2 hops, got %d", len(r2.Chain))
	}
}

// ── Chain depth enforcement ───────────────────────────────────────────────────

func TestVerifyAndExtend_ExceedsMaxDepth(t *testing.T) {
	pub, priv := testKeyPair(t)
	v := NewVerifier(pub, priv, 2) // Max depth = 2

	// Build a 3-hop chain
	r1 := v.VerifyAndExtend("", "agent-a")
	e1, _ := Encode(r1.Chain)

	r2 := v.VerifyAndExtend(e1, "agent-b")
	e2, _ := Encode(r2.Chain)

	r3 := v.VerifyAndExtend(e2, "agent-c")

	if !r3.Valid {
		t.Fatalf("chain should be valid (signatures OK): %s", r3.Error)
	}
	if !r3.ExceedsMax {
		t.Error("depth 3 should exceed max of 2")
	}
}

// ── Tampered signature detection ──────────────────────────────────────────────

func TestVerifyAndExtend_TamperedSignature(t *testing.T) {
	pub, priv := testKeyPair(t)
	v := NewVerifier(pub, priv, 3)

	// Build a valid chain
	r1 := v.VerifyAndExtend("", "agent-alpha")

	// Tamper with the signature
	r1.Chain[0].Signature[0] ^= 0xFF

	tampered, err := Encode(r1.Chain)
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}

	r2 := v.VerifyAndExtend(tampered, "agent-beta")
	if r2.Valid {
		t.Fatal("tampered signature should be detected as invalid")
	}
	if r2.Error == "" {
		t.Error("should include error message for tampered signature")
	}
}

// ── Forged depth reset detection ──────────────────────────────────────────────

func TestVerifyAndExtend_ForgedDepthReset(t *testing.T) {
	pub, priv := testKeyPair(t)
	v := NewVerifier(pub, priv, 3)

	// Build 2-hop chain
	r1 := v.VerifyAndExtend("", "agent-a")
	e1, _ := Encode(r1.Chain)
	r2 := v.VerifyAndExtend(e1, "agent-b")

	// Attacker tries to reset depth to 1 by modifying the hop
	r2.Chain[1].Depth = 1

	forged, err := Encode(r2.Chain)
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}

	r3 := v.VerifyAndExtend(forged, "agent-c")
	if r3.Valid {
		t.Fatal("forged depth reset should fail signature verification")
	}
}

// ── Different key detection ───────────────────────────────────────────────────

func TestVerifyAndExtend_DifferentKey(t *testing.T) {
	pub1, priv1 := testKeyPair(t)
	pub2, _ := testKeyPair(t)

	// Sign with key 1
	v1 := NewVerifier(pub1, priv1, 3)
	r1 := v1.VerifyAndExtend("", "agent-a")
	e1, _ := Encode(r1.Chain)

	// Verify with key 2 — should fail
	v2 := NewVerifier(pub2, priv1, 3) // Wrong pub key for verification
	r2 := v2.VerifyAndExtend(e1, "agent-b")
	if r2.Valid {
		t.Fatal("chain signed with different key should fail verification")
	}
}

// ── ExtractUpstreamAgent ──────────────────────────────────────────────────────

func TestExtractUpstreamAgent(t *testing.T) {
	// Empty chain
	if got := ExtractUpstreamAgent(nil); got != "" {
		t.Errorf("nil chain should return empty, got %q", got)
	}

	// Single hop (no upstream)
	single := []ChainHop{{AgentID: "agent-a"}}
	if got := ExtractUpstreamAgent(single); got != "" {
		t.Errorf("single hop should return empty, got %q", got)
	}

	// Two hops
	two := []ChainHop{
		{AgentID: "agent-a"},
		{AgentID: "agent-b"},
	}
	if got := ExtractUpstreamAgent(two); got != "agent-a" {
		t.Errorf("expected agent-a, got %q", got)
	}
}

// ── Encode/Decode roundtrip ───────────────────────────────────────────────────

func TestEncodeDecode_Roundtrip(t *testing.T) {
	pub, priv := testKeyPair(t)
	v := NewVerifier(pub, priv, 3)

	r1 := v.VerifyAndExtend("", "agent-a")
	encoded, err := Encode(r1.Chain)
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}

	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if len(decoded) != 1 {
		t.Fatalf("expected 1 hop, got %d", len(decoded))
	}
	if decoded[0].AgentID != "agent-a" {
		t.Errorf("expected agent-a, got %s", decoded[0].AgentID)
	}
}
