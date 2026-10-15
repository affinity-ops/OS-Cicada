// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package auth — Tests for user-context parsing, OAuth token exchange claim
// validation, actor chain flattening, and audience validation.
//
// Test categories:
//   - Plain identifier mode (no JWKS)
//   - Actor chain (RFC 8693) flattening
//   - String() representation with delegation chains
//   - ToJSON() serialisation
//   - Audience validation
//   - Configuration helpers
package auth

import (
	"encoding/json"
	"os"
	"testing"
)

// ── Plain Identifier Mode ───────────────────────────────────────────────────

func TestParseUserContext_EmptyHeader(t *testing.T) {
	result := ParseUserContext("")
	if result != nil {
		t.Errorf("expected nil for empty header, got %+v", result)
	}
}

func TestParseUserContext_WhitespaceOnly(t *testing.T) {
	result := ParseUserContext("   ")
	if result != nil {
		t.Errorf("expected nil for whitespace-only header, got %+v", result)
	}
}

func TestParseUserContext_PlainEmail(t *testing.T) {
	result := ParseUserContext("user@example.com")
	if result == nil {
		t.Fatal("expected non-nil result for plain email")
	}
	if result.Subject != "user@example.com" {
		t.Errorf("expected subject=user@example.com, got %q", result.Subject)
	}
	if result.Verified {
		t.Error("plain identifier should be unverified")
	}
	if result.Raw != "user@example.com" {
		t.Errorf("expected raw=user@example.com, got %q", result.Raw)
	}
}

func TestParseUserContext_PlainUserID(t *testing.T) {
	result := ParseUserContext("usr_12345abcde")
	if result == nil {
		t.Fatal("expected non-nil result for plain user ID")
	}
	if result.Subject != "usr_12345abcde" {
		t.Errorf("expected subject=usr_12345abcde, got %q", result.Subject)
	}
}

// ── Actor Chain (RFC 8693) ──────────────────────────────────────────────────

func TestFlattenActClaim_Nil(t *testing.T) {
	chain := flattenActClaim(nil)
	if chain != nil {
		t.Errorf("expected nil chain for nil input, got %+v", chain)
	}
}

func TestFlattenActClaim_SingleActor(t *testing.T) {
	act := map[string]interface{}{
		"sub": "agent-service-01",
	}
	chain := flattenActClaim(act)
	if len(chain) != 1 {
		t.Fatalf("expected 1 actor, got %d", len(chain))
	}
	if chain[0].Subject != "agent-service-01" {
		t.Errorf("expected sub=agent-service-01, got %q", chain[0].Subject)
	}
}

func TestFlattenActClaim_NestedChain(t *testing.T) {
	// Simulates: User → orchestrator-api → agent-service → Gateway
	act := map[string]interface{}{
		"sub":       "agent-service",
		"client_id": "client-abc",
		"act": map[string]interface{}{
			"sub": "orchestrator-api",
			"act": map[string]interface{}{
				"sub": "user-gateway",
			},
		},
	}
	chain := flattenActClaim(act)
	if len(chain) != 3 {
		t.Fatalf("expected 3 actors, got %d", len(chain))
	}
	if chain[0].Subject != "agent-service" {
		t.Errorf("actor[0].sub = %q, want agent-service", chain[0].Subject)
	}
	if chain[0].ClientID != "client-abc" {
		t.Errorf("actor[0].client_id = %q, want client-abc", chain[0].ClientID)
	}
	if chain[1].Subject != "orchestrator-api" {
		t.Errorf("actor[1].sub = %q, want orchestrator-api", chain[1].Subject)
	}
	if chain[2].Subject != "user-gateway" {
		t.Errorf("actor[2].sub = %q, want user-gateway", chain[2].Subject)
	}
}

func TestFlattenActClaim_DepthLimit(t *testing.T) {
	// Build a chain deeper than the 10-level limit.
	deepest := map[string]interface{}{"sub": "depth-11"}
	current := deepest
	for i := 10; i >= 1; i-- {
		current = map[string]interface{}{
			"sub": "depth-" + string(rune('0'+i%10)),
			"act": current,
		}
	}
	chain := flattenActClaim(current)
	if len(chain) > 10 {
		t.Errorf("chain length %d exceeds maxDepth 10", len(chain))
	}
}

func TestFlattenActClaim_EmptySubAndClientID(t *testing.T) {
	// An act claim with no sub and no client_id should stop extraction.
	act := map[string]interface{}{
		"some_other_field": "irrelevant",
	}
	chain := flattenActClaim(act)
	if len(chain) != 0 {
		t.Errorf("expected empty chain for act with no sub/client_id, got %d", len(chain))
	}
}

func TestFlattenActClaim_ClientIDOnly(t *testing.T) {
	// An actor identified only by client_id (no sub) is still valid.
	act := map[string]interface{}{
		"client_id": "service-x",
	}
	chain := flattenActClaim(act)
	if len(chain) != 1 {
		t.Fatalf("expected 1 actor, got %d", len(chain))
	}
	if chain[0].ClientID != "service-x" {
		t.Errorf("expected client_id=service-x, got %q", chain[0].ClientID)
	}
	if chain[0].Subject != "" {
		t.Errorf("expected empty sub, got %q", chain[0].Subject)
	}
}

// ── String() Representation ─────────────────────────────────────────────────

func TestString_PlainUnverified(t *testing.T) {
	uc := UserContext{Subject: "user_123", Verified: false}
	got := uc.String()
	expected := "user_123 [unverified]"
	if got != expected {
		t.Errorf("String() = %q, want %q", got, expected)
	}
}

func TestString_VerifiedWithEmail(t *testing.T) {
	uc := UserContext{Email: "alice@example.com", Name: "Alice", Verified: true}
	got := uc.String()
	expected := "alice@example.com (Alice) [verified]"
	if got != expected {
		t.Errorf("String() = %q, want %q", got, expected)
	}
}

func TestString_WithActorChain(t *testing.T) {
	uc := UserContext{
		Subject:  "user_123",
		Verified: true,
		ActorChain: []ActorClaim{
			{Subject: "agent-service"},
			{Subject: "orchestrator"},
		},
	}
	got := uc.String()
	if got != "user_123 [verified] via agent-service → orchestrator" {
		t.Errorf("String() = %q", got)
	}
}

// ── ToJSON() Serialisation ──────────────────────────────────────────────────

func TestToJSON_Empty(t *testing.T) {
	uc := UserContext{}
	got := uc.ToJSON()
	if got != "" {
		t.Errorf("ToJSON() should return empty string for empty context, got %q", got)
	}
}

func TestToJSON_WithTokenExchangeFields(t *testing.T) {
	uc := UserContext{
		Subject:  "user_456",
		Email:    "bob@example.com",
		Verified: true,
		ClientID: "client-xyz",
		Scope:    "read:profile write:orders",
		ActorChain: []ActorClaim{
			{Subject: "agent-svc", ClientID: "client-xyz"},
		},
	}
	jsonStr := uc.ToJSON()
	if jsonStr == "" {
		t.Fatal("ToJSON() returned empty string for populated context")
	}

	// Parse back and verify fields survive round-trip.
	var parsed UserContext
	if err := json.Unmarshal([]byte(jsonStr), &parsed); err != nil {
		t.Fatalf("failed to unmarshal ToJSON output: %v", err)
	}
	if parsed.ClientID != "client-xyz" {
		t.Errorf("round-trip ClientID = %q, want client-xyz", parsed.ClientID)
	}
	if parsed.Scope != "read:profile write:orders" {
		t.Errorf("round-trip Scope = %q, want read:profile write:orders", parsed.Scope)
	}
	if len(parsed.ActorChain) != 1 {
		t.Fatalf("round-trip ActorChain length = %d, want 1", len(parsed.ActorChain))
	}
	if parsed.ActorChain[0].Subject != "agent-svc" {
		t.Errorf("round-trip ActorChain[0].Subject = %q, want agent-svc", parsed.ActorChain[0].Subject)
	}
}

// ── Configuration Helpers ───────────────────────────────────────────────────

func TestIsUserContextRequired_Default(t *testing.T) {
	os.Unsetenv("CICADA_USER_CONTEXT_REQUIRED")
	if IsUserContextRequired() {
		t.Error("expected false when env var is not set")
	}
}

func TestIsUserContextRequired_True(t *testing.T) {
	os.Setenv("CICADA_USER_CONTEXT_REQUIRED", "true")
	defer os.Unsetenv("CICADA_USER_CONTEXT_REQUIRED")
	if !IsUserContextRequired() {
		t.Error("expected true when env var is 'true'")
	}
}

func TestIsUserContextRequired_CaseInsensitive(t *testing.T) {
	os.Setenv("CICADA_USER_CONTEXT_REQUIRED", "TRUE")
	defer os.Unsetenv("CICADA_USER_CONTEXT_REQUIRED")
	if !IsUserContextRequired() {
		t.Error("expected true for 'TRUE' (case-insensitive)")
	}
}

func TestIsUserContextRequired_False(t *testing.T) {
	os.Setenv("CICADA_USER_CONTEXT_REQUIRED", "false")
	defer os.Unsetenv("CICADA_USER_CONTEXT_REQUIRED")
	if IsUserContextRequired() {
		t.Error("expected false when env var is 'false'")
	}
}

// ── ParseUserContext with JWKS fallback ─────────────────────────────────────

func TestParseUserContext_InvalidJWTFallsBackToPlain(t *testing.T) {
	// When JWKS is configured but the token is not a valid JWT, we should
	// fall back to plain identifier mode rather than rejecting.
	os.Setenv("CICADA_USER_CONTEXT_JWKS_URL", "https://example.com/.well-known/jwks.json")
	defer os.Unsetenv("CICADA_USER_CONTEXT_JWKS_URL")

	result := ParseUserContext("not-a-jwt-token")
	if result == nil {
		t.Fatal("expected non-nil result (should fall back to plain mode)")
	}
	if result.Verified {
		t.Error("expected unverified (JWKS fetch will fail)")
	}
	if result.Subject != "not-a-jwt-token" {
		t.Errorf("expected raw value as subject, got %q", result.Subject)
	}
}
