// © 2026 Affinity Ops Ltd. All rights reserved.
// Proprietary and confidential. Unauthorized copying or distribution prohibited.

package canary

import (
	"strings"
	"testing"
)

// ── Token Format ──────────────────────────────────────────────────────────────

func TestTokenTypes(t *testing.T) {
	if TokenTypeAPIKey != "APIKEY" {
		t.Errorf("TokenTypeAPIKey = %q", TokenTypeAPIKey)
	}
	if TokenTypeJWT != "JWT" {
		t.Errorf("TokenTypeJWT = %q", TokenTypeJWT)
	}
	if TokenTypeSecret != "SECRET" {
		t.Errorf("TokenTypeSecret = %q", TokenTypeSecret)
	}
	if TokenTypeDBCreds != "DBCREDS" {
		t.Errorf("TokenTypeDBCreds = %q", TokenTypeDBCreds)
	}
}

// ── Redis Key Helpers ─────────────────────────────────────────────────────────

func TestRedisKey_Format(t *testing.T) {
	key := redisKey("CICADA_CANARY_APIKEY_acme12_a3f7b9c2d1e4f508")
	expected := "cicada:canary:CICADA_CANARY_APIKEY_acme12_a3f7b9c2d1e4f508"
	if key != expected {
		t.Errorf("redisKey = %q, want %q", key, expected)
	}
}

func TestTenantSetKey_Format(t *testing.T) {
	key := tenantSetKey("tenant-uuid-123")
	expected := "cicada:canary:tenant:tenant-uuid-123"
	if key != expected {
		t.Errorf("tenantSetKey = %q, want %q", key, expected)
	}
}

// ── Issue without Redis (fail path) ───────────────────────────────────────────

func TestIssue_NilRedis_ReturnsError(t *testing.T) {
	_, err := Issue(t.Context(), "agent-1", "tenant-1", TokenTypeAPIKey)
	if err == nil {
		t.Error("Issue with nil Redis should return error")
	}
	if !strings.Contains(err.Error(), "Redis") {
		t.Errorf("error should mention Redis, got: %v", err)
	}
}

// ── CheckOutbound without Redis (fail-open) ───────────────────────────────────

func TestCheckOutbound_NilRedis_ReturnsNil(t *testing.T) {
	result := CheckOutbound(t.Context(), "tenant-1", "some content with CICADA_CANARY_APIKEY_acme12_a3f7b9c2d1e4f508")
	if result != nil {
		t.Error("CheckOutbound with nil Redis should return nil (fail-open)")
	}
}

// ── Revoke without Redis ──────────────────────────────────────────────────────

func TestRevoke_NilRedis_ReturnsError(t *testing.T) {
	err := Revoke(t.Context(), "tenant-1", "CICADA_CANARY_APIKEY_acme12_a3f7b9c2d1e4f508")
	if err == nil {
		t.Error("Revoke with nil Redis should return error")
	}
}

// ── Token struct fields ───────────────────────────────────────────────────────

func TestTokenStruct(t *testing.T) {
	tok := Token{
		Value:    "CICADA_CANARY_APIKEY_acme12_a3f7b9c2d1e4f508",
		Type:     TokenTypeAPIKey,
		AgentID:  "agent-1",
		TenantID: "tenant-1",
	}
	if !strings.HasPrefix(tok.Value, "CICADA_CANARY_") {
		t.Errorf("canary token should have CICADA_CANARY_ prefix, got %q", tok.Value)
	}
	if tok.Type != TokenTypeAPIKey {
		t.Errorf("token type = %q", tok.Type)
	}
}

func TestTriggerResult_Struct(t *testing.T) {
	tr := TriggerResult{
		TokenValue: "CICADA_CANARY_APIKEY_acme12_abc123",
		AgentID:    "agent-rogue",
		TenantID:   "tenant-victim",
	}
	if tr.AgentID != "agent-rogue" {
		t.Errorf("AgentID = %q", tr.AgentID)
	}
}

func TestContainsCanaryToken_RawAndEncoded(t *testing.T) {
	// Raw canary token
	found, tok := ContainsCanaryToken(`{"token": "CICADA_CANARY_APIKEY_acme_a3f7b9c2d1e4f508"}`)
	if !found || tok != "CICADA_CANARY_APIKEY_acme_a3f7b9c2d1e4f508" {
		t.Fatalf("expected raw canary match, got found=%v tok=%q", found, tok)
	}

	// Base64("CICADA_CANARY_APIKEY_acme_a3f7b9c2d1e4f508") = "Q0lDQURB_Q0FOQVJZX0FQSUtFWV9hY21lX2EzZjdiOWMyZDFlNGY1MDg="
	b64Canary := `{"encoded": "Q0lDQURBX0NBTkFSWV9BUElLRVlfYWNtZV9hM2Y3YjljMmQxZTRmNTA4"}`
	foundB64, tokB64 := ContainsCanaryToken(b64Canary)
	if !foundB64 || tokB64 != "CICADA_CANARY_APIKEY_acme_a3f7b9c2d1e4f508" {
		t.Fatalf("expected Base64 canary match, got found=%v tok=%q", foundB64, tokB64)
	}

	// Clean string
	foundClean, _ := ContainsCanaryToken(`{"action": "normal_operation"}`)
	if foundClean {
		t.Fatal("clean string should not trigger canary detection")
	}
}
