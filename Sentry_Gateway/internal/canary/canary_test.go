// © 2026 Patrick Matthews (Affinity Ops / Affinity Smart AI)
// SPDX-License-Identifier: Apache-2.0

package canary

import (
	"encoding/base64"
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

// ── Issue / CheckOutbound / Revoke In-Memory Fallback (Nil Redis) ────────────

func TestIssue_CheckOutbound_Revoke_InMemoryLifecycle(t *testing.T) {
	ctx := t.Context()

	// Empty agentID or tenantID returns error
	if _, err := Issue(ctx, "", "tenant-1", TokenTypeAPIKey); err == nil {
		t.Fatal("Issue with empty agentID should return error")
	}

	tok, err := Issue(ctx, "agent-rogue-1", "tenant-acme-99", TokenTypeAPIKey)
	if err != nil {
		t.Fatalf("Issue failed in standalone in-memory mode: %v", err)
	}
	if !strings.HasPrefix(tok.Value, "CICADA_CANARY_APIKEY_tenant_") {
		t.Fatalf("unexpected token format: %q", tok.Value)
	}

	// Unissued token for another tenant returns nil
	if res := CheckOutbound(ctx, "other-tenant", tok.Value); res != nil {
		t.Fatalf("expected nil for mismatched tenant, got %+v", res)
	}

	// Raw match triggers incident with exact AgentID & CreatedAt timestamp
	res := CheckOutbound(ctx, "tenant-acme-99", `{"leak":"`+tok.Value+`"}`)
	if res == nil {
		t.Fatal("expected CheckOutbound to detect issued canary token")
	}
	if res.AgentID != "agent-rogue-1" || res.TokenValue != tok.Value || res.InjectedAt.IsZero() {
		t.Fatalf("unexpected TriggerResult: %+v", res)
	}

	// Base64-encoded match also triggers incident
	b64 := base64.StdEncoding.EncodeToString([]byte(tok.Value))
	resB64 := CheckOutbound(ctx, "tenant-acme-99", `{"payload":"`+b64+`"}`)
	if resB64 == nil || resB64.TokenValue != tok.Value {
		t.Fatalf("expected CheckOutbound to detect Base64-encoded canary token, got %+v", resB64)
	}

	// Revoke removes token from active monitoring
	if err := Revoke(ctx, "tenant-acme-99", tok.Value); err != nil {
		t.Fatalf("Revoke failed: %v", err)
	}
	if after := CheckOutbound(ctx, "tenant-acme-99", tok.Value); after != nil {
		t.Fatalf("expected nil after Revoke, got %+v", after)
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
