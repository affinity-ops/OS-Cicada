// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/asai/cicada/sentry/internal/auth"
)

// TestMain generates a fresh in-memory Ed25519 keypair for all session tests.
// No file I/O, no environment variables required.
func TestMain(m *testing.M) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic("failed to generate test Ed25519 keypair: " + err.Error())
	}
	auth.GlobalSentryPrivateKey = priv
	auth.GlobalSentryPublicKey = pub
	m.Run()
}

// ── Issue ────────────────────────────────────────────────────────────────────

func TestIssue_ReturnsJWT(t *testing.T) {
	tok, err := Issue("agent-1", "tenant-1", []string{"proxy:chat"}, false, "", nil, "")
	if err != nil {
		t.Fatalf("Issue returned error: %v", err)
	}
	if !strings.HasPrefix(tok, "eyJ") {
		t.Errorf("Issued token does not look like a JWT: %q", tok[:min(len(tok), 20)])
	}
}

func TestIssue_ClaimsRoundTrip(t *testing.T) {
	scopes := []string{"proxy:chat", "proxy:read"}
	tok, err := Issue("agent-claims", "tenant-claims", scopes, true, "https://hooks.example.com/hitl", nil, "eu-west-1")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	claims, err := Verify(tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	if claims.AgentID != "agent-claims" {
		t.Errorf("AgentID = %q, want %q", claims.AgentID, "agent-claims")
	}
	if claims.TenantID != "tenant-claims" {
		t.Errorf("TenantID = %q, want %q", claims.TenantID, "tenant-claims")
	}
	if len(claims.Scopes) != 2 || claims.Scopes[0] != "proxy:chat" {
		t.Errorf("Scopes = %v, want %v", claims.Scopes, scopes)
	}
	if !claims.HITLRequired {
		t.Error("HITLRequired = false, want true")
	}
	if claims.HITLWebhookURL != "https://hooks.example.com/hitl" {
		t.Errorf("HITLWebhookURL = %q", claims.HITLWebhookURL)
	}
	if claims.DataResidencyRegion != "eu-west-1" {
		t.Errorf("DataResidencyRegion = %q, want %q", claims.DataResidencyRegion, "eu-west-1")
	}
	if claims.Type != "session" {
		t.Errorf("Type = %q, want %q", claims.Type, "session")
	}
}

func TestIssue_TTLIs15Minutes(t *testing.T) {
	// Truncate to second precision before recording because JWT NumericDate
	// stores unix seconds — sub-second components are lost on round-trip.
	before := time.Now().Truncate(time.Second)
	tok, _ := Issue("agent-ttl", "tenant-ttl", nil, false, "", nil, "")
	after := time.Now().Truncate(time.Second)

	claims, err := Verify(tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	exp := claims.ExpiresAt.Time
	minExp := before.Add(SessionTTL())
	maxExp := after.Add(SessionTTL())

	if exp.Before(minExp) || exp.After(maxExp) {
		t.Errorf("ExpiresAt %v not within expected window [%v, %v]", exp, minExp, maxExp)
	}
}

func TestIssue_NilPrivateKey(t *testing.T) {
	// Temporarily unset key to verify error path.
	orig := auth.GlobalSentryPrivateKey
	auth.GlobalSentryPrivateKey = nil
	defer func() { auth.GlobalSentryPrivateKey = orig }()

	_, err := Issue("agent-x", "tenant-x", nil, false, "", nil, "")
	if err == nil {
		t.Error("Expected error when private key is nil, got nil")
	}
}

// ── Verify ───────────────────────────────────────────────────────────────────

func TestVerify_TamperedSignature(t *testing.T) {
	tok, _ := Issue("agent-tamper", "tenant-tamper", nil, false, "", nil, "")

	// Corrupt the payload (middle segment) to guarantee signature mismatch.
	// Flipping just the last character of a JWT can land on base64 padding
	// and not actually corrupt the EdDSA signature.
	parts := strings.SplitN(tok, ".", 3)
	if len(parts) != 3 {
		t.Fatalf("token does not have 3 parts: %q", tok)
	}
	// Mutate a byte in the payload segment
	payload := []byte(parts[1])
	if len(payload) > 5 {
		payload[5] ^= 0xFF // flip bits in a payload byte
	}
	tampered := parts[0] + "." + string(payload) + "." + parts[2]

	_, err := Verify(tampered)
	if err == nil {
		t.Error("Expected error for tampered token, got nil")
	}
}


func TestVerify_RejectsEVARTypeToken(t *testing.T) {
	// Mint a token with type="evar" using the same key — Verify must reject it.
	now := time.Now()
	claims := jwt.MapClaims{
		"type":     "evar", // wrong type discriminator
		"agent_id": "agent-evar",
		"iss":      "cicada-cocoon-lab",
		"iat":      now.Unix(),
		"exp":      now.Add(24 * time.Hour).Unix(),
	}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims).SignedString(auth.GlobalSentryPrivateKey)
	if err != nil {
		t.Fatalf("failed to mint evar-type token: %v", err)
	}

	_, verifyErr := Verify(tok)
	if verifyErr == nil {
		t.Error("Expected Verify to reject type=evar token, got nil error")
	}
	if !strings.Contains(verifyErr.Error(), "not a session token") {
		t.Errorf("Expected 'not a session token' in error, got: %v", verifyErr)
	}
}

func TestVerify_RejectsExpiredToken(t *testing.T) {
	// Mint a token that expired 1 second ago.
	past := time.Now().Add(-1 * time.Second)
	claims := SessionClaims{
		Type:     "session",
		AgentID:  "agent-expired",
		TenantID: "tenant-expired",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "cicada-gateway-session",
			IssuedAt:  jwt.NewNumericDate(past.Add(-SessionTTL())),
			ExpiresAt: jwt.NewNumericDate(past),
		},
	}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims).SignedString(auth.GlobalSentryPrivateKey)
	if err != nil {
		t.Fatalf("failed to mint expired token: %v", err)
	}

	_, verifyErr := Verify(tok)
	if verifyErr == nil {
		t.Error("Expected Verify to reject expired token, got nil error")
	}
}

func TestVerify_RejectsWrongAlgorithm(t *testing.T) {
	// HS256-signed token must be rejected — algorithm confusion attack vector.
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"type":     "session",
		"agent_id": "agent-alg",
		"exp":      time.Now().Add(time.Hour).Unix(),
	}).SignedString([]byte("weak-secret"))
	if err != nil {
		t.Fatalf("failed to mint HS256 token: %v", err)
	}

	_, verifyErr := Verify(tok)
	if verifyErr == nil {
		t.Error("Expected Verify to reject HS256 token, got nil error")
	}
}

func TestVerify_NilPublicKey(t *testing.T) {
	tok, _ := Issue("agent-nopub", "tenant-nopub", nil, false, "", nil, "")

	orig := auth.GlobalSentryPublicKey
	auth.GlobalSentryPublicKey = nil
	defer func() { auth.GlobalSentryPublicKey = orig }()

	_, err := Verify(tok)
	if err == nil {
		t.Error("Expected error when public key is nil")
	}
}

// ── ScopesContainWriteOrTransact ─────────────────────────────────────────────

func TestScopesContainWriteOrTransact(t *testing.T) {
	cases := []struct {
		scopes []string
		want   bool
	}{
		{[]string{"proxy:write"}, true},
		{[]string{"proxy:transact"}, true},
		{[]string{"proxy:chat", "proxy:write"}, true},
		{[]string{"proxy:chat", "proxy:read"}, false},
		{[]string{}, false},
		{nil, false},
		{[]string{"proxy:WRITE"}, false}, // case-sensitive — exact match only
	}

	for _, tc := range cases {
		got := ScopesContainWriteOrTransact(tc.scopes)
		if got != tc.want {
			t.Errorf("ScopesContainWriteOrTransact(%v) = %v, want %v", tc.scopes, got, tc.want)
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
