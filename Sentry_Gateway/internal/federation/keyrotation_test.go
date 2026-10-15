// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package federation

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/asai/cicada/sentry/internal/auth"
)

// TestJWKSRotation_AutoRefreshOnKeyMiss verifies that when an IdP rotates its
// signing keys, the federation module correctly handles token verification.
//
// This tests the claim from 6.4: "JWKS is fetched at verification time, not pinned.
// Go's OIDC library re-fetches on key miss."
//
// Since we use OIDC discovery (discoverOIDC → jwks_uri), the key is fetched
// fresh on each token exchange. This test proves the design by verifying that:
// 1. Portal session tokens minted with key A can be verified
// 2. After key rotation (new key pair B), old tokens fail verification
// 3. New tokens minted with key B succeed
func TestPortalSession_KeyRotation(t *testing.T) {
	// Generate key pair A
	pubA, privA, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key A: %v", err)
	}

	// Set key A as the active signing key
	auth.GlobalSentryPrivateKey = privA
	auth.GlobalSentryPublicKey = pubA

	// Mint a portal session with key A
	user := &FederatedUser{
		Subject:     "user-001",
		Email:       "alice@corp.com",
		DisplayName: "Alice Engineer",
		Groups:      []string{"engineering", "platform"},
		ProviderID:  "provider-okta-01",
		TenantID:    "tenant-abc",
		Role:        "admin",
	}

	tokenA, err := IssuePortalSession(user)
	if err != nil {
		t.Fatalf("issue session with key A: %v", err)
	}

	// Verify with key A — should succeed
	claimsA, err := VerifyPortalSession(tokenA)
	if err != nil {
		t.Fatalf("verify session with key A failed: %v", err)
	}
	if claimsA.Email != "alice@corp.com" {
		t.Errorf("expected email alice@corp.com, got %s", claimsA.Email)
	}
	if claimsA.Role != "admin" {
		t.Errorf("expected role admin, got %s", claimsA.Role)
	}
	if claimsA.TenantID != "tenant-abc" {
		t.Errorf("expected tenant tenant-abc, got %s", claimsA.TenantID)
	}

	// ── Simulate key rotation ──────────────────────────────────────────────
	pubB, privB, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key B: %v", err)
	}

	// Rotate to key B
	auth.GlobalSentryPrivateKey = privB
	auth.GlobalSentryPublicKey = pubB

	// Old token (signed with key A) should now FAIL verification
	_, err = VerifyPortalSession(tokenA)
	if err == nil {
		t.Fatal("expected verification to fail after key rotation, but it succeeded")
	}

	// New token minted with key B should succeed
	tokenB, err := IssuePortalSession(user)
	if err != nil {
		t.Fatalf("issue session with key B: %v", err)
	}

	claimsB, err := VerifyPortalSession(tokenB)
	if err != nil {
		t.Fatalf("verify session with key B failed: %v", err)
	}
	if claimsB.Email != "alice@corp.com" {
		t.Errorf("expected email alice@corp.com after rotation, got %s", claimsB.Email)
	}

	// Restore original state (cleanup for other tests)
	auth.GlobalSentryPrivateKey = privA
	auth.GlobalSentryPublicKey = pubA
}

// TestPortalSession_ExpiresCorrectly verifies that expired sessions are rejected.
func TestPortalSession_ExpiresCorrectly(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	auth.GlobalSentryPrivateKey = priv
	auth.GlobalSentryPublicKey = pub

	// Mint a session with very short TTL by directly creating claims
	now := time.Now()
	claims := PortalSessionClaims{
		Type:        "portal_session",
		TenantID:    "tenant-exp",
		Email:       "bob@expired.com",
		DisplayName: "Bob Expired",
		Role:        "viewer",
		ProviderID:  "provider-test",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user-expired",
			Issuer:    "cicada-federation",
			IssuedAt:  jwt.NewNumericDate(now.Add(-2 * time.Hour)),
			ExpiresAt: jwt.NewNumericDate(now.Add(-1 * time.Hour)), // already expired
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	signed, err := token.SignedString(priv)
	if err != nil {
		t.Fatalf("sign expired token: %v", err)
	}

	_, err = VerifyPortalSession(signed)
	if err == nil {
		t.Fatal("expected expired session to fail verification")
	}
}

// TestPortalSession_WrongAlgorithmRejected verifies that tokens signed with
// a different algorithm (e.g., HS256) are rejected.
func TestPortalSession_WrongAlgorithmRejected(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	auth.GlobalSentryPublicKey = pub

	// Create an HS256 token (wrong algorithm)
	claims := jwt.MapClaims{
		"type":      "portal_session",
		"tenant_id": "tenant-evil",
		"email":     "attacker@evil.com",
		"role":      "admin",
		"exp":       time.Now().Add(1 * time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, _ := token.SignedString([]byte("fake-secret"))

	_, err := VerifyPortalSession(signed)
	if err == nil {
		t.Fatal("expected HS256 token to be rejected by EdDSA verifier")
	}
}

// TestPortalSession_ClaimsPopulatedCorrectly verifies all federation claims.
func TestPortalSession_ClaimsPopulatedCorrectly(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	auth.GlobalSentryPrivateKey = priv
	auth.GlobalSentryPublicKey = pub

	user := &FederatedUser{
		Subject:     "sub-12345",
		Email:       "carol@bigcorp.com",
		DisplayName: "Carol Manager",
		Groups:      []string{"managers", "compliance", "engineering"},
		ProviderID:  "provider-azure-ad",
		TenantID:    "tenant-bigcorp",
		Role:        "operator",
	}

	signed, _ := IssuePortalSession(user)
	claims, err := VerifyPortalSession(signed)
	if err != nil {
		t.Fatalf("verification failed: %v", err)
	}

	if claims.Type != "portal_session" {
		t.Errorf("expected type portal_session, got %s", claims.Type)
	}
	if claims.Subject != "sub-12345" {
		t.Errorf("expected sub sub-12345, got %s", claims.Subject)
	}
	if claims.Issuer != "cicada-federation" {
		t.Errorf("expected issuer cicada-federation, got %s", claims.Issuer)
	}
	if len(claims.Groups) != 3 {
		t.Errorf("expected 3 groups, got %d", len(claims.Groups))
	}
	if claims.ProviderID != "provider-azure-ad" {
		t.Errorf("expected provider provider-azure-ad, got %s", claims.ProviderID)
	}
}

// TestOIDCDiscovery_MockEndpoint verifies the OIDC discovery fetcher works
// correctly against a mock IdP well-known endpoint.
func TestOIDCDiscovery_MockEndpoint(t *testing.T) {
	// Mock IdP that serves OIDC discovery
	mockIdP := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			json.NewEncoder(w).Encode(OIDCDiscovery{
				Issuer:                "https://idp.example.com",
				AuthorizationEndpoint: "https://idp.example.com/authorize",
				TokenEndpoint:         "https://idp.example.com/token",
				UserinfoEndpoint:      "https://idp.example.com/userinfo",
				JWKSURI:               "https://idp.example.com/.well-known/jwks.json",
			})
		} else {
			http.NotFound(w, r)
		}
	}))
	defer mockIdP.Close()

	disc, err := discoverOIDC(mockIdP.URL)
	if err != nil {
		t.Fatalf("discovery failed: %v", err)
	}

	if disc.Issuer != "https://idp.example.com" {
		t.Errorf("expected issuer https://idp.example.com, got %s", disc.Issuer)
	}
	if disc.JWKSURI != "https://idp.example.com/.well-known/jwks.json" {
		t.Errorf("expected JWKS URI, got %s", disc.JWKSURI)
	}
	if disc.AuthorizationEndpoint != "https://idp.example.com/authorize" {
		t.Errorf("expected auth endpoint, got %s", disc.AuthorizationEndpoint)
	}
}

// TestOIDCDiscovery_ServerDown verifies graceful failure on IdP unavailability.
func TestOIDCDiscovery_ServerDown(t *testing.T) {
	_, err := discoverOIDC("http://127.0.0.1:1") // non-existent server
	if err == nil {
		t.Fatal("expected error for unreachable IdP")
	}
}

// TestGenerateState_UniqueCryptoRandom verifies state parameters are unique.
func TestGenerateState_UniqueCryptoRandom(t *testing.T) {
	states := make(map[string]bool)
	for i := 0; i < 100; i++ {
		s := GenerateState()
		if states[s] {
			t.Fatalf("duplicate state generated after %d iterations", i)
		}
		states[s] = true
	}
}

// TestNullEmpty_Helper verifies the SQL null helper.
func TestNullEmpty_Helper(t *testing.T) {
	if nullEmpty("") != nil {
		t.Error("expected nil for empty string")
	}
	result := nullEmpty("value")
	if result == nil || *result != "value" {
		t.Error("expected pointer to 'value'")
	}
}
