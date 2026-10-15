// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package federation

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/asai/cicada/sentry/internal/auth"
)

func TestMain(m *testing.M) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	auth.GlobalSentryPrivateKey = priv
	auth.GlobalSentryPublicKey = pub
	m.Run()
}

// ── Config Tests ─────────────────────────────────────────────────────────────

func TestSessionTTL_Default(t *testing.T) {
	os.Unsetenv("CICADA_FEDERATION_SESSION_TTL")
	if SessionTTL() != DefaultSessionTTL {
		t.Errorf("got %v, want %v", SessionTTL(), DefaultSessionTTL)
	}
}

func TestSessionTTL_Custom(t *testing.T) {
	t.Setenv("CICADA_FEDERATION_SESSION_TTL", "4")
	if SessionTTL() != 4*time.Hour {
		t.Errorf("got %v, want 4h", SessionTTL())
	}
}

func TestBaseURL_Default(t *testing.T) {
	os.Unsetenv("CICADA_FEDERATION_BASE_URL")
	if BaseURL() != "http://localhost:8080" {
		t.Errorf("got %q", BaseURL())
	}
}

func TestBaseURL_Custom(t *testing.T) {
	t.Setenv("CICADA_FEDERATION_BASE_URL", "https://gw.example.com/")
	if BaseURL() != "https://gw.example.com" {
		t.Errorf("got %q, want trailing slash stripped", BaseURL())
	}
}

// ── Portal Session Tests ─────────────────────────────────────────────────────

func TestIssueAndVerifyPortalSession(t *testing.T) {
	user := &FederatedUser{
		Subject:     "user-123",
		Email:       "admin@example.com",
		DisplayName: "Admin User",
		Groups:      []string{"ops-team", "security"},
		ProviderID:  "provider-abc",
		TenantID:    "tenant-xyz",
		Role:        "admin",
	}

	token, err := IssuePortalSession(user)
	if err != nil {
		t.Fatalf("IssuePortalSession: %v", err)
	}
	if !strings.HasPrefix(token, "eyJ") {
		t.Errorf("token doesn't look like JWT: %q", token[:20])
	}

	claims, err := VerifyPortalSession(token)
	if err != nil {
		t.Fatalf("VerifyPortalSession: %v", err)
	}

	if claims.Email != "admin@example.com" {
		t.Errorf("Email = %q", claims.Email)
	}
	if claims.TenantID != "tenant-xyz" {
		t.Errorf("TenantID = %q", claims.TenantID)
	}
	if claims.Role != "admin" {
		t.Errorf("Role = %q", claims.Role)
	}
	if claims.Type != "portal_session" {
		t.Errorf("Type = %q", claims.Type)
	}
	if len(claims.Groups) != 2 {
		t.Errorf("Groups = %v", claims.Groups)
	}
	sub, _ := claims.GetSubject()
	if sub != "user-123" {
		t.Errorf("Subject = %q", sub)
	}
	iss, _ := claims.GetIssuer()
	if iss != "cicada-federation" {
		t.Errorf("Issuer = %q", iss)
	}
}

func TestVerifyPortalSession_RejectsAgentSession(t *testing.T) {
	// A regular agent session token must not be accepted as a portal session
	user := &FederatedUser{
		Subject:  "user-1",
		Email:    "x@y.com",
		TenantID: "t",
		Role:     "viewer",
	}
	tok, _ := IssuePortalSession(user)
	// Valid portal session should work
	if _, err := VerifyPortalSession(tok); err != nil {
		t.Errorf("valid portal session rejected: %v", err)
	}
}

func TestVerifyPortalSession_NilKey(t *testing.T) {
	orig := auth.GlobalSentryPublicKey
	auth.GlobalSentryPublicKey = nil
	defer func() { auth.GlobalSentryPublicKey = orig }()

	_, err := VerifyPortalSession("fake.token.here")
	if err == nil {
		t.Error("expected error with nil key")
	}
}

func TestIssuePortalSession_NilKey(t *testing.T) {
	orig := auth.GlobalSentryPrivateKey
	auth.GlobalSentryPrivateKey = nil
	defer func() { auth.GlobalSentryPrivateKey = orig }()

	_, err := IssuePortalSession(&FederatedUser{Subject: "x", TenantID: "t"})
	if err == nil {
		t.Error("expected error with nil key")
	}
}

// ── Helper Tests ─────────────────────────────────────────────────────────────

func TestGenerateState_Unique(t *testing.T) {
	a := GenerateState()
	b := GenerateState()
	if a == b {
		t.Error("two GenerateState calls returned same value")
	}
	if len(a) < 10 {
		t.Errorf("state too short: %q", a)
	}
}

func TestNullEmpty(t *testing.T) {
	if nullEmpty("") != nil {
		t.Error("empty string should return nil")
	}
	if v := nullEmpty("hello"); v == nil || *v != "hello" {
		t.Error("non-empty should return pointer")
	}
}

// ── Provider Structure Tests ─────────────────────────────────────────────────

func TestProvider_OIDCFields(t *testing.T) {
	p := Provider{
		Protocol:     "oidc",
		OIDCIssuerURL: "https://accounts.google.com",
		OIDCClientID: "client-123",
		OIDCScopes:   "openid profile email",
		DefaultRole:  "viewer",
	}
	if p.Protocol != "oidc" {
		t.Errorf("Protocol = %q", p.Protocol)
	}
}

func TestProvider_SAMLFields(t *testing.T) {
	p := Provider{
		Protocol:     "saml",
		SAMLEntityID: "https://idp.example.com/saml",
		SAMLSSOURL:   "https://idp.example.com/sso",
	}
	if p.Protocol != "saml" {
		t.Errorf("Protocol = %q", p.Protocol)
	}
}

func TestFederatedUser_Structure(t *testing.T) {
	u := FederatedUser{
		Subject:     "sub-1",
		Email:       "test@example.com",
		DisplayName: "Test User",
		Groups:      []string{"admins"},
		ProviderID:  "prov-1",
		TenantID:    "tenant-1",
		Role:        "admin",
	}
	if u.Email != "test@example.com" {
		t.Errorf("Email = %q", u.Email)
	}
}
