// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package output

import (
	"testing"
)

// ── Destination Classification Tests ─────────────────────────────────────────

func TestClassifyDestination_ExfiltrationSink(t *testing.T) {
	sinks := []string{
		"https://webhook.site/abc123",
		"https://pastebin.com/raw/xyz",
		"https://requestbin.com/r/abc",
		"https://evil.burpcollaborator.net/leak",
		"https://abc123.ngrok.io/collect",
	}

	for _, url := range sinks {
		trust := ClassifyDestination(url, nil, nil)
		if trust != TrustExfiltrationSink {
			t.Errorf("expected TrustExfiltrationSink for %s, got %d", url, trust)
		}
	}
}

func TestClassifyDestination_PropagationAllowlist(t *testing.T) {
	allowlist := []string{"api.stripe.com", "vault.hashicorp.com"}

	trust := ClassifyDestination("https://api.stripe.com/v1/tokens", allowlist, nil)
	if trust != TrustPropagation {
		t.Errorf("expected TrustPropagation for allowlisted domain, got %d", trust)
	}
}

func TestClassifyDestination_KnownDomain(t *testing.T) {
	historical := map[string]bool{
		"api.example.com": true,
		"db.internal.com": true,
	}

	trust := ClassifyDestination("https://api.example.com/v1/data", nil, historical)
	if trust != TrustKnown {
		t.Errorf("expected TrustKnown for historical domain, got %d", trust)
	}
}

func TestClassifyDestination_NewDomain(t *testing.T) {
	historical := map[string]bool{
		"api.example.com": true,
	}

	trust := ClassifyDestination("https://never-seen-before.com/collect", nil, historical)
	if trust != TrustNewDomain {
		t.Errorf("expected TrustNewDomain, got %d", trust)
	}
}

func TestClassifyDestination_PropagationTakesPriority(t *testing.T) {
	// Even if a domain is in the historical set, propagation allowlist wins
	allowlist := []string{"api.stripe.com"}
	historical := map[string]bool{"api.stripe.com": true}

	trust := ClassifyDestination("https://api.stripe.com/v1/tokens", allowlist, historical)
	if trust != TrustPropagation {
		t.Errorf("propagation allowlist should take priority, got %d", trust)
	}
}

// ── Vault-Aware Inspection Tests ─────────────────────────────────────────────

func TestInspectWithVault_NoFindings(t *testing.T) {
	body := []byte(`{"name": "test", "value": 42}`)
	result := InspectWithVaultContext(body, "application/json", "https://api.example.com/v1/data", nil, nil, nil)

	if result.MustBlock {
		t.Error("clean body should not be blocked")
	}
	if result.VaultMatch {
		t.Error("clean body should not have vault match")
	}
}

func TestInspectWithVault_VaultedKeyToSink(t *testing.T) {
	body := []byte(`{"key": "sk-abc123456789secretkey"}`)
	vaultPrefixes := []string{"sk-"}

	result := InspectWithVaultContext(body, "application/json",
		"https://webhook.site/abc",
		vaultPrefixes, nil, nil)

	if !result.MustBlock {
		t.Error("vaulted secret to exfiltration sink MUST be blocked")
	}
	if !result.VaultMatch {
		t.Error("should detect vault match for sk- prefix")
	}
}

func TestInspectWithVault_VaultedKeyToPropagation(t *testing.T) {
	body := []byte(`{"key": "sk_live_abc123456789"}`)
	vaultPrefixes := []string{"sk_live_"}
	propagation := []string{"api.stripe.com"}

	result := InspectWithVaultContext(body, "application/json",
		"https://api.stripe.com/v1/tokens",
		vaultPrefixes, propagation, nil)

	if result.MustBlock {
		t.Error("vaulted secret to propagation-allowed domain should NOT be blocked")
	}
}

func TestInspectWithVault_VaultedKeyToNewDomain(t *testing.T) {
	body := []byte(`{"api_key": "sk-abc123456789secretkey"}`)
	vaultPrefixes := []string{"sk-"}
	historical := map[string]bool{"known.example.com": true}

	result := InspectWithVaultContext(body, "application/json",
		"https://suspicious-new-domain.com/api",
		vaultPrefixes, nil, historical)

	if !result.MustBlock {
		t.Error("vaulted secret to new domain MUST be blocked")
	}
}

func TestInspectWithVault_NonVaultedPIIToSink(t *testing.T) {
	body := []byte(`{"note": "Patient SSN is 123-45-6789 please save"}`)

	result := InspectWithVaultContext(body, "application/json",
		"https://pastebin.com/api/create",
		nil, nil, nil)

	if !result.MustBlock {
		t.Error("PII to exfiltration sink should be blocked")
	}
}

func TestInspectWithVault_NonVaultedPIIToKnown(t *testing.T) {
	body := []byte(`{"contact": "user@example.com"}`)
	historical := map[string]bool{"api.example.com": true}

	result := InspectWithVaultContext(body, "application/json",
		"https://api.example.com/v1/contacts",
		nil, nil, historical)

	// Email to known domain — log only, not block
	if result.MustBlock {
		t.Error("email to known domain should NOT be hard blocked")
	}
}

func TestInspectWithVault_VaultedKeyToKnown_NonPropagation(t *testing.T) {
	body := []byte(`{"secret": "sk-test-key-12345678"}`)
	vaultPrefixes := []string{"sk-"}
	historical := map[string]bool{"api.example.com": true}

	result := InspectWithVaultContext(body, "application/json",
		"https://api.example.com/v1/webhook",
		vaultPrefixes, nil, historical)

	// Vaulted secret to known but non-propagation domain — flagged, not hard blocked
	if result.MustBlock {
		t.Error("vaulted secret to known non-propagation domain should be flagged, not hard blocked")
	}
	if !result.VaultMatch {
		t.Error("should detect vault match")
	}
}

// ── Domain Extraction Tests ──────────────────────────────────────────────────

func TestExtractDomain(t *testing.T) {
	tests := []struct {
		url    string
		expect string
	}{
		{"https://api.example.com/v1/data", "api.example.com"},
		{"http://localhost:8080/test", "localhost"},
		{"https://webhook.site/abc123", "webhook.site"},
		{"api.stripe.com/v1/charges", "api.stripe.com"},
	}

	for _, tt := range tests {
		got := extractDomain(tt.url)
		if got != tt.expect {
			t.Errorf("extractDomain(%q) = %q, want %q", tt.url, got, tt.expect)
		}
	}
}

// ── Empty / Edge Case Tests ──────────────────────────────────────────────────

func TestInspectWithVault_EmptyBody(t *testing.T) {
	result := InspectWithVaultContext(nil, "application/json", "https://example.com", nil, nil, nil)
	if result.MustBlock {
		t.Error("empty body should never block")
	}
}

func TestInspectWithVault_BinaryContentSkipped(t *testing.T) {
	body := []byte("sk-abc123456789")
	result := InspectWithVaultContext(body, "image/png", "https://webhook.site/abc", []string{"sk-"}, nil, nil)
	if result.MustBlock {
		t.Error("binary content types should be skipped")
	}
}
