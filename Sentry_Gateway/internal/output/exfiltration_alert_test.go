// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package output

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// ── ExfiltrationAlert Tests ──────────────────────────────────────────────────
// These tests verify the Gateway's alert emission to the Core API.

// TestEmitExfiltrationAlert_VaultMatch verifies that a vault-matched credential
// exfiltration fires a "credential_exfiltration" event with "critical" severity.
func TestEmitExfiltrationAlert_VaultMatch(t *testing.T) {
	var receivedPayload ExfiltrationAlertPayload

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/internal/threat-alert" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("X-Gateway-Secret") != "test-key" {
			t.Errorf("missing or wrong X-Gateway-Secret header")
		}

		json.NewDecoder(r.Body).Decode(&receivedPayload)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "accepted"})
	}))
	defer server.Close()

	os.Setenv("CICADA_CORE_API_URL", server.URL)
	os.Setenv("CICADA_INTERNAL_KEY", "test-key")
	defer os.Unsetenv("CICADA_CORE_API_URL")
	defer os.Unsetenv("CICADA_INTERNAL_KEY")

	EmitExfiltrationAlert(
		"tenant-001", "agent-001",
		"https://webhook.site/abc123",
		true,                    // vault match
		TrustExfiltrationSink,   // destination trust
		"Stripe API key (sk-) detected in POST body to webhook.site",
		"trace-abc-123",
	)

	// Verify payload structure
	if receivedPayload.EventType != "credential_exfiltration" {
		t.Errorf("expected event_type=credential_exfiltration, got %q", receivedPayload.EventType)
	}
	if receivedPayload.TenantID != "tenant-001" {
		t.Errorf("expected tenant_id=tenant-001, got %q", receivedPayload.TenantID)
	}
	if receivedPayload.AgentID != "agent-001" {
		t.Errorf("expected agent_id=agent-001, got %q", receivedPayload.AgentID)
	}
	if receivedPayload.Context.Severity != "critical" {
		t.Errorf("expected severity=critical for vault match, got %q", receivedPayload.Context.Severity)
	}
	if !receivedPayload.Context.VaultMatch {
		t.Error("expected vault_match=true in context")
	}
	if receivedPayload.Context.DestinationTrust != "exfiltration_sink" {
		t.Errorf("expected destination_trust=exfiltration_sink, got %q", receivedPayload.Context.DestinationTrust)
	}
	if receivedPayload.Context.TraceID != "trace-abc-123" {
		t.Errorf("expected trace_id=trace-abc-123, got %q", receivedPayload.Context.TraceID)
	}
	if receivedPayload.Source != "Sentry-Gateway/threat-scanner" {
		t.Errorf("expected source=Sentry-Gateway/exfiltration-scanner, got %q", receivedPayload.Source)
	}
}

// TestEmitExfiltrationAlert_PIIExfiltration verifies that a non-vault PII
// exfiltration fires a "pii_exfiltration" event.
func TestEmitExfiltrationAlert_PIIExfiltration(t *testing.T) {
	var receivedPayload ExfiltrationAlertPayload

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&receivedPayload)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	os.Setenv("CICADA_CORE_API_URL", server.URL)
	os.Setenv("CICADA_INTERNAL_KEY", "key")
	defer os.Unsetenv("CICADA_CORE_API_URL")
	defer os.Unsetenv("CICADA_INTERNAL_KEY")

	EmitExfiltrationAlert(
		"tenant-002", "agent-002",
		"https://pastebin.com/api/create",
		false,                   // NOT a vault match
		TrustExfiltrationSink,   // but going to a known sink
		"SSN pattern detected in POST body",
		"trace-xyz-456",
	)

	if receivedPayload.EventType != "pii_exfiltration" {
		t.Errorf("expected event_type=pii_exfiltration, got %q", receivedPayload.EventType)
	}
	// PII to exfiltration sink should be critical severity
	if receivedPayload.Context.Severity != "critical" {
		t.Errorf("expected severity=critical for exfiltration sink, got %q", receivedPayload.Context.Severity)
	}
}

// TestEmitExfiltrationAlert_NoCoreAPI verifies graceful handling when Core API
// is not configured (expected in standalone Gateway deployments).
func TestEmitExfiltrationAlert_NoCoreAPI(t *testing.T) {
	os.Unsetenv("CICADA_CORE_API_URL")

	// Should not panic or error — just log locally
	EmitExfiltrationAlert(
		"tenant-003", "agent-003",
		"https://somewhere.com",
		false, TrustUnknown,
		"test alert", "",
	)
	// No assertion needed — just verify it doesn't panic
}

// TestEmitExfiltrationAlert_CoreAPIDown verifies that a failing Core API does
// not block the proxy path (fire-and-forget semantics).
func TestEmitExfiltrationAlert_CoreAPIDown(t *testing.T) {
	os.Setenv("CICADA_CORE_API_URL", "http://127.0.0.1:1") // will fail immediately
	os.Setenv("CICADA_INTERNAL_KEY", "key")
	defer os.Unsetenv("CICADA_CORE_API_URL")
	defer os.Unsetenv("CICADA_INTERNAL_KEY")

	// Should not panic — just log the failure
	EmitExfiltrationAlert(
		"tenant-004", "agent-004",
		"https://webhook.site/test",
		true, TrustExfiltrationSink,
		"vault key detected", "trace-down",
	)
	// No assertion — just verify no panic
}

// TestEmitExfiltrationAlert_VaultMatchToNewDomain verifies that vault match
// to a new (non-exfiltration-sink) domain correctly reports "critical" severity.
func TestEmitExfiltrationAlert_VaultMatchToNewDomain(t *testing.T) {
	var receivedPayload ExfiltrationAlertPayload

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&receivedPayload)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	os.Setenv("CICADA_CORE_API_URL", server.URL)
	os.Setenv("CICADA_INTERNAL_KEY", "key")
	defer os.Unsetenv("CICADA_CORE_API_URL")
	defer os.Unsetenv("CICADA_INTERNAL_KEY")

	EmitExfiltrationAlert(
		"tenant-005", "agent-005",
		"https://suspicious-new.com/api",
		true,            // vault match
		TrustNewDomain,  // new domain (not a known sink)
		"BYOK key prefix sk- detected in POST body",
		"trace-new-domain",
	)

	if receivedPayload.EventType != "credential_exfiltration" {
		t.Errorf("expected credential_exfiltration, got %q", receivedPayload.EventType)
	}
	if receivedPayload.Context.Severity != "critical" {
		t.Errorf("expected critical severity for vault match, got %q", receivedPayload.Context.Severity)
	}
	if receivedPayload.Context.DestinationTrust != "new_domain" {
		t.Errorf("expected new_domain, got %q", receivedPayload.Context.DestinationTrust)
	}
}

// TestDestinationTrustLabel verifies the human-readable trust label conversion.
func TestDestinationTrustLabel(t *testing.T) {
	tests := []struct {
		trust  DestinationTrust
		expect string
	}{
		{TrustExfiltrationSink, "exfiltration_sink"},
		{TrustNewDomain, "new_domain"},
		{TrustKnown, "known_domain"},
		{TrustPropagation, "propagation_allowed"},
		{TrustUnknown, "unknown"},
	}

	for _, tt := range tests {
		got := destinationTrustLabel(tt.trust)
		if got != tt.expect {
			t.Errorf("destinationTrustLabel(%d) = %q, want %q", tt.trust, got, tt.expect)
		}
	}
}
