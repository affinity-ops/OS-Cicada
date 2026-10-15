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

// ── VaultAPICheck Integration Tests ──────────────────────────────────────────
// These tests use httptest.Server to mock the Core API vault check endpoint.
// They verify the full request/response cycle without requiring a real Core API.

// TestVaultAPICheck_Match verifies that a matching vault credential is correctly
// identified via the Core API cross-reference.
func TestVaultAPICheck_Match(t *testing.T) {
	// Mock Core API that always returns match=true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request structure
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/internal/vault/check-hash" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected application/json content type")
		}
		if r.Header.Get("X-Gateway-Secret") != "test-internal-key" {
			t.Errorf("expected X-Gateway-Secret header, got %q", r.Header.Get("X-Gateway-Secret"))
		}

		// Decode and verify payload
		var payload map[string]string
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("failed to decode request body: %v", err)
		}
		if payload["tenant_id"] != "tenant-123" {
			t.Errorf("expected tenant_id=tenant-123, got %q", payload["tenant_id"])
		}
		// credential_hash should be a 64-char hex SHA-256
		if len(payload["credential_hash"]) != 64 {
			t.Errorf("expected 64-char SHA-256 hash, got %d chars", len(payload["credential_hash"]))
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"match": true})
	}))
	defer server.Close()

	// Set env vars for the test
	os.Setenv("CICADA_CORE_API_URL", server.URL)
	os.Setenv("CICADA_INTERNAL_KEY", "test-internal-key")
	defer os.Unsetenv("CICADA_CORE_API_URL")
	defer os.Unsetenv("CICADA_INTERNAL_KEY")

	result := VaultAPICheck("sk-test-secret-key-12345", "tenant-123")

	if !result.Checked {
		t.Error("expected Checked=true when Core API URL is set")
	}
	if !result.Match {
		t.Error("expected Match=true when Core API returns match=true")
	}
	if result.Error != nil {
		t.Errorf("unexpected error: %v", result.Error)
	}
}

// TestVaultAPICheck_NoMatch verifies that a non-matching credential correctly
// returns Match=false.
func TestVaultAPICheck_NoMatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"match": false})
	}))
	defer server.Close()

	os.Setenv("CICADA_CORE_API_URL", server.URL)
	os.Setenv("CICADA_INTERNAL_KEY", "key")
	defer os.Unsetenv("CICADA_CORE_API_URL")
	defer os.Unsetenv("CICADA_INTERNAL_KEY")

	result := VaultAPICheck("some-unknown-credential", "tenant-456")

	if !result.Checked {
		t.Error("expected Checked=true")
	}
	if result.Match {
		t.Error("expected Match=false when Core API returns match=false")
	}
}

// TestVaultAPICheck_NoCoreAPIURL verifies that vault check is gracefully skipped
// when CICADA_CORE_API_URL is not configured.
func TestVaultAPICheck_NoCoreAPIURL(t *testing.T) {
	os.Unsetenv("CICADA_CORE_API_URL")

	result := VaultAPICheck("sk-anything", "tenant-789")

	if result.Checked {
		t.Error("expected Checked=false when Core API URL is not set")
	}
	if result.Match {
		t.Error("expected Match=false when check is skipped")
	}
}

// TestVaultAPICheck_CoreAPIError verifies that a Core API returning a non-200
// status is handled gracefully (treated as "no match").
func TestVaultAPICheck_CoreAPIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	os.Setenv("CICADA_CORE_API_URL", server.URL)
	os.Setenv("CICADA_INTERNAL_KEY", "key")
	defer os.Unsetenv("CICADA_CORE_API_URL")
	defer os.Unsetenv("CICADA_INTERNAL_KEY")

	result := VaultAPICheck("sk-test-key", "tenant-err")

	if !result.Checked {
		t.Error("expected Checked=true (API was called)")
	}
	if result.Match {
		t.Error("expected Match=false on API error")
	}
	if result.Error == nil {
		t.Error("expected Error to be set on API 500")
	}
}

// TestVaultAPICheck_CoreAPIUnreachable verifies that a network timeout/failure
// is treated as "no match" (fail-open for vault check, fail-closed would break traffic).
func TestVaultAPICheck_CoreAPIUnreachable(t *testing.T) {
	// Point to a URL that will refuse connections immediately
	os.Setenv("CICADA_CORE_API_URL", "http://127.0.0.1:1")
	os.Setenv("CICADA_INTERNAL_KEY", "key")
	defer os.Unsetenv("CICADA_CORE_API_URL")
	defer os.Unsetenv("CICADA_INTERNAL_KEY")

	result := VaultAPICheck("sk-test-key", "tenant-timeout")

	if !result.Checked {
		t.Error("expected Checked=true (attempt was made)")
	}
	if result.Match {
		t.Error("expected Match=false on network failure")
	}
	if result.Error == nil {
		t.Error("expected Error to be set on network failure")
	}
}

// TestVaultAPICheck_MalformedJSON verifies graceful handling of garbled JSON
// from the Core API (defensive programming against API version mismatches).
func TestVaultAPICheck_MalformedJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{not valid json`))
	}))
	defer server.Close()

	os.Setenv("CICADA_CORE_API_URL", server.URL)
	os.Setenv("CICADA_INTERNAL_KEY", "key")
	defer os.Unsetenv("CICADA_CORE_API_URL")
	defer os.Unsetenv("CICADA_INTERNAL_KEY")

	result := VaultAPICheck("sk-test-key", "tenant-malformed")

	if result.Match {
		t.Error("expected Match=false on malformed JSON")
	}
	if result.Error == nil {
		t.Error("expected Error to be set on decode failure")
	}
}

// TestVaultAPICheck_CredentialIsHashedLocally verifies that the raw credential
// is SHA-256 hashed before being sent — the Core API never sees the raw value.
func TestVaultAPICheck_CredentialIsHashedLocally(t *testing.T) {
	var receivedHash string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]string
		json.NewDecoder(r.Body).Decode(&payload)
		receivedHash = payload["credential_hash"]

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"match": false})
	}))
	defer server.Close()

	os.Setenv("CICADA_CORE_API_URL", server.URL)
	os.Setenv("CICADA_INTERNAL_KEY", "key")
	defer os.Unsetenv("CICADA_CORE_API_URL")
	defer os.Unsetenv("CICADA_INTERNAL_KEY")

	// Known credential with known SHA-256 hash
	credential := "sk-test-key-exfiltration-check"
	VaultAPICheck(credential, "tenant-hash-test")

	// The received hash must NOT be the raw credential
	if receivedHash == credential {
		t.Fatal("CRITICAL: raw credential was sent to Core API instead of hash")
	}

	// Verify it's a valid 64-char hex string (SHA-256)
	if len(receivedHash) != 64 {
		t.Errorf("expected 64-char SHA-256 hex hash, got %d chars: %q", len(receivedHash), receivedHash)
	}
}

// TestVaultAPICheck_InternalKeyHeader verifies that the X-Gateway-Secret header
// is correctly set from CICADA_INTERNAL_KEY when making the API call.
func TestVaultAPICheck_InternalKeyHeader(t *testing.T) {
	var receivedKey string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedKey = r.Header.Get("X-Gateway-Secret")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"match": false})
	}))
	defer server.Close()

	os.Setenv("CICADA_CORE_API_URL", server.URL)
	os.Setenv("CICADA_INTERNAL_KEY", "super-secret-gateway-key-xyz")
	defer os.Unsetenv("CICADA_CORE_API_URL")
	defer os.Unsetenv("CICADA_INTERNAL_KEY")

	VaultAPICheck("anything", "tenant-key-test")

	if receivedKey != "super-secret-gateway-key-xyz" {
		t.Errorf("expected X-Gateway-Secret=%q, got %q", "super-secret-gateway-key-xyz", receivedKey)
	}
}
