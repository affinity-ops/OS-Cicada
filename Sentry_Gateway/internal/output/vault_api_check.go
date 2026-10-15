// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package output — vault API cross-reference for credential exfiltration detection.
//
// This file implements the Gateway-to-Core-API integration for S1.1: when the
// exfiltration scanner detects a credential in an outbound request body, this
// module hashes the detected credential and sends it to the Core API's
// /v1/internal/vault/check-hash endpoint for cross-reference against the
// tenant's encrypted BYOK vault.
//
// Why this is a separate file from vault_exfiltration.go:
// vault_exfiltration.go handles local decision logic (prefix matching, destination
// trust classification). This file handles the REMOTE verification — the HTTP
// call to the Core API. Keeping them separate means:
//   - vault_exfiltration.go can be tested without network mocks
//   - this file can be tested with httptest.Server
//   - the vault API check is opt-in (only fires when CICADA_CORE_API_URL is set)
//
// Integration flow:
//   1. InspectWithVaultContext (vault_exfiltration.go) runs prefix-based local check
//   2. If Risk=true AND the result warrants API verification, VaultAPICheck fires
//   3. Core API decrypts tenant BYOK keys, SHA-256 hashes them, compares
//   4. If match → severity escalates to CRITICAL in the action ledger
//
// Security:
//   - Only SHA-256 hashes cross the network (not raw credentials)
//   - Authentication via X-Gateway-Secret header (same as all internal routes)
//   - Timeout: 3 seconds — exfiltration detection must not slow the proxy path
//   - Failure mode: false (no match) — a broken vault check does not block traffic
package output

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

// VaultAPICheckResult is the result of cross-referencing a detected credential
// against the tenant's BYOK vault via the Core API.
type VaultAPICheckResult struct {
	// Checked is true if the API call was attempted (Core API URL configured).
	Checked bool `json:"checked"`

	// Match is true if the detected credential matches a vaulted BYOK key.
	Match bool `json:"match"`

	// Error is non-nil if the API call failed. The caller should treat this
	// as "no match" and proceed with the standard exfiltration decision.
	Error error `json:"error,omitempty"`
}

// vaultCheckTimeout is the maximum time we wait for the Core API response.
// Exfiltration detection is inline in the proxy path — we cannot block for long.
const vaultCheckTimeout = 3 * time.Second

// vaultAPICheckResponse is the JSON response from POST /v1/internal/vault/check-hash.
type vaultAPICheckResponse struct {
	Match bool `json:"match"`
}

// VaultAPICheck sends a SHA-256 hash of a suspected credential to the Core API
// for cross-reference against the tenant's encrypted BYOK vault.
//
// Parameters:
//   - credential: the raw credential string detected in the request body.
//     This is hashed locally — the raw value never leaves the Gateway process.
//   - tenantID: the tenant whose vault should be checked.
//
// Configuration:
//   - CICADA_CORE_API_URL: base URL of the Core API (e.g., "http://localhost:8000")
//   - CICADA_INTERNAL_KEY: the gateway internal secret for X-Gateway-Secret header
//
// Returns VaultAPICheckResult with Checked=false if configuration is missing.
func VaultAPICheck(credential string, tenantID string) VaultAPICheckResult {
	coreAPIURL := os.Getenv("CICADA_CORE_API_URL")
	internalKey := os.Getenv("CICADA_INTERNAL_KEY")

	// If Core API is not configured, skip vault check entirely.
	// This is expected in test environments and standalone gateway deployments.
	if coreAPIURL == "" {
		return VaultAPICheckResult{Checked: false}
	}

	// SHA-256 hash the credential locally. The raw credential never leaves
	// the Gateway process boundary. The Core API receives only the hash and
	// compares it against hashes of decrypted vault entries.
	hash := sha256.Sum256([]byte(credential))
	hashHex := hex.EncodeToString(hash[:])

	// Build the request payload.
	payload, err := json.Marshal(map[string]string{
		"tenant_id":       tenantID,
		"credential_hash": hashHex,
	})
	if err != nil {
		return VaultAPICheckResult{Checked: true, Error: fmt.Errorf("failed to marshal vault check payload: %w", err)}
	}

	// POST to the Core API internal vault check endpoint.
	url := fmt.Sprintf("%s/api/v1/internal/vault/check-hash", coreAPIURL)
	client := &http.Client{Timeout: vaultCheckTimeout}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return VaultAPICheckResult{Checked: true, Error: fmt.Errorf("failed to build vault check request: %w", err)}
	}
	req.Header.Set("Content-Type", "application/json")

	// Authenticate with the same internal key used for HITL suspend, CIBA, etc.
	if internalKey != "" {
		req.Header.Set("X-Gateway-Secret", internalKey)
	}

	resp, err := client.Do(req)
	if err != nil {
		// Network error or timeout — treat as "no match" to avoid blocking traffic.
		log.Printf("[VaultAPICheck] Core API unreachable for tenant %s: %v", tenantID, err)
		return VaultAPICheckResult{Checked: true, Error: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("[VaultAPICheck] Core API returned %d for tenant %s", resp.StatusCode, tenantID)
		return VaultAPICheckResult{
			Checked: true,
			Error:   fmt.Errorf("vault check returned HTTP %d", resp.StatusCode),
		}
	}

	var apiResp vaultAPICheckResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return VaultAPICheckResult{Checked: true, Error: fmt.Errorf("vault check response decode error: %w", err)}
	}

	if apiResp.Match {
		log.Printf("[VaultAPICheck] CRITICAL — detected credential matches vaulted BYOK key for tenant %s", tenantID)
	}

	return VaultAPICheckResult{
		Checked: true,
		Match:   apiResp.Match,
	}
}
