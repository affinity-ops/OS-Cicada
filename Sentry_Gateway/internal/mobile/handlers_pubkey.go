// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package mobile

// handlers_pubkey.go — Public key endpoint for QR signature verification.
//
// GET /v1/gateway/pubkey
//
// Returns the Gateway's Ed25519 public key as base64. This is the same key
// that signs EVARs, session tokens, and QR pairing payloads.
//
// This endpoint is unauthenticated — the public key is not a secret.
// The Aegis app calls this before verifying a scanned QR code to ensure
// the payload was signed by this Gateway, not a spoofed one.
//
// The private key (sentry_ed25519.key) is never exposed. It is only used
// by the running Gateway process to sign tokens.

import (
	"encoding/base64"
	"net/http"

	"github.com/asai/cicada/sentry/internal/auth"
)

// HandleGetPublicKey returns the Gateway's Ed25519 public key as base64.
//
// Response 200:
//
//	{"public_key": "base64-encoded-32-byte-ed25519-public-key"}
//
// Response 503 (key not loaded — gateway startup failed):
//
//	{"error": "gateway signing key not available"}
func HandleGetPublicKey(w http.ResponseWriter, r *http.Request) {
	if auth.GlobalSentryPublicKey == nil {
		writeError(w, "gateway signing key not available", http.StatusServiceUnavailable)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"public_key": base64.StdEncoding.EncodeToString(auth.GlobalSentryPublicKey),
	})
}
