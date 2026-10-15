// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package crypto

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

type LicenseClaims struct {
	TenantID     string    `json:"tenant_id"`      // Unique identifier linking this gateway to the Core API
	MaxAgents    int       `json:"max_agents"`     // Hard cap on the number of agents this gateway can register
	IssuedAt     time.Time `json:"issued_at"`      // Timestamp of license generation
	ExpiresAt    time.Time `json:"expires_at"`     // Hard expiration timestamp for this license
	Tier         string    `json:"tier"`           // e.g., "enterprise", "defense", "standard"
	LicenseTier  string    `json:"license_tier"`   // "root" (for HQ) or "subsidiary" (for local gateways)
	RootTenantID string    `json:"root_tenant_id"` // Mandatory if LicenseTier == "subsidiary", otherwise empty
	MeshAccess   bool      `json:"mesh_access"`    // Whether this gateway can join the P2P gossip mesh
	MeshTier     string    `json:"mesh_tier"`      // "standalone" (no mesh), "connected" (mesh + threat intel), "enterprise" (priority feeds)
}

// SignedLicense is the final artifact delivered to the customer (e.g., as a .lic file).
// It uses a dual-signature (PQC Hybrid) architecture to ensure mathematical resistance 
// against both classical supercomputers (via Ed25519) and future quantum computers (via ML-DSA-65).
type SignedLicense struct {
	// The raw, unencrypted JSON payload so the Gateway can read its configuration limits.
	PayloadB64 string `json:"payload"` 
	
	// Classical cryptographic signature (FIPS 186-5)
	SignatureEd25519 string `json:"sig_ed25519"`
	
	// Post-Quantum cryptographic signature (NIST FIPS 204)
	SignatureMLDSA65 string `json:"sig_mldsa65"`
}

// MintLicense takes the cleartext claims and the highly-secure master keys,
// and generates a quantum-resistant signed license artifact.
func MintLicense(claims LicenseClaims, keys *MasterKeyPair) (*SignedLicense, error) {
	// 1. Serialize the claims into a canonical JSON payload.
	// This exact byte slice is what the Sentry Gateway will reconstruct and verify.
	payloadBytes, err := json.Marshal(claims)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal license claims: %w", err)
	}

	// 2. Decode the classical Ed25519 private key from the master vault.
	edPrivBytes, err := base64.StdEncoding.DecodeString(keys.Ed25519PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ed25519 private key: %w", err)
	}
	if len(edPrivBytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid ed25519 private key size")
	}
	edPriv := ed25519.PrivateKey(edPrivBytes)

	// 3. Generate the Classical Signature (Ed25519).
	// This protects against current threats and ensures broad compatibility.
	sigEd25519 := ed25519.Sign(edPriv, payloadBytes)

	// 4. Decode the post-quantum ML-DSA-65 private key from the master vault.
	mldsaPrivBytes, err := base64.StdEncoding.DecodeString(keys.MLDSA65PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode mldsa65 private key: %w", err)
	}
	if len(mldsaPrivBytes) != mldsa65.PrivateKeySize {
		return nil, fmt.Errorf("invalid mldsa65 private key size")
	}
	
	var mldsaPriv mldsa65.PrivateKey
	mldsaPriv.Unpack((*[mldsa65.PrivateKeySize]byte)(mldsaPrivBytes))

	// 5. Generate the Post-Quantum Signature (ML-DSA-65).
	// This protects against Shor's Algorithm attacks from quantum computers.
	// We pass 'nil' for context, 'false' for deterministic (use random noise),
	// and slice the signature array.
	var sigMLDSA65 [mldsa65.SignatureSize]byte
	mldsa65.SignTo(&mldsaPriv, payloadBytes, nil, false, sigMLDSA65[:])

	// 6. Package the final artifact for delivery.
	license := &SignedLicense{
		PayloadB64:       base64.StdEncoding.EncodeToString(payloadBytes),
		SignatureEd25519: base64.StdEncoding.EncodeToString(sigEd25519),
		SignatureMLDSA65: base64.StdEncoding.EncodeToString(sigMLDSA65[:]),
	}

	return license, nil
}
