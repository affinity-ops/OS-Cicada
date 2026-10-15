// © 2026 Affinity Ops Ltd.
// SPDX-License-Identifier: Apache-2.0

package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"log"
	"os"
	"time"

	"github.com/asai/cicada/sentry/pkg/pqc"
)

// Hardcoded Master Public Keys used for enterprise zero-trust enforcement.
// If the private keys are lost, these values must be updated in a new binary release.
const (
	masterEd25519Pub = "vhJYqy+mag/srEBs+abtSNI9lRQ51/4W8z01GHoFgmo="
	masterMLDSA65Pub = "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"
)

// ActiveLicense holds the verified entitlements for the currently running node.
var ActiveLicense *LicenseClaims

type LicenseClaims struct {
	TenantID   string    `json:"tenant_id"`
	MaxAgents  int       `json:"max_agents"`
	IssuedAt   time.Time `json:"issued_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	Tier       string    `json:"tier"`
	MeshAccess bool      `json:"mesh_access"`  // Whether this gateway can join the P2P mesh
	MeshTier   string    `json:"mesh_tier"`    // "standalone", "connected", "enterprise"
}

type SignedLicense struct {
	PayloadB64       string `json:"payload"`
	SignatureEd25519 string `json:"sig_ed25519"`
	SignatureMLDSA65 string `json:"sig_mldsa65"`
}

// EnforceOrDie reads the .lic file provided at boot, verifies both the classical
// and post-quantum cryptographic signatures, checks expiration, and halts the binary
// if any check fails.
func EnforceOrDie(licensePath string) {
	// DEV MODE BYPASS — for local development and standalone simulation only.
	// Set CICADA_DEV_MODE=true or CICADA_SIMULATION_MODE=true to boot the gateway without a .lic file.
	// Production appliance binaries MUST NOT have this flag set.
	if os.Getenv("CICADA_DEV_MODE") == "true" || os.Getenv("CICADA_SIMULATION_MODE") == "true" {
		log.Printf("[LICENSING] ⚠️  DEV MODE — bypassing license verification. DO NOT USE IN PRODUCTION.")
		ActiveLicense = &LicenseClaims{
			TenantID:   "dev-tenant",
			MaxAgents:  9999,
			IssuedAt:   time.Now(),
			ExpiresAt:  time.Now().AddDate(1, 0, 0),
			Tier:       "enterprise",
			MeshAccess: true,
			MeshTier:   "enterprise",
		}
		log.Printf("[LICENSING] Dev license active: TenantID=%s, MaxAgents=%d, MeshAccess=%v",
			ActiveLicense.TenantID, ActiveLicense.MaxAgents, ActiveLicense.MeshAccess)
		return
	}

	log.Printf("[LICENSING] Initialising Enterprise Zero-Trust License Verification...")

	data, err := os.ReadFile(licensePath)
	if err != nil {
		log.Fatalf("[FATAL] [LICENSING] Could not read license file at %s: %v. The Sentry Gateway cannot boot without a valid license.", licensePath, err)
	}

	var lic SignedLicense
	if err := json.Unmarshal(data, &lic); err != nil {
		log.Fatalf("[FATAL] [LICENSING] License file is corrupt or invalid JSON: %v", err)
	}

	// 1. Reconstruct the payload bytes
	payloadBytes, err := base64.StdEncoding.DecodeString(lic.PayloadB64)
	if err != nil {
		log.Fatalf("[FATAL] [LICENSING] License payload encoding invalid: %v", err)
	}

	// 2. Verify Classical Ed25519 Signature
	edPubBytes, err := base64.StdEncoding.DecodeString(masterEd25519Pub)
	if err != nil {
		log.Fatalf("[FATAL] [LICENSING] Hardcoded Ed25519 public key is invalid")
	}
	
	sigBytes, sigErr := base64.StdEncoding.DecodeString(lic.SignatureEd25519)
	if sigErr != nil || !ed25519.Verify(ed25519.PublicKey(edPubBytes), payloadBytes, sigBytes) {
		log.Fatalf("[FATAL] [LICENSING] Classical Ed25519 verification FAILED. The license has been tampered with or is forged.")
	}

	// 3. Verify Post-Quantum ML-DSA-65 Signature
	err = pqc.VerifyMLDSA65(masterMLDSA65Pub, payloadBytes, lic.SignatureMLDSA65)
	if err != nil {
		log.Fatalf("[FATAL] [LICENSING] Post-Quantum ML-DSA-65 verification FAILED: %v", err)
	}

	// 4. Parse the claims
	var claims LicenseClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		log.Fatalf("[FATAL] [LICENSING] Could not parse verified license claims: %v", err)
	}

	// 5. Check Expiration
	if time.Now().UTC().After(claims.ExpiresAt) {
		log.Fatalf("[FATAL] [LICENSING] License for Tenant '%s' EXPIRED on %s. Gateway boot halted.", claims.TenantID, claims.ExpiresAt.Format(time.RFC1123))
	}

	ActiveLicense = &claims

	log.Printf("[LICENSING] ✅ Cryptographic verification passed. PQC Hybrid signatures valid.")
	log.Printf("[LICENSING] ✅ License active for Tenant: %s (Tier: %s, Max Agents: %d, Expires: %s)",
		claims.TenantID, claims.Tier, claims.MaxAgents, claims.ExpiresAt.Format("2006-01-02"))
	if claims.MeshAccess {
		log.Printf("[LICENSING] ✅ Mesh access granted (tier: %s)", claims.MeshTier)
	} else {
		log.Printf("[LICENSING] Mesh access not included in license — gateway will operate standalone")
	}
}

// GetMaxAgents returns the capacity limit enforced by the current license.
func GetMaxAgents() int {
	if ActiveLicense == nil {
		return 0
	}
	return ActiveLicense.MaxAgents
}

// MeshAllowed returns true if the current license grants mesh access.
// If no license is loaded (shouldn't happen in production), returns false.
func MeshAllowed() bool {
	if ActiveLicense == nil {
		return false
	}
	return ActiveLicense.MeshAccess
}

// GetMeshTier returns the mesh tier from the current license.
func GetMeshTier() string {
	if ActiveLicense == nil {
		return "standalone"
	}
	if ActiveLicense.MeshTier == "" {
		return "standalone"
	}
	return ActiveLicense.MeshTier
}
