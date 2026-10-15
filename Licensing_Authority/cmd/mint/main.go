// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/asai/cicada/licensing/internal/crypto"
)

func main() {
	fmt.Println("Cicada Licensing Authority - Enterprise License Minter")
	fmt.Println("======================================================")

	tenantID := flag.String("tenant", "", "Tenant ID (e.g., 'tenant_prod_001')")
	maxAgents := flag.Int("agents", 50, "Maximum number of agents allowed to register")
	daysValid := flag.Int("days", 365, "Number of days until the license expires")
	tier := flag.String("tier", "enterprise", "Service tier (e.g., enterprise, defense)")
	keysFile := flag.String("keys", "master_keys.json", "Path to the Master Keys JSON file")
	licenseTier := flag.String("license-tier", "root", "License hierarchy tier (root or subsidiary)")
	rootTenantID := flag.String("root-tenant", "", "Required if license-tier is 'subsidiary'. The parent root tenant ID.")
	meshAccess := flag.Bool("mesh-access", true, "Whether this gateway can join the P2P gossip mesh")
	meshTier := flag.String("mesh-tier", "connected", "Mesh tier: standalone (no mesh), connected (mesh + threat intel), enterprise (priority feeds)")
	outPath := flag.String("output", ".", "Output directory for the generated .lic file")
	flag.Parse()

	if *tenantID == "" {
		log.Fatalf("ABORTING: You must provide a valid --tenant flag.")
	}

	// Validation for root vs subsidiary
	if *licenseTier != "root" && *licenseTier != "subsidiary" {
		log.Fatalf("ABORTING: --license-tier must be either 'root' or 'subsidiary'.")
	}

	if *licenseTier == "root" && *rootTenantID != "" {
		log.Fatalf("ABORTING: --root-tenant must be empty when --license-tier is 'root'.")
	}

	if *licenseTier == "subsidiary" && *rootTenantID == "" {
		log.Fatalf("ABORTING: --root-tenant is required when --license-tier is 'subsidiary'.")
	}

	// Mesh tier validation
	if *meshTier != "standalone" && *meshTier != "connected" && *meshTier != "enterprise" {
		log.Fatalf("ABORTING: --mesh-tier must be 'standalone', 'connected', or 'enterprise'.")
	}

	// 1. Load the Highly-Secure Master Keys
	fmt.Printf("[*] Loading Master Keys from %s...\n", *keysFile)
	keys, err := crypto.LoadMasterKeys(*keysFile)
	if err != nil {
		log.Fatalf("Failed to load master keys (Do they exist? Did you run keygen?): %v", err)
	}

	// 2. Construct the cleartext claims
	claims := crypto.LicenseClaims{
		TenantID:     *tenantID,
		MaxAgents:    *maxAgents,
		IssuedAt:     time.Now().UTC(),
		ExpiresAt:    time.Now().UTC().AddDate(0, 0, *daysValid),
		Tier:         *tier,
		LicenseTier:  *licenseTier,
		RootTenantID: *rootTenantID,
		MeshAccess:   *meshAccess,
		MeshTier:     *meshTier,
	}

	fmt.Printf("[*] Minting PQC Hybrid License for Tenant: %s (Expires: %s)\n", claims.TenantID, claims.ExpiresAt.Format("2006-01-02"))

	// 3. Cryptographically sign the claims using the dual-signature architecture
	signedLicense, err := crypto.MintLicense(claims, keys)
	if err != nil {
		log.Fatalf("Failed to mint license: %v", err)
	}

	// 4. Save the final .lic artifact
	outputFilename := filepath.Join(*outPath, fmt.Sprintf("%s.lic", *tenantID))
	
	// Format as pretty JSON so the customer can inspect the base64 boundaries
	licenseData, err := json.MarshalIndent(signedLicense, "", "  ")
	if err != nil {
		log.Fatalf("Failed to serialize signed license: %v", err)
	}

	err = os.WriteFile(outputFilename, licenseData, 0644)
	if err != nil {
		log.Fatalf("Failed to write .lic file: %v", err)
	}

	absPath, _ := filepath.Abs(outputFilename)
	fmt.Printf("[+] Success! Enterprise License generated and signed with Ed25519 & ML-DSA-65.\n")
	fmt.Printf("    File saved to: %s\n", absPath)
}
