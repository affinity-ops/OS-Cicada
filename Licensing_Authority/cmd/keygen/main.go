// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/asai/cicada/licensing/internal/crypto"
)

const MasterKeyFile = "master_keys.json"

func main() {
	fmt.Println("Cicada Licensing Authority - Master Key Generator")
	fmt.Println("=================================================")

	// Ensure we don't overwrite existing keys by accident
	if _, err := os.Stat(MasterKeyFile); err == nil {
		log.Fatalf("ABORTING: %s already exists. Refusing to overwrite the Master Keys.", MasterKeyFile)
	}

	fmt.Println("[*] Generating Ed25519 Classical Keys...")
	fmt.Println("[*] Generating ML-DSA-65 Post-Quantum Keys...")
	
	kp, err := crypto.GenerateMasterKeys()
	if err != nil {
		log.Fatalf("Failed to generate master keys: %v", err)
	}

	err = crypto.SaveMasterKeys(MasterKeyFile, kp)
	if err != nil {
		log.Fatalf("Failed to save master keys: %v", err)
	}

	absPath, _ := filepath.Abs(MasterKeyFile)
	fmt.Printf("[+] Success! Master keys securely generated and saved to:\n    %s\n", absPath)
	fmt.Println("[!] WARNING: Back up this file securely. If lost, you cannot mint or verify licenses.")
	fmt.Println("[!] WARNING: Keep this file AIR-GAPPED. Never commit it to version control.")
}
