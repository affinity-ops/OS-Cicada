// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/asai/cicada/licensing/internal/crypto"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

type BinaryManifest struct {
	BinaryName       string    `json:"binary_name"`
	Version          string    `json:"version"`
	BuildDate        time.Time `json:"build_date"`
	SHA256Hash       string    `json:"sha256_hash"`
	SignatureEd25519 string    `json:"sig_ed25519"`
	SignatureMLDSA65 string    `json:"sig_mldsa65"`
}

func main() {
	fmt.Println("Cicada Licensing Authority - PQC Binary Signer")
	fmt.Println("==============================================")

	binaryPath := flag.String("binary", "", "Path to the binary file to sign")
	version := flag.String("version", "v1.0.0", "Release version of the binary")
	keysFile := flag.String("keys", "master_keys.json", "Path to the Master Keys JSON file")
	outPath := flag.String("output", ".", "Output directory for the generated manifest")
	flag.Parse()

	if *binaryPath == "" {
		log.Fatalf("ABORTING: You must provide a valid --binary flag.")
	}

	binaryName := filepath.Base(*binaryPath)

	// 1. Read binary and compute SHA256 hash
	fmt.Printf("[*] Reading binary: %s\n", *binaryPath)
	data, err := os.ReadFile(*binaryPath)
	if err != nil {
		log.Fatalf("Failed to read binary: %v", err)
	}

	hash := sha256.Sum256(data)
	hashHex := fmt.Sprintf("%x", hash)
	fmt.Printf("[*] SHA-256 Hash: %s\n", hashHex)

	// 2. Load the Highly-Secure Master Keys
	fmt.Printf("[*] Loading Master Keys from %s...\n", *keysFile)
	keys, err := crypto.LoadMasterKeys(*keysFile)
	if err != nil {
		log.Fatalf("Failed to load master keys: %v", err)
	}

	// 3. Decode the classical Ed25519 private key from the master vault.
	edPrivBytes, err := base64.StdEncoding.DecodeString(keys.Ed25519PrivateKey)
	if err != nil {
		log.Fatalf("Failed to decode ed25519 private key: %v", err)
	}
	if len(edPrivBytes) != ed25519.PrivateKeySize {
		log.Fatalf("Invalid ed25519 private key size")
	}
	edPriv := ed25519.PrivateKey(edPrivBytes)

	// 4. Generate the Classical Signature (Ed25519).
	sigEd25519 := ed25519.Sign(edPriv, hash[:])

	// 5. Decode the post-quantum ML-DSA-65 private key.
	mldsaPrivBytes, err := base64.StdEncoding.DecodeString(keys.MLDSA65PrivateKey)
	if err != nil {
		log.Fatalf("Failed to decode mldsa65 private key: %v", err)
	}
	if len(mldsaPrivBytes) != mldsa65.PrivateKeySize {
		log.Fatalf("Invalid mldsa65 private key size")
	}

	var mldsaPriv mldsa65.PrivateKey
	mldsaPriv.Unpack((*[mldsa65.PrivateKeySize]byte)(mldsaPrivBytes))

	// 6. Generate the Post-Quantum Signature (ML-DSA-65).
	var sigMLDSA65 [mldsa65.SignatureSize]byte
	mldsa65.SignTo(&mldsaPriv, hash[:], nil, false, sigMLDSA65[:])

	// 7. Package the final manifest artifact.
	manifest := &BinaryManifest{
		BinaryName:       binaryName,
		Version:          *version,
		BuildDate:        time.Now().UTC(),
		SHA256Hash:       hashHex,
		SignatureEd25519: base64.StdEncoding.EncodeToString(sigEd25519),
		SignatureMLDSA65: base64.StdEncoding.EncodeToString(sigMLDSA65[:]),
	}

	outputFilename := filepath.Join(*outPath, fmt.Sprintf("%s.manifest.json", binaryName))

	manifestData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		log.Fatalf("Failed to serialize signed manifest: %v", err)
	}

	err = os.WriteFile(outputFilename, manifestData, 0644)
	if err != nil {
		log.Fatalf("Failed to write manifest file: %v", err)
	}

	absPath, _ := filepath.Abs(outputFilename)
	fmt.Printf("[+] Success! Binary %s signed with Ed25519 & ML-DSA-65.\n", binaryName)
	fmt.Printf("    Manifest saved to: %s\n", absPath)
}
