// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// MasterKeyPair holds the PQC Hybrid keys used to sign licenses.
type MasterKeyPair struct {
	Ed25519PrivateKey string `json:"ed25519_private_key"`
	Ed25519PublicKey  string `json:"ed25519_public_key"`
	MLDSA65PrivateKey string `json:"mldsa65_private_key"`
	MLDSA65PublicKey  string `json:"mldsa65_public_key"`
}

// GenerateMasterKeys generates both Ed25519 and ML-DSA-65 key pairs
// and returns them as base64-encoded strings within the MasterKeyPair struct.
func GenerateMasterKeys() (*MasterKeyPair, error) {
	// 1. Generate Ed25519 Keys
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	// 2. Generate ML-DSA-65 Keys
	mldsaPub, mldsaPriv, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	// Pack ML-DSA keys to byte slices
	var mldsaPubBytes [mldsa65.PublicKeySize]byte
	mldsaPub.Pack(&mldsaPubBytes)

	var mldsaPrivBytes [mldsa65.PrivateKeySize]byte
	mldsaPriv.Pack(&mldsaPrivBytes)

	// 3. Encode all to Base64
	kp := &MasterKeyPair{
		Ed25519PrivateKey: base64.StdEncoding.EncodeToString(edPriv),
		Ed25519PublicKey:  base64.StdEncoding.EncodeToString(edPub),
		MLDSA65PrivateKey: base64.StdEncoding.EncodeToString(mldsaPrivBytes[:]),
		MLDSA65PublicKey:  base64.StdEncoding.EncodeToString(mldsaPubBytes[:]),
	}

	return kp, nil
}

// SaveMasterKeys writes the keys to a highly secure JSON file.
// In a true production environment, this would go into a hardware security module (HSM)
// or an encrypted vault.
func SaveMasterKeys(filepath string, kp *MasterKeyPair) error {
	data, err := json.MarshalIndent(kp, "", "  ")
	if err != nil {
		return err
	}

	// 0600 ensures only the owner can read/write this file.
	return os.WriteFile(filepath, data, 0600)
}

// LoadMasterKeys reads the keys from the JSON file.
func LoadMasterKeys(filepath string) (*MasterKeyPair, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}

	var kp MasterKeyPair
	if err := json.Unmarshal(data, &kp); err != nil {
		return nil, err
	}

	return &kp, nil
}
