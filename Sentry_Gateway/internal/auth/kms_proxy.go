// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
)

// KeyVault provides AES-256-GCM envelope encryption for tenant API keys.
// In production this wraps AWS KMS or HashiCorp Vault Transit; locally it
// uses a master key from the CICADA_AES_MASTER_KEY environment variable.
type KeyVault struct {
	masterKey []byte
}

// NewVaultFromEnv initializes the KeyVault using the CICADA_AES_MASTER_KEY
// environment variable. Returns an error if the key is missing or invalid.
func NewVaultFromEnv() (*KeyVault, error) {
	secret := os.Getenv("CICADA_AES_MASTER_KEY")
	if secret == "" {
		return nil, errors.New("CICADA_AES_MASTER_KEY environment variable is required")
	}
	if len(secret) != 32 {
		return nil, fmt.Errorf("CICADA_AES_MASTER_KEY must be exactly 32 bytes for AES-256 (got %d)", len(secret))
	}
	return &KeyVault{masterKey: []byte(secret)}, nil
}

// EncryptUserKey encrypts a plaintext API key with AES-256-GCM, binding the
// ciphertext to the tenant's orgID via authenticated additional data. This
// prevents cross-tenant decryption attacks.
func (v *KeyVault) EncryptUserKey(_ context.Context, plainTextKey string, orgID string) (string, error) {
	block, err := aes.NewCipher(v.masterKey)
	if err != nil {
		return "", fmt.Errorf("aes cipher init: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("gcm init: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("nonce generation: %w", err)
	}

	// Bind ciphertext to origin and tenant so Tenant_B cannot decrypt Tenant_A's blob.
	authData := []byte(fmt.Sprintf("Cicada-Sentry-v1:%s", orgID))
	cipherBlob := gcm.Seal(nonce, nonce, []byte(plainTextKey), authData)

	return base64.StdEncoding.EncodeToString(cipherBlob), nil
}

// DecryptForSentry decrypts a base64-encoded ciphertext blob, verifying the
// tenant context. Returns an error on cross-tenant mismatch.
func (v *KeyVault) DecryptForSentry(_ context.Context, b64CipherText string, orgID string) (string, error) {
	blob, err := base64.StdEncoding.DecodeString(b64CipherText)
	if err != nil {
		return "", fmt.Errorf("base64 decode: %w", err)
	}

	block, err := aes.NewCipher(v.masterKey)
	if err != nil {
		return "", fmt.Errorf("aes cipher init: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("gcm init: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(blob) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertextBytes := blob[:nonceSize], blob[nonceSize:]
	authData := []byte(fmt.Sprintf("Cicada-Sentry-v1:%s", orgID))

	plainText, err := gcm.Open(nil, nonce, ciphertextBytes, authData)
	if err != nil {
		return "", errors.New("gcm open failed: potential cross-tenant breach attempt or invalid envelope")
	}

	return string(plainText), nil
}
