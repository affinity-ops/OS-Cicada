// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"log"
	"os"
)

// GlobalSentryPrivateKey and GlobalSentryPublicKey represent the Sentry
// Node's cryptographic identity. In production these are loaded from disk
// so EVAR tokens survive restarts.
var (
	GlobalSentryPrivateKey ed25519.PrivateKey
	GlobalSentryPublicKey  ed25519.PublicKey
)

// InitializeGatewayAuthority loads the Ed25519 keypair from the path specified
// by the CICADA_KEY_PATH environment variable. If the file does not exist, it
// generates a new keypair, writes it to disk, and logs a warning.
func InitializeGatewayAuthority() error {
	keyPath := os.Getenv("CICADA_KEY_PATH")
	if keyPath == "" {
		keyPath = "sentry_ed25519.key"
	}

	// Attempt to load from disk first
	data, err := os.ReadFile(keyPath)
	if err == nil {
		block, _ := pem.Decode(data)
		if block == nil || block.Type != "ED25519 PRIVATE KEY" {
			return fmt.Errorf("invalid PEM block in key file %s", keyPath)
		}
		if len(block.Bytes) != ed25519.SeedSize {
			return fmt.Errorf("key file %s has invalid seed length %d (expected %d)", keyPath, len(block.Bytes), ed25519.SeedSize)
		}

		GlobalSentryPrivateKey = ed25519.NewKeyFromSeed(block.Bytes)
		GlobalSentryPublicKey = GlobalSentryPrivateKey.Public().(ed25519.PublicKey)
		log.Printf("[AUTH] Loaded Ed25519 identity from %s", keyPath)
		return nil
	}

	if !os.IsNotExist(err) {
		return fmt.Errorf("failed to read key file %s: %w", keyPath, err)
	}

	// Key file does not exist — generate new keypair
	log.Printf("[AUTH WARNING] No key file found at %s — generating new Ed25519 keypair. This should only happen once.", keyPath)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("Ed25519 key generation failed: %w", err)
	}

	GlobalSentryPrivateKey = priv
	GlobalSentryPublicKey = pub

	// Persist the seed to disk
	block := &pem.Block{
		Type:  "ED25519 PRIVATE KEY",
		Bytes: priv.Seed(),
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(block), 0600); err != nil {
		return fmt.Errorf("failed to write key file %s: %w", keyPath, err)
	}

	log.Printf("[AUTH] Generated and persisted new Ed25519 identity to %s", keyPath)
	return nil
}
