// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package pqc provides post-quantum cryptographic verification for the
// Cicada Sentry Gateway.
//
// This package uses Cloudflare CIRCL (github.com/cloudflare/circl) which
// provides native Go implementations of NIST FIPS 204 (ML-DSA) and
// FIPS 203 (ML-KEM). No CGO or external C libraries required.
//
// Security model:
//
//	Every decision submitted by the Aegis app MUST carry BOTH an Ed25519
//	signature (classical) AND an ML-DSA-65 signature (post-quantum). The
//	Gateway verifies both independently — if either fails, the decision
//	is rejected. This hybrid approach ensures security against both
//	classical and quantum adversaries.
//
// NIST references:
//   - ML-DSA-65: FIPS 204 (formerly Dilithium3), security level 3
//   - ML-KEM-768: FIPS 203 (formerly Kyber768), security level 3
package pqc

import (
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// ─── ML-DSA-65 Signature Verification ────────────────────────────────────────

// VerifyMLDSA65 verifies an ML-DSA-65 (FIPS 204) signature.
//
// Parameters:
//   - publicKeyB64: base64-encoded ML-DSA-65 public key (1952 bytes decoded)
//   - message: the raw bytes that were signed
//   - signatureB64: base64-encoded ML-DSA-65 signature (3309 bytes decoded)
//
// Returns nil if the signature is valid, or an error describing the failure.
// The error messages are intentionally detailed for audit logging but do NOT
// leak the actual key material.
func VerifyMLDSA65(publicKeyB64 string, message []byte, signatureB64 string) error {
	// ── Decode and validate the public key ────────────────────────────────
	pubKeyBytes, err := base64.StdEncoding.DecodeString(publicKeyB64)
	if err != nil {
		return fmt.Errorf("ml-dsa-65: invalid public key encoding: %w", err)
	}

	// ML-DSA-65 public key is exactly 1952 bytes (FIPS 204 spec)
	if len(pubKeyBytes) != mldsa65.PublicKeySize {
		return fmt.Errorf("ml-dsa-65: public key size mismatch: got %d bytes, expected %d",
			len(pubKeyBytes), mldsa65.PublicKeySize)
	}

	var pubKey mldsa65.PublicKey
	pubKey.Unpack((*[mldsa65.PublicKeySize]byte)(pubKeyBytes))

	// ── Decode and validate the signature ─────────────────────────────────
	sigBytes, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return fmt.Errorf("ml-dsa-65: invalid signature encoding: %w", err)
	}

	// ML-DSA-65 signature is exactly 3309 bytes (FIPS 204 spec)
	if len(sigBytes) != mldsa65.SignatureSize {
		return fmt.Errorf("ml-dsa-65: signature size mismatch: got %d bytes, expected %d",
			len(sigBytes), mldsa65.SignatureSize)
	}

	// ── Verify the signature ──────────────────────────────────────────────
	// CIRCL's Verify returns true if the signature is valid.
	// We pass nil for the context string (no domain separation required
	// for our use case — the signing payload already includes hold_ref,
	// decision, nonce, timestamp, and hash for uniqueness).
	valid := mldsa65.Verify(&pubKey, message, nil, sigBytes)
	if !valid {
		return errors.New("ml-dsa-65: signature verification failed — payload may have been tampered with")
	}

	return nil
}

// IsMLDSA65Available returns true if ML-DSA-65 support is compiled in.
// This is always true when using Cloudflare CIRCL, but provides a clean
// feature flag for the handlers to check.
func IsMLDSA65Available() bool {
	return true
}

// ─── ML-DSA-65 Key Generation ────────────────────────────────────────────────

// GenerateMLDSA65Keypair generates a new ML-DSA-65 keypair for gossip signing.
// Returns the public key and private key as base64-encoded strings.
// The public key is 1952 bytes (base64: ~2,604 chars).
// The private key is 4032 bytes (base64: ~5,376 chars).
func GenerateMLDSA65Keypair() (pubKeyB64, privKeyB64 string, err error) {
	pubKey, privKey, err := mldsa65.GenerateKey(nil)
	if err != nil {
		return "", "", fmt.Errorf("ml-dsa-65: key generation failed: %w", err)
	}

	var pubBytes [mldsa65.PublicKeySize]byte
	var privBytes [mldsa65.PrivateKeySize]byte
	pubKey.Pack(&pubBytes)
	privKey.Pack(&privBytes)

	return base64.StdEncoding.EncodeToString(pubBytes[:]),
		base64.StdEncoding.EncodeToString(privBytes[:]),
		nil
}

// SignMLDSA65 signs a message with an ML-DSA-65 private key.
//
// Parameters:
//   - privKeyB64: base64-encoded ML-DSA-65 private key (4032 bytes decoded)
//   - message: the raw bytes to sign
//
// Returns the base64-encoded signature (3309 bytes decoded), or an error.
func SignMLDSA65(privKeyB64 string, message []byte) (string, error) {
	privKeyBytes, err := base64.StdEncoding.DecodeString(privKeyB64)
	if err != nil {
		return "", fmt.Errorf("ml-dsa-65: invalid private key encoding: %w", err)
	}

	if len(privKeyBytes) != mldsa65.PrivateKeySize {
		return "", fmt.Errorf("ml-dsa-65: private key size mismatch: got %d bytes, expected %d",
			len(privKeyBytes), mldsa65.PrivateKeySize)
	}

	var privKey mldsa65.PrivateKey
	privKey.Unpack((*[mldsa65.PrivateKeySize]byte)(privKeyBytes))

	// Sign with nil context string, deterministic mode (not randomized).
	// Same convention as verification.
	var sig [mldsa65.SignatureSize]byte
	if err := mldsa65.SignTo(&privKey, message, nil, false, sig[:]); err != nil {
		return "", fmt.Errorf("ml-dsa-65: signing failed: %w", err)
	}

	return base64.StdEncoding.EncodeToString(sig[:]), nil
}
