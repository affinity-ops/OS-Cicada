// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package pqc_test

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/asai/cicada/sentry/pkg/pqc"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

func TestVerifyMLDSA65_Success(t *testing.T) {
	// 1. Generate a genuine keypair
	pubKey, privKey, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate keys: %v", err)
	}

	// 2. Pack and encode the public key
	var pubKeyBytes [mldsa65.PublicKeySize]byte
	pubKey.Pack(&pubKeyBytes)
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKeyBytes[:])

	// 3. Create and sign a payload
	payload := []byte(`{"action":"approve","amount":50000}`)
	var sigBytes [mldsa65.SignatureSize]byte
	err = mldsa65.SignTo(privKey, payload, nil, false, sigBytes[:])
	if err != nil {
		t.Fatalf("Failed to sign payload: %v", err)
	}
	sigB64 := base64.StdEncoding.EncodeToString(sigBytes[:])

	// 4. Verify using our wrapper
	err = pqc.VerifyMLDSA65(pubKeyB64, payload, sigB64)
	if err != nil {
		t.Fatalf("Expected valid signature to pass, got error: %v", err)
	}
}

func TestVerifyMLDSA65_TamperedPayload(t *testing.T) {
	pubKey, privKey, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate keys: %v", err)
	}

	var pubKeyBytes [mldsa65.PublicKeySize]byte
	pubKey.Pack(&pubKeyBytes)
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKeyBytes[:])

	originalPayload := []byte(`{"action":"approve","amount":50}`)
	tamperedPayload := []byte(`{"action":"approve","amount":50000}`) // Tampered

	var sigBytes [mldsa65.SignatureSize]byte
	err = mldsa65.SignTo(privKey, originalPayload, nil, false, sigBytes[:])
	if err != nil {
		t.Fatalf("Failed to sign payload: %v", err)
	}
	sigB64 := base64.StdEncoding.EncodeToString(sigBytes[:])

	// Verify using our wrapper with the TAMPERED payload
	err = pqc.VerifyMLDSA65(pubKeyB64, tamperedPayload, sigB64)
	if err == nil {
		t.Fatal("Expected tampered payload to fail verification, but it passed")
	}
	if !strings.Contains(err.Error(), "verification failed") {
		t.Errorf("Expected verification failure error, got: %v", err)
	}
}

func TestVerifyMLDSA65_ValidationFailures(t *testing.T) {
	// Generate valid lengths for the tests
	validKey := base64.StdEncoding.EncodeToString(make([]byte, mldsa65.PublicKeySize))
	validSig := base64.StdEncoding.EncodeToString(make([]byte, mldsa65.SignatureSize))

	// Create a corrupt signature with the correct length by modifying one byte
	corruptSigBytes := make([]byte, mldsa65.SignatureSize)
	corruptSigBytes[100] = 0xFF // Flipping an interior byte
	corruptSig := base64.StdEncoding.EncodeToString(corruptSigBytes)

	tests := []struct {
		name        string
		pubKey      string
		signature   string
		expectedErr string
	}{
		{"Short Public Key", base64.StdEncoding.EncodeToString([]byte("short")), validSig, "public key size mismatch"},
		{"Short Signature", validKey, base64.StdEncoding.EncodeToString([]byte("short")), "signature size mismatch"},
		{"Corrupt Key Base64", "!!!not-valid!!!", validSig, "invalid public key encoding"},
		{"Corrupt Sig Base64", validKey, "!!!not-valid!!!", "invalid signature encoding"},
		{"Interior Byte Corruption", validKey, corruptSig, "signature verification failed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := pqc.VerifyMLDSA65(tt.pubKey, []byte("test"), tt.signature)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.expectedErr)
			}
			if !strings.Contains(err.Error(), tt.expectedErr) {
				t.Errorf("expected error %q, got: %v", tt.expectedErr, err)
			}
		})
	}
}

func TestVerifyMLDSA65_FeatureFlag(t *testing.T) {
	if !pqc.IsMLDSA65Available() {
		t.Fatal("Expected IsMLDSA65Available to return true")
	}
}
