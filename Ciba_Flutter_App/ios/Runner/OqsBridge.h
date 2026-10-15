/*
 * Cicada Aegis — OQS C Bridge Header
 *
 * C interface to liboqs for ML-DSA-65 (signatures) and ML-KEM-768 (KEM).
 * Called from AppDelegate.swift via the post_quantum platform channel.
 *
 * Prerequisites:
 *   - liboqs compiled as a static library for iOS (arm64).
 *   - liboqs.a linked in Xcode: Build Phases → Link Binary With Libraries.
 *   - Header search path: $(PROJECT_DIR)/Runner/liboqs/include
 *
 * Add this file to the Xcode project and include it in
 * Runner-Bridging-Header.h:
 *   #import "OqsBridge.h"
 */

#ifndef OqsBridge_h
#define OqsBridge_h

#include <stddef.h>
#include <stdint.h>

/* ── Result structures ──────────────────────────────────────────────────── */

typedef struct {
    uint8_t *data;
    size_t length;
} OqsBuffer;

typedef struct {
    uint8_t *public_key;
    size_t public_key_length;
    uint8_t *secret_key;
    size_t secret_key_length;
} OqsKeyPair;

typedef struct {
    uint8_t *ciphertext;
    size_t ciphertext_length;
    uint8_t *shared_secret;
    size_t shared_secret_length;
} OqsEncapsResult;

/* ── ML-DSA-65 (Digital Signatures) ─────────────────────────────────────── */

/// Generates an ML-DSA-65 key pair.
/// Caller must free with oqs_free_keypair().
OqsKeyPair* oqs_ml_dsa65_keygen(void);

/// Signs a message with ML-DSA-65.
/// Caller must free the returned buffer with oqs_free_buffer().
OqsBuffer* oqs_ml_dsa65_sign(
    const uint8_t *message, size_t message_len,
    const uint8_t *secret_key, size_t secret_key_len
);

/// Verifies an ML-DSA-65 signature.
/// Returns 1 if valid, 0 if invalid.
int oqs_ml_dsa65_verify(
    const uint8_t *message, size_t message_len,
    const uint8_t *signature, size_t signature_len,
    const uint8_t *public_key, size_t public_key_len
);

/* ── ML-KEM-768 (Key Encapsulation Mechanism) ───────────────────────────── */

/// Generates an ML-KEM-768 key pair.
/// Caller must free with oqs_free_keypair().
OqsKeyPair* oqs_ml_kem768_keygen(void);

/// Encapsulates a shared secret using the public key.
/// Caller must free with oqs_free_encaps().
OqsEncapsResult* oqs_ml_kem768_encaps(
    const uint8_t *public_key, size_t public_key_len
);

/// Decapsulates a shared secret using the secret key and ciphertext.
/// Caller must free with oqs_free_buffer().
OqsBuffer* oqs_ml_kem768_decaps(
    const uint8_t *ciphertext, size_t ciphertext_len,
    const uint8_t *secret_key, size_t secret_key_len
);

/* ── Memory management ──────────────────────────────────────────────────── */

void oqs_free_buffer(OqsBuffer *buf);
void oqs_free_keypair(OqsKeyPair *kp);
void oqs_free_encaps(OqsEncapsResult *er);

#endif /* OqsBridge_h */
