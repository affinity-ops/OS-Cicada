/*
 * Cicada Aegis — OQS C Bridge Implementation
 *
 * Wraps liboqs calls for ML-DSA-65 and ML-KEM-768 into a simple C API
 * that can be called from Swift via the bridging header.
 *
 * This file links against liboqs.a. Build liboqs with:
 *   cmake -DCMAKE_OSX_ARCHITECTURES=arm64 \
 *         -DCMAKE_SYSTEM_NAME=iOS \
 *         -DCMAKE_OSX_DEPLOYMENT_TARGET=14.0 \
 *         -DOQS_ENABLE_SIG_ML_DSA=ON \
 *         -DOQS_ENABLE_KEM_ML_KEM=ON ..
 */

#include "OqsBridge.h"
#include <oqs/oqs.h>
#include <stdlib.h>
#include <string.h>

/* ── ML-DSA-65 (Digital Signatures) ─────────────────────────────────────── */

OqsKeyPair* oqs_ml_dsa65_keygen(void) {
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    if (!sig) return NULL;

    OqsKeyPair *kp = (OqsKeyPair *)calloc(1, sizeof(OqsKeyPair));
    if (!kp) { OQS_SIG_free(sig); return NULL; }

    kp->public_key_length = sig->length_public_key;
    kp->secret_key_length = sig->length_secret_key;
    kp->public_key = (uint8_t *)malloc(kp->public_key_length);
    kp->secret_key = (uint8_t *)malloc(kp->secret_key_length);

    if (!kp->public_key || !kp->secret_key) {
        oqs_free_keypair(kp);
        OQS_SIG_free(sig);
        return NULL;
    }

    if (OQS_SIG_keypair(sig, kp->public_key, kp->secret_key) != OQS_SUCCESS) {
        oqs_free_keypair(kp);
        OQS_SIG_free(sig);
        return NULL;
    }

    OQS_SIG_free(sig);
    return kp;
}

OqsBuffer* oqs_ml_dsa65_sign(
    const uint8_t *message, size_t message_len,
    const uint8_t *secret_key, size_t secret_key_len
) {
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    if (!sig) return NULL;

    /* Verify key size. */
    if (secret_key_len != sig->length_secret_key) {
        OQS_SIG_free(sig);
        return NULL;
    }

    OqsBuffer *buf = (OqsBuffer *)calloc(1, sizeof(OqsBuffer));
    if (!buf) { OQS_SIG_free(sig); return NULL; }

    buf->data = (uint8_t *)malloc(sig->length_signature);
    if (!buf->data) {
        free(buf);
        OQS_SIG_free(sig);
        return NULL;
    }

    if (OQS_SIG_sign(sig, buf->data, &buf->length,
                      message, message_len, secret_key) != OQS_SUCCESS) {
        oqs_free_buffer(buf);
        OQS_SIG_free(sig);
        return NULL;
    }

    OQS_SIG_free(sig);
    return buf;
}

int oqs_ml_dsa65_verify(
    const uint8_t *message, size_t message_len,
    const uint8_t *signature, size_t signature_len,
    const uint8_t *public_key, size_t public_key_len
) {
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    if (!sig) return 0;

    int valid = (OQS_SIG_verify(sig, message, message_len,
                                signature, signature_len, public_key) == OQS_SUCCESS) ? 1 : 0;

    OQS_SIG_free(sig);
    return valid;
}

/* ── ML-KEM-768 (Key Encapsulation Mechanism) ───────────────────────────── */

OqsKeyPair* oqs_ml_kem768_keygen(void) {
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (!kem) return NULL;

    OqsKeyPair *kp = (OqsKeyPair *)calloc(1, sizeof(OqsKeyPair));
    if (!kp) { OQS_KEM_free(kem); return NULL; }

    kp->public_key_length = kem->length_public_key;
    kp->secret_key_length = kem->length_secret_key;
    kp->public_key = (uint8_t *)malloc(kp->public_key_length);
    kp->secret_key = (uint8_t *)malloc(kp->secret_key_length);

    if (!kp->public_key || !kp->secret_key) {
        oqs_free_keypair(kp);
        OQS_KEM_free(kem);
        return NULL;
    }

    if (OQS_KEM_keypair(kem, kp->public_key, kp->secret_key) != OQS_SUCCESS) {
        oqs_free_keypair(kp);
        OQS_KEM_free(kem);
        return NULL;
    }

    OQS_KEM_free(kem);
    return kp;
}

OqsEncapsResult* oqs_ml_kem768_encaps(
    const uint8_t *public_key, size_t public_key_len
) {
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (!kem) return NULL;

    if (public_key_len != kem->length_public_key) {
        OQS_KEM_free(kem);
        return NULL;
    }

    OqsEncapsResult *er = (OqsEncapsResult *)calloc(1, sizeof(OqsEncapsResult));
    if (!er) { OQS_KEM_free(kem); return NULL; }

    er->ciphertext = (uint8_t *)malloc(kem->length_ciphertext);
    er->shared_secret = (uint8_t *)malloc(kem->length_shared_secret);
    er->ciphertext_length = kem->length_ciphertext;
    er->shared_secret_length = kem->length_shared_secret;

    if (!er->ciphertext || !er->shared_secret) {
        oqs_free_encaps(er);
        OQS_KEM_free(kem);
        return NULL;
    }

    if (OQS_KEM_encaps(kem, er->ciphertext, er->shared_secret,
                        public_key) != OQS_SUCCESS) {
        oqs_free_encaps(er);
        OQS_KEM_free(kem);
        return NULL;
    }

    OQS_KEM_free(kem);
    return er;
}

OqsBuffer* oqs_ml_kem768_decaps(
    const uint8_t *ciphertext, size_t ciphertext_len,
    const uint8_t *secret_key, size_t secret_key_len
) {
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (!kem) return NULL;

    OqsBuffer *buf = (OqsBuffer *)calloc(1, sizeof(OqsBuffer));
    if (!buf) { OQS_KEM_free(kem); return NULL; }

    buf->data = (uint8_t *)malloc(kem->length_shared_secret);
    buf->length = kem->length_shared_secret;

    if (!buf->data) {
        free(buf);
        OQS_KEM_free(kem);
        return NULL;
    }

    if (OQS_KEM_decaps(kem, buf->data, ciphertext, secret_key) != OQS_SUCCESS) {
        oqs_free_buffer(buf);
        OQS_KEM_free(kem);
        return NULL;
    }

    OQS_KEM_free(kem);
    return buf;
}

/* ── Memory management ──────────────────────────────────────────────────── */

void oqs_free_buffer(OqsBuffer *buf) {
    if (buf) {
        if (buf->data) {
            /* Zero-wipe secret data before freeing. */
            OQS_MEM_cleanse(buf->data, buf->length);
            free(buf->data);
        }
        free(buf);
    }
}

void oqs_free_keypair(OqsKeyPair *kp) {
    if (kp) {
        if (kp->public_key) free(kp->public_key);
        if (kp->secret_key) {
            OQS_MEM_cleanse(kp->secret_key, kp->secret_key_length);
            free(kp->secret_key);
        }
        free(kp);
    }
}

void oqs_free_encaps(OqsEncapsResult *er) {
    if (er) {
        if (er->ciphertext) free(er->ciphertext);
        if (er->shared_secret) {
            OQS_MEM_cleanse(er->shared_secret, er->shared_secret_length);
            free(er->shared_secret);
        }
        free(er);
    }
}
