/*
 * Cicada Aegis — liboqs JNI Bridge
 *
 * JNI native methods for ML-DSA-65 (FIPS 204) and ML-KEM-768 (FIPS 203)
 * called from MainActivity.kt via System.loadLibrary("oqs_jni").
 *
 * Build with CMake (via android/app/build.gradle.kts):
 *   android {
 *       externalNativeBuild {
 *           cmake { path = file("src/main/cpp/CMakeLists.txt") }
 *       }
 *   }
 *
 * Prerequisites:
 *   - liboqs cross-compiled for Android ARM64 (scripts/build_liboqs_android.sh)
 *   - liboqs.a in src/main/cpp/liboqs/lib/arm64-v8a/
 *   - liboqs headers in src/main/cpp/liboqs/include/oqs/
 *
 * Security invariants:
 *   - Secret keys are zero-wiped with OQS_MEM_cleanse() before free().
 *   - All JNI byte arrays released with JNI_ABORT (no copy-back of secrets).
 */

#include <jni.h>
#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h>

/*
 * JNI function name prefix for com.cicada.aegis.aegis_ciba_companion.MainActivity.
 * JNI encodes underscores in package names as _1, so:
 *   com.cicada.aegis.aegis_ciba_companion.MainActivity
 *   → Java_com_cicada_aegis_aegis_1ciba_1companion_MainActivity_<method>
 */
#define JNI_FN(method) Java_com_cicada_aegis_aegis_1ciba_1companion_MainActivity_##method

/* ── ML-DSA-65 (FIPS 204) ───────────────────────────────────────────────── */

JNIEXPORT jbyteArray JNICALL
JNI_FN(nativeMlDsa65Sign)(
    JNIEnv *env, jclass cls,
    jbyteArray jmessage, jbyteArray jsecretKey
) {
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    if (!sig) return NULL;

    jsize msg_len = (*env)->GetArrayLength(env, jmessage);

    jbyte *msg = (*env)->GetByteArrayElements(env, jmessage, NULL);
    jbyte *sk = (*env)->GetByteArrayElements(env, jsecretKey, NULL);

    uint8_t *signature = (uint8_t *)malloc(sig->length_signature);
    size_t sig_len = 0;

    OQS_STATUS status = OQS_SIG_sign(
        sig, signature, &sig_len,
        (const uint8_t *)msg, (size_t)msg_len,
        (const uint8_t *)sk
    );

    (*env)->ReleaseByteArrayElements(env, jmessage, msg, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, jsecretKey, sk, JNI_ABORT);

    jbyteArray result = NULL;
    if (status == OQS_SUCCESS) {
        result = (*env)->NewByteArray(env, (jsize)sig_len);
        (*env)->SetByteArrayRegion(env, result, 0, (jsize)sig_len, (jbyte *)signature);
    }

    /* Zero-wipe before free. */
    OQS_MEM_cleanse(signature, sig->length_signature);
    free(signature);
    OQS_SIG_free(sig);
    return result;
}

JNIEXPORT jboolean JNICALL
JNI_FN(nativeMlDsa65Verify)(
    JNIEnv *env, jclass cls,
    jbyteArray jmessage, jbyteArray jsignature, jbyteArray jpublicKey
) {
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    if (!sig) return JNI_FALSE;

    jbyte *msg = (*env)->GetByteArrayElements(env, jmessage, NULL);
    jbyte *sigbuf = (*env)->GetByteArrayElements(env, jsignature, NULL);
    jbyte *pk = (*env)->GetByteArrayElements(env, jpublicKey, NULL);

    jsize msg_len = (*env)->GetArrayLength(env, jmessage);
    jsize sig_len = (*env)->GetArrayLength(env, jsignature);

    OQS_STATUS status = OQS_SIG_verify(
        sig,
        (const uint8_t *)msg, (size_t)msg_len,
        (const uint8_t *)sigbuf, (size_t)sig_len,
        (const uint8_t *)pk
    );

    (*env)->ReleaseByteArrayElements(env, jmessage, msg, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, jsignature, sigbuf, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, jpublicKey, pk, JNI_ABORT);
    OQS_SIG_free(sig);

    return (status == OQS_SUCCESS) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jobjectArray JNICALL
JNI_FN(nativeMlDsa65Keygen)(JNIEnv *env, jclass cls) {
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    if (!sig) return NULL;

    uint8_t *pk = (uint8_t *)malloc(sig->length_public_key);
    uint8_t *sk = (uint8_t *)malloc(sig->length_secret_key);

    if (OQS_SIG_keypair(sig, pk, sk) != OQS_SUCCESS) {
        free(pk);
        OQS_MEM_cleanse(sk, sig->length_secret_key);
        free(sk);
        OQS_SIG_free(sig);
        return NULL;
    }

    /* Return as Object[] { byte[] publicKey, byte[] secretKey } */
    jclass byteArrayClass = (*env)->FindClass(env, "[B");
    jobjectArray result = (*env)->NewObjectArray(env, 2, byteArrayClass, NULL);

    jbyteArray jpk = (*env)->NewByteArray(env, (jsize)sig->length_public_key);
    (*env)->SetByteArrayRegion(env, jpk, 0, (jsize)sig->length_public_key, (jbyte *)pk);

    jbyteArray jsk = (*env)->NewByteArray(env, (jsize)sig->length_secret_key);
    (*env)->SetByteArrayRegion(env, jsk, 0, (jsize)sig->length_secret_key, (jbyte *)sk);

    (*env)->SetObjectArrayElement(env, result, 0, jpk);
    (*env)->SetObjectArrayElement(env, result, 1, jsk);

    free(pk);
    OQS_MEM_cleanse(sk, sig->length_secret_key);
    free(sk);
    OQS_SIG_free(sig);

    return result;
}

/* ── ML-KEM-768 (FIPS 203) ──────────────────────────────────────────────── */

JNIEXPORT jobjectArray JNICALL
JNI_FN(nativeMlKem768Encaps)(JNIEnv *env, jclass cls, jbyteArray jpublicKey) {
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (!kem) return NULL;

    jbyte *pk = (*env)->GetByteArrayElements(env, jpublicKey, NULL);

    uint8_t *ct = (uint8_t *)malloc(kem->length_ciphertext);
    uint8_t *ss = (uint8_t *)malloc(kem->length_shared_secret);

    OQS_STATUS status = OQS_KEM_encaps(kem, ct, ss, (const uint8_t *)pk);

    (*env)->ReleaseByteArrayElements(env, jpublicKey, pk, JNI_ABORT);

    if (status != OQS_SUCCESS) {
        free(ct);
        OQS_MEM_cleanse(ss, kem->length_shared_secret);
        free(ss);
        OQS_KEM_free(kem);
        return NULL;
    }

    jclass byteArrayClass = (*env)->FindClass(env, "[B");
    jobjectArray result = (*env)->NewObjectArray(env, 2, byteArrayClass, NULL);

    jbyteArray jct = (*env)->NewByteArray(env, (jsize)kem->length_ciphertext);
    (*env)->SetByteArrayRegion(env, jct, 0, (jsize)kem->length_ciphertext, (jbyte *)ct);

    jbyteArray jss = (*env)->NewByteArray(env, (jsize)kem->length_shared_secret);
    (*env)->SetByteArrayRegion(env, jss, 0, (jsize)kem->length_shared_secret, (jbyte *)ss);

    (*env)->SetObjectArrayElement(env, result, 0, jct);
    (*env)->SetObjectArrayElement(env, result, 1, jss);

    free(ct);
    OQS_MEM_cleanse(ss, kem->length_shared_secret);
    free(ss);
    OQS_KEM_free(kem);

    return result;
}

JNIEXPORT jbyteArray JNICALL
JNI_FN(nativeMlKem768Decaps)(
    JNIEnv *env, jclass cls,
    jbyteArray jciphertext, jbyteArray jsecretKey
) {
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (!kem) return NULL;

    jbyte *ct = (*env)->GetByteArrayElements(env, jciphertext, NULL);
    jbyte *sk = (*env)->GetByteArrayElements(env, jsecretKey, NULL);

    uint8_t *ss = (uint8_t *)malloc(kem->length_shared_secret);

    OQS_STATUS status = OQS_KEM_decaps(kem, ss, (const uint8_t *)ct, (const uint8_t *)sk);

    (*env)->ReleaseByteArrayElements(env, jciphertext, ct, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, jsecretKey, sk, JNI_ABORT);

    jbyteArray result = NULL;
    if (status == OQS_SUCCESS) {
        result = (*env)->NewByteArray(env, (jsize)kem->length_shared_secret);
        (*env)->SetByteArrayRegion(env, result, 0, (jsize)kem->length_shared_secret, (jbyte *)ss);
    }

    OQS_MEM_cleanse(ss, kem->length_shared_secret);
    free(ss);
    OQS_KEM_free(kem);
    return result;
}

JNIEXPORT jobjectArray JNICALL
JNI_FN(nativeMlKem768Keygen)(JNIEnv *env, jclass cls) {
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (!kem) return NULL;

    uint8_t *pk = (uint8_t *)malloc(kem->length_public_key);
    uint8_t *sk = (uint8_t *)malloc(kem->length_secret_key);

    if (OQS_KEM_keypair(kem, pk, sk) != OQS_SUCCESS) {
        free(pk);
        OQS_MEM_cleanse(sk, kem->length_secret_key);
        free(sk);
        OQS_KEM_free(kem);
        return NULL;
    }

    jclass byteArrayClass = (*env)->FindClass(env, "[B");
    jobjectArray result = (*env)->NewObjectArray(env, 2, byteArrayClass, NULL);

    jbyteArray jpk = (*env)->NewByteArray(env, (jsize)kem->length_public_key);
    (*env)->SetByteArrayRegion(env, jpk, 0, (jsize)kem->length_public_key, (jbyte *)pk);

    jbyteArray jsk = (*env)->NewByteArray(env, (jsize)kem->length_secret_key);
    (*env)->SetByteArrayRegion(env, jsk, 0, (jsize)kem->length_secret_key, (jbyte *)sk);

    (*env)->SetObjectArrayElement(env, result, 0, jpk);
    (*env)->SetObjectArrayElement(env, result, 1, jsk);

    free(pk);
    OQS_MEM_cleanse(sk, kem->length_secret_key);
    free(sk);
    OQS_KEM_free(kem);

    return result;
}
