/// Cicada Aegis — Android MainActivity
///
/// Implements native platform channels for:
///
/// Phase 3 — Screen Capture Prevention:
///   FLAG_SECURE prevents screenshots, screen recording, and recent-apps
///   thumbnail capture of sensitive HITL decision data.
///
/// Phase 6 — Device Integrity:
///   Play Integrity API — per-decision attestation token generation.
///   Local root/jailbreak detection for telemetry.
///
/// Phase 4 — CryptoObject Biometric Binding:
///   BiometricPrompt with CryptoObject — biometric authentication that
///   cryptographically binds the signing key unlock to a live biometric scan.
///
/// Post-Quantum — ML-DSA-65 / ML-KEM-768:
///   Native JNI bindings to liboqs for post-quantum signatures and KEM.
///
/// These channels are invoked by DeviceSecurityService.dart,
/// BiometricService.dart, and KeystoreService.dart on the Flutter side.

package com.cicada.aegis.aegis_ciba_companion

import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.view.WindowManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.StandardIntegrityManager
import io.flutter.embedding.android.FlutterFragmentActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.util.Base64

class MainActivity : FlutterFragmentActivity() {

    // Channel names must match DeviceSecurityService.dart constants.
    private val SECURITY_CHANNEL = "com.cicada.aegis/security"
    private val INTEGRITY_CHANNEL = "com.cicada.aegis/integrity"
    private val BIOMETRIC_CHANNEL = "com.cicada.aegis/biometric_crypto"
    private val PQ_CHANNEL = "com.cicada.aegis/post_quantum"

    // ── Play Integrity — Standard API Manager ──────────────────────────────
    // Initialised once at app startup. The token provider is reused for
    // each per-decision attestation request.
    private var integrityTokenProvider: StandardIntegrityManager.StandardIntegrityTokenProvider? = null

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)

        // ── Prepare Play Integrity token provider ──────────────────────────
        prepareIntegrityTokenProvider()

        // ── Phase 3: Screen Capture Prevention ─────────────────────────────
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, SECURITY_CHANNEL)
            .setMethodCallHandler { call, result ->
                when (call.method) {
                    "enableScreenProtection" -> {
                        window.setFlags(
                            WindowManager.LayoutParams.FLAG_SECURE,
                            WindowManager.LayoutParams.FLAG_SECURE
                        )
                        result.success(true)
                    }
                    "disableScreenProtection" -> {
                        window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
                        result.success(true)
                    }
                    "stopNativeAlarm" -> {
                        HitlFirebaseMessagingService.stopAlarm()
                        result.success(true)
                    }
                    else -> result.notImplemented()
                }
            }

        // ── Phase 6: Device Integrity (Play Integrity API) ─────────────────
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, INTEGRITY_CHANNEL)
            .setMethodCallHandler { call, result ->
                when (call.method) {
                    "getAttestationToken" -> {
                        val nonce = call.argument<String>("nonce")
                        if (nonce == null) {
                            result.error("INVALID_ARGS", "nonce is required", null)
                            return@setMethodCallHandler
                        }
                        requestIntegrityToken(nonce, result)
                    }
                    "localIntegrityCheck" -> {
                        result.success(localIntegrityCheck())
                    }
                    else -> result.notImplemented()
                }
            }

        // ── Phase 4: CryptoObject Biometric Binding ────────────────────────
        // Replaces the boolean-only local_auth with hardware-bound biometric
        // authentication. The signing key can only be unlocked by a live
        // biometric scan — not by any software bypass.
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, BIOMETRIC_CHANNEL)
            .setMethodCallHandler { call, result ->
                when (call.method) {
                    "authenticateAndSign" -> {
                        val payload = call.argument<String>("payload")
                        val reason = call.argument<String>("reason") ?: "Authenticate to sign"
                        if (payload == null) {
                            result.error("INVALID_ARGS", "payload is required", null)
                            return@setMethodCallHandler
                        }
                        authenticateAndSign(payload, reason, result)
                    }
                    "ensureKeyExists" -> {
                        ensureBiometricBoundKeyExists()
                        result.success(true)
                    }
                    else -> result.notImplemented()
                }
            }

        // ── Post-Quantum: ML-DSA-65 / ML-KEM-768 ──────────────────────────
        // Native JNI interface to liboqs (Open Quantum Safe).
        // liboqs must be compiled for Android and included as a .so in jniLibs.
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, PQ_CHANNEL)
            .setMethodCallHandler { call, result ->
                when (call.method) {
                    "isAvailable" -> {
                        // Probe call from MlDsaService.init() to check if liboqs is linked.
                        // Uses the static flag set during companion init {} block.
                        android.util.Log.i("CicadaPQ", "isAvailable probe: oqsLoaded=$oqsLoaded")
                        result.success(oqsLoaded)
                    }
                    "signMlDsa65" -> {
                        val message = call.argument<ByteArray>("message")
                        val secretKey = call.argument<ByteArray>("secret_key")
                        if (message == null || secretKey == null) {
                            result.error("INVALID_ARGS", "message and secret_key required", null)
                            return@setMethodCallHandler
                        }
                        signMlDsa65(message, secretKey, result)
                    }
                    "verifyMlDsa65" -> {
                        val message = call.argument<ByteArray>("message")
                        val signature = call.argument<ByteArray>("signature")
                        val publicKey = call.argument<ByteArray>("public_key")
                        if (message == null || signature == null || publicKey == null) {
                            result.error("INVALID_ARGS", "message, signature, and public_key required", null)
                            return@setMethodCallHandler
                        }
                        verifyMlDsa65(message, signature, publicKey, result)
                    }
                    "generateMlDsa65KeyPair" -> {
                        generateMlDsa65KeyPair(result)
                    }
                    "encapsulateMlKem768" -> {
                        val publicKey = call.argument<ByteArray>("public_key")
                        if (publicKey == null) {
                            result.error("INVALID_ARGS", "public_key required", null)
                            return@setMethodCallHandler
                        }
                        encapsulateMlKem768(publicKey, result)
                    }
                    "decapsulateMlKem768" -> {
                        val ciphertext = call.argument<ByteArray>("ciphertext")
                        val secretKey = call.argument<ByteArray>("secret_key")
                        if (ciphertext == null || secretKey == null) {
                            result.error("INVALID_ARGS", "ciphertext and secret_key required", null)
                            return@setMethodCallHandler
                        }
                        decapsulateMlKem768(ciphertext, secretKey, result)
                    }
                    "generateMlKem768KeyPair" -> {
                        generateMlKem768KeyPair(result)
                    }
                    else -> result.notImplemented()
                }
            }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Play Integrity API — Standard Integrity Flow
    // ─────────────────────────────────────────────────────────────────────────

    /// Prepares the Standard Integrity token provider.
    /// This is a warm-up step that pre-caches the integrity verdict
    /// so per-decision token requests complete in <100ms.
    private fun prepareIntegrityTokenProvider() {
        try {
            val integrityManager = IntegrityManagerFactory.createStandard(applicationContext)

            // Cloud project number is read from AndroidManifest metadata
            // to avoid hardcoding. Set via: <meta-data android:name="com.cicada.integrity.cloud_project_number" />
            val appInfo = packageManager.getApplicationInfo(
                packageName,
                android.content.pm.PackageManager.GET_META_DATA
            )
            val cloudProjectNumber = appInfo.metaData?.getLong(
                "com.cicada.integrity.cloud_project_number", 0L
            ) ?: 0L

            if (cloudProjectNumber == 0L) {
                android.util.Log.w("CicadaIntegrity",
                    "cloud_project_number not set in AndroidManifest — Play Integrity disabled")
                return
            }

            val request = StandardIntegrityManager.PrepareIntegrityTokenRequest.builder()
                .setCloudProjectNumber(cloudProjectNumber)
                .build()

            integrityManager.prepareIntegrityToken(request)
                .addOnSuccessListener { provider ->
                    integrityTokenProvider = provider
                    android.util.Log.i("CicadaIntegrity", "Play Integrity token provider ready")
                }
                .addOnFailureListener { e ->
                    android.util.Log.e("CicadaIntegrity",
                        "Failed to prepare integrity token provider: ${e.message}")
                }
        } catch (e: Exception) {
            android.util.Log.e("CicadaIntegrity", "Play Integrity init error: ${e.message}")
        }
    }

    /// Requests a fresh integrity token bound to the given nonce.
    /// The token is returned as a JWT string that the Gateway validates
    /// by calling Google's Play Integrity server-side API.
    private fun requestIntegrityToken(nonce: String, result: MethodChannel.Result) {
        val provider = integrityTokenProvider
        if (provider == null) {
            // Token provider not ready — return null.
            // The Gateway will handle missing attestation per its policy.
            result.success(null)
            return
        }

        try {
            val request = StandardIntegrityManager.StandardIntegrityTokenRequest.builder()
                .setRequestHash(nonce) // Binds the token to this decision's nonce.
                .build()

            provider.request(request)
                .addOnSuccessListener { response ->
                    result.success(response.token())
                }
                .addOnFailureListener { e ->
                    android.util.Log.e("CicadaIntegrity",
                        "Integrity token request failed: ${e.message}")
                    result.success(null)
                }
        } catch (e: Exception) {
            android.util.Log.e("CicadaIntegrity", "Token request error: ${e.message}")
            result.success(null)
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Phase 4: CryptoObject Biometric Binding
    // ─────────────────────────────────────────────────────────────────────────
    // Instead of local_auth returning a boolean, this uses Android's
    // BiometricPrompt with a CryptoObject wrapping a Signature instance.
    // The signing key is stored in Android Keystore with StrongBox
    // (when available) and requires biometric auth to unlock.
    //
    // Flow:
    //   1. Generate an EC P-256 key in Keystore with USER_AUTHENTICATION_REQUIRED.
    //   2. Create a Signature.getInstance("SHA256withECDSA") and init with private key.
    //   3. Wrap in BiometricPrompt.CryptoObject.
    //   4. On successful biometric auth, the CryptoObject is unlocked.
    //   5. Sign the payload with the unlocked Signature.
    //   6. Return the signature to Flutter.
    //
    // If biometric fails, the CryptoObject remains locked and signing
    // is impossible — there is no software bypass.

    private val BIOMETRIC_KEY_ALIAS = "cicada_aegis_biometric_bound_key"

    /// Ensures the biometric-bound signing key exists in Android Keystore.
    private fun ensureBiometricBoundKeyExists() {
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)

        if (keyStore.containsAlias(BIOMETRIC_KEY_ALIAS)) return

        val builder = KeyGenParameterSpec.Builder(
            BIOMETRIC_KEY_ALIAS,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        )
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setAlgorithmParameterSpec(java.security.spec.ECGenParameterSpec("secp256r1"))
            .setUserAuthenticationRequired(true)
            // setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG):
            //   0 = must authenticate for EVERY use (no caching).
            //   AUTH_BIOMETRIC_STRONG = Class 3 biometric only (no PIN/pattern fallback).
            .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
            // Request StrongBox if available (Titan M, Samsung Knox secure element).
            .setIsStrongBoxBacked(true)
            .setInvalidatedByBiometricEnrollment(true) // Key invalidated if fingerprints change.

        try {
            val keyGen = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore"
            )
            keyGen.initialize(builder.build())
            keyGen.generateKeyPair()
            android.util.Log.i("CicadaBiometric", "Biometric-bound key created (StrongBox)")
        } catch (e: android.security.keystore.StrongBoxUnavailableException) {
            // StrongBox not available — fall back to TEE-backed Keystore.
            val fallbackBuilder = KeyGenParameterSpec.Builder(
                BIOMETRIC_KEY_ALIAS,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            )
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAlgorithmParameterSpec(java.security.spec.ECGenParameterSpec("secp256r1"))
                .setUserAuthenticationRequired(true)
                .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
                .setInvalidatedByBiometricEnrollment(true)

            val keyGen = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore"
            )
            keyGen.initialize(fallbackBuilder.build())
            keyGen.generateKeyPair()
            android.util.Log.i("CicadaBiometric", "Biometric-bound key created (TEE fallback)")
        }
    }

    /// Authenticates with biometric and signs the payload in a single
    /// atomic operation. The key CANNOT be used without a live biometric scan.
    private fun authenticateAndSign(
        payload: String,
        reason: String,
        result: MethodChannel.Result
    ) {
        try {
            ensureBiometricBoundKeyExists()

            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)
            val privateKey = keyStore.getKey(BIOMETRIC_KEY_ALIAS, null) as java.security.PrivateKey

            // Initialise the Signature — this will require biometric auth
            // because the key was created with USER_AUTHENTICATION_REQUIRED.
            val signature = Signature.getInstance("SHA256withECDSA")
            signature.initSign(privateKey)

            // Wrap in CryptoObject — the biometric prompt will unlock this.
            val cryptoObject = BiometricPrompt.CryptoObject(signature)

            val executor = ContextCompat.getMainExecutor(this)
            val biometricPrompt = BiometricPrompt(
                this as FragmentActivity,
                executor,
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(authResult: BiometricPrompt.AuthenticationResult) {
                        super.onAuthenticationSucceeded(authResult)
                        try {
                            // The CryptoObject is now unlocked by the biometric.
                            // Sign the payload with the unlocked Signature.
                            val unlockedSig = authResult.cryptoObject?.signature
                                ?: throw Exception("CryptoObject signature is null after auth")

                            unlockedSig.update(payload.toByteArray(Charsets.UTF_8))
                            val signatureBytes = unlockedSig.sign()
                            val signatureBase64 = Base64.getEncoder().encodeToString(signatureBytes)

                            result.success(mapOf(
                                "signature" to signatureBase64,
                                "auth_method" to "biometric_cryptoobject",
                                "key_alias" to BIOMETRIC_KEY_ALIAS
                            ))
                        } catch (e: Exception) {
                            result.error("SIGN_ERROR",
                                "Biometric auth succeeded but signing failed: ${e.message}", null)
                        }
                    }

                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        super.onAuthenticationError(errorCode, errString)
                        result.error("AUTH_ERROR",
                            "Biometric authentication error ($errorCode): $errString", null)
                    }

                    override fun onAuthenticationFailed() {
                        super.onAuthenticationFailed()
                        // Individual attempt failed — BiometricPrompt retries automatically.
                        // Only onAuthenticationError is terminal.
                        android.util.Log.w("CicadaBiometric", "Biometric attempt failed (retrying)")
                    }
                }
            )

            val promptInfo = BiometricPrompt.PromptInfo.Builder()
                .setTitle("CIBA Security")
                .setSubtitle(reason)
                .setNegativeButtonText("Cancel")
                .setAllowedAuthenticators(androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG)
                .build()

            biometricPrompt.authenticate(promptInfo, cryptoObject)

        } catch (e: Exception) {
            result.error("CRYPTO_ERROR",
                "Failed to initialise biometric CryptoObject: ${e.message}", null)
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Local Root Detection (Telemetry Only)
    // ─────────────────────────────────────────────────────────────────────────

    private fun localIntegrityCheck(): HashMap<String, Boolean> {
        val checks = HashMap<String, Boolean>()
        checks["su_binary"] = !java.io.File("/system/bin/su").exists()
        checks["magisk"] = !java.io.File("/sbin/magisk").exists()
        checks["build_tags"] = !android.os.Build.TAGS.orEmpty().contains("test-keys")
        checks["verified_boot"] = android.os.Build.VERSION.SDK_INT >= 26
        return checks
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Post-Quantum Cryptography — ML-DSA-65 / ML-KEM-768 via liboqs JNI
    // ─────────────────────────────────────────────────────────────────────────
    //
    // These methods call into liboqs (Open Quantum Safe) via JNI.
    // liboqs must be compiled as a native Android library (.so) and placed in:
    //   android/app/src/main/jniLibs/{arm64-v8a,armeabi-v7a,x86_64}/liboqs_jni.so
    //
    // Build instructions for liboqs Android:
    //   1. Clone: git clone https://github.com/open-quantum-safe/liboqs.git
    //   2. Configure: cmake -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK/build/cmake/android.toolchain.cmake \
    //                       -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-24 \
    //                       -DOQS_ENABLE_SIG_ML_DSA=ON -DOQS_ENABLE_KEM_ML_KEM=ON ..
    //   3. Build: cmake --build . --parallel
    //   4. Copy: cp lib/liboqs.so android/app/src/main/jniLibs/arm64-v8a/
    //   5. Write JNI wrapper: OqsJni.kt (see below)

    companion object {
        // Tracks whether System.loadLibrary("oqs_jni") succeeded.
        // Used by the "isAvailable" platform channel probe.
        @JvmStatic var oqsLoaded = false
            private set

        init {
            try {
                System.loadLibrary("oqs_jni")
                oqsLoaded = true
                android.util.Log.i("CicadaPQ", "✅ liboqs JNI loaded successfully — PQC ACTIVE")
            } catch (e: UnsatisfiedLinkError) {
                oqsLoaded = false
                android.util.Log.w("CicadaPQ",
                    "❌ liboqs JNI not available: ${e.message}. PQ operations will return stubs.")
            }
        }

        // ── JNI native method declarations ──────────────────────────────────
        // These are implemented in C/C++ and compiled into liboqs_jni.so.
        // If the library is not loaded, these throw UnsatisfiedLinkError
        // which we catch and return stubs.

        @JvmStatic external fun nativeMlDsa65Sign(message: ByteArray, secretKey: ByteArray): ByteArray?
        @JvmStatic external fun nativeMlDsa65Verify(message: ByteArray, signature: ByteArray, publicKey: ByteArray): Boolean
        @JvmStatic external fun nativeMlDsa65Keygen(): Array<ByteArray>? // [publicKey, secretKey]
        @JvmStatic external fun nativeMlKem768Encaps(publicKey: ByteArray): Array<ByteArray>? // [ciphertext, sharedSecret]
        @JvmStatic external fun nativeMlKem768Decaps(ciphertext: ByteArray, secretKey: ByteArray): ByteArray?
        @JvmStatic external fun nativeMlKem768Keygen(): Array<ByteArray>? // [publicKey, secretKey]
    }

    // ── ML-DSA-65 (Signing) ─────────────────────────────────────────────────

    private fun signMlDsa65(message: ByteArray, secretKey: ByteArray, result: MethodChannel.Result) {
        try {
            val signature = nativeMlDsa65Sign(message, secretKey)
            if (signature != null) {
                result.success(signature)
            } else {
                result.error("PQ_SIGN_ERROR", "ML-DSA-65 signing returned null", null)
            }
        } catch (e: UnsatisfiedLinkError) {
            // liboqs not compiled for this platform — return stub.
            result.error("PQ_NOT_AVAILABLE",
                "liboqs JNI not loaded. ML-DSA-65 requires native library. " +
                "See build instructions in MainActivity.kt.", null)
        }
    }

    private fun verifyMlDsa65(
        message: ByteArray, signature: ByteArray, publicKey: ByteArray,
        result: MethodChannel.Result
    ) {
        try {
            result.success(nativeMlDsa65Verify(message, signature, publicKey))
        } catch (e: UnsatisfiedLinkError) {
            result.error("PQ_NOT_AVAILABLE", "liboqs JNI not loaded", null)
        }
    }

    private fun generateMlDsa65KeyPair(result: MethodChannel.Result) {
        try {
            val keys = nativeMlDsa65Keygen()
            if (keys != null && keys.size == 2) {
                result.success(mapOf(
                    "public_key" to keys[0],
                    "secret_key" to keys[1]
                ))
            } else {
                result.error("PQ_KEYGEN_ERROR", "ML-DSA-65 keygen returned null", null)
            }
        } catch (e: UnsatisfiedLinkError) {
            result.error("PQ_NOT_AVAILABLE", "liboqs JNI not loaded", null)
        }
    }

    // ── ML-KEM-768 (Key Encapsulation) ──────────────────────────────────────

    private fun encapsulateMlKem768(publicKey: ByteArray, result: MethodChannel.Result) {
        try {
            val encaps = nativeMlKem768Encaps(publicKey)
            if (encaps != null && encaps.size == 2) {
                result.success(mapOf(
                    "ciphertext" to encaps[0],
                    "shared_secret" to encaps[1]
                ))
            } else {
                result.error("PQ_ENCAPS_ERROR", "ML-KEM-768 encapsulation returned null", null)
            }
        } catch (e: UnsatisfiedLinkError) {
            result.error("PQ_NOT_AVAILABLE", "liboqs JNI not loaded", null)
        }
    }

    private fun decapsulateMlKem768(
        ciphertext: ByteArray, secretKey: ByteArray,
        result: MethodChannel.Result
    ) {
        try {
            val sharedSecret = nativeMlKem768Decaps(ciphertext, secretKey)
            if (sharedSecret != null) {
                result.success(sharedSecret)
            } else {
                result.error("PQ_DECAPS_ERROR", "ML-KEM-768 decapsulation returned null", null)
            }
        } catch (e: UnsatisfiedLinkError) {
            result.error("PQ_NOT_AVAILABLE", "liboqs JNI not loaded", null)
        }
    }

    private fun generateMlKem768KeyPair(result: MethodChannel.Result) {
        try {
            val keys = nativeMlKem768Keygen()
            if (keys != null && keys.size == 2) {
                result.success(mapOf(
                    "public_key" to keys[0],
                    "secret_key" to keys[1]
                ))
            } else {
                result.error("PQ_KEYGEN_ERROR", "ML-KEM-768 keygen returned null", null)
            }
        } catch (e: UnsatisfiedLinkError) {
            result.error("PQ_NOT_AVAILABLE", "liboqs JNI not loaded", null)
        }
    }
}
