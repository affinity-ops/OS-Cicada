/// Cicada Aegis — iOS AppDelegate
///
/// Implements native platform channels for:
///
/// Phase 3 — Screen Capture Prevention:
///   Uses UIScreen.capturedDidChangeNotification to detect screen recording
///   and overlays a secure blank view to prevent data capture.
///   Also disables idle timer during active HITL decisions.
///
/// Phase 6 — Device Integrity:
///   App Attest (DeviceCheck framework) for per-decision attestation.
///   Local jailbreak detection indicators for telemetry (not enforcement).
///
/// Phase 4 — Biometric-Bound Signing (LAContext + Keychain ACL):
///   Replaces boolean-only local_auth with Keychain key protected by
///   .biometryCurrentSet access control — the private key can only be
///   used after a successful Face ID / Touch ID scan. No software bypass.
///
/// Post-Quantum — ML-DSA-65 / ML-KEM-768 via liboqs:
///   Native C bridge to liboqs for post-quantum signatures and KEM.
///
/// These channels are invoked by DeviceSecurityService.dart,
/// BiometricService.dart, and KeystoreService.dart on the Flutter side.

import Flutter
import UIKit
import DeviceCheck
import LocalAuthentication
import Security

@main
@objc class AppDelegate: FlutterAppDelegate {

    // ── Screen protection overlay ──────────────────────────────────────────
    private var securityOverlay: UIView?

    // ── Biometric-bound key tag ────────────────────────────────────────────
    private let biometricKeyTag = "com.cicada.aegis.biometric-bound-key"

    override func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?
    ) -> Bool {
        GeneratedPluginRegistrant.register(with: self)

        let controller = window?.rootViewController as! FlutterViewController

        // ── Phase 3: Screen capture prevention channel ─────────────────────
        let securityChannel = FlutterMethodChannel(
            name: "com.cicada.aegis/security",
            binaryMessenger: controller.binaryMessenger
        )
        securityChannel.setMethodCallHandler { [weak self] call, result in
            switch call.method {
            case "enableScreenProtection":
                self?.enableScreenProtection()
                result(true)
            case "disableScreenProtection":
                self?.disableScreenProtection()
                result(true)
            default:
                result(FlutterMethodNotImplemented)
            }
        }

        // ── Phase 6: Device integrity channel ──────────────────────────────
        let integrityChannel = FlutterMethodChannel(
            name: "com.cicada.aegis/integrity",
            binaryMessenger: controller.binaryMessenger
        )
        integrityChannel.setMethodCallHandler { call, result in
            switch call.method {
            case "getAttestationToken":
                self.getAppAttestToken(call: call, result: result)
            case "localIntegrityCheck":
                result(self.localIntegrityCheck())
            default:
                result(FlutterMethodNotImplemented)
            }
        }

        // ── Phase 4: CryptoObject biometric binding channel ────────────────
        let biometricChannel = FlutterMethodChannel(
            name: "com.cicada.aegis/biometric_crypto",
            binaryMessenger: controller.binaryMessenger
        )
        biometricChannel.setMethodCallHandler { [weak self] call, result in
            switch call.method {
            case "authenticateAndSign":
                guard let args = call.arguments as? [String: Any],
                      let payload = args["payload"] as? String else {
                    result(FlutterError(code: "INVALID_ARGS",
                                        message: "payload is required", details: nil))
                    return
                }
                let reason = args["reason"] as? String ?? "Authenticate to sign"
                self?.authenticateAndSign(payload: payload, reason: reason, result: result)
            case "ensureKeyExists":
                self?.ensureBiometricBoundKeyExists()
                result(true)
            default:
                result(FlutterMethodNotImplemented)
            }
        }

        // ── Post-Quantum: ML-DSA-65 / ML-KEM-768 channel ──────────────────
        let pqChannel = FlutterMethodChannel(
            name: "com.cicada.aegis/post_quantum",
            binaryMessenger: controller.binaryMessenger
        )
        pqChannel.setMethodCallHandler { call, result in
            switch call.method {
            case "signMlDsa65":
                guard let args = call.arguments as? [String: Any],
                      let message = (args["message"] as? FlutterStandardTypedData)?.data,
                      let secretKey = (args["secret_key"] as? FlutterStandardTypedData)?.data else {
                    result(FlutterError(code: "INVALID_ARGS",
                                        message: "message and secret_key required", details: nil))
                    return
                }
                self.signMlDsa65(message: message, secretKey: secretKey, result: result)
            case "generateMlDsa65KeyPair":
                self.generateMlDsa65KeyPair(result: result)
            case "encapsulateMlKem768":
                guard let args = call.arguments as? [String: Any],
                      let publicKey = (args["public_key"] as? FlutterStandardTypedData)?.data else {
                    result(FlutterError(code: "INVALID_ARGS",
                                        message: "public_key required", details: nil))
                    return
                }
                self.encapsulateMlKem768(publicKey: publicKey, result: result)
            case "generateMlKem768KeyPair":
                self.generateMlKem768KeyPair(result: result)
            default:
                result(FlutterMethodNotImplemented)
            }
        }

        return super.application(application, didFinishLaunchingWithOptions: launchOptions)
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Phase 3: Screen Capture Prevention
    // ─────────────────────────────────────────────────────────────────────────

    private func enableScreenProtection() {
        UIApplication.shared.isIdleTimerDisabled = true

        NotificationCenter.default.addObserver(
            self,
            selector: #selector(screenCaptureChanged),
            name: UIScreen.capturedDidChangeNotification,
            object: nil
        )

        if UIScreen.main.isCaptured {
            showSecurityOverlay()
        }
    }

    private func disableScreenProtection() {
        UIApplication.shared.isIdleTimerDisabled = false
        NotificationCenter.default.removeObserver(
            self,
            name: UIScreen.capturedDidChangeNotification,
            object: nil
        )
        hideSecurityOverlay()
    }

    @objc private func screenCaptureChanged() {
        if UIScreen.main.isCaptured {
            showSecurityOverlay()
        } else {
            hideSecurityOverlay()
        }
    }

    private func showSecurityOverlay() {
        guard securityOverlay == nil else { return }

        let overlay = UIView(frame: UIScreen.main.bounds)
        overlay.backgroundColor = UIColor.black
        overlay.tag = 999

        let label = UILabel()
        label.text = "SCREEN RECORDING DETECTED\n\nHITL decision data is protected."
        label.textColor = UIColor.red
        label.textAlignment = .center
        label.numberOfLines = 0
        label.font = UIFont.boldSystemFont(ofSize: 18)
        label.translatesAutoresizingMaskIntoConstraints = false

        overlay.addSubview(label)
        NSLayoutConstraint.activate([
            label.centerXAnchor.constraint(equalTo: overlay.centerXAnchor),
            label.centerYAnchor.constraint(equalTo: overlay.centerYAnchor),
            label.leadingAnchor.constraint(equalTo: overlay.leadingAnchor, constant: 32),
            label.trailingAnchor.constraint(equalTo: overlay.trailingAnchor, constant: -32),
        ])

        window?.addSubview(overlay)
        securityOverlay = overlay
    }

    private func hideSecurityOverlay() {
        securityOverlay?.removeFromSuperview()
        securityOverlay = nil
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Phase 6: App Attest (Device Integrity)
    // ─────────────────────────────────────────────────────────────────────────

    private func getAppAttestToken(call: FlutterMethodCall, result: @escaping FlutterResult) {
        guard #available(iOS 14.0, *) else {
            result(nil)
            return
        }

        let service = DCAppAttestService.shared

        guard service.isSupported else {
            result(nil)
            return
        }

        guard let args = call.arguments as? [String: Any],
              let nonce = args["nonce"] as? String,
              let nonceData = nonce.data(using: .utf8) else {
            result(nil)
            return
        }

        let hashedNonce = SHA256Hash(data: nonceData)

        service.generateKey { keyId, error in
            guard let keyId = keyId, error == nil else {
                result(nil)
                return
            }

            service.attestKey(keyId, clientDataHash: hashedNonce) { attestation, error in
                guard let attestation = attestation, error == nil else {
                    result(nil)
                    return
                }

                result(attestation.base64EncodedString())
            }
        }
    }

    private func SHA256Hash(data: Data) -> Data {
        var hash = [UInt8](repeating: 0, count: 32)
        data.withUnsafeBytes { buffer in
            _ = CC_SHA256(buffer.baseAddress, CC_LONG(data.count), &hash)
        }
        return Data(hash)
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Phase 6: Local Jailbreak Detection (Telemetry Only)
    // ─────────────────────────────────────────────────────────────────────────

    private func localIntegrityCheck() -> [String: Bool] {
        var checks = [String: Bool]()
        checks["cydia_absent"] = !FileManager.default.fileExists(atPath: "/Applications/Cydia.app")
        checks["no_jb_binaries"] = !FileManager.default.fileExists(atPath: "/usr/sbin/sshd")
            && !FileManager.default.fileExists(atPath: "/bin/bash")
            && !FileManager.default.fileExists(atPath: "/private/var/lib/apt/")
        let testPath = "/private/jailbreak_test_\(UUID().uuidString)"
        checks["sandbox_intact"] = !FileManager.default.isWritableFile(atPath: testPath)
        #if targetEnvironment(simulator)
        checks["not_simulator"] = false
        #else
        checks["not_simulator"] = true
        #endif
        return checks
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Phase 4: Biometric-Bound Signing (LAContext + Keychain ACL)
    // ─────────────────────────────────────────────────────────────────────────
    //
    // This replaces the boolean-only local_auth approach. The private key
    // is stored in the Secure Enclave with an access control policy that
    // requires .biometryCurrentSet — meaning:
    //   - The key can ONLY be used after a successful Face ID / Touch ID scan.
    //   - If biometric enrollment changes (new fingerprint added), the key
    //     is invalidated and must be regenerated.
    //   - There is no software bypass — the Secure Enclave enforces this.
    //
    // Flow:
    //   1. Generate an EC P-256 key in Secure Enclave with biometric ACL.
    //   2. When signing is requested, create an LAContext.
    //   3. The Keychain operation prompts for biometric automatically.
    //   4. On success, the Secure Enclave signs the data.
    //   5. Return the signature to Flutter.

    /// Ensures the biometric-bound key exists in the Secure Enclave.
    private func ensureBiometricBoundKeyExists() {
        // Check if key already exists.
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: biometricKeyTag.data(using: .utf8)!,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
        ]
        var item: CFTypeRef?
        if SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess {
            return // Key already exists.
        }

        // Create access control requiring biometric authentication.
        var error: Unmanaged<CFError>?
        guard let accessControl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
            [.privateKeyUsage, .biometryCurrentSet], // Requires current enrolled biometrics.
            &error
        ) else {
            NSLog("[CicadaBiometric] Failed to create access control: \(error.debugDescription)")
            return
        }

        // Generate key pair in Secure Enclave.
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: biometricKeyTag.data(using: .utf8)!,
                kSecAttrAccessControl as String: accessControl,
            ] as [String: Any],
        ]

        var privateKey: SecKey?
        SecKeyCreateRandomKey(attributes as CFDictionary, &error)
        if error != nil {
            NSLog("[CicadaBiometric] Failed to generate Secure Enclave key: \(error.debugDescription)")
        } else {
            NSLog("[CicadaBiometric] Biometric-bound key created in Secure Enclave")
        }
    }

    /// Authenticates with biometric and signs the payload atomically.
    /// The Secure Enclave key can ONLY be used after Face ID / Touch ID.
    private func authenticateAndSign(payload: String, reason: String, result: @escaping FlutterResult) {
        // Create LAContext for this authentication session.
        let context = LAContext()
        context.localizedReason = reason
        // Do NOT allow fallback to device passcode — biometric only.
        context.localizedFallbackTitle = ""

        // Retrieve the private key from Keychain, requiring biometric auth.
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: biometricKeyTag.data(using: .utf8)!,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
            kSecUseAuthenticationContext as String: context,
            // This triggers the biometric prompt automatically.
            kSecUseOperationPrompt as String: reason,
        ]

        DispatchQueue.global(qos: .userInitiated).async {
            var item: CFTypeRef?
            let status = SecItemCopyMatching(query as CFDictionary, &item)

            DispatchQueue.main.async {
                guard status == errSecSuccess, let privateKey = item else {
                    if status == errSecUserCanceled {
                        result(FlutterError(code: "AUTH_CANCELED",
                                            message: "Biometric authentication was cancelled", details: nil))
                    } else if status == errSecAuthFailed {
                        result(FlutterError(code: "AUTH_FAILED",
                                            message: "Biometric authentication failed", details: nil))
                    } else {
                        result(FlutterError(code: "KEY_ERROR",
                                            message: "Failed to retrieve biometric key: \(status)", details: nil))
                    }
                    return
                }

                // Key is now unlocked by biometric — sign the payload.
                guard let payloadData = payload.data(using: .utf8) else {
                    result(FlutterError(code: "DATA_ERROR",
                                        message: "Failed to encode payload", details: nil))
                    return
                }

                // The Secure Enclave key is a SecKey — use it for signing.
                let secKey = privateKey as! SecKey
                var signError: Unmanaged<CFError>?
                guard let signatureData = SecKeyCreateSignature(
                    secKey,
                    .ecdsaSignatureMessageX962SHA256,
                    payloadData as CFData,
                    &signError
                ) else {
                    result(FlutterError(code: "SIGN_ERROR",
                                        message: "Signing failed: \(signError.debugDescription)", details: nil))
                    return
                }

                let signatureBase64 = (signatureData as Data).base64EncodedString()
                result([
                    "signature": signatureBase64,
                    "auth_method": "biometric_secureenclave",
                    "key_tag": self.biometricKeyTag,
                ] as [String: Any])
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Post-Quantum Cryptography — ML-DSA-65 / ML-KEM-768 via liboqs
    // ─────────────────────────────────────────────────────────────────────────
    //
    // These methods call into liboqs (Open Quantum Safe) compiled as a
    // static library (.a) and linked via the Xcode project.
    //
    // Build instructions for liboqs iOS:
    //   1. Clone: git clone https://github.com/open-quantum-safe/liboqs.git
    //   2. Configure: cmake -DCMAKE_OSX_ARCHITECTURES=arm64 \
    //                       -DCMAKE_SYSTEM_NAME=iOS \
    //                       -DCMAKE_OSX_DEPLOYMENT_TARGET=14.0 \
    //                       -DOQS_ENABLE_SIG_ML_DSA=ON \
    //                       -DOQS_ENABLE_KEM_ML_KEM=ON ..
    //   3. Build: cmake --build . --parallel
    //   4. Copy liboqs.a to ios/Runner/liboqs/
    //   5. Add to Xcode project: Link Binary With Libraries → liboqs.a
    //   6. Add Header Search Path: ios/Runner/liboqs/include
    //
    // The C bridge functions are declared in OqsBridge.h and implemented
    // in OqsBridge.c (added to the Xcode project).

    private func signMlDsa65(message: Data, secretKey: Data, result: @escaping FlutterResult) {
        // Call into the C bridge for ML-DSA-65 signing.
        // If liboqs is not linked, this will fail at compile time (not runtime).
        let signature = oqs_ml_dsa65_sign(
            [UInt8](message), message.count,
            [UInt8](secretKey), secretKey.count
        )
        if let sig = signature {
            let sigData = Data(bytes: sig.pointee.data, count: sig.pointee.length)
            oqs_free_buffer(sig)
            result(FlutterStandardTypedData(bytes: sigData))
        } else {
            result(FlutterError(code: "PQ_SIGN_ERROR",
                                message: "ML-DSA-65 signing failed", details: nil))
        }
    }

    private func generateMlDsa65KeyPair(result: @escaping FlutterResult) {
        let keys = oqs_ml_dsa65_keygen()
        if let k = keys {
            let pubData = Data(bytes: k.pointee.public_key, count: k.pointee.public_key_length)
            let secData = Data(bytes: k.pointee.secret_key, count: k.pointee.secret_key_length)
            oqs_free_keypair(k)
            result([
                "public_key": FlutterStandardTypedData(bytes: pubData),
                "secret_key": FlutterStandardTypedData(bytes: secData),
            ] as [String: Any])
        } else {
            result(FlutterError(code: "PQ_KEYGEN_ERROR",
                                message: "ML-DSA-65 keygen failed", details: nil))
        }
    }

    private func encapsulateMlKem768(publicKey: Data, result: @escaping FlutterResult) {
        let encaps = oqs_ml_kem768_encaps(
            [UInt8](publicKey), publicKey.count
        )
        if let e = encaps {
            let ctData = Data(bytes: e.pointee.ciphertext, count: e.pointee.ciphertext_length)
            let ssData = Data(bytes: e.pointee.shared_secret, count: e.pointee.shared_secret_length)
            oqs_free_encaps(e)
            result([
                "ciphertext": FlutterStandardTypedData(bytes: ctData),
                "shared_secret": FlutterStandardTypedData(bytes: ssData),
            ] as [String: Any])
        } else {
            result(FlutterError(code: "PQ_ENCAPS_ERROR",
                                message: "ML-KEM-768 encapsulation failed", details: nil))
        }
    }

    private func generateMlKem768KeyPair(result: @escaping FlutterResult) {
        let keys = oqs_ml_kem768_keygen()
        if let k = keys {
            let pubData = Data(bytes: k.pointee.public_key, count: k.pointee.public_key_length)
            let secData = Data(bytes: k.pointee.secret_key, count: k.pointee.secret_key_length)
            oqs_free_keypair(k)
            result([
                "public_key": FlutterStandardTypedData(bytes: pubData),
                "secret_key": FlutterStandardTypedData(bytes: secData),
            ] as [String: Any])
        } else {
            result(FlutterError(code: "PQ_KEYGEN_ERROR",
                                message: "ML-KEM-768 keygen failed", details: nil))
        }
    }
}
