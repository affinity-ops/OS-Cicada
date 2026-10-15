// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// ML-DSA-65 (FIPS 204) Post-Quantum Digital Signature Service.
//
// Flutter platform channel bridge to native ML-DSA-65 and ML-KEM-768
// implementations via liboqs.
//
// Android: JNI bridge to liboqs_jni.so (NDK-compiled)
// iOS:     C bridge to liboqs.a (OqsBridge.c)
//
// When the native library is not available (development/emulator),
// methods return clearly-marked stubs so the Gateway can differentiate.
//
// Security invariants:
//   1. Private keys NEVER leave flutter_secure_storage after generation.
//   2. Private keys are NEVER logged, printed, or transmitted.
//   3. Key generation happens BEFORE any network call (called during pairing).
//   4. The Gateway verifies ML-DSA-65 signatures via CIRCL (pkg/pqc/mldsa.go).

import 'dart:convert';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import '../storage/secure_storage.dart';

class MlDsaService {
  static const _channel = MethodChannel('com.cicada.aegis/post_quantum');

  /// Whether liboqs is available on this device.
  /// Set to false after the first PlatformException with 'PQ_NOT_AVAILABLE'
  /// or a MissingPluginException (no native handler registered).
  bool _nativeAvailable = true;

  /// In-memory copies of the key pair (loaded from secure storage).
  Uint8List? _secretKey;
  Uint8List? _publicKey;

  // ─────────────────────────────────────────────────────────────────────────
  // Initialisation
  // ─────────────────────────────────────────────────────────────────────────

  /// Probe whether the native liboqs bridge is available.
  ///
  /// Called once during app startup (app.dart _initializeFromStorage).
  /// If the native side isn't compiled in, this sets [_nativeAvailable]
  /// to false and all subsequent operations degrade gracefully.
  Future<void> init() async {
    try {
      // Attempt a lightweight probe call. If the native handler exists
      // and liboqs is linked, this succeeds. If not, it throws.
      debugPrint('[PQ] init() — probing isAvailable...');
      final result = await _channel.invokeMethod<bool>('isAvailable');
      _nativeAvailable = result ?? false;
      debugPrint('[PQ] init() — isAvailable returned: $result → _nativeAvailable=$_nativeAvailable');
    } on MissingPluginException {
      _nativeAvailable = false;
      debugPrint('[PQ] init() — MissingPluginException → _nativeAvailable=false');
    } on PlatformException catch (e) {
      debugPrint('[PQ] init() — PlatformException: ${e.code} ${e.message}');
      if (e.code == 'PQ_NOT_AVAILABLE') {
        _nativeAvailable = false;
      }
    } catch (e) {
      debugPrint('[PQ] init() — unexpected error: $e');
      _nativeAvailable = false;
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // ML-DSA-65 Key Generation
  // ─────────────────────────────────────────────────────────────────────────

  /// Generate an ML-DSA-65 key pair via the native bridge and persist
  /// both keys to hardware-backed secure storage.
  ///
  /// Called during device pairing (pairing_bloc.dart) alongside Ed25519
  /// and X25519 key generation. If liboqs is not available, this is a
  /// no-op — the pairing handshake sends an empty ml_dsa65_pub and the
  /// Gateway accepts it (PQC enforcement is opt-in via CICADA_ENFORCE_PQC).
  Future<void> generateAndStore(SecureStorage storage) async {
    debugPrint('[PQ] generateAndStore() — _nativeAvailable=$_nativeAvailable');
    if (!_nativeAvailable) {
      debugPrint('[PQ] generateAndStore() — SKIPPED (native not available)');
      return;
    }
    try {
      debugPrint('[PQ] generateAndStore() — calling generateMlDsa65KeyPair...');
      final result = await _channel.invokeMethod<Map>('generateMlDsa65KeyPair');
      debugPrint('[PQ] generateAndStore() — result: ${result != null ? "got keys" : "NULL"}');
      if (result != null) {
        _publicKey = result['public_key'] as Uint8List;
        _secretKey = result['secret_key'] as Uint8List;
        debugPrint('[PQ] generateAndStore() — pubKey=${_publicKey!.length} bytes, secKey=${_secretKey!.length} bytes');

        // Persist to hardware-backed secure storage (hex-encoded).
        await storage.write(
          'aegis_ml_dsa65_secret',
          _bytesToHex(_secretKey!.toList()),
        );
        await storage.write(
          'aegis_ml_dsa65_public',
          _bytesToHex(_publicKey!.toList()),
        );
        debugPrint('[PQ] generateAndStore() — ✅ ML-DSA-65 keys generated and stored');
      } else {
        debugPrint('[PQ] generateAndStore() — ❌ generateMlDsa65KeyPair returned null');
      }
    } on PlatformException catch (e) {
      debugPrint('[PQ] generateAndStore() — PlatformException: ${e.code} ${e.message}');
      if (e.code == 'PQ_NOT_AVAILABLE') {
        _nativeAvailable = false;
      }
    } on MissingPluginException {
      debugPrint('[PQ] generateAndStore() — MissingPluginException');
      _nativeAvailable = false;
    } catch (e) {
      debugPrint('[PQ] generateAndStore() — unexpected error: $e');
    }
  }

  /// Load an existing ML-DSA-65 key pair from secure storage.
  ///
  /// Returns true if keys were found and loaded, false otherwise.
  Future<bool> loadFromStorage(SecureStorage storage) async {
    final secHex = await storage.read('aegis_ml_dsa65_secret');
    final pubHex = await storage.read('aegis_ml_dsa65_public');
    if (secHex != null && pubHex != null) {
      _secretKey = Uint8List.fromList(_hexToBytes(secHex));
      _publicKey = Uint8List.fromList(_hexToBytes(pubHex));
      return true;
    }
    return false;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Public Key Export
  // ─────────────────────────────────────────────────────────────────────────

  /// Returns the ML-DSA-65 public key as a standard base64 string.
  ///
  /// The Gateway expects base64-encoded public keys for ML-DSA-65
  /// (1952 bytes decoded = FIPS 204 spec). This is sent during the
  /// pairing handshake and stored in mobile_devices.ml_dsa65_pub.
  String getPublicKeyBase64() {
    if (_publicKey == null) return '';
    // Standard Base64 encoding — matches the Gateway's
    // base64.StdEncoding.DecodeString() expectation.
    return base64Encode(_publicKey!);
  }

  // ─────────────────────────────────────────────────────────────────────────
  // ML-DSA-65 Signing
  // ─────────────────────────────────────────────────────────────────────────

  /// Signs a payload with ML-DSA-65 for the post-quantum audit trail.
  ///
  /// Uses the native platform channel (liboqs JNI on Android, liboqs C bridge
  /// on iOS) to produce a real FIPS 204 ML-DSA-65 signature.
  ///
  /// If the native library is not available (emulator, development), returns
  /// 'STUB_ML_DSA65_SIGNATURE' so the Gateway can differentiate.
  ///
  /// The signing payload is the same as Ed25519:
  ///   hold_ref|decision|decision_nonce|gateway_timestamp|hold_payload_hash
  Future<String> sign(String payload) async {
    if (!_nativeAvailable) return 'STUB_ML_DSA65_SIGNATURE';
    if (_secretKey == null) return '';

    try {
      final messageBytes = Uint8List.fromList(utf8.encode(payload));
      final result = await _channel.invokeMethod<Uint8List>('signMlDsa65', {
        'message': messageBytes,
        'secret_key': _secretKey!,
      });
      if (result != null) {
        // Standard Base64 encoding — matches the Gateway's
        // base64.StdEncoding.DecodeString() in pqc.VerifyMLDSA65().
        // The previous implementation used Uri.encodeComponent(String.fromCharCodes())
        // which produced corrupt output for binary data > 127.
        return base64Encode(result);
      }
      return 'STUB_ML_DSA65_SIGNATURE';
    } on PlatformException catch (_) {
      return 'STUB_ML_DSA65_SIGNATURE';
    } on MissingPluginException {
      return 'STUB_ML_DSA65_SIGNATURE';
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // ML-KEM-768 Key Encapsulation (Future Use)
  // ─────────────────────────────────────────────────────────────────────────

  /// Generates an ML-KEM-768 key pair via the native bridge.
  ///
  /// Returns a map with 'public_key' and 'secret_key' as Uint8List,
  /// or null if the native library is unavailable.
  ///
  /// ML-KEM-768 (FIPS 203) is used for post-quantum key encapsulation
  /// in the hold payload encryption path (Phase PQ).
  Future<Map<String, Uint8List>?> generateMlKem768KeyPair() async {
    if (!_nativeAvailable) return null;

    try {
      final result = await _channel.invokeMethod<Map>('generateMlKem768KeyPair');
      if (result != null) {
        return {
          'public_key': result['public_key'] as Uint8List,
          'secret_key': result['secret_key'] as Uint8List,
        };
      }
      return null;
    } on PlatformException {
      return null;
    } on MissingPluginException {
      _nativeAvailable = false;
      return null;
    }
  }

  /// Encapsulates a shared secret using the recipient's ML-KEM-768 public key.
  ///
  /// Returns a map with 'ciphertext' and 'shared_secret' as Uint8List,
  /// or null if the native library is unavailable.
  Future<Map<String, Uint8List>?> encapsulateMlKem768(List<int> publicKey) async {
    if (!_nativeAvailable) return null;

    try {
      final result = await _channel.invokeMethod<Map>('encapsulateMlKem768', {
        'public_key': Uint8List.fromList(publicKey),
      });
      if (result != null) {
        return {
          'ciphertext': result['ciphertext'] as Uint8List,
          'shared_secret': result['shared_secret'] as Uint8List,
        };
      }
      return null;
    } on PlatformException {
      return null;
    } on MissingPluginException {
      _nativeAvailable = false;
      return null;
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Status
  // ─────────────────────────────────────────────────────────────────────────

  /// Whether ML-DSA-65 signing is available AND keys are loaded.
  bool get isAvailable => _nativeAvailable && _secretKey != null;

  /// Whether the native liboqs bridge is compiled into this build.
  bool get isNativeAvailable => _nativeAvailable;

  void dispose() {
    // Zero-fill sensitive key material before releasing.
    // See PRE_PRODUCTION_REQUIREMENTS.md — explicit memory zeroing deferred
    // until Dart FFI supports secure memory wipe. Key material is nulled here
    // and will be garbage collected.
    _secretKey = null;
    _publicKey = null;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Utility — hex encoding/decoding
  // ─────────────────────────────────────────────────────────────────────────

  String _bytesToHex(List<int> bytes) {
    return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  }

  List<int> _hexToBytes(String hex) {
    final result = <int>[];
    for (var i = 0; i < hex.length; i += 2) {
      result.add(int.parse(hex.substring(i, i + 2), radix: 16));
    }
    return result;
  }
}