// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// ML-DSA-65 (FIPS 204) Post-Quantum Digital Signature Service.
//
// Sentinel's ML-DSA-65 implementation using the same platform channel
// pattern as Aegis. The native liboqs bridge is shared between both apps
// via CMake (Android) and CocoaPods (iOS).
//
// When the native library is not available (development/emulator),
// methods degrade gracefully — sign() returns an empty string and
// isAvailable returns false.
//
// The Master Admin Panel's verify endpoint uses this signature alongside
// Ed25519 for hybrid post-quantum authentication.

import 'dart:convert';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import '../storage/secure_storage.dart';

class MlDsaService {
  static const _channel = MethodChannel('com.cicada.sentinel/post_quantum');

  /// Whether liboqs is available on this device.
  bool _nativeAvailable = true;

  /// In-memory copies of the key pair (loaded from secure storage).
  Uint8List? _secretKey;
  Uint8List? _publicKey;

  // ─────────────────────────────────────────────────────────────────────────
  // Initialisation
  // ─────────────────────────────────────────────────────────────────────────

  /// Probe whether the native liboqs bridge is available.
  Future<void> init() async {
    try {
      final result = await _channel.invokeMethod<bool>('isAvailable');
      _nativeAvailable = result ?? false;
    } on MissingPluginException {
      _nativeAvailable = false;
    } on PlatformException catch (e) {
      if (e.code == 'PQ_NOT_AVAILABLE') {
        _nativeAvailable = false;
      }
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Key Generation
  // ─────────────────────────────────────────────────────────────────────────

  /// Generate an ML-DSA-65 key pair via the native bridge and persist
  /// both keys to hardware-backed secure storage.
  Future<void> generateAndStore(SecureStorage storage) async {
    if (!_nativeAvailable) return;
    try {
      final result = await _channel.invokeMethod<Map>('generateMlDsa65KeyPair');
      if (result != null) {
        _publicKey = result['public_key'] as Uint8List;
        _secretKey = result['secret_key'] as Uint8List;

        await storage.write(
          'sentinel_mldsa65_secret',
          _bytesToHex(_secretKey!.toList()),
        );
        await storage.write(
          'sentinel_mldsa65_public',
          _bytesToHex(_publicKey!.toList()),
        );
      }
    } on PlatformException catch (e) {
      if (e.code == 'PQ_NOT_AVAILABLE') {
        _nativeAvailable = false;
        debugPrint('[PQ] liboqs not available on Sentinel — PQC keys not generated');
      }
    } on MissingPluginException {
      _nativeAvailable = false;
    }
  }

  /// Load an existing ML-DSA-65 key pair from secure storage.
  Future<bool> loadFromStorage(SecureStorage storage) async {
    final secHex = await storage.read('sentinel_mldsa65_secret');
    final pubHex = await storage.read('sentinel_mldsa65_public');
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
  String getPublicKeyBase64() {
    if (_publicKey == null) return '';
    return base64Encode(_publicKey!);
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Signing
  // ─────────────────────────────────────────────────────────────────────────

  /// Signs a payload with ML-DSA-65 via the native platform channel.
  ///
  /// Returns an empty string if liboqs is unavailable (graceful degradation).
  /// The Master Admin Panel's verify endpoint accepts empty mldsa_signature
  /// when PQC enforcement is disabled.
  Future<String> sign(String payload) async {
    if (!_nativeAvailable) return '';
    if (_secretKey == null) return '';

    try {
      final messageBytes = Uint8List.fromList(utf8.encode(payload));
      final result = await _channel.invokeMethod<Uint8List>('signMlDsa65', {
        'message': messageBytes,
        'secret_key': _secretKey!,
      });
      if (result != null) {
        return base64Encode(result);
      }
      return '';
    } on PlatformException catch (_) {
      return '';
    } on MissingPluginException {
      return '';
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Status
  // ─────────────────────────────────────────────────────────────────────────

  /// Whether ML-DSA-65 signing is available AND keys are loaded.
  bool get isAvailable => _nativeAvailable && _secretKey != null;

  void dispose() {
    // TODO(security): Implement explicit memory zeroing when Dart supports it.
    _secretKey = null;
    _publicKey = null;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Utility
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
