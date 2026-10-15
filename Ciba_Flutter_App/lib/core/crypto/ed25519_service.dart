// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import 'dart:convert';
import 'package:cryptography/cryptography.dart';
import '../storage/secure_storage.dart';
import '../../config/constants.dart';

/// Real Ed25519 signing service backed by the `cryptography` package.
/// Keys are persisted to Secure Enclave / Android Keystore via [SecureStorage].
class Ed25519Service {
  final _algorithm = Ed25519();
  SimpleKeyPair? _keyPair;

  /// Generate a new Ed25519 key pair and persist the seed to secure storage.
  Future<void> generateAndStore(SecureStorage storage) async {
    _keyPair = await _algorithm.newKeyPair();
    final seed = await _keyPair!.extractPrivateKeyBytes();
    final publicKey = await _keyPair!.extractPublicKey();
    await storage.write(AppConstants.keyEd25519Seed, base64Encode(seed));
    await storage.write(AppConstants.keyEd25519Public, base64Encode(publicKey.bytes));
  }

  /// Load an existing key pair from secure storage.
  Future<bool> loadFromStorage(SecureStorage storage) async {
    final seedB64 = await storage.read(AppConstants.keyEd25519Seed);
    if (seedB64 == null) return false;
    final seed = base64Decode(seedB64);
    _keyPair = await _algorithm.newKeyPairFromSeed(seed);
    return true;
  }

  /// Get the base64-encoded public key.
  Future<String> getPublicKeyBase64() async {
    if (_keyPair == null) throw StateError('Ed25519: no key pair loaded');
    final pub = await _keyPair!.extractPublicKey();
    return base64Encode(pub.bytes);
  }

  /// Sign a payload, returning a base64-encoded signature.
  ///
  /// CRITICAL: The `cryptography` package v2.x may append the 32-byte public
  /// key to the 64-byte Ed25519 signature (96 bytes total). The Sentry Gateway
  /// expects exactly 64 bytes (ed25519.SignatureSize in Go). We extract only
  /// the first 64 bytes to ensure cross-platform compatibility.
  Future<String> sign(String payload) async {
    if (_keyPair == null) throw StateError('Ed25519: no key pair loaded');
    final signature = await _algorithm.sign(
      utf8.encode(payload),
      keyPair: _keyPair!,
    );
    // Extract ONLY the raw 64-byte Ed25519 signature.
    // The cryptography package may append the 32-byte public key.
    final rawSigBytes = signature.bytes.length > 64
        ? signature.bytes.sublist(0, 64)
        : signature.bytes;
    return base64Encode(rawSigBytes);
  }

  /// Verify a signature against a payload and public key (all base64).
  Future<bool> verify(String payload, String signatureB64, String publicKeyB64) async {
    final pubKeyBytes = base64Decode(publicKeyB64);
    final sigBytes = base64Decode(signatureB64);
    final publicKey = SimplePublicKey(pubKeyBytes, type: KeyPairType.ed25519);
    final signature = Signature(sigBytes, publicKey: publicKey);
    return _algorithm.verify(utf8.encode(payload), signature: signature);
  }

  bool get hasKeyPair => _keyPair != null;
}