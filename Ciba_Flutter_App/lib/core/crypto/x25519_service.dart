// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import 'dart:convert';
import 'package:cryptography/cryptography.dart';
import '../storage/secure_storage.dart';
import '../../config/constants.dart';

/// Real X25519 key exchange service for deriving shared secrets.
/// Used for hybrid encryption of HITL payloads (Phase 2).
class X25519Service {
  final _algorithm = X25519();
  SimpleKeyPair? _keyPair;

  /// Generate a new X25519 key pair and persist to secure storage.
  Future<void> generateAndStore(SecureStorage storage) async {
    _keyPair = await _algorithm.newKeyPair();
    final privBytes = await _keyPair!.extractPrivateKeyBytes();
    final pubKey = await _keyPair!.extractPublicKey();
    await storage.write(AppConstants.keyX25519Seed, base64Encode(privBytes));
    await storage.write(AppConstants.keyX25519Public, base64Encode(pubKey.bytes));
  }

  /// Load an existing key pair from secure storage.
  Future<bool> loadFromStorage(SecureStorage storage) async {
    final seedB64 = await storage.read(AppConstants.keyX25519Seed);
    if (seedB64 == null) return false;
    final seed = base64Decode(seedB64);
    _keyPair = await _algorithm.newKeyPairFromSeed(seed);
    return true;
  }

  /// Get the base64-encoded public key.
  Future<String> getPublicKeyBase64() async {
    if (_keyPair == null) throw StateError('X25519: no key pair loaded');
    final pub = await _keyPair!.extractPublicKey();
    return base64Encode(pub.bytes);
  }

  /// Derive a shared secret from a remote public key (for payload decryption).
  Future<SecretKey> deriveSharedSecret(String remotePublicKeyB64) async {
    if (_keyPair == null) throw StateError('X25519: no key pair loaded');
    final remoteBytes = base64Decode(remotePublicKeyB64);
    final remoteKey = SimplePublicKey(remoteBytes, type: KeyPairType.x25519);
    return _algorithm.sharedSecretKey(
      keyPair: _keyPair!,
      remotePublicKey: remoteKey,
    );
  }

  bool get hasKeyPair => _keyPair != null;
}