// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import 'dart:convert';
import 'package:cryptography/cryptography.dart';
import '../storage/secure_storage.dart';
import '../../config/constants.dart';

/// Real Ed25519 signing service backed by the `cryptography` package.
class Ed25519Service {
  final _algorithm = Ed25519();
  SimpleKeyPair? _keyPair;

  Future<void> generateAndStore(SecureStorage storage) async {
    _keyPair = await _algorithm.newKeyPair();
    final seed = await _keyPair!.extractPrivateKeyBytes();
    final publicKey = await _keyPair!.extractPublicKey();
    await storage.write(SentinelConstants.keyEd25519Private, base64Encode(seed));
    await storage.write(SentinelConstants.keyEd25519Public, base64Encode(publicKey.bytes));
  }

  Future<bool> loadFromStorage(SecureStorage storage) async {
    final seedB64 = await storage.read(SentinelConstants.keyEd25519Private);
    if (seedB64 == null) return false;
    final seed = base64Decode(seedB64);
    _keyPair = await _algorithm.newKeyPairFromSeed(seed);
    return true;
  }

  Future<String> getPublicKeyBase64() async {
    if (_keyPair == null) throw StateError('Ed25519: no key pair loaded');
    final pub = await _keyPair!.extractPublicKey();
    return base64Encode(pub.bytes);
  }

  Future<String> sign(String payload) async {
    if (_keyPair == null) throw StateError('Ed25519: no key pair loaded');
    final signature = await _algorithm.sign(
      utf8.encode(payload),
      keyPair: _keyPair!,
    );
    final rawSigBytes = signature.bytes.length > 64
        ? signature.bytes.sublist(0, 64)
        : signature.bytes;
    return base64Encode(rawSigBytes);
  }

  Future<bool> verify(String payload, String signatureB64, String publicKeyB64) async {
    final pubKeyBytes = base64Decode(publicKeyB64);
    final sigBytes = base64Decode(signatureB64);
    final publicKey = SimplePublicKey(pubKeyBytes, type: KeyPairType.ed25519);
    final signature = Signature(sigBytes, publicKey: publicKey);
    return _algorithm.verify(utf8.encode(payload), signature: signature);
  }

  bool get hasKeyPair => _keyPair != null;
}
