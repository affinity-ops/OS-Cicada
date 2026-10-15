// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import 'dart:convert';
import 'package:flutter_test/flutter_test.dart';
import 'package:aegis_ciba_companion/core/crypto/ed25519_service.dart';
import 'package:aegis_ciba_companion/core/crypto/ml_dsa_service.dart';
import 'package:aegis_ciba_companion/core/storage/secure_storage.dart';
import 'package:aegis_ciba_companion/config/constants.dart';

/// In-memory implementation of SecureStorage for testing.
/// Replaces FlutterSecureStorage so tests don't need a real device.
class InMemoryStorage extends SecureStorage {
  final _store = <String, String>{};

  @override
  Future<void> write(String key, String value) async {
    _store[key] = value;
  }

  @override
  Future<String?> read(String key) async => _store[key];

  @override
  Future<void> delete(String key) async => _store.remove(key);
}

void main() {
  late Ed25519Service ed25519;
  late MlDsaService mlDsa;
  late InMemoryStorage storage;

  setUp(() {
    ed25519 = Ed25519Service();
    mlDsa = MlDsaService();
    storage = InMemoryStorage();
  });

  // ─────────────────────────────────────────────────────────────────────────────
  // Ed25519Service — crypto round-trip
  // ─────────────────────────────────────────────────────────────────────────────
  group('Ed25519Service — full round-trip', () {
    test('generates a key pair and persists to storage', () async {
      await ed25519.generateAndStore(storage);

      // Keys should be written to storage
      final seedB64 = await storage.read(AppConstants.keyEd25519Seed);
      final pubB64 = await storage.read(AppConstants.keyEd25519Public);
      expect(seedB64, isNotNull);
      expect(pubB64, isNotNull);

      // Public key should be valid base64 of reasonable length
      final pubBytes = base64Decode(pubB64!);
      expect(pubBytes.length, equals(32)); // Ed25519 public key is 32 bytes
    });

    test('loads a previously generated key pair from storage', () async {
      await ed25519.generateAndStore(storage);
      final pubKey1 = await ed25519.getPublicKeyBase64();

      // Create a new service instance and load from the same storage
      final ed25519Loaded = Ed25519Service();
      final loaded = await ed25519Loaded.loadFromStorage(storage);
      expect(loaded, isTrue);

      final pubKey2 = await ed25519Loaded.getPublicKeyBase64();
      expect(pubKey2, equals(pubKey1)); // Same key pair recovered
    });

    test('signs a payload and produces a 64-byte signature (Go compat)', () async {
      await ed25519.generateAndStore(storage);

      final payload = 'hold_ref|APPROVE|abc123|2026-01-01T00:00:00Z|hash';
      final signatureB64 = await ed25519.sign(payload);

      // Verify the raw signature is exactly 64 bytes
      final signatureBytes = base64Decode(signatureB64);
      expect(
        signatureBytes.length,
        equals(64),
        reason: 'Ed25519 signatures MUST be exactly 64 bytes for Go-side '
            'compatibility. The cryptography package may append the 32-byte '
            'public key (96 bytes total) — the service must trim to 64.',
      );
    });

    test('signature round-trip: sign → verify succeeds', () async {
      await ed25519.generateAndStore(storage);

      final payload = 'hold_ref|REJECT|nonce456|2026-01-01T00:00:00Z|hash';
      final signatureB64 = await ed25519.sign(payload);
      final pubKeyB64 = await ed25519.getPublicKeyBase64();

      final isValid = await ed25519.verify(payload, signatureB64, pubKeyB64);
      expect(isValid, isTrue,
          reason: 'Ed25519 signature verification must succeed for a '
              'correctly signed payload.');
    });

    test('rejects a tampered payload', () async {
      await ed25519.generateAndStore(storage);

      final originalPayload = 'hold_ref|APPROVE|nonce789|2026-01-01T00:00:00Z|hash';
      final tamperedPayload = 'hold_ref|REJECT|nonce789|2026-01-01T00:00:00Z|hash';
      final signatureB64 = await ed25519.sign(originalPayload);
      final pubKeyB64 = await ed25519.getPublicKeyBase64();

      final isValid = await ed25519.verify(tamperedPayload, signatureB64, pubKeyB64);
      expect(isValid, isFalse,
          reason: 'A modified payload must fail verification — this is the '
              'non-repudiation guarantee.');
    });

    test('loadFromStorage returns false when no keys exist', () async {
      final freshService = Ed25519Service();
      final loaded = await freshService.loadFromStorage(storage);
      expect(loaded, isFalse);
    });

    test('throws StateError when signing without a key pair', () {
      expect(
        () => ed25519.sign('payload'),
        throwsA(isA<StateError>()),
      );
    });

    test('throws StateError when getting public key without a key pair', () {
      expect(
        () => ed25519.getPublicKeyBase64(),
        throwsA(isA<StateError>()),
      );
    });

    test('hasKeyPair returns false before key generation', () {
      expect(ed25519.hasKeyPair, isFalse);
    });

    test('hasKeyPair returns true after key generation', () async {
      await ed25519.generateAndStore(storage);
      expect(ed25519.hasKeyPair, isTrue);
    });
  });

  // ─────────────────────────────────────────────────────────────────────────────
  // Ed25519Service — 64-byte signature extraction edge cases
  // ─────────────────────────────────────────────────────────────────────────────
  group('Ed25519Service — 64-byte extraction', () {
    test('signature is never longer than 64 bytes', () async {
      // Run multiple sign operations to catch non-determinism
      await ed25519.generateAndStore(storage);

      for (int i = 0; i < 10; i++) {
        final payload = 'test-payload-$i-${DateTime.now().microsecondsSinceEpoch}';
        final sigB64 = await ed25519.sign(payload);
        final sigBytes = base64Decode(sigB64);
        expect(sigBytes.length, 64,
            reason: 'Iteration $i: signature must be exactly 64 bytes.');
      }
    });

    test('same payload produces a valid 64-byte signature each time', () async {
      await ed25519.generateAndStore(storage);
      final payload = 'hold_ref|APPROVE|fixed-nonce|fixed-timestamp|fixed-hash';

      final sig1 = await ed25519.sign(payload);
      final sig2 = await ed25519.sign(payload);

      // Ed25519 is deterministic — same payload + same key = same signature
      expect(sig1, equals(sig2));

      // Both are 64 bytes
      expect(base64Decode(sig1).length, 64);
      expect(base64Decode(sig2).length, 64);
    });
  });

  // ─────────────────────────────────────────────────────────────────────────────
  // Ed25519Service — cross-payload signing (different decisions)
  // ─────────────────────────────────────────────────────────────────────────────
  group('Ed25519Service — different decision payloads', () {
    test('APPROVE and REJECT produce different signatures', () async {
      await ed25519.generateAndStore(storage);

      final approvePayload = 'hold_ref|APPROVE|nonce|ts|hash';
      final rejectPayload = 'hold_ref|REJECT|nonce|ts|hash';

      final approveSig = await ed25519.sign(approvePayload);
      final rejectSig = await ed25519.sign(rejectPayload);

      expect(approveSig, isNot(equals(rejectSig)),
          reason: 'APPROVE and REJECT of the same hold must produce different '
              'signatures to prevent decision forgery.');
    });
  });

  // ─────────────────────────────────────────────────────────────────────────────
  // MlDsaService — graceful degradation
  // ─────────────────────────────────────────────────────────────────────────────
  group('MlDsaService — PQC graceful degradation', () {
    test('isAvailable returns false (no native liboqs bindings)', () {
      expect(mlDsa.isAvailable, isFalse);
    });

    test('sign returns empty string', () async {
      final sig = await mlDsa.sign('any payload');
      expect(sig, isEmpty);
    });

    test('getPublicKeyBase64 returns empty string', () {
      expect(mlDsa.getPublicKeyBase64(), isEmpty);
    });

    test('loadFromStorage returns false', () async {
      final loaded = await mlDsa.loadFromStorage(storage);
      expect(loaded, isFalse);
    });

    test('generateAndStore is a no-op (does not throw)', () async {
      // Must not throw even though it does nothing
      await mlDsa.generateAndStore(storage);

      // No keys should have been written to storage
      final secret = await storage.read('aegis_ml_dsa65_secret');
      final pub = await storage.read('aegis_ml_dsa65_public');
      expect(secret, isNull);
      expect(pub, isNull);
    });

    test('multiple calls to init are safe (idempotent)', () async {
      await mlDsa.init();
      await mlDsa.init(); // Second call must not throw
      expect(mlDsa.isAvailable, isFalse);
    });

    test('dispose is safe to call', () {
      // Must not throw
      mlDsa.dispose();
      mlDsa.dispose(); // Double dispose must not throw either
    });
  });

  // ─────────────────────────────────────────────────────────────────────────────
  // MlDsaService — integration with Ed25519 (dual signing pattern)
  // ─────────────────────────────────────────────────────────────────────────────
  group('MlDsaService + Ed25519 — dual signing pattern', () {
    test('decision payload produces valid Ed25519 sig + empty PQC sig', () async {
      // This mirrors what DecisionBloc._executeDecision does
      await ed25519.generateAndStore(storage);

      final holdRef = 'hold-test-001';
      final decision = 'APPROVE';
      final nonce = 'abc123';
      final timestamp = '2026-01-01T00:00:00Z';
      final payloadHash = holdRef; // Simplified
      final signingPayload = '$holdRef|$decision|$nonce|$timestamp|$payloadHash';

      final ed25519Sig = await ed25519.sign(signingPayload);
      final mldsaSig = await mlDsa.sign(signingPayload);
      final pubKey = await ed25519.getPublicKeyBase64();

      // Ed25519 signature is valid
      expect(base64Decode(ed25519Sig).length, equals(64));
      final isValid = await ed25519.verify(signingPayload, ed25519Sig, pubKey);
      expect(isValid, isTrue);

      // ML-DSA-65 sig is empty (PQC unavailable)
      expect(mldsaSig, isEmpty,
          reason: 'When liboqs is not bundled, ML-DSA-65 must return empty '
              'string. The Gateway accepts this when PQC enforcement is '
              'not strictly mandated.');
    });

    test('dual signing payload format matches Gateway expectations', () async {
      // Verify the exact format the Gateway's HandleBatchDecisions expects
      await ed25519.generateAndStore(storage);

      final payload = 'hold-ref-42|REJECT|nonce-val|2026-05-26T12:00:00Z|hold-ref-42';
      final sig = await ed25519.sign(payload);

      // The payload format must be: hold_ref|decision|nonce|timestamp|hash
      expect(payload.contains('|REJECT|'), isTrue);
      expect(payload.startsWith('hold-ref-42'), isTrue);

      // Signature must be base64-encoded 64 bytes
      final rawSig = base64Decode(sig);
      expect(rawSig.length, 64,
          reason: 'Gateway Go code expects ed25519.SignatureSize (64) bytes. '
              'If a 96-byte signature (64 + 32-byte pub key suffix) is sent, '
              'the Gateway will reject it.');
    });
  });
}
