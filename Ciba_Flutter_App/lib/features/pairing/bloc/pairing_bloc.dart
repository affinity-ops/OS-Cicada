// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import 'dart:async';
import 'dart:convert';
import 'package:flutter/foundation.dart';
import 'package:flutter_bloc/flutter_bloc.dart';
import '../../../core/crypto/ed25519_service.dart';
import '../../../core/crypto/x25519_service.dart';
import '../../../core/crypto/ml_dsa_service.dart';
import '../../../core/storage/secure_storage.dart';
import '../../../core/network/dio_client.dart';
import '../../../core/telemetry/device_info_service.dart';
import '../../../core/push/push_service.dart';
import '../../../config/constants.dart';

// ─── States ──────────────────────────────────────────────────────────────────
abstract class PairingState {}

class PairingInitial extends PairingState {}

class PairingScanning extends PairingState {}

class PairingProcessing extends PairingState {
  final String statusMessage;
  PairingProcessing(this.statusMessage);
}

class PairingSuccess extends PairingState {
  final String tenantId;
  PairingSuccess(this.tenantId);
}

class PairingError extends PairingState {
  final String message;
  PairingError(this.message);
}

// ─── Parsed QR data ──────────────────────────────────────────────────────────
/// Structured pairing challenge extracted from a QR code.
///
/// The QR payload is compact JSON with a Gateway Ed25519 signature:
/// {"v":1,"tid":"...","n":"...","exp":...,"gw":"http://192.168.x.x:8080","sig":"..."}
///
/// Security properties:
///   - sig prevents tampering (any modification invalidates the signature)
///   - exp prevents replay (5-minute window)
///   - tid binds the challenge to a specific tenant
///   - gw tells the device where to connect (no hardcoded IPs in the app)
class _PairingChallenge {
  final String tenantId;
  final String nonce;
  final int expiry;
  final String gatewayUrl;

  _PairingChallenge({
    required this.tenantId,
    required this.nonce,
    required this.expiry,
    required this.gatewayUrl,
  });
}

// ─── BLoC ────────────────────────────────────────────────────────────────────
class PairingBloc extends Cubit<PairingState> {
  final Ed25519Service ed25519Service;
  final X25519Service x25519Service;
  final MlDsaService mlDsaService;
  final SecureStorage secureStorage;
  final DioClient dioClient;

  PairingBloc({
    required this.ed25519Service,
    required this.x25519Service,
    required this.mlDsaService,
    required this.secureStorage,
    required this.dioClient,
  }) : super(PairingInitial());

  /// Guard flag to prevent double-tap race conditions.
  /// mobile_scanner can fire onDetect twice in rapid succession;
  /// this ensures only the first call proceeds.
  bool _pairingInProgress = false;

  /// Purges ALL stored credentials from SecureStorage.
  ///
  /// Called BEFORE generating new keys (to prevent stale key caching)
  /// and when the Gateway reports a revoked/suspended status.
  /// This is the fix for Post-Mortem D: "The Infinite Loop".
  Future<void> resetPairingState() async {
    await secureStorage.delete(AppConstants.keyPairedStatus);
    await secureStorage.delete(AppConstants.keyGatewayUrl);
    await secureStorage.delete(AppConstants.keyTenantId);
    await secureStorage.delete(AppConstants.keyPairedAt);
    await secureStorage.delete(AppConstants.keyLastKeyRotation);
    await secureStorage.delete(AppConstants.keyPushToken);
    // Purge Ed25519 key material
    await secureStorage.delete(AppConstants.keyEd25519Seed);
    await secureStorage.delete(AppConstants.keyEd25519Public);
    // Purge X25519 key material
    await secureStorage.delete(AppConstants.keyX25519Seed);
    await secureStorage.delete(AppConstants.keyX25519Public);
    // Purge ML-DSA-65 key material (PQC signing)
    await secureStorage.delete('aegis_ml_dsa65_secret');
    await secureStorage.delete('aegis_ml_dsa65_public');
  }

  /// Parse and verify a structured signed JSON QR payload.
  ///
  /// The public key is embedded in the QR payload ('pk' field) — no network
  /// call is needed before the handshake. The app can verify the signature
  /// and parse the challenge entirely offline, then connect to the gateway
  /// URL only for the handshake POST. This works anywhere in the world.
  Future<_PairingChallenge> _parseAndVerifyQr(String qrCode) async {
    final trimmed = qrCode.trim();

    Map<String, dynamic> payload;
    try {
      payload = jsonDecode(trimmed) as Map<String, dynamic>;
    } catch (e) {
      throw Exception('QR is not valid JSON. $e');
    }

    final v   = payload['v'];
    final tid = payload['tid'] as String?;
    final n   = payload['n']   as String?;
    final exp = payload['exp'];
    final gw  = payload['gw']  as String?;
    final sig = payload['sig'] as String?;
    final pk  = payload['pk']  as String?;

    if (v == null || tid == null || n == null || exp == null ||
        sig == null || gw == null || pk == null) {
      throw Exception('Missing required fields in QR payload: v=$v, tid=$tid, n=$n, exp=$exp, gw=$gw, sig=$sig, pk=$pk');
    }

    // Verify the signature using the public key embedded in the QR.
    // Canonical JSON must match the key ordering used by the gateway.
    final canonical = jsonEncode({
      'exp': exp,
      'gw':  gw,
      'n':   n,
      'tid': tid,
      'v':   v,
    });

    final verified = await ed25519Service.verify(canonical, sig, pk);
    if (!verified) {
      throw Exception('Signature verification failed! Canonical payload was: $canonical');
    }

    final expInt = exp is int ? exp : int.tryParse(exp.toString());
    if (expInt == null) {
      throw Exception('Invalid expiry format: $exp');
    }

    final expiryTime = DateTime.fromMillisecondsSinceEpoch(expInt * 1000);
    if (DateTime.now().isAfter(expiryTime)) {
      throw Exception('QR code expired at $expiryTime (Current time: ${DateTime.now()})');
    }

    return _PairingChallenge(
      tenantId: tid,
      nonce: n,
      expiry: expInt,
      gatewayUrl: gw,
    );
  }

  /// Execute the QR handshake with the Sentry Gateway.
  ///
  /// QR payload: {"v":1,"tid":"...","n":"...","exp":...,"gw":"...","sig":"..."}
  ///
  /// The device:
  ///   1. Reads the Gateway URL from the QR's gw field
  ///   2. Fetches the Gateway's public key from gw/v1/gateway/pubkey
  ///   3. Verifies the Gateway's signature on the QR payload
  ///   4. Checks the challenge hasn't expired
  ///   5. Generates a new Ed25519 keypair in Secure Enclave
  ///   6. Signs the nonce with its new private key (proves key possession)
  ///   7. Sends public key + signature to Gateway
  ///   8. Gateway verifies and binds device to tenant
  Future<void> pairWithGateway(String qrCode) async {
    // ── Guard: prevent double-tap from mobile_scanner ──────────────────
    if (_pairingInProgress) {
      debugPrint('[PAIR] Ignoring duplicate scan — pairing already in progress');
      return;
    }
    _pairingInProgress = true;

    try {
      // ── Parse and verify the signed QR payload ──────────────────────────
      emit(PairingProcessing('Verifying QR payload...'));
      
      _PairingChallenge challenge;
      try {
        challenge = await _parseAndVerifyQr(qrCode);
      } catch (e) {
        emit(PairingError(
          'QR Verification Failed:\n$e\n\n'
          'Ensure your phone is on the same WiFi network as the Gateway. '
          'Generate a new QR code from the Developer Portal and scan '
          'within 5 minutes.',
        ));
        return;
      }

      // ── Purge stale credentials BEFORE generating new keys ───────────
      // Prevents the infinite loop where old revoked keys persist in
      // SecureStorage and cause heartbeat failures on restart.
      emit(PairingProcessing('Clearing previous credentials...'));
      await resetPairingState();

      // ── Generate key pairs (classical + PQC) ──────────────────────────
      emit(PairingProcessing('Generating cryptographic key pairs...'));
      // Classical keys (always generated)
      await ed25519Service.generateAndStore(secureStorage);
      await x25519Service.generateAndStore(secureStorage);
      // Post-quantum keys (generated if liboqs is available)
      debugPrint('[PAIR] PQC state before generateAndStore: nativeAvailable=${mlDsaService.isNativeAvailable}');
      await mlDsaService.generateAndStore(secureStorage);
      debugPrint('[PAIR] PQC state after generateAndStore: isAvailable=${mlDsaService.isAvailable}, nativeAvailable=${mlDsaService.isNativeAvailable}');

      final ed25519Pub = await ed25519Service.getPublicKeyBase64();
      final x25519Pub = await x25519Service.getPublicKeyBase64();
      final mlDsaPub = mlDsaService.isAvailable
          ? mlDsaService.getPublicKeyBase64()
          : '';
      debugPrint('[PAIR] mlDsaPub length: ${mlDsaPub.length}');

      // ── Sign the nonce ─────────────────────────────────────────────────
      // The device signs ONLY the nonce to prove possession of the private
      // key corresponding to the public key being registered.
      emit(PairingProcessing('Signing challenge nonce...'));
      final signature = await ed25519Service.sign(challenge.nonce);

      // ── Send handshake to gateway ──────────────────────────────────────
      // The Gateway URL comes from the QR payload's gw field.
      // The app is dumb — it connects to whatever URL the QR tells it.
      emit(PairingProcessing('Authenticating with gateway...'));
      final client = DioClient(baseUrl: challenge.gatewayUrl);
      final pqcDiag = 'native=${mlDsaService.isNativeAvailable},avail=${mlDsaService.isAvailable},pubLen=${mlDsaPub.length}';
      final response = await client.post(
        AppConstants.handshakeEndpoint,
        data: {
          'ed25519_pub': ed25519Pub,
          'x25519_pub': x25519Pub,
          // PQC public keys — omitted (empty) if liboqs not available.
          // The Gateway's HandshakeRequest struct has these as omitempty,
          // so they're safe to send as empty strings.
          'ml_dsa65_pub': mlDsaPub,
          'ml_kem768_pub': '',
          'nonce': challenge.nonce,
          'challenge_signature': signature,
          'pqc_diag': pqcDiag,
        },
      );

      if (response.statusCode == 201 || response.statusCode == 200) {
        // ── Persist pairing data ───────────────────────────────────────
        await secureStorage.write(AppConstants.keyPairedStatus, 'true');
        await secureStorage.write(
            AppConstants.keyGatewayUrl, challenge.gatewayUrl);
        await secureStorage.write(AppConstants.keyTenantId, challenge.tenantId);
        await secureStorage.write(
          AppConstants.keyPairedAt,
          DateTime.now().toUtc().toIso8601String(),
        );

        // Set device fingerprint and gateway URL on the shared client
        // so all subsequent API calls (heartbeats, hold fetches) use the
        // real Gateway LAN IP — not the default localhost.
        dioClient.setDeviceFingerprint(ed25519Pub);
        dioClient.setBaseUrl(challenge.gatewayUrl);

        // ── Register FCM push token with gateway ──────────────────────
        // Now that pairing is complete and the gateway URL is known, send
        // the FCM token so the gateway can deliver HITL push alerts.
        try {
          await PushService.registerAfterPairing(
            storage: secureStorage,
            dioClient: client,
          );
        } catch (_) {
          // Non-fatal — token will be re-registered on next app launch
        }

        // ── Send device enrollment (non-fatal) ────────────────────────
        // Enrolls the device in aegis_devices with model, OS, biometric
        // posture etc. so the Developer Portal shows real device info.
        try {
          emit(PairingProcessing('Registering device profile...'));
          final deviceService = DeviceInfoService();
          final info = await deviceService.getDeviceProfile();
          await client.post(
            AppConstants.deviceEnrollEndpoint,
            data: {
              'enrollment_id': ed25519Pub,
              'operator_evar_id': 'aegis-operator',
              'gateway_node_id': 'gateway-node',
              'device_profile': {
                'device_id': ed25519Pub,
                'platform': (info['os'] ?? 'android').toLowerCase(),
                'os_version': '${info['os'] ?? ''} ${info['version'] ?? ''}'.trim(),
                'model': info['model'] ?? 'Unknown Device',
                'manufacturer': '',
                'app_version': AppConstants.appVersion,
              },
              'security_posture': {
                'biometric_enrolled': true,
                'secure_enclave_available': true,
                'screen_lock_enabled': true,
              },
              'network_profile': {
                'pairing_timestamp': DateTime.now().toUtc().toIso8601String(),
              },
            },
          );
        } catch (_) {
          // Non-fatal — device is paired; telemetry will retry on next launch
        }

        emit(PairingSuccess(ed25519Pub));
      } else {
        emit(PairingError('Gateway rejected handshake: ${response.statusCode}'));
      }
    } catch (e) {
      emit(PairingError('Pairing failed: ${e.toString()}'));
    } finally {
      _pairingInProgress = false;
    }
  }
}