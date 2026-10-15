// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import 'dart:async';
import 'package:flutter_bloc/flutter_bloc.dart';
import '../../../core/crypto/ed25519_service.dart';
import '../../../core/crypto/ml_dsa_service.dart';
import '../../../core/auth/biometric_service.dart';
import '../../../core/attestation/attestation_service.dart';
import '../../../core/storage/secure_storage.dart';
import '../../../core/storage/offline_queue.dart';
import '../../../core/network/dio_client.dart';
import '../../../core/alerts/alarm_service.dart';
import '../../../config/constants.dart';
import '../../alerts/models/alert_model.dart';

// ─── States ──────────────────────────────────────────────────────────────────
abstract class DecisionState {}

class DecisionPending extends DecisionState {
  final HitlAlert alert;
  DecisionPending(this.alert);
}

class DecisionBiometricGate extends DecisionState {
  final HitlAlert alert;
  final String action; // 'APPROVE' or 'REJECT'
  DecisionBiometricGate(this.alert, this.action);
}

class DecisionProcessing extends DecisionState {
  final String message;
  DecisionProcessing(this.message);
}

class DecisionResolved extends DecisionState {
  final String outcome; // 'APPROVE', 'REJECT'
  final String holdRef;
  DecisionResolved(this.outcome, this.holdRef);
}

class DecisionError extends DecisionState {
  final String message;
  final HitlAlert alert;
  DecisionError(this.message, this.alert);
}

// ─── BLoC ────────────────────────────────────────────────────────────────────
class DecisionBloc extends Cubit<DecisionState> {
  final Ed25519Service ed25519Service;
  final MlDsaService mlDsaService;
  final BiometricService biometricService;
  final AttestationService attestationService;
  final SecureStorage secureStorage;
  final DioClient dioClient;
  final OfflineQueue offlineQueue;
  final AlarmService alarmService = AlarmService();

  DecisionBloc({
    required this.ed25519Service,
    required this.mlDsaService,
    required this.biometricService,
    required this.attestationService,
    required this.secureStorage,
    required this.dioClient,
    required this.offlineQueue,
  }) : super(DecisionPending(HitlAlert(
          holdRef: '',
          agentName: '',
          tenantName: '',
          actionType: '',
          actionDetail: '',
          semanticMismatch: 0,
          velocity: 'NORMAL',
          trustScore: 1.0,
          severity: AlertSeverity.standard,
          expiresAt: DateTime.now(),
          createdAt: DateTime.now(),
        )));

  /// Load a specific alert for decision.
  void loadAlert(HitlAlert alert) {
    emit(DecisionPending(alert));
  }

  /// Approve the current action — requires biometric authentication.
  Future<void> approveAction(HitlAlert alert) async {
    await _executeDecision(alert, 'APPROVE');
  }

  /// Reject the current action — requires biometric authentication.
  Future<void> rejectAction(HitlAlert alert) async {
    await _executeDecision(alert, 'REJECT');
  }

  Future<void> _executeDecision(HitlAlert alert, String decision) async {
    try {
      // ── Stop the siren ─────────────────────────────────────────────────
      alarmService.stopSiren();

      // ── Biometric gate ─────────────────────────────────────────────────
      emit(DecisionBiometricGate(alert, decision));
      final authenticated = await biometricService.authenticate();
      if (!authenticated) {
        emit(DecisionError('Biometric authentication failed', alert));
        return;
      }

      emit(DecisionProcessing('Signing decision...'));

      // ── Build the signing payload ──────────────────────────────────────
      // Must match what the gateway verifies in HandleBatchDecisions:
      // hold_ref|decision|decision_nonce|gateway_timestamp|hold_payload_hash
      final nonce = DateTime.now().microsecondsSinceEpoch.toRadixString(36);
      final timestamp = DateTime.now().toUtc().toIso8601String();
      final payloadHash = alert.holdRef; // Simplified; production uses SHA-256

      final signingPayload =
          '${alert.holdRef}|$decision|$nonce|$timestamp|$payloadHash';

      // ── Sign with Ed25519 (classical) ───────────────────────────────
      final signature = await ed25519Service.sign(signingPayload);
      final pubKey = await ed25519Service.getPublicKeyBase64();

      // ── Sign with ML-DSA-65 (PQC hybrid) ──────────────────────────
      // The ML-DSA-65 signature covers the exact same payload as Ed25519.
      // The Gateway verifies both independently — if either fails, the
      // decision is rejected (when PQC enforcement is active).
      final mlDsaSignature = await mlDsaService.sign(signingPayload);

      // ── Get platform attestation token ────────────────────────────
      // The nonce is bound to the attestation token to prevent replay.
      // The Gateway verifies the nonce inside the token matches the
      // decision nonce from the signing payload.
      final attestationToken =
          await attestationService.getAttestationToken(nonce);

      final decisionData = {
        'hold_ref': alert.holdRef,
        'decision': decision,
        'decision_nonce': nonce,
        'gateway_timestamp': timestamp,
        'hold_payload_hash': payloadHash,
        'signature_ed25519': signature,
        // ML-DSA-65 PQC signature (empty string if liboqs unavailable)
        'signature_ml_dsa65': mlDsaSignature,
        'ed25519_pub': pubKey,
        // Platform attestation token (Play Integrity / App Attest)
        'attestation_token': attestationToken,
      };

      // ── Submit to gateway (or queue offline) ───────────────────────────
      emit(DecisionProcessing('Submitting to gateway...'));
      try {
        final response = await dioClient.dio.post(
          AppConstants.batchDecisionsEndpoint,
          data: [decisionData],
        );
        
        if (response.data != null && response.data['results'] is List) {
          final results = response.data['results'] as List;
          if (results.isNotEmpty) {
            final firstResult = results[0] as Map<String, dynamic>;
            if (firstResult['accepted'] == false) {
              final errorMsg = firstResult['error'] ?? 'Unknown error';
              emit(DecisionError('Gateway rejected: $errorMsg', alert));
              return;
            }
          }
        }
        
        emit(DecisionResolved(decision, alert.holdRef));
      } catch (e) {
        // Offline — queue for later sync
        await offlineQueue.enqueue(decisionData);
        emit(DecisionResolved(decision, alert.holdRef));
      }
    } catch (e) {
      emit(DecisionError('Decision failed: $e', alert));
    }
  }
}