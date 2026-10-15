// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import 'dart:async';
import 'package:flutter_bloc/flutter_bloc.dart';
import '../../../core/network/dio_client.dart';
import '../../../core/crypto/ed25519_service.dart';
import '../../../core/storage/secure_storage.dart';
import '../../../core/alerts/alarm_service.dart';
import '../../../config/constants.dart';
import '../models/alert_model.dart';

// ─── States ──────────────────────────────────────────────────────────────────
abstract class AlertState {}

class AlertLoading extends AlertState {}

class AlertLoaded extends AlertState {
  final List<HitlAlert> alerts;
  AlertLoaded(this.alerts);
}

class AlertEmpty extends AlertState {}

class AlertError extends AlertState {
  final String message;
  AlertError(this.message);
}

// ─── BLoC ────────────────────────────────────────────────────────────────────
class AlertBloc extends Cubit<AlertState> {
  final DioClient dioClient;
  final Ed25519Service ed25519Service;
  final SecureStorage secureStorage;
  final AlarmService alarmService = AlarmService();
  Timer? _heartbeatTimer;
  final List<HitlAlert> _alerts = [];

  AlertBloc({
    required this.dioClient,
    required this.ed25519Service,
    required this.secureStorage,
  }) : super(AlertLoading());

  /// Start polling for HITL alerts via heartbeat. No persistent connections.
  Future<void> startListening() async {
    emit(AlertLoading());

    try {
      final pubKey = await ed25519Service.getPublicKeyBase64();

      // Initial fetch
      await _sendHeartbeat(pubKey);

      // Poll every 30 seconds while the app is open
      _heartbeatTimer = Timer.periodic(
        const Duration(seconds: 30),
        (_) => _sendHeartbeat(pubKey),
      );

      _emitCurrentState();
    } catch (e) {
      emit(AlertError('Failed to connect: $e'));
    }
  }

  Future<void> _sendHeartbeat(String pubKey) async {
    try {
      final response = await dioClient.post(
        AppConstants.heartbeatEndpoint,
        data: {
          'ed25519_pub': pubKey,
          'offline_queue_count': 0,
        },
      );

      if (response.data != null) {
        final data = response.data as Map<String, dynamic>;
        final status = data['status'] as String?;
        if (status == 'revoked' || status == 'suspended') {
          // CRITICAL: Stop heartbeat and purge credentials so the splash
          // screen routes to QR scanner on next launch. This breaks the
          // infinite loop from Post-Mortem D.
          _heartbeatTimer?.cancel();
          _heartbeatTimer = null;
          await secureStorage.delete(AppConstants.keyPairedStatus);
          emit(AlertError('Device $status by gateway. Re-pair required.'));
          return;
        }

        final alerts = data['alerts'] as List<dynamic>?;
        if (alerts != null && alerts.isNotEmpty) {
          for (final alertJson in alerts) {
            final alert = HitlAlert.fromJson(alertJson as Map<String, dynamic>);
            if (!_alerts.any((a) => a.holdRef == alert.holdRef)) {
              _alerts.insert(0, alert);
              alarmService.triggerSiren();
            }
          }
          _emitCurrentState();
        }
      }
    } catch (_) {
      // Heartbeat failures are non-fatal
    }
  }

  void removeAlert(String holdRef) {
    _alerts.removeWhere((a) => a.holdRef == holdRef);
    _emitCurrentState();
  }

  void _emitCurrentState() {
    _alerts.removeWhere((a) => a.isExpired);
    if (_alerts.isEmpty) {
      emit(AlertEmpty());
    } else {
      emit(AlertLoaded(List.unmodifiable(_alerts)));
    }
  }

  @override
  Future<void> close() {
    _heartbeatTimer?.cancel();
    return super.close();
  }
}
