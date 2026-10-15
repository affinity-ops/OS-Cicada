// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import 'dart:convert';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

/// The categories of telemetry events tracked locally.
enum TelemetryEvent {
  appOpen,
  alertReceived,
  alertOpened,
  decisionMade,
  offlineDecisionQueued,
  offlineDecisionSynced,
  pushDeliverySuccess,
  pushDeliveryFailure,
  biometricSuccess,
  biometricFailure,
}

/// A single telemetry entry stored locally.
class TelemetryEntry {
  final TelemetryEvent event;
  final String date;
  final int? latencyMs;

  TelemetryEntry({
    required this.event,
    required this.date,
    this.latencyMs,
  });

  Map<String, dynamic> toJson() => {
    'event': event.name,
    'date': date,
    if (latencyMs != null) 'latency_ms': latencyMs,
  };

  factory TelemetryEntry.fromJson(Map<String, dynamic> json) {
    return TelemetryEntry(
      event: TelemetryEvent.values.firstWhere(
        (e) => e.name == json['event'],
        orElse: () => TelemetryEvent.appOpen,
      ),
      date: json['date'] as String,
      latencyMs: json['latency_ms'] as int?,
    );
  }
}

/// Telemetry service that implements Phase 5: Privacy-Preserving Telemetry & Immutable Ledger.
class TelemetryService {
  static const _storage = FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: false),
    iOptions: IOSOptions(
      accessibility: KeychainAccessibility.first_unlock_this_device,
    ),
  );

  static const String _telemetryKey = 'aegis_telemetry_log';
  static const String _optInKey = 'aegis_telemetry_opt_in';
  static const String _lastSyncKey = 'aegis_telemetry_last_sync';

  /// Records a telemetry event locally.
  static Future<void> record(TelemetryEvent event, {int? latencyMs}) async {
    final entries = await _loadEntries();

    entries.add(TelemetryEntry(
      event: event,
      date: DateTime.now().toUtc().toIso8601String().substring(0, 10),
      latencyMs: latencyMs,
    ));

    final sevenDaysAgo = DateTime.now().toUtc().subtract(const Duration(days: 7));
    final cutoff = sevenDaysAgo.toIso8601String().substring(0, 10);
    entries.removeWhere((e) => e.date.compareTo(cutoff) < 0);

    await _saveEntries(entries);
  }

  /// Generates a privacy-preserving weekly aggregate report.
  static Future<Map<String, dynamic>> generateWeeklyReport() async {
    final entries = await _loadEntries();

    int appOpens = 0;
    int alertsReceived = 0;
    int decisionsMade = 0;
    int offlineDecisions = 0;
    int pushSuccesses = 0;
    int pushFailures = 0;
    int biometricSuccesses = 0;
    int biometricFailures = 0;
    final latencies = <int>[];
    final alertLatencies = <int>[];

    for (final entry in entries) {
      switch (entry.event) {
        case TelemetryEvent.appOpen:
          appOpens++;
          break;
        case TelemetryEvent.alertReceived:
          alertsReceived++;
          break;
        case TelemetryEvent.decisionMade:
          decisionsMade++;
          if (entry.latencyMs != null) latencies.add(entry.latencyMs!);
          break;
        case TelemetryEvent.alertOpened:
          if (entry.latencyMs != null) alertLatencies.add(entry.latencyMs!);
          break;
        case TelemetryEvent.offlineDecisionQueued:
          offlineDecisions++;
          break;
        case TelemetryEvent.pushDeliverySuccess:
          pushSuccesses++;
          break;
        case TelemetryEvent.pushDeliveryFailure:
          pushFailures++;
          break;
        case TelemetryEvent.biometricSuccess:
          biometricSuccesses++;
          break;
        case TelemetryEvent.biometricFailure:
          biometricFailures++;
          break;
        default:
          break;
      }
    }

    return {
      'period_days': 7,
      'app_open_count': appOpens,
      'alerts_received': alertsReceived,
      'decisions_made': decisionsMade,
      'offline_decisions': offlineDecisions,
      'push_delivery_rate': pushSuccesses + pushFailures > 0
          ? (pushSuccesses / (pushSuccesses + pushFailures) * 100).round()
          : null,
      'biometric_success_rate': biometricSuccesses + biometricFailures > 0
          ? (biometricSuccesses / (biometricSuccesses + biometricFailures) * 100).round()
          : null,
      'avg_decision_latency_bucket': _bucketLatency(_averageLatency(latencies)),
      'avg_alert_to_open_latency_bucket': _bucketLatency(_averageLatency(alertLatencies)),
    };
  }

  /// Returns true if the operator has opted in to telemetry sync.
  static Future<bool> isOptedIn() async {
    final value = await _storage.read(key: _optInKey);
    return value == 'true';
  }

  /// Sets the telemetry opt-in preference.
  static Future<void> setOptIn(bool optIn) async {
    await _storage.write(key: _optInKey, value: optIn.toString());
  }

  static String _bucketLatency(int? ms) {
    if (ms == null) return 'no_data';
    if (ms < 5000) return '0-5s';
    if (ms < 15000) return '5-15s';
    if (ms < 30000) return '15-30s';
    return '30s+';
  }

  static int? _averageLatency(List<int> values) {
    if (values.isEmpty) return null;
    return (values.reduce((a, b) => a + b) / values.length).round();
  }

  static Future<List<TelemetryEntry>> _loadEntries() async {
    final raw = await _storage.read(key: _telemetryKey);
    if (raw == null || raw.isEmpty) return [];
    try {
      final List<dynamic> decoded = jsonDecode(raw);
      return decoded
          .map((item) => TelemetryEntry.fromJson(item as Map<String, dynamic>))
          .toList();
    } catch (_) {
      return [];
    }
  }

  static Future<void> _saveEntries(List<TelemetryEntry> entries) async {
    final encoded = jsonEncode(entries.map((e) => e.toJson()).toList());
    await _storage.write(key: _telemetryKey, value: encoded);
  }

  static Future<void> clearAfterSync() async {
    await _storage.delete(key: _telemetryKey);
    await _storage.write(
      key: _lastSyncKey,
      value: DateTime.now().toUtc().toIso8601String(),
    );
  }
}
