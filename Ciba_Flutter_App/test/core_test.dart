// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import 'package:flutter_test/flutter_test.dart';
import 'package:aegis_ciba_companion/core/crypto/ed25519_service.dart';
import 'package:aegis_ciba_companion/core/crypto/x25519_service.dart';
import 'package:aegis_ciba_companion/features/alerts/models/alert_model.dart';
import 'package:aegis_ciba_companion/config/constants.dart';

void main() {
  group('Ed25519Service', () {
    late Ed25519Service service;

    setUp(() {
      service = Ed25519Service();
    });

    test('has no key pair initially', () {
      expect(service.hasKeyPair, isFalse);
    });

    test('throws when signing without key pair', () {
      expect(() => service.sign('test'), throwsA(isA<StateError>()));
    });

    test('throws when getting public key without key pair', () {
      expect(() => service.getPublicKeyBase64(), throwsA(isA<StateError>()));
    });
  });

  group('X25519Service', () {
    late X25519Service service;

    setUp(() {
      service = X25519Service();
    });

    test('has no key pair initially', () {
      expect(service.hasKeyPair, isFalse);
    });

    test('throws when getting public key without key pair', () {
      expect(() => service.getPublicKeyBase64(), throwsA(isA<StateError>()));
    });
  });

  group('HitlAlert', () {
    test('parses from JSON correctly', () {
      final json = {
        'hold_ref': 'hold-001',
        'agent_name': 'CI Orchestrator',
        'tenant_name': 'Nexus Dynamics Ltd',
        'action_type': 'shell/exec',
        'action_detail': 'POST /api/v1/db/drop-table',
        'action_target': 'prod-db-03',
        'semantic_mismatch': 0.91,
        'velocity': 'HIGH',
        'trust_score': 0.68,
        'trust_threshold': 0.75,
        'severity': 'critical',
        'expires_at': DateTime.now().add(const Duration(minutes: 5)).toIso8601String(),
        'created_at': DateTime.now().toIso8601String(),
        'agent_role': 'Sub-agent',
        'parent_agent': 'CI',
        'declared_tools': [
          {'name': 'stripe/charge', 'is_declared': true},
          {'name': 'slack/notify', 'is_declared': true},
          {'name': 'shell/exec', 'is_declared': false},
        ],
        'quorum': {
          'required_votes': 2,
          'total_voters': 3,
          'current_approvals': 1,
          'current_rejections': 0,
          'resolved': false,
        },
      };

      final alert = HitlAlert.fromJson(json);

      expect(alert.holdRef, equals('hold-001'));
      expect(alert.agentName, equals('CI Orchestrator'));
      expect(alert.tenantName, equals('Nexus Dynamics Ltd'));
      expect(alert.actionType, equals('shell/exec'));
      expect(alert.actionDetail, equals('POST /api/v1/db/drop-table'));
      expect(alert.actionTarget, equals('prod-db-03'));
      expect(alert.semanticMismatch, equals(0.91));
      expect(alert.velocity, equals('HIGH'));
      expect(alert.trustScore, equals(0.68));
      expect(alert.severity, equals(AlertSeverity.critical));
      expect(alert.isBelowTrustThreshold, isTrue);
      expect(alert.isExpired, isFalse);
    });

    test('parses declared tools', () {
      final json = {
        'hold_ref': 'hold-002',
        'agent_name': 'Test',
        'tenant_name': 'Test',
        'action_type': 'test',
        'action_detail': 'test',
        'semantic_mismatch': 0.5,
        'velocity': 'NORMAL',
        'trust_score': 0.9,
        'severity': 'elevated',
        'expires_at': DateTime.now().add(const Duration(minutes: 5)).toIso8601String(),
        'created_at': DateTime.now().toIso8601String(),
        'declared_tools': [
          {'name': 'shell/exec', 'is_declared': false},
        ],
      };

      final alert = HitlAlert.fromJson(json);
      expect(alert.declaredTools.length, equals(1));
      expect(alert.declaredTools.first.isDeclared, isFalse);
      expect(alert.declaredTools.first.name, equals('shell/exec'));
    });

    test('parses quorum status', () {
      final json = {
        'hold_ref': 'hold-003',
        'agent_name': 'Test',
        'tenant_name': 'Test',
        'action_type': 'test',
        'action_detail': 'test',
        'semantic_mismatch': 0.5,
        'velocity': 'NORMAL',
        'trust_score': 0.9,
        'severity': 'standard',
        'expires_at': DateTime.now().add(const Duration(minutes: 5)).toIso8601String(),
        'created_at': DateTime.now().toIso8601String(),
        'quorum': {
          'required_votes': 3,
          'total_voters': 5,
          'current_approvals': 1,
          'current_rejections': 0,
          'resolved': false,
        },
      };

      final alert = HitlAlert.fromJson(json);
      expect(alert.requiresQuorum, isTrue);
      expect(alert.quorum!.requiredVotes, equals(3));
      expect(alert.quorum!.totalVoters, equals(5));
      expect(alert.quorum!.pendingVotes, equals(2));
    });

    test('detects expired alerts', () {
      final json = {
        'hold_ref': 'hold-expired',
        'agent_name': 'Test',
        'tenant_name': 'Test',
        'action_type': 'test',
        'action_detail': 'test',
        'semantic_mismatch': 0.5,
        'velocity': 'LOW',
        'trust_score': 0.9,
        'severity': 'standard',
        'expires_at': DateTime.now().subtract(const Duration(minutes: 1)).toIso8601String(),
        'created_at': DateTime.now().subtract(const Duration(minutes: 6)).toIso8601String(),
      };

      final alert = HitlAlert.fromJson(json);
      expect(alert.isExpired, isTrue);
    });

    test('severity parsing', () {
      expect(AlertSeverity.fromString('critical'), equals(AlertSeverity.critical));
      expect(AlertSeverity.fromString('elevated'), equals(AlertSeverity.elevated));
      expect(AlertSeverity.fromString('standard'), equals(AlertSeverity.standard));
      expect(AlertSeverity.fromString('unknown'), equals(AlertSeverity.standard));
      expect(AlertSeverity.fromString('CRITICAL'), equals(AlertSeverity.critical));
    });
  });

  group('AppConstants', () {
    test('gateway base URL has correct default', () {
      expect(AppConstants.gatewayBaseUrl, equals('http://localhost:8080'));
    });

    test('hold payload endpoint generates correct path', () {
      expect(
        AppConstants.holdPayloadEndpoint('trace-123'),
        equals('/v1/hitl/hold/trace-123/payload'),
      );
    });

    test('quorum endpoint generates correct path', () {
      expect(
        AppConstants.quorumEndpoint('trace-456'),
        equals('/v1/hitl/hold/trace-456/quorum'),
      );
    });

    test('endpoints match gateway RegisterRoutes', () {
      expect(AppConstants.handshakeEndpoint, equals('/v1/mobile/pair/handshake'));
      expect(AppConstants.pushTokenEndpoint, equals('/v1/mobile/push-token'));
      expect(AppConstants.heartbeatEndpoint, equals('/v1/mobile/heartbeat'));
      expect(AppConstants.batchDecisionsEndpoint, equals('/v1/mobile/decisions/batch'));
      expect(AppConstants.telemetryEndpoint, equals('/v1/mobile/telemetry'));
      expect(AppConstants.deviceEnrollEndpoint, equals('/v1/device/enroll'));
    });

    test('rate limits match gateway enforcement', () {
      expect(AppConstants.maxDecisionsPerBatch, equals(10));
      expect(AppConstants.maxDecisionsPerMinute, equals(10));
    });
  });
}
