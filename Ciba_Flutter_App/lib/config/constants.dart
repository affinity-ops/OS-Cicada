// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/// Centralised constants for the Aegis CIBA companion.
///
/// All gateway endpoint paths match the routes registered in
/// `Sentry_Gateway/internal/mobile/mobile.go → RegisterRoutes()`.
class AppConstants {
  AppConstants._();

  // ── Gateway Base URL ───────────────────────────────────────────────────────
  static const String gatewayBaseUrl = String.fromEnvironment(
    'GATEWAY_URL',
    defaultValue: 'http://localhost:8080',
  );

  // ── Gateway Public Key Endpoint ───────────────────────────────────────────
  // The app fetches the Gateway's Ed25519 public key from this endpoint
  // to verify QR pairing payload signatures. The public key is not a secret.
  static const String pubkeyEndpoint = '/v1/gateway/pubkey';

  // ── Mobile Endpoints (Phase 1-7) ──────────────────────────────────────────
  static const String handshakeEndpoint = '/v1/mobile/pair/handshake';
  static const String pushTokenEndpoint = '/v1/mobile/push-token';
  static const String heartbeatEndpoint = '/v1/mobile/heartbeat';
  static const String batchDecisionsEndpoint = '/v1/mobile/decisions/batch';
  static const String telemetryEndpoint = '/v1/mobile/telemetry';
  static const String deviceEnrollEndpoint = '/v1/device/enroll';

  static String holdPayloadEndpoint(String holdRef) =>
      '/v1/hitl/hold/$holdRef/payload';
  static String quorumEndpoint(String holdRef) =>
      '/v1/hitl/hold/$holdRef/quorum';

  // ── Timeouts ───────────────────────────────────────────────────────────────
  static const Duration connectTimeout = Duration(seconds: 10);
  static const Duration receiveTimeout = Duration(seconds: 30);
  static const Duration heartbeatInterval = Duration(seconds: 10);
  static const Duration keyRotationThreshold = Duration(days: 90);
  static const Duration defaultHoldTimeout = Duration(minutes: 5);
  static const Duration pairingTokenExpiry = Duration(minutes: 5);

  // ── Rate Limits ────────────────────────────────────────────────────────────
  static const int maxDecisionsPerBatch = 10;
  static const int maxDecisionsPerMinute = 10;

  // ── Secure Storage Keys ────────────────────────────────────────────────────
  static const String keyPairedStatus = 'aegis_paired';
  static const String keyEd25519Seed = 'aegis_ed25519_seed';
  static const String keyEd25519Public = 'aegis_ed25519_pub';
  static const String keyX25519Seed = 'aegis_x25519_seed';
  static const String keyX25519Public = 'aegis_x25519_pub';
  static const String keyTenantId = 'aegis_tenant_id';
  static const String keyGatewayUrl = 'aegis_gateway_url';
  static const String keyPairedAt = 'aegis_paired_at';
  static const String keyLastKeyRotation = 'aegis_last_key_rotation';
  static const String keyPushToken = 'aegis_push_token';

  // ── App Info ───────────────────────────────────────────────────────────────
  // IMPORTANT: This MUST match the version in pubspec.yaml (currently 3.0.0+5).
  // The Gateway device enrollment sends this value to the Developer Portal's
  // device registry. A mismatch causes version confusion in the UI.
  static const String appVersion = '3.0.0';
}
