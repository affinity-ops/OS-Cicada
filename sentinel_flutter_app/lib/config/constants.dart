// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0


class SentinelConstants {
  // Auth API endpoints
  static const String challengeEndpoint = '/api/auth/challenge';
  static const String verifyEndpoint = '/api/auth/verify';
  static const String statusEndpoint = '/api/auth/status';
  
  // Storage keys
  static const String keyEd25519Private = 'ed25519_private_key';
  static const String keyEd25519Public = 'ed25519_public_key';
  static const String keyMldsaPrivate = 'mldsa_private_key';
  static const String keyMldsaPublic = 'mldsa_public_key';
  
  // Timeouts
  static const Duration verifyTimeout = Duration(seconds: 10);
  
  // Default host fallback
  static const String defaultHost = '192.168.0.35:3005';
  
  // QR URL scheme
  static const String qrScheme = 'cicada';
  static const String qrHost = 'master-auth';
}
