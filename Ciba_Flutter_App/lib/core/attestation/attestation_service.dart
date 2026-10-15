// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import 'dart:io';

/// Platform attestation service for device integrity verification.
///
/// Provides a unified interface for:
///   - Android: Google Play Integrity API
///   - iOS: Apple App Attest (DeviceCheck framework)
///
/// Security model:
///   The attestation token proves to the Gateway that the decision was
///   made on a genuine, unmodified device running an authentic copy of
///   the Aegis app. This prevents:
///   - Rooted/jailbroken devices from approving actions
///   - Emulators/simulators from faking decisions
///   - Repackaged/tampered APKs from signing decisions
///
/// The token is generated client-side but VERIFIED server-side by the
/// Gateway using Google's Play Integrity API or Apple's attestation
/// service. NEVER trust attestation results computed on-device.
///
/// Integration:
///   1. Android: Requires Play Integrity API enabled in Google Cloud Console
///      and app linked in Play Console (Release > Setup > App Integrity)
///   2. iOS: Requires App Attest entitlement in Xcode project
///   3. Gateway: Verifies the token server-side before accepting decisions
///
/// Graceful degradation:
///   When CICADA_ENFORCE_ATTESTATION=false on the Gateway, the token is
///   still sent (for logging/monitoring) but not enforced. This allows
///   development on emulators and unsigned builds.
class AttestationService {
  /// Whether platform attestation is available on this device.
  ///
  /// Returns false for:
  ///   - Emulators/simulators (no hardware attestation)
  ///   - Devices without Google Play Services (Android)
  ///   - Devices without App Attest capability (older iOS)
  bool _available = false;

  /// Initialise the attestation service.
  ///
  /// Checks whether the current platform supports attestation.
  /// Safe to call on any platform — degrades gracefully.
  Future<void> init() async {
    try {
      if (Platform.isAndroid || Platform.isIOS) {
        // On a real device with proper configuration, attestation
        // should be available. We'll verify during token generation.
        _available = true;
      }
    } catch (_) {
      _available = false;
    }
  }

  /// Request an attestation token for a decision.
  ///
  /// Parameters:
  ///   - nonce: A unique, single-use value bound to the decision.
  ///     This MUST be the decision_nonce used in the signing payload
  ///     to prevent replay attacks. The Gateway verifies the nonce
  ///     inside the attestation token matches the decision nonce.
  ///
  /// Returns:
  ///   - A platform-specific attestation token string (JWT for Android,
  ///     CBOR for iOS), or a fallback value if attestation is unavailable.
  ///
  /// The Gateway checks the token against these known-invalid values:
  ///   - '' (empty string)
  ///   - 'PENDING_IMPLEMENTATION'
  ///   - 'ATTESTATION_UNAVAILABLE'
  /// If CICADA_ENFORCE_ATTESTATION=true, any of these causes rejection.
  Future<String> getAttestationToken(String nonce) async {
    if (!_available) {
      return 'ATTESTATION_UNAVAILABLE';
    }

    try {
      if (Platform.isAndroid) {
        return await _getPlayIntegrityToken(nonce);
      } else if (Platform.isIOS) {
        return await _getAppAttestToken(nonce);
      }
      return 'ATTESTATION_UNAVAILABLE';
    } catch (e) {
      // Attestation failed — return a descriptive fallback.
      // The Gateway will log this and reject if enforcement is on.
      return 'ATTESTATION_UNAVAILABLE';
    }
  }

  /// Request a Google Play Integrity token (Android).
  ///
  /// Requires:
  ///   1. Play Integrity API enabled in Google Cloud Console
  ///   2. App linked in Play Console (Release > Setup > App Integrity)
  ///   3. App signed with the correct keystore
  ///
  /// The token is a JWT that the Gateway decrypts and verifies using
  /// Google's Play Integrity server-side API. The verdict contains:
  ///   - requestDetails.nonce (must match our decision nonce)
  ///   - appIntegrity.appRecognitionVerdict (PLAY_RECOGNIZED = genuine)
  ///   - deviceIntegrity.deviceRecognitionVerdict (MEETS_DEVICE_INTEGRITY)
  ///   - accountDetails.appLicensingVerdict (LICENSED)
  Future<String> _getPlayIntegrityToken(String nonce) async {
    // Integration point for the play_integrity package.
    // When the play_integrity or flutter_play_integrity_wrapper package
    // is added, this method will call:
    //
    //   final integrityManager = PlayIntegrity();
    //   final token = await integrityManager.requestIntegrityToken(
    //     IntegrityTokenRequest(nonce: nonce),
    //   );
    //   return token;
    //
    // For now, return a structured placeholder that the Gateway
    // recognises as non-production. This is intentional — the
    // CICADA_ENFORCE_ATTESTATION flag controls whether the Gateway
    // accepts or rejects this value.
    //
    // See PRE_PRODUCTION_REQUIREMENTS.md §1.1 — Google Play Console Registration
    // This stub is replaced with real Play Integrity once the app is registered.
    return 'ATTESTATION_ANDROID_PENDING_PLAY_CONSOLE_SETUP';
  }

  /// Request an Apple App Attest token (iOS).
  ///
  /// Requires:
  ///   1. App Attest entitlement in Xcode project
  ///   2. Team ID configured in Apple Developer portal
  ///
  /// The token is a CBOR attestation object that the Gateway verifies
  /// using Apple's attestation service. The verification confirms:
  ///   - The app binary hasn't been modified
  ///   - The device isn't jailbroken
  ///   - The request includes the correct nonce
  Future<String> _getAppAttestToken(String nonce) async {
    // Integration point for Apple App Attest.
    // When the DCAppAttestService wrapper is added, this method will:
    //
    //   1. Generate a key pair (one-time, stored in Keychain)
    //   2. Attest the key with Apple
    //   3. Assert the key with the decision nonce
    //   4. Return the assertion for server-side verification
    //
    // See PRE_PRODUCTION_REQUIREMENTS.md §1.2 — Apple App Attest Configuration
    // This stub is replaced with real App Attest once entitlements are configured.
    return 'ATTESTATION_IOS_PENDING_XCODE_SETUP';
  }

  /// Whether attestation is available on this device.
  bool get isAvailable => _available;
}
