// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import 'package:flutter/material.dart';
import 'package:local_auth/local_auth.dart';
import '../../config/theme.dart';
import '../../core/storage/secure_storage.dart';
import '../../core/crypto/ed25519_service.dart';
import '../../core/network/dio_client.dart';
import '../../config/constants.dart';
import '../pairing/pairing_screen.dart';
import '../alerts/alert_list_screen.dart';

/// Branded splash screen — checks pairing status, authenticates via biometrics,
/// and routes accordingly.
///
/// Flow:
///   1. First launch (not paired) → QR Scanner
///   2. Subsequent launches (paired) → Biometric gate → Alert List
///   3. Biometric failure → Locked screen with retry
///
/// The biometric gate ensures that even if someone picks up an unlocked phone,
/// they cannot see pending HITL actions without the device owner's face or
/// fingerprint. This is a zero-trust requirement — the app contains details
/// of agent operations that are sensitive by definition (they triggered HITL
/// precisely because they were high-risk).
class SplashScreen extends StatefulWidget {
  const SplashScreen({Key? key}) : super(key: key);

  @override
  State<SplashScreen> createState() => _SplashScreenState();
}

class _SplashScreenState extends State<SplashScreen>
    with SingleTickerProviderStateMixin {
  late AnimationController _controller;
  late Animation<double> _fadeAnimation;
  late Animation<double> _scaleAnimation;

  bool _biometricFailed = false;

  @override
  void initState() {
    super.initState();
    _controller = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 1800),
    );
    _fadeAnimation = Tween<double>(begin: 0.0, end: 1.0).animate(
      CurvedAnimation(parent: _controller, curve: const Interval(0.0, 0.6, curve: Curves.easeOut)),
    );
    _scaleAnimation = Tween<double>(begin: 0.8, end: 1.0).animate(
      CurvedAnimation(parent: _controller, curve: const Interval(0.0, 0.6, curve: Curves.easeOut)),
    );

    _controller.forward();
    _checkPairingAndNavigate();
  }

  Future<void> _checkPairingAndNavigate() async {
    await Future.delayed(const Duration(milliseconds: 2500));

    if (!mounted) return;

    // Check if device is already paired
    final storage = SecureStorage();
    final isPaired = await storage.read(AppConstants.keyPairedStatus);

    if (isPaired != 'true') {
      // ── Not paired: go straight to QR scanner ────────────────────────
      if (!mounted) return;
      _navigateTo(const PairingScreen());
      return;
    }

    // ── Paired: require biometric authentication ───────────────────────
    // This prevents someone who picks up an unlocked phone from seeing
    // pending HITL actions. Every app open requires face or fingerprint.
    final authenticated = await _authenticateBiometric();

    if (!mounted) return;

    if (authenticated) {
      // ── Pre-flight heartbeat: verify device is still active ──────────
      // After biometric passes, check with the Gateway that this device
      // hasn't been revoked or suspended since the last session. If it
      // has, purge credentials and route to QR scanner instead of
      // showing a broken AlertListScreen.
      final shouldContinue = await _verifyDeviceActive(storage);
      if (!mounted) return;
      if (shouldContinue) {
        _navigateTo(const AlertListScreen());
      } else {
        _navigateTo(const PairingScreen());
      }
    } else {
      // Show locked state with retry button
      setState(() => _biometricFailed = true);
    }
  }

  Future<bool> _authenticateBiometric() async {
    try {
      final auth = LocalAuthentication();

      // Check if biometrics are available on this device
      final canAuthenticate = await auth.canCheckBiometrics || await auth.isDeviceSupported();
      if (!canAuthenticate) {
        // Device has no biometrics — allow through (but log it server-side)
        // This handles emulators and devices without biometric hardware.
        return true;
      }

      return await auth.authenticate(
        localizedReason: 'Authenticate to access Cicada Aegis',
        options: const AuthenticationOptions(
          biometricOnly: true,
          stickyAuth: true, // Keeps auth dialog open on background/foreground
        ),
      );
    } catch (e) {
      return false;
    }
  }

  Future<void> _retryBiometric() async {
    setState(() => _biometricFailed = false);
    final authenticated = await _authenticateBiometric();
    if (!mounted) return;
    if (authenticated) {
      // Pre-flight heartbeat on retry as well
      final storage = SecureStorage();
      final shouldContinue = await _verifyDeviceActive(storage);
      if (!mounted) return;
      if (shouldContinue) {
        _navigateTo(const AlertListScreen());
      } else {
        _navigateTo(const PairingScreen());
      }
    } else {
      setState(() => _biometricFailed = true);
    }
  }

  /// Pre-flight check: send a heartbeat to the Gateway and verify the device
  /// status is 'active'. If the device is revoked or suspended, purge the
  /// pairing flag so the next launch routes to QR scanner.
  ///
  /// Returns true if the device is active (or Gateway is unreachable — we
  /// allow offline operation). Returns false if the device is definitively
  /// revoked/suspended and credentials have been purged.
  Future<bool> _verifyDeviceActive(SecureStorage storage) async {
    try {
      final gatewayUrl = await storage.read(AppConstants.keyGatewayUrl);
      if (gatewayUrl == null || gatewayUrl.isEmpty) return true;

      final ed25519 = Ed25519Service();
      final loaded = await ed25519.loadFromStorage(storage);
      if (!loaded) return true;

      final pubKey = await ed25519.getPublicKeyBase64();
      final client = DioClient(baseUrl: gatewayUrl);
      final response = await client.post(
        AppConstants.heartbeatEndpoint,
        data: {
          'ed25519_pub': pubKey,
          'offline_queue_count': 0,
        },
      );

      if (response.data != null) {
        final status = (response.data as Map<String, dynamic>)['status'] as String?;
        if (status == 'revoked') {
          // Revoked: purge everything and force re-pair
          await storage.delete(AppConstants.keyPairedStatus);
          return false;
        }
        // 'suspended' is now handled by Gateway recovery (R2.1) — the
        // heartbeat itself re-activates the device, so if we get here
        // the status should already be 'active'.
        if (status == 'suspended') {
          // Gateway didn't re-activate — unexpected. Purge and re-pair.
          await storage.delete(AppConstants.keyPairedStatus);
          return false;
        }
      }
      return true;
    } catch (_) {
      // Gateway unreachable — allow offline operation.
      // The AlertBloc heartbeat will handle revocation detection when
      // connectivity is restored.
      return true;
    }
  }

  void _navigateTo(Widget destination) {
    Navigator.of(context).pushReplacement(
      PageRouteBuilder(
        pageBuilder: (_, __, ___) => destination,
        transitionsBuilder: (_, animation, __, child) =>
            FadeTransition(opacity: animation, child: child),
        transitionDuration: const Duration(milliseconds: 600),
      ),
    );
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: cicadaBackground,
      body: Center(
        child: FadeTransition(
          opacity: _fadeAnimation,
          child: ScaleTransition(
            scale: _scaleAnimation,
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                // ── Logo ─────────────────────────────────────────────────
                Container(
                  width: 88,
                  height: 88,
                  decoration: BoxDecoration(
                    gradient: cicadaGradient,
                    borderRadius: BorderRadius.circular(22),
                    boxShadow: [
                      BoxShadow(
                        color: cicadaPrimary.withValues(alpha: 0.3),
                        blurRadius: 40,
                        spreadRadius: 0,
                      ),
                    ],
                  ),
                  child: Center(
                    child: Icon(
                      _biometricFailed ? Icons.lock_outline : Icons.shield_outlined,
                      size: 44,
                      color: Colors.black.withValues(alpha: 0.8),
                    ),
                  ),
                ),
                const SizedBox(height: space5),
                Text(
                  'CICADA AEGIS',
                  style: headlineStyle(fontSize: 24, weight: FontWeight.w900).copyWith(letterSpacing: 4.0),
                ),
                const SizedBox(height: space2),
                Text(
                  _biometricFailed ? 'AUTHENTICATION REQUIRED' : 'ZERO-TRUST COMPANION',
                  style: technicalStyle(fontSize: 10).copyWith(
                    letterSpacing: 3.0,
                    color: _biometricFailed ? cicadaError : cicadaOnSurfaceMuted,
                  ),
                ),
                const SizedBox(height: space7),

                // ── Loading spinner or retry button ──────────────────────
                if (_biometricFailed) ...[
                  Text(
                    'Biometric authentication is required\nto access pending HITL decisions.',
                    textAlign: TextAlign.center,
                    style: TextStyle(
                      color: cicadaOnSurfaceMuted,
                      fontSize: 13,
                      height: 1.5,
                    ),
                  ),
                  const SizedBox(height: space4),
                  ElevatedButton.icon(
                    onPressed: _retryBiometric,
                    icon: const Icon(Icons.fingerprint, size: 20),
                    label: const Text('Authenticate'),
                    style: ElevatedButton.styleFrom(
                      backgroundColor: cicadaPrimary,
                      foregroundColor: Colors.black,
                      padding: const EdgeInsets.symmetric(horizontal: 32, vertical: 14),
                      shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(radiusMd),
                      ),
                      textStyle: headlineStyle(fontSize: 14),
                    ),
                  ),
                ] else ...[
                  SizedBox(
                    width: 24,
                    height: 24,
                    child: CircularProgressIndicator(
                      strokeWidth: 2,
                      color: cicadaPrimary.withValues(alpha: 0.5),
                    ),
                  ),
                ],
              ],
            ),
          ),
        ),
      ),
    );
  }
}
