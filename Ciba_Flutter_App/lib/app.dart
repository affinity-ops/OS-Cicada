// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import 'package:flutter/material.dart';
import 'package:flutter_bloc/flutter_bloc.dart';
import 'config/theme.dart';
import 'config/constants.dart';
import 'features/splash/splash_screen.dart';
import 'features/pairing/bloc/pairing_bloc.dart';
import 'features/decision/bloc/decision_bloc.dart';
import 'features/alerts/bloc/alert_bloc.dart';
import 'core/auth/biometric_service.dart';
import 'core/attestation/attestation_service.dart';
import 'core/crypto/ed25519_service.dart';
import 'core/crypto/x25519_service.dart';
import 'core/crypto/ml_dsa_service.dart';
import 'core/storage/secure_storage.dart';
import 'core/storage/offline_queue.dart';
import 'core/network/dio_client.dart';
import 'core/push/push_service.dart' show navigatorKey;
import 'core/push/push_service.dart';

class AegisApp extends StatefulWidget {
  final OfflineQueue offlineQueue;
  const AegisApp({Key? key, required this.offlineQueue}) : super(key: key);

  @override
  State<AegisApp> createState() => _AegisAppState();
}

class _AegisAppState extends State<AegisApp> {
  late final Ed25519Service _ed25519;
  late final X25519Service _x25519;
  late final MlDsaService _mlDsa;
  late final SecureStorage _storage;
  late final DioClient _dioClient;
  late final BiometricService _biometric;
  late final AttestationService _attestation;

  @override
  void initState() {
    super.initState();
    _ed25519 = Ed25519Service();
    _x25519 = X25519Service();
    _mlDsa = MlDsaService();
    _storage = SecureStorage();
    _dioClient = DioClient();
    _biometric = BiometricService();
    _attestation = AttestationService();

    _initializeFromStorage();
  }

  Future<void> _initializeFromStorage() async {
    final loaded = await _ed25519.loadFromStorage(_storage);
    if (loaded) {
      final pubKey = await _ed25519.getPublicKeyBase64();
      _dioClient.setDeviceFingerprint(pubKey);

      final gatewayUrl = await _storage.read(AppConstants.keyGatewayUrl) ?? AppConstants.gatewayBaseUrl;
      _dioClient.setBaseUrl(gatewayUrl);

      await PushService.initialize(storage: _storage, dioClient: _dioClient);
    } else {
      await PushService.initialize(storage: _storage);
    }
    await _x25519.loadFromStorage(_storage);

    // Initialise PQC services (non-blocking — degrades gracefully
    // if liboqs binaries aren't available on this platform).
    await _mlDsa.init();
    await _mlDsa.loadFromStorage(_storage);

    // Initialise platform attestation (Play Integrity / App Attest).
    // Safe to call on any platform — degrades gracefully.
    await _attestation.init();
  }

  @override
  Widget build(BuildContext context) {
    return MultiBlocProvider(
      providers: [
        BlocProvider<PairingBloc>(
          create: (_) => PairingBloc(
            ed25519Service: _ed25519,
            x25519Service: _x25519,
            mlDsaService: _mlDsa,
            secureStorage: _storage,
            dioClient: _dioClient,
          ),
        ),
        BlocProvider<DecisionBloc>(
          create: (_) => DecisionBloc(
            ed25519Service: _ed25519,
            mlDsaService: _mlDsa,
            biometricService: _biometric,
            attestationService: _attestation,
            secureStorage: _storage,
            dioClient: _dioClient,
            offlineQueue: widget.offlineQueue,
          ),
        ),
        BlocProvider<AlertBloc>(
          create: (_) => AlertBloc(
            dioClient: _dioClient,
            ed25519Service: _ed25519,
            secureStorage: _storage,
          ),
        ),
      ],
      child: MaterialApp(
        title: 'Cicada Aegis',
        navigatorKey: navigatorKey,
        theme: buildCicadaTheme(),
        debugShowCheckedModeBanner: false,
        home: const SplashScreen(),
      ),
    );
  }
}
