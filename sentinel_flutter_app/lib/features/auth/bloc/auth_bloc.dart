// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import 'dart:io';
import 'package:flutter_bloc/flutter_bloc.dart';
import 'auth_event.dart';
import 'auth_state.dart';
import '../../../core/storage/secure_storage.dart';
import '../../../core/crypto/ed25519_service.dart';
import '../../../core/crypto/ml_dsa_service.dart';
import '../../../core/auth/biometric_service.dart';
import '../../../core/network/auth_client.dart';
import '../../../config/constants.dart';

class AuthBloc extends Bloc<AuthEvent, AuthState> {
  final SecureStorage storage;
  final Ed25519Service ed25519Service;
  final MlDsaService mldsaService;
  final BiometricService biometricService;
  final AuthClient authClient;

  AuthBloc({
    required this.storage,
    required this.ed25519Service,
    required this.mldsaService,
    required this.biometricService,
    required this.authClient,
  }) : super(AuthInitial()) {
    on<AuthInitializeRequested>(_onInitializeRequested);
    on<AuthKeysRevealed>(_onKeysRevealed);
    on<AuthScanRequested>(_onScanRequested);
  }

  Future<void> _onInitializeRequested(
    AuthInitializeRequested event,
    Emitter<AuthState> emit,
  ) async {
    emit(AuthLoading('Initializing Crypto Environment...'));
    try {
      await mldsaService.init();

      bool hasEd25519 = await ed25519Service.loadFromStorage(storage);
      if (!hasEd25519) {
        await ed25519Service.generateAndStore(storage);
      }
      final ed25519Pub = await ed25519Service.getPublicKeyBase64();

      String mldsaPub = 'Unavailable on this architecture';
      if (mldsaService.isAvailable || (await mldsaService.loadFromStorage(storage))) {
          if (!mldsaService.isAvailable) {
             await mldsaService.generateAndStore(storage);
          }
          if (mldsaService.isAvailable) {
             mldsaPub = mldsaService.getPublicKeyBase64();
          }
      } else {
          await mldsaService.generateAndStore(storage);
          if (mldsaService.isAvailable) {
             mldsaPub = mldsaService.getPublicKeyBase64();
          }
      }

      emit(AuthReady(ed25519PubKey: ed25519Pub, mldsaPubKey: mldsaPub));
    } catch (e) {
      emit(AuthFailure('Failed to initialize: $e'));
    }
  }

  void _onKeysRevealed(AuthKeysRevealed event, Emitter<AuthState> emit) {
    if (state is AuthReady) {
      final current = state as AuthReady;
      emit(current.copyWith(keysVisible: !current.keysVisible));
    }
  }

  Future<void> _onScanRequested(
    AuthScanRequested event,
    Emitter<AuthState> emit,
  ) async {
    // Preserve current ready state
    AuthReady? previousReadyState;
    if (state is AuthReady) {
      previousReadyState = state as AuthReady;
    }

    emit(AuthLoading('Authenticating...'));
    
    try {
      final uri = Uri.parse(event.sessionUrl);
      if (uri.scheme != SentinelConstants.qrScheme || uri.host != SentinelConstants.qrHost) {
        emit(AuthFailure('Invalid QR format'));
        if (previousReadyState != null) emit(previousReadyState);
        return;
      }

      final sessionId = uri.queryParameters['session'];
      final challengeId = uri.queryParameters['challenge'];
      final host = uri.queryParameters['host'] ?? SentinelConstants.defaultHost;
      
      if (sessionId == null || challengeId == null) {
        emit(AuthFailure('Missing session or challenge ID'));
        if (previousReadyState != null) emit(previousReadyState);
        return;
      }

      final authenticated = await biometricService.authenticate('Authorize Vendor Login');
      if (!authenticated) {
        emit(AuthFailure('Biometric auth failed or canceled'));
        if (previousReadyState != null) emit(previousReadyState);
        return;
      }

      if (!ed25519Service.hasKeyPair) {
        emit(AuthFailure('Ed25519 keys missing. Restart app.'));
        if (previousReadyState != null) emit(previousReadyState);
        return;
      }

      final ed25519Sig = await ed25519Service.sign(challengeId);
      final mldsaSig = await mldsaService.sign(challengeId);

      final ed25519Pub = await ed25519Service.getPublicKeyBase64();
      final mldsaPub = mldsaService.isAvailable ? mldsaService.getPublicKeyBase64() : '';

      // NOTE: The Master Admin Panel verify endpoint currently requires
      // mldsa_signature to be non-empty and returns 400 otherwise.
      // If PQC is unavailable (isAvailable == false), the empty string
      // will be rejected by the server. Either:
      //   a) Run `npm run setup:admin-device` to disable PQC enforcement
      //   b) Fix verify/route.ts to treat empty mldsa_signature as "PQC unavailable"
      final response = await authClient.verifyChallenge(
        host: host,
        sessionId: sessionId,
        challengeId: challengeId,
        ed25519Signature: ed25519Sig,
        mldsaSignature: mldsaSig,
        ed25519PubKey: ed25519Pub,
        mldsaPubKey: mldsaPub,
        osName: Platform.operatingSystem,
      );

      if (response.statusCode == 200) {
        emit(AuthScanSuccess());
        if (previousReadyState != null) emit(previousReadyState);
      } else {
        emit(AuthFailure('Auth Failed: ${response.body}'));
        if (previousReadyState != null) emit(previousReadyState);
      }
    } catch (e) {
      emit(AuthFailure('Network Error: Unreachable Gateway'));
      if (previousReadyState != null) emit(previousReadyState);
    }
  }
}
