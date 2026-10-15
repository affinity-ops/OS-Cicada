// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import 'package:flutter/material.dart';
import 'package:flutter_bloc/flutter_bloc.dart';

import 'config/theme.dart';
import 'features/splash/splash_screen.dart';

import 'core/storage/secure_storage.dart';
import 'core/crypto/ed25519_service.dart';
import 'core/crypto/ml_dsa_service.dart';
import 'core/auth/biometric_service.dart';
import 'core/network/auth_client.dart';
import 'features/auth/bloc/auth_bloc.dart';
import 'features/auth/bloc/auth_event.dart';

class SentinelApp extends StatelessWidget {
  const SentinelApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MultiRepositoryProvider(
      providers: [
        RepositoryProvider(create: (_) => SecureStorage()),
        RepositoryProvider(create: (_) => Ed25519Service()),
        RepositoryProvider(create: (_) => MlDsaService()),
        RepositoryProvider(create: (_) => BiometricService()),
        RepositoryProvider(create: (_) => AuthClient()),
      ],
      child: MultiBlocProvider(
        providers: [
          BlocProvider(
            create: (context) => AuthBloc(
              storage: context.read<SecureStorage>(),
              ed25519Service: context.read<Ed25519Service>(),
              mldsaService: context.read<MlDsaService>(),
              biometricService: context.read<BiometricService>(),
              authClient: context.read<AuthClient>(),
            )..add(AuthInitializeRequested()),
          ),
        ],
        child: MaterialApp(
          title: 'Cicada Sentinel',
          theme: SentinelTheme.darkTheme,
          home: const SplashScreen(),
          debugShowCheckedModeBanner: false,
        ),
      ),
    );
  }
}
