// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import 'package:flutter/material.dart';
import 'package:flutter_bloc/flutter_bloc.dart';
import '../config/theme.dart';
import '../features/auth/bloc/auth_bloc.dart';
import '../features/auth/bloc/auth_event.dart';
import '../features/auth/bloc/auth_state.dart';
import '../core/auth/biometric_service.dart';

class KeyDisplayCard extends StatelessWidget {
  const KeyDisplayCard({super.key});

  Future<void> _revealKeys(BuildContext context) async {
    final biometricService = context.read<BiometricService>();
    final authenticated = await biometricService.authenticate(
      'Authenticate to view hardware keys',
    );
    if (authenticated && context.mounted) {
      context.read<AuthBloc>().add(AuthKeysRevealed());
    }
  }

  @override
  Widget build(BuildContext context) {
    return BlocBuilder<AuthBloc, AuthState>(
      builder: (context, state) {
        AuthReady? readyState;
        if (state is AuthReady) {
          readyState = state;
        }

        return Container(
          width: double.infinity,
          padding: const EdgeInsets.all(SentinelTheme.space4 - 4),
          decoration: BoxDecoration(
            color: SentinelTheme.surface,
            borderRadius: BorderRadius.circular(SentinelTheme.radiusXl),
            border: Border.all(color: SentinelTheme.textMuted.withValues(alpha: 0.1)),
          ),
          child: (readyState != null && readyState.keysVisible)
              ? Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      mainAxisAlignment: MainAxisAlignment.spaceBetween,
                      children: [
                        const Text('Public Keys (Register in .env)', style: TextStyle(color: SentinelTheme.textSecondary, fontSize: 12, fontWeight: FontWeight.bold)),
                        IconButton(
                          icon: const Icon(Icons.visibility_off, color: SentinelTheme.textSecondary, size: 16),
                          onPressed: () => context.read<AuthBloc>().add(AuthKeysRevealed()),
                          constraints: const BoxConstraints(),
                          padding: EdgeInsets.zero,
                        )
                      ],
                    ),
                    const SizedBox(height: SentinelTheme.space3 - 4),
                    const Text('Ed25519:', style: TextStyle(color: SentinelTheme.accent, fontSize: 11, fontWeight: FontWeight.bold)),
                    const SizedBox(height: SentinelTheme.space1),
                    SelectableText(readyState.ed25519PubKey, style: const TextStyle(fontSize: 11, fontFamily: 'monospace', color: SentinelTheme.textPrimary)),
                    const SizedBox(height: SentinelTheme.space3),
                    const Text('ML-DSA-65:', style: TextStyle(color: SentinelTheme.accent, fontSize: 11, fontWeight: FontWeight.bold)),
                    const SizedBox(height: SentinelTheme.space1),
                    SelectableText(readyState.mldsaPubKey, style: const TextStyle(fontSize: 11, fontFamily: 'monospace', color: SentinelTheme.textPrimary)),
                  ],
                )
              : Column(
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    Icon(Icons.lock_outline, color: SentinelTheme.textPrimary.withValues(alpha: 0.24), size: 48),
                    const SizedBox(height: SentinelTheme.space3),
                    ElevatedButton.icon(
                      icon: const Icon(Icons.fingerprint, color: Colors.black),
                      label: const Text('Reveal Device Identity', style: TextStyle(color: Colors.black, fontWeight: FontWeight.bold)),
                      style: ElevatedButton.styleFrom(
                        backgroundColor: SentinelTheme.accent,
                        padding: const EdgeInsets.symmetric(horizontal: SentinelTheme.space4, vertical: SentinelTheme.space3 - 4),
                        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(SentinelTheme.radiusMd)),
                      ),
                      onPressed: () => _revealKeys(context),
                    ),
                  ],
                ),
        );
      },
    );
  }
}
