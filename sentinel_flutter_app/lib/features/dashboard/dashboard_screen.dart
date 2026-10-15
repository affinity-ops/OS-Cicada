// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import 'package:flutter/material.dart';
import 'package:flutter_bloc/flutter_bloc.dart';

import '../../config/theme.dart';
import '../../widgets/grid_background.dart';
import '../../widgets/device_status_badge.dart';
import '../../widgets/key_display_card.dart';
import '../../widgets/authorize_button.dart';
import '../auth/bloc/auth_bloc.dart';
import '../auth/bloc/auth_state.dart';

class DashboardScreen extends StatelessWidget {
  const DashboardScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Cicada Sentinel', style: TextStyle(fontWeight: FontWeight.bold, letterSpacing: 1.5)),
      ),
      body: Stack(
        children: [
          Positioned.fill(
            child: Opacity(
              opacity: 0.05,
              child: const GridBackground(),
            ),
          ),
          BlocConsumer<AuthBloc, AuthState>(
            listener: (context, state) {
              if (state is AuthScanSuccess) {
                ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(
                    content: Row(
                      children: [
                        Icon(Icons.check_circle, color: Colors.white),
                        SizedBox(width: 12),
                        Expanded(child: Text('SESSION AUTHORIZED', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 16, letterSpacing: 1.2))),
                      ],
                    ),
                    backgroundColor: SentinelTheme.success,
                  ),
                );
              } else if (state is AuthFailure) {
                ScaffoldMessenger.of(context).showSnackBar(
                  SnackBar(
                    content: Text(state.error),
                    backgroundColor: SentinelTheme.error,
                  ),
                );
              }
            },
            builder: (context, state) {
              if (state is AuthInitial || (state is AuthLoading && !state.message.contains('Authenticating'))) {
                return const Center(child: CircularProgressIndicator(color: SentinelTheme.accent));
              }

              return Stack(
                children: [
                  Padding(
                    padding: const EdgeInsets.all(SentinelTheme.space4),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: const [
                        DeviceStatusBadge(),
                        SizedBox(height: SentinelTheme.space5),
                        Text('Hardware Identity', style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold, color: Colors.white)),
                        SizedBox(height: SentinelTheme.space3),
                        KeyDisplayCard(),
                        Spacer(),
                        AuthorizeButton(),
                        SizedBox(height: SentinelTheme.space3 + 4),
                      ],
                    ),
                  ),
                  if (state is AuthLoading && state.message.contains('Authenticating'))
                    Container(
                      color: Colors.black.withValues(alpha: 0.7),
                      child: Center(
                        child: Column(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            const CircularProgressIndicator(color: SentinelTheme.accent),
                            const SizedBox(height: SentinelTheme.space3),
                            Text(state.message, style: const TextStyle(color: Colors.white, fontWeight: FontWeight.bold)),
                          ],
                        ),
                      ),
                    ),
                ],
              );
            },
          ),
        ],
      ),
    );
  }
}

