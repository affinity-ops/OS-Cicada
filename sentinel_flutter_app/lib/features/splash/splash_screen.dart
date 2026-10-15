// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import 'package:flutter/material.dart';
import '../../config/theme.dart';
import '../../widgets/grid_background.dart';
import '../dashboard/dashboard_screen.dart';

class SplashScreen extends StatefulWidget {
  const SplashScreen({super.key});

  @override
  State<SplashScreen> createState() => _SplashScreenState();
}

class _SplashScreenState extends State<SplashScreen> with SingleTickerProviderStateMixin {
  late AnimationController _controller;
  late Animation<double> _glowAnimation;
  
  int _statusIndex = 0;
  final List<String> _bootSequence = [
    "INITIALIZING SECURE ENCLAVE...",
    "VERIFYING HARDWARE INTEGRITY...",
    "LOADING POST-QUANTUM CRYPTOGRAPHY...",
    "ED25519 + ML-DSA-65 HYBRID READY."
  ];

  @override
  void initState() {
    super.initState();
    
    _controller = AnimationController(
      vsync: this,
      duration: const Duration(seconds: 2),
    )..repeat(reverse: true);

    _glowAnimation = Tween<double>(begin: 10.0, end: 40.0).animate(
      CurvedAnimation(parent: _controller, curve: Curves.easeInOut),
    );

    _runBootSequence();
  }

  Future<void> _runBootSequence() async {
    for (int i = 0; i < _bootSequence.length; i++) {
      await Future.delayed(const Duration(milliseconds: 800));
      if (mounted) {
        setState(() {
          _statusIndex = i;
        });
      }
    }
    
    await Future.delayed(const Duration(milliseconds: 1000));
    
    if (mounted) {
      Navigator.of(context).pushReplacement(
        PageRouteBuilder(
          pageBuilder: (context, animation, secondaryAnimation) => const DashboardScreen(),
          transitionsBuilder: (context, animation, secondaryAnimation, child) {
            return FadeTransition(opacity: animation, child: child);
          },
          transitionDuration: const Duration(milliseconds: 800),
        ),
      );
    }
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: SentinelTheme.background,
      body: Stack(
        children: [
          Positioned.fill(
            child: Opacity(
              opacity: 0.05,
              child: const GridBackground(),
            ),
          ),
          
          Center(
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                AnimatedBuilder(
                  animation: _glowAnimation,
                  builder: (context, child) {
                    return Container(
                      width: 120,
                      height: 120,
                      decoration: BoxDecoration(
                        shape: BoxShape.circle,
                        color: SentinelTheme.surface,
                        boxShadow: [
                          BoxShadow(
                            color: SentinelTheme.accent.withValues(alpha: 0.3),
                            blurRadius: _glowAnimation.value,
                            spreadRadius: _glowAnimation.value / 4,
                          ),
                        ],
                        border: Border.all(
                          color: SentinelTheme.accent.withValues(alpha: 0.5),
                          width: 2,
                        ),
                      ),
                      child: const Icon(
                        Icons.admin_panel_settings,
                        size: 64,
                        color: SentinelTheme.accent,
                      ),
                    );
                  },
                ),
                const SizedBox(height: SentinelTheme.space6 - 8),
                const Text(
                  'CICADA',
                  style: TextStyle(
                    color: SentinelTheme.textPrimary,
                    fontSize: 32,
                    fontWeight: FontWeight.w900,
                    letterSpacing: 8.0,
                  ),
                ),
                const Text(
                  'S E N T I N E L',
                  style: TextStyle(
                    color: SentinelTheme.accent,
                    fontSize: 16,
                    fontWeight: FontWeight.bold,
                    letterSpacing: 12.0,
                  ),
                ),
              ],
            ),
          ),
          
          Positioned(
            bottom: SentinelTheme.space6 - 8,
            left: 0,
            right: 0,
            child: Column(
              children: [
                const SizedBox(
                  width: 40,
                  height: 40,
                  child: CircularProgressIndicator(
                    strokeWidth: 2,
                    valueColor: AlwaysStoppedAnimation<Color>(SentinelTheme.accent),
                  ),
                ),
                const SizedBox(height: SentinelTheme.space4),
                Text(
                  _bootSequence[_statusIndex],
                  style: const TextStyle(
                    color: SentinelTheme.textMuted,
                    fontSize: 12,
                    fontFamily: 'monospace',
                    fontWeight: FontWeight.bold,
                    letterSpacing: 2.0,
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}
