// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import 'package:flutter/material.dart';
import '../config/theme.dart';

class DeviceStatusBadge extends StatelessWidget {
  const DeviceStatusBadge({super.key});

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: SentinelTheme.space3, vertical: SentinelTheme.space3 - 4),
      decoration: BoxDecoration(
        color: SentinelTheme.success.withValues(alpha: 0.1),
        borderRadius: BorderRadius.circular(SentinelTheme.radiusLg),
        border: Border.all(color: SentinelTheme.success.withValues(alpha: 0.3)),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Container(
            width: 12,
            height: 12,
            decoration: const BoxDecoration(color: SentinelTheme.success, shape: BoxShape.circle),
          ),
          const SizedBox(width: SentinelTheme.space3),
          const Text('DEVICE ACTIVE', style: TextStyle(color: SentinelTheme.success, fontWeight: FontWeight.bold, letterSpacing: 1.5)),
        ],
      ),
    );
  }
}
