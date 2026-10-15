// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import 'package:flutter/material.dart';
import '../config/theme.dart';

enum CicadaStatus {
  secure(cicadaSuccess, 'SECURE'),
  warning(cicadaWarning, 'ELEVATED'),
  danger(cicadaDanger, 'CRITICAL'),
  neutral(cicadaInfo, 'INFO');

  final Color color;
  final String label;
  const CicadaStatus(this.color, this.label);
}

class CicadaBadge extends StatelessWidget {
  final CicadaStatus status;

  const CicadaBadge({Key? key, required this.status}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: space2, vertical: space1),
      decoration: BoxDecoration(
        color: status.color.withValues(alpha: 0.15),
        borderRadius: BorderRadius.circular(radiusFull),
        border: Border.all(color: status.color.withValues(alpha: 0.3)),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Container(
            width: 6,
            height: 6,
            decoration: BoxDecoration(color: status.color, shape: BoxShape.circle),
          ),
          const SizedBox(width: 6),
          Text(
            status.label,
            style: TextStyle(
              color: status.color,
              fontSize: 11,
              fontWeight: FontWeight.w700,
              letterSpacing: 0.5,
            ),
          ),
        ],
      ),
    );
  }
}