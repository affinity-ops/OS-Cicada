// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import 'package:flutter/material.dart';
import '../../config/theme.dart';
import '../../widgets/cicada_badge.dart';
import '../../widgets/cicada_timer.dart';
import '../../widgets/cicada_card.dart';
import '../../widgets/cicada_button.dart';
import '../alerts/models/alert_model.dart';

/// Alert card for the Alert List screen — one card per pending HITL hold.
class AlertCard extends StatelessWidget {
  final HitlAlert alert;
  final VoidCallback onReview;

  const AlertCard({Key? key, required this.alert, required this.onReview}) : super(key: key);

  CicadaStatus get _badgeStatus {
    switch (alert.severity) {
      case AlertSeverity.critical:
        return CicadaStatus.danger;
      case AlertSeverity.elevated:
        return CicadaStatus.warning;
      case AlertSeverity.standard:
        return CicadaStatus.neutral;
    }
  }

  @override
  Widget build(BuildContext context) {
    return CicadaCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // ── Header: Severity + Timer ─────────────────────────────────
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              CicadaBadge(status: _badgeStatus),
              CicadaTimer(expiresAt: alert.expiresAt),
            ],
          ),

          const SizedBox(height: space3),

          // ── Agent + Tenant ───────────────────────────────────────────
          Text(alert.agentName, style: headlineStyle(fontSize: 16)),
          const SizedBox(height: space1),
          Text(alert.tenantName, style: TextStyle(color: cicadaOnSurfaceMuted, fontSize: 13)),

          const SizedBox(height: space3),

          // ── Action type ──────────────────────────────────────────────
          Container(
            padding: const EdgeInsets.symmetric(horizontal: space2, vertical: space1),
            decoration: BoxDecoration(
              color: cicadaError.withValues(alpha: 0.1),
              borderRadius: BorderRadius.circular(radiusSm),
            ),
            child: Text(
              alert.actionType,
              style: technicalStyle(fontSize: 12, color: cicadaError),
            ),
          ),

          const SizedBox(height: space3),

          // ── Metrics row ──────────────────────────────────────────────
          Row(
            children: [
              _MetricChip(label: 'Mismatch', value: alert.semanticMismatch.toStringAsFixed(2)),
              const SizedBox(width: space2),
              _MetricChip(label: 'Velocity', value: alert.velocity),
              if (alert.requiresQuorum) ...[
                const Spacer(),
                Text(
                  '${alert.quorum!.currentApprovals}/${alert.quorum!.requiredVotes}',
                  style: technicalStyle(fontSize: 12, color: cicadaWarning),
                ),
              ],
            ],
          ),

          const SizedBox(height: space3),

          // ── Review button ────────────────────────────────────────────
          SizedBox(
            width: double.infinity,
            child: CicadaButton(
              label: 'Review Now',
              icon: Icons.arrow_forward,
              onPressed: onReview,
            ),
          ),
        ],
      ),
    );
  }
}

class _MetricChip extends StatelessWidget {
  final String label;
  final String value;

  const _MetricChip({required this.label, required this.value});

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: space2, vertical: space1),
      decoration: BoxDecoration(
        color: cicadaSurfaceVariant.withValues(alpha: 0.5),
        borderRadius: BorderRadius.circular(radiusSm),
      ),
      child: Text(
        '$label: $value',
        style: technicalStyle(fontSize: 11),
      ),
    );
  }
}
