// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:flutter_local_notifications/flutter_local_notifications.dart';
import '../../config/theme.dart';
import '../../core/alerts/alarm_service.dart';
import '../../widgets/cicada_button.dart';
import '../../widgets/cicada_card.dart';
import '../../widgets/cicada_timer.dart';
import 'bloc/decision_bloc.dart';
import '../alerts/bloc/alert_bloc.dart';
import '../alerts/models/alert_model.dart';

/// Phase 4, Screen 3: Decision Screen — full HITL review and approve/reject.
class DecisionScreen extends StatelessWidget {
  final HitlAlert alert;
  const DecisionScreen({Key? key, required this.alert}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return BlocConsumer<DecisionBloc, DecisionState>(
      listener: (context, state) {
        if (state is DecisionResolved) {
          try {
            context.read<AlertBloc>().removeAlert(state.holdRef);
          } catch (_) {}
          final color = state.outcome == 'APPROVE' ? cicadaSuccess : cicadaDanger;
          final label = state.outcome == 'APPROVE' ? 'Approved' : 'Rejected';
          ScaffoldMessenger.of(context).showSnackBar(SnackBar(
            content: Row(children: [
              Icon(Icons.check_circle, color: color, size: 18),
              const SizedBox(width: 8),
              Expanded(child: Text('Action $label', style: headlineStyle(fontSize: 14))),
            ]),
            backgroundColor: cicadaSurface,
          ));
          if (Navigator.canPop(context)) {
            Navigator.pop(context);
          }
        } else if (state is DecisionError) {
          // ALWAYS stop the siren on error — user must not be stuck with alarm
          _silenceEverything(context);
          ScaffoldMessenger.of(context).showSnackBar(SnackBar(
            content: Row(children: [
              const Icon(Icons.error, color: Colors.red, size: 18),
              const SizedBox(width: 8),
              Expanded(child: Text(state.message, style: headlineStyle(fontSize: 14))),
            ]),
            backgroundColor: cicadaSurface,
            duration: const Duration(seconds: 5),
          ));
        }
      },
      builder: (context, state) {
        final isProcessing = state is DecisionProcessing || state is DecisionBiometricGate;
        return Scaffold(
          backgroundColor: cicadaBackground,
          appBar: AppBar(
            backgroundColor: cicadaBackground,
            leading: IconButton(icon: const Icon(Icons.arrow_back), onPressed: () {
              _silenceEverything(context);
              Navigator.pop(context);
            }),
            title: Row(children: [
              Icon(Icons.error, color: cicadaDanger, size: 20),
              const SizedBox(width: 8),
              Text('HITL HOLD', style: headlineStyle(fontSize: 18, color: cicadaDanger)),
            ]),
            actions: [CicadaTimer(expiresAt: alert.expiresAt), const SizedBox(width: space3)],
          ),
          body: SingleChildScrollView(
            padding: const EdgeInsets.all(space4),
            child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
              // ── Agent Identity ──────────────────────────────────
              _AgentSection(alert: alert),
              const SizedBox(height: space3),
              // ── Attempted Action ───────────────────────────────
              _ActionSection(alert: alert),
              const SizedBox(height: space3),
              // ── Declared Tools ─────────────────────────────────
              if (alert.declaredTools.isNotEmpty) ...[
                _ToolsSection(tools: alert.declaredTools),
                const SizedBox(height: space3),
              ],
              // ── Risk Metrics ───────────────────────────────────
              _MetricsSection(alert: alert),
              const SizedBox(height: space3),
              // ── Quorum Status ──────────────────────────────────
              if (alert.requiresQuorum) ...[
                _QuorumSection(quorum: alert.quorum!),
                const SizedBox(height: space3),
              ],
              // ── Processing indicator ───────────────────────────
              if (isProcessing) ...[
                Center(child: Column(children: [
                  const CircularProgressIndicator(color: cicadaPrimary),
                  const SizedBox(height: space2),
                  Text(state is DecisionProcessing ? state.message : 'Authenticate with biometrics...',
                    style: technicalStyle(fontSize: 12)),
                ])),
                const SizedBox(height: space3),
              ],
              // ── Decision Buttons ───────────────────────────────
              if (!isProcessing) ...[
                Row(children: [
                  Expanded(child: CicadaButton(
                    label: 'REJECT', variant: CicadaButtonVariant.danger, icon: Icons.close,
                    onPressed: () => context.read<DecisionBloc>().rejectAction(alert),
                  )),
                  const SizedBox(width: space3),
                  Expanded(child: CicadaButton(
                    label: 'APPROVE', icon: Icons.check,
                    onPressed: () => context.read<DecisionBloc>().approveAction(alert),
                  )),
                ]),
                const SizedBox(height: space3),
                // ── Silence button — always available ─────────────
                SizedBox(
                  width: double.infinity,
                  child: TextButton.icon(
                    onPressed: () {
                      _silenceEverything(context);
                      ScaffoldMessenger.of(context).showSnackBar(SnackBar(
                        content: Row(children: [
                          const Icon(Icons.volume_off, color: Colors.white, size: 18),
                          const SizedBox(width: 8),
                          Text('Alarm silenced', style: headlineStyle(fontSize: 14)),
                        ]),
                        backgroundColor: cicadaSurface,
                        duration: const Duration(seconds: 2),
                      ));
                    },
                    icon: const Icon(Icons.volume_off, color: cicadaOnSurfaceMuted),
                    label: Text('SILENCE ALARM', style: technicalStyle(fontSize: 12, color: cicadaOnSurfaceMuted)),
                    style: TextButton.styleFrom(
                      padding: const EdgeInsets.symmetric(vertical: 14),
                      shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(8),
                        side: BorderSide(color: cicadaOnSurfaceMuted.withValues(alpha: 0.3)),
                      ),
                    ),
                  ),
                ),
              ],
              const SizedBox(height: space5),
            ]),
          ),
        );
      },
    );
  }

  /// Silences ALL alarm sources:
  ///   1. Flutter SoLoud siren (singleton AlarmService)
  ///   2. Native Kotlin MediaPlayer (via MethodChannel)
  ///   3. Android persistent notification
  static void _silenceEverything(BuildContext context) {
    // 1. Stop the Flutter-side SoLoud siren (singleton — same instance everywhere)
    try {
      AlarmService().stopSiren();
    } catch (_) {}

    // 2. Stop the native Kotlin MediaPlayer alarm
    try {
      const MethodChannel('com.cicada.aegis/security')
          .invokeMethod('stopNativeAlarm');
    } catch (_) {}

    // 3. Cancel the persistent Android notification
    try {
      FlutterLocalNotificationsPlugin().cancelAll();
    } catch (_) {}
  }
}

class _AgentSection extends StatelessWidget {
  final HitlAlert alert;
  const _AgentSection({required this.alert});

  @override
  Widget build(BuildContext context) {
    return CicadaCard(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
      Text('Agent: ${alert.agentName}', style: headlineStyle(fontSize: 16)),
      const SizedBox(height: space1),
      Text('Tenant: ${alert.tenantName}', style: TextStyle(color: cicadaOnSurfaceMuted, fontSize: 13)),
      if (alert.agentRole != null) ...[
        const SizedBox(height: space1),
        Text('Role: ${alert.agentRole}${alert.parentAgent != null ? ' (Orchestrator: ${alert.parentAgent})' : ''}',
          style: TextStyle(color: cicadaOnSurfaceMuted, fontSize: 13)),
      ],
    ]));
  }
}

class _ActionSection extends StatelessWidget {
  final HitlAlert alert;
  const _ActionSection({required this.alert});

  @override
  Widget build(BuildContext context) {
    return CicadaCard(
      backgroundColor: cicadaError.withValues(alpha: 0.05),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Text('ATTEMPTED ACTION', style: technicalStyle(fontSize: 10).copyWith(letterSpacing: 1.5, color: cicadaOnSurfaceMuted)),
        const SizedBox(height: space2),
        Text(alert.actionDetail, style: technicalStyle(fontSize: 14, color: cicadaOnSurface)),
        if (alert.actionTarget.isNotEmpty) ...[
          const SizedBox(height: space1),
          Text('Target: ${alert.actionTarget}', style: technicalStyle(fontSize: 12, color: cicadaOnSurfaceMuted)),
        ],
      ]),
    );
  }
}

class _ToolsSection extends StatelessWidget {
  final List<DeclaredTool> tools;
  const _ToolsSection({required this.tools});

  @override
  Widget build(BuildContext context) {
    return CicadaCard(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
      Text('DECLARED TOOLS', style: technicalStyle(fontSize: 10).copyWith(letterSpacing: 1.5, color: cicadaOnSurfaceMuted)),
      const SizedBox(height: space2),
      ...tools.map((tool) => Padding(
        padding: const EdgeInsets.only(bottom: space1),
        child: Row(children: [
          Icon(tool.isDeclared ? Icons.check_circle : Icons.cancel, size: 16,
            color: tool.isDeclared ? cicadaSuccess : cicadaDanger),
          const SizedBox(width: space2),
          Text(tool.name, style: technicalStyle(fontSize: 13, color: cicadaOnSurface)),
          if (!tool.isDeclared) ...[
            const SizedBox(width: space2),
            Text('NOT DECLARED', style: technicalStyle(fontSize: 10, color: cicadaDanger)),
          ],
        ]),
      )),
    ]));
  }
}

class _MetricsSection extends StatelessWidget {
  final HitlAlert alert;
  const _MetricsSection({required this.alert});

  @override
  Widget build(BuildContext context) {
    return CicadaCard(child: Column(children: [
      _MetricRow('Semantic Mismatch', alert.semanticMismatch.toStringAsFixed(2),
        alert.semanticMismatch > 0.8 ? cicadaDanger : cicadaOnSurface),
      _MetricRow('Velocity', alert.velocity,
        alert.velocity == 'HIGH' ? cicadaDanger : cicadaOnSurface),
      _MetricRow('Trust Score', '${alert.trustScore.toStringAsFixed(2)}${alert.isBelowTrustThreshold ? ' (BELOW THRESHOLD)' : ''}',
        alert.isBelowTrustThreshold ? cicadaDanger : cicadaSuccess),
    ]));
  }
}

class _MetricRow extends StatelessWidget {
  final String label;
  final String value;
  final Color valueColor;
  const _MetricRow(this.label, this.value, this.valueColor);

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: space1),
      child: Row(mainAxisAlignment: MainAxisAlignment.spaceBetween, children: [
        Text(label, style: TextStyle(color: cicadaOnSurfaceMuted, fontSize: 13)),
        Text(value, style: technicalStyle(fontSize: 13, color: valueColor)),
      ]),
    );
  }
}

class _QuorumSection extends StatelessWidget {
  final QuorumStatus quorum;
  const _QuorumSection({required this.quorum});

  @override
  Widget build(BuildContext context) {
    return CicadaCard(
      backgroundColor: cicadaWarning.withValues(alpha: 0.05),
      child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Icon(Icons.groups_outlined, color: cicadaWarning, size: 20),
        const SizedBox(width: space3),
        Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text('Multi-Approval Required', style: headlineStyle(fontSize: 14, color: cicadaWarning)),
          const SizedBox(height: space1),
          Text('${quorum.currentApprovals} of ${quorum.requiredVotes} approvals (${quorum.pendingVotes} pending)',
            style: TextStyle(color: cicadaOnSurfaceMuted, fontSize: 13)),
        ])),
      ]),
    );
  }
}