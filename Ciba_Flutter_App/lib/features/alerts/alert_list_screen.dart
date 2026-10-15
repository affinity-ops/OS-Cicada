// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import 'package:flutter/material.dart';
import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:local_auth/local_auth.dart';
import '../../config/theme.dart';
import '../../widgets/cicada_badge.dart';
import '../../widgets/cicada_skeleton.dart';
import 'bloc/alert_bloc.dart';
import 'alert_card.dart';
import '../decision/decision_screen.dart';
import '../settings/device_info_screen.dart';
import '../settings/notification_settings_screen.dart';
import '../splash/splash_screen.dart';

class AlertListScreen extends StatefulWidget {
  const AlertListScreen({Key? key}) : super(key: key);

  @override
  State<AlertListScreen> createState() => _AlertListScreenState();
}

class _AlertListScreenState extends State<AlertListScreen>
    with WidgetsBindingObserver {
  bool _wasBackgrounded = false;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    context.read<AlertBloc>().startListening();
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.paused) {
      _wasBackgrounded = true;
    } else if (state == AppLifecycleState.resumed && _wasBackgrounded) {
      _wasBackgrounded = false;
      _requireBiometric();
    }
  }

  Future<void> _requireBiometric() async {
    try {
      final auth = LocalAuthentication();
      final canAuth = await auth.canCheckBiometrics || await auth.isDeviceSupported();
      if (!canAuth) return;
      final ok = await auth.authenticate(
        localizedReason: 'Authenticate to access Cicada Aegis',
        options: const AuthenticationOptions(biometricOnly: true, stickyAuth: true),
      );
      if (!ok && mounted) {
        Navigator.of(context).pushAndRemoveUntil(
          MaterialPageRoute(builder: (_) => const SplashScreen()),
          (_) => false,
        );
      }
    } catch (_) {
      if (mounted) {
        Navigator.of(context).pushAndRemoveUntil(
          MaterialPageRoute(builder: (_) => const SplashScreen()),
          (_) => false,
        );
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: cicadaBackground,
      appBar: AppBar(
        backgroundColor: cicadaBackground,
        title: Text('Aegis Alerts', style: headlineStyle(fontSize: 20, weight: FontWeight.w900)),
        automaticallyImplyLeading: false,
        actions: [
          const CicadaBadge(status: CicadaStatus.secure),
          const SizedBox(width: space2),
          // Notification settings button
          IconButton(
            icon: const Icon(Icons.notifications_outlined, color: cicadaOnSurfaceMuted),
            tooltip: 'Alert Settings',
            onPressed: () => Navigator.push(context,
                MaterialPageRoute(builder: (_) => const NotificationSettingsScreen())),
          ),
          // Device info / security settings button
          IconButton(
            icon: const Icon(Icons.settings_outlined, color: cicadaOnSurfaceMuted),
            tooltip: 'Device Info',
            onPressed: () => Navigator.push(context,
                MaterialPageRoute(builder: (_) => const DeviceInfoScreen())),
          ),
          const SizedBox(width: space1),
        ],
      ),
      body: BlocBuilder<AlertBloc, AlertState>(
        builder: (context, state) {
          if (state is AlertLoading) return _loading();
          if (state is AlertError) return _error(state.message);
          if (state is AlertEmpty) return _empty();
          if (state is AlertLoaded) return _list(state.alerts);
          return const SizedBox.shrink();
        },
      ),
    );
  }

  Widget _loading() => Padding(
    padding: const EdgeInsets.all(space4),
    child: Column(children: List.generate(3, (_) => CicadaSkeleton.card())),
  );

  Widget _error(String msg) => Center(
    child: Padding(
      padding: const EdgeInsets.all(space4),
      child: Column(mainAxisAlignment: MainAxisAlignment.center, children: [
        Icon(Icons.error_outline, size: 48, color: cicadaError.withValues(alpha: 0.6)),
        const SizedBox(height: space4),
        Text(msg, style: headlineStyle(fontSize: 16), textAlign: TextAlign.center),
        const SizedBox(height: space4),
        ElevatedButton.icon(
          onPressed: () => context.read<AlertBloc>().startListening(),
          icon: const Icon(Icons.refresh),
          label: const Text('Retry'),
          style: ElevatedButton.styleFrom(backgroundColor: cicadaPrimary, foregroundColor: Colors.black),
        ),
      ]),
    ),
  );

  Widget _empty() => Center(
    child: Column(mainAxisAlignment: MainAxisAlignment.center, children: [
      Container(
        width: 80, height: 80,
        decoration: BoxDecoration(color: cicadaSuccess.withValues(alpha: 0.1), shape: BoxShape.circle),
        child: Icon(Icons.shield_outlined, size: 40, color: cicadaSuccess.withValues(alpha: 0.6)),
      ),
      const SizedBox(height: space4),
      Text('System Secure', style: headlineStyle(fontSize: 20)),
      const SizedBox(height: space2),
      Text('No active HITL holds.\nAll agents operating within policy.',
        style: TextStyle(color: cicadaOnSurfaceMuted, fontSize: 14, height: 1.5), textAlign: TextAlign.center),
    ]),
  );

  Widget _list(List alerts) => ListView(
    padding: const EdgeInsets.all(space4),
    children: [
      Container(
        padding: const EdgeInsets.all(space3),
        margin: const EdgeInsets.only(bottom: space4),
        decoration: BoxDecoration(
          color: cicadaDanger.withValues(alpha: 0.08),
          borderRadius: BorderRadius.circular(radiusMd),
          border: Border.all(color: cicadaDanger.withValues(alpha: 0.2)),
        ),
        child: Row(children: [
          Icon(Icons.warning_amber_rounded, color: cicadaDanger, size: 20),
          const SizedBox(width: space2),
          Text('${alerts.length} pending HITL decision${alerts.length > 1 ? 's' : ''}',
            style: headlineStyle(fontSize: 14, color: cicadaDanger)),
        ]),
      ),
      ...alerts.map((alert) => Padding(
        padding: const EdgeInsets.only(bottom: space3),
        child: AlertCard(alert: alert, onReview: () => Navigator.push(
          context, MaterialPageRoute(builder: (_) => DecisionScreen(alert: alert)))),
      )),
    ],
  );
}
