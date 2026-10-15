// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import 'dart:async';
import 'package:flutter/material.dart';
import '../config/theme.dart';

/// Countdown timer widget for HITL hold auto-deny deadlines.
///
/// Displays time remaining until the hold auto-denies. Changes color
/// from primary → warning → danger as time decreases.
class CicadaTimer extends StatefulWidget {
  final DateTime expiresAt;
  final VoidCallback? onExpired;

  const CicadaTimer({Key? key, required this.expiresAt, this.onExpired}) : super(key: key);

  @override
  State<CicadaTimer> createState() => _CicadaTimerState();
}

class _CicadaTimerState extends State<CicadaTimer> {
  late Timer _timer;
  Duration _remaining = Duration.zero;

  @override
  void initState() {
    super.initState();
    _updateRemaining();
    _timer = Timer.periodic(const Duration(seconds: 1), (_) => _updateRemaining());
  }

  void _updateRemaining() {
    final now = DateTime.now().toUtc();
    final remaining = widget.expiresAt.difference(now);
    if (remaining.isNegative) {
      setState(() => _remaining = Duration.zero);
      _timer.cancel();
      widget.onExpired?.call();
    } else {
      setState(() => _remaining = remaining);
    }
  }

  @override
  void dispose() {
    _timer.cancel();
    super.dispose();
  }

  Color get _timerColor {
    if (_remaining.inSeconds <= 30) return cicadaDanger;
    if (_remaining.inSeconds <= 120) return cicadaWarning;
    return cicadaPrimary;
  }

  String get _formatted {
    final m = _remaining.inMinutes;
    final s = _remaining.inSeconds % 60;
    return '${m.toString().padLeft(2, '0')}:${s.toString().padLeft(2, '0')}';
  }

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: space3, vertical: space2),
      decoration: BoxDecoration(
        color: _timerColor.withValues(alpha: 0.15),
        borderRadius: BorderRadius.circular(radiusMd),
        border: Border.all(color: _timerColor.withValues(alpha: 0.3)),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(Icons.timer_outlined, size: 16, color: _timerColor),
          const SizedBox(width: 6),
          Text(
            _formatted,
            style: technicalStyle(fontSize: 16, color: _timerColor),
          ),
        ],
      ),
    );
  }
}
