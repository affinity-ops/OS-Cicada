// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import 'dart:io' show Platform;
import 'package:flutter/material.dart';
import '../../config/theme.dart';
import '../../widgets/cicada_card.dart';
import '../../core/alerts/notification_settings_service.dart';

/// Notification & Alert Settings screen.
///
/// This screen directly addresses the operational reliability gap identified
/// in the Cicada Aegis architecture: the CIBA timeout is 120 seconds.
/// If the operator's phone is face-down, on silent, display off — the
/// notification gets missed and the HITL request fails closed.
///
/// These settings give the operator control over:
///   - Screen wake behaviour (break through sleep state on alert)
///   - Alert sound selection (emergency siren vs softer tones)
///   - Volume override (force volume up for critical alerts)
///   - Vibration pattern (urgent vs standard)
///   - Smartwatch forwarding (automatically enabled via OS notifications)
class NotificationSettingsScreen extends StatefulWidget {
  const NotificationSettingsScreen({Key? key}) : super(key: key);

  @override
  State<NotificationSettingsScreen> createState() =>
      _NotificationSettingsScreenState();
}

class _NotificationSettingsScreenState
    extends State<NotificationSettingsScreen> {
  /// The current settings snapshot, loaded from SharedPreferences on init.
  NotificationSettings? _settings;
  bool _loading = true;

  @override
  void initState() {
    super.initState();
    _loadSettings();
  }

  Future<void> _loadSettings() async {
    final settings = await NotificationSettingsService.load();
    if (mounted) {
      setState(() {
        _settings = settings;
        _loading = false;
      });
    }
  }

  // ── Helper: update a single setting and refresh the snapshot ────────────────
  Future<void> _update(Future<void> Function() persist) async {
    await persist();
    await _loadSettings();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: cicadaBackground,
      appBar: AppBar(
        backgroundColor: cicadaBackground,
        leading: IconButton(
          icon: const Icon(Icons.arrow_back),
          onPressed: () => Navigator.pop(context),
        ),
        title: Text('Alert Settings', style: headlineStyle(fontSize: 18)),
        actions: [
          // Reset to defaults button
          IconButton(
            icon: const Icon(Icons.restart_alt, color: cicadaOnSurfaceMuted),
            tooltip: 'Reset to Defaults',
            onPressed: () => _confirmReset(context),
          ),
          const SizedBox(width: space1),
        ],
      ),
      body: _loading || _settings == null
          ? const Center(
              child: CircularProgressIndicator(color: cicadaPrimary))
          : SingleChildScrollView(
              padding: const EdgeInsets.all(space4),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  // ── Warning banner ────────────────────────────────────────
                  Container(
                    padding: const EdgeInsets.all(space3),
                    decoration: BoxDecoration(
                      color: cicadaWarning.withValues(alpha: 0.08),
                      borderRadius: BorderRadius.circular(radiusMd),
                      border: Border.all(
                          color: cicadaWarning.withValues(alpha: 0.2)),
                    ),
                    child: Row(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        const Icon(Icons.timer_outlined,
                            color: cicadaWarning, size: 20),
                        const SizedBox(width: space2),
                        Expanded(
                          child: Text(
                            'CIBA timeout is 120 seconds. These settings ensure '
                            'you never miss a critical HITL decision.',
                            style: TextStyle(
                                color: cicadaWarning,
                                fontSize: 12,
                                height: 1.4),
                          ),
                        ),
                      ],
                    ),
                  ),
                  const SizedBox(height: space4),

                  // ── Section: Sleep & Wake ─────────────────────────────────
                  _sectionHeader('SLEEP & WAKE', Icons.screen_lock_portrait),
                  const SizedBox(height: space2),
                  CicadaCard(
                    child: Column(
                      children: [
                        _toggleRow(
                          icon: Icons.phonelink_ring,
                          title: 'Wake Screen on Alert',
                          subtitle: Platform.isIOS
                              ? 'iOS: Requires Critical Alert entitlement from Apple'
                              : 'Turns the screen on when a HITL alert arrives',
                          value: _settings!.wakeScreenOnAlert,
                          onChanged: (v) => _update(
                              () => NotificationSettingsService.setWakeScreen(v)),
                        ),
                        const Divider(color: cicadaBorder),
                        _toggleRow(
                          icon: Icons.lock_open,
                          title: 'Keep Awake During Alert',
                          subtitle:
                              'Prevents the phone from sleeping while a decision is pending',
                          value: _settings!.keepAwakeDuringAlert,
                          onChanged: (v) => _update(
                              () => NotificationSettingsService.setKeepAwake(v)),
                        ),
                      ],
                    ),
                  ),
                  const SizedBox(height: space4),

                  // ── Section: Alert Sound ──────────────────────────────────
                  _sectionHeader('ALERT SOUND', Icons.volume_up),
                  const SizedBox(height: space2),
                  CicadaCard(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          'SOUND',
                          style: technicalStyle(fontSize: 10)
                              .copyWith(letterSpacing: 1.5),
                        ),
                        const SizedBox(height: space2),
                        ...NotificationSettingsService.availableSounds
                            .map((sound) => _soundRadio(sound)),
                        const SizedBox(height: space3),
                        const Divider(color: cicadaBorder),
                        const SizedBox(height: space3),
                        Text(
                          'VIBRATION PATTERN',
                          style: technicalStyle(fontSize: 10)
                              .copyWith(letterSpacing: 1.5),
                        ),
                        const SizedBox(height: space2),
                        ...NotificationSettingsService
                            .availableVibrationPatterns
                            .map((pattern) => _vibrationRadio(pattern)),
                      ],
                    ),
                  ),
                  const SizedBox(height: space4),

                  // ── Section: Volume Control ───────────────────────────────
                  _sectionHeader('VOLUME CONTROL', Icons.tune),
                  const SizedBox(height: space2),
                  CicadaCard(
                    child: Column(
                      children: [
                        _toggleRow(
                          icon: Icons.volume_up,
                          title: 'Override Device Volume',
                          subtitle: Platform.isIOS
                              ? 'iOS does not allow apps to control device volume'
                              : 'Force notification volume when a HITL alert fires',
                          value: _settings!.overrideVolume,
                          onChanged: Platform.isIOS
                              ? null // Disabled on iOS — system restriction
                              : (v) => _update(() =>
                                  NotificationSettingsService.setOverrideVolume(
                                      v)),
                        ),
                        // Only show the slider if override is enabled and not iOS
                        if (_settings!.overrideVolume && !Platform.isIOS) ...[
                          const SizedBox(height: space2),
                          Padding(
                            padding:
                                const EdgeInsets.symmetric(horizontal: space2),
                            child: Row(
                              children: [
                                const Icon(Icons.volume_mute,
                                    color: cicadaOnSurfaceMuted, size: 16),
                                Expanded(
                                  child: SliderTheme(
                                    data: SliderThemeData(
                                      activeTrackColor: cicadaPrimary,
                                      inactiveTrackColor:
                                          cicadaPrimary.withValues(alpha: 0.2),
                                      thumbColor: cicadaPrimary,
                                      overlayColor:
                                          cicadaPrimary.withValues(alpha: 0.1),
                                    ),
                                    child: Slider(
                                      value: _settings!.volumeLevel,
                                      min: 0.1,
                                      max: 1.0,
                                      divisions: 9,
                                      label:
                                          '${(_settings!.volumeLevel * 100).round()}%',
                                      onChanged: (v) => _update(() =>
                                          NotificationSettingsService
                                              .setVolumeLevel(v)),
                                    ),
                                  ),
                                ),
                                const Icon(Icons.volume_up,
                                    color: cicadaPrimary, size: 16),
                                const SizedBox(width: space1),
                                Text(
                                  '${(_settings!.volumeLevel * 100).round()}%',
                                  style: technicalStyle(
                                      fontSize: 12, color: cicadaPrimary),
                                ),
                              ],
                            ),
                          ),
                        ],
                        const Divider(color: cicadaBorder),
                        _toggleRow(
                          icon: Icons.priority_high,
                          title: 'Force Maximum for Critical',
                          subtitle:
                              'Always play at maximum volume regardless of slider',
                          value: _settings!.forceMaxCritical,
                          onChanged: Platform.isIOS
                              ? null
                              : (v) => _update(() =>
                                  NotificationSettingsService
                                      .setForceMaxCritical(v)),
                        ),
                      ],
                    ),
                  ),
                  const SizedBox(height: space4),

                  // ── Section: Smartwatch ───────────────────────────────────
                  _sectionHeader('SMARTWATCH', Icons.watch),
                  const SizedBox(height: space2),
                  CicadaCard(
                    child: Column(
                      children: [
                        _toggleRow(
                          icon: Icons.watch,
                          title: 'Smartwatch Forwarding',
                          subtitle:
                              'Alerts are automatically forwarded to your '
                              'connected Apple Watch or Wear OS device',
                          value: _settings!.smartwatchForwarding,
                          onChanged: (v) => _update(
                              () => NotificationSettingsService.setSmartwatch(v)),
                        ),
                        const SizedBox(height: space2),
                        // Info callout — the watch mirroring is handled by the OS
                        Container(
                          padding: const EdgeInsets.all(space3),
                          decoration: BoxDecoration(
                            color: cicadaInfo.withValues(alpha: 0.06),
                            borderRadius: BorderRadius.circular(radiusSm),
                            border: Border.all(
                                color: cicadaInfo.withValues(alpha: 0.15)),
                          ),
                          child: Row(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Icon(Icons.info_outline,
                                  color: cicadaInfo.withValues(alpha: 0.7),
                                  size: 16),
                              const SizedBox(width: space2),
                              Expanded(
                                child: Text(
                                  'When enabled, high-priority notifications are '
                                  'mirrored to your connected wearable via the '
                                  'operating system. No additional pairing needed — '
                                  'if your watch is on your wrist, you\'ll feel '
                                  'the haptic alert.',
                                  style: TextStyle(
                                      color: cicadaInfo.withValues(alpha: 0.7),
                                      fontSize: 11,
                                      height: 1.4),
                                ),
                              ),
                            ],
                          ),
                        ),
                      ],
                    ),
                  ),
                  const SizedBox(height: space5),

                  // ── Platform note ─────────────────────────────────────────
                  if (Platform.isIOS)
                    Container(
                      padding: const EdgeInsets.all(space3),
                      decoration: BoxDecoration(
                        color: cicadaOnSurfaceMuted.withValues(alpha: 0.06),
                        borderRadius: BorderRadius.circular(radiusMd),
                        border: Border.all(
                            color:
                                cicadaOnSurfaceMuted.withValues(alpha: 0.1)),
                      ),
                      child: Row(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Icon(Icons.apple,
                              color: cicadaOnSurfaceMuted, size: 18),
                          const SizedBox(width: space2),
                          Expanded(
                            child: Text(
                              'Some features are limited on iOS. Apple does not '
                              'allow apps to control device volume or wake the '
                              'screen programmatically. Critical Alert entitlement '
                              '(approved by Apple) is required for full override.',
                              style: TextStyle(
                                  color: cicadaOnSurfaceMuted,
                                  fontSize: 11,
                                  height: 1.4),
                            ),
                          ),
                        ],
                      ),
                    ),

                  const SizedBox(height: space6),
                ],
              ),
            ),
    );
  }

  // ── Section header widget ──────────────────────────────────────────────────
  Widget _sectionHeader(String label, IconData icon) {
    return Row(
      children: [
        Icon(icon, color: cicadaPrimary, size: 16),
        const SizedBox(width: space2),
        Text(
          label,
          style: technicalStyle(fontSize: 10).copyWith(
            letterSpacing: 1.5,
            color: cicadaPrimary,
          ),
        ),
      ],
    );
  }

  // ── Toggle row widget ──────────────────────────────────────────────────────
  Widget _toggleRow({
    required IconData icon,
    required String title,
    required String subtitle,
    required bool value,
    required void Function(bool)? onChanged,
  }) {
    final isDisabled = onChanged == null;
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: space1),
      child: Row(
        children: [
          Icon(icon,
              color: isDisabled
                  ? cicadaOnSurfaceMuted.withValues(alpha: 0.3)
                  : cicadaOnSurfaceMuted,
              size: 20),
          const SizedBox(width: space3),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  title,
                  style: TextStyle(
                    color: isDisabled
                        ? cicadaOnSurfaceMuted.withValues(alpha: 0.5)
                        : cicadaOnSurface,
                    fontSize: 14,
                    fontWeight: FontWeight.w600,
                  ),
                ),
                const SizedBox(height: 2),
                Text(
                  subtitle,
                  style: TextStyle(
                    color: cicadaOnSurfaceMuted.withValues(
                        alpha: isDisabled ? 0.3 : 0.7),
                    fontSize: 11,
                    height: 1.3,
                  ),
                ),
              ],
            ),
          ),
          Switch(
            value: value,
            onChanged: onChanged,
            activeColor: cicadaPrimary,
            inactiveTrackColor: cicadaSurfaceVariant,
          ),
        ],
      ),
    );
  }

  // ── Sound radio tile ───────────────────────────────────────────────────────
  Widget _soundRadio(String sound) {
    final isSelected = _settings!.alertSound == sound;
    // Human-readable labels and icons for each sound option
    final labels = {
      'siren': ('Emergency Siren', Icons.crisis_alert, 'Looping alarm — maximum urgency'),
      'klaxon': ('Klaxon Horn', Icons.campaign, 'Short, sharp alarm burst'),
      'pulse': ('Rhythmic Pulse', Icons.graphic_eq, 'Pulsing alert tone'),
      'chime': ('Soft Chime', Icons.notifications_none, 'Gentler tone for quiet environments'),
      'silent': ('Silent', Icons.notifications_off, 'Vibration only — no sound'),
    };
    final (label, iconData, desc) = labels[sound] ?? (sound, Icons.music_note, '');

    return InkWell(
      onTap: () =>
          _update(() => NotificationSettingsService.setAlertSound(sound)),
      borderRadius: BorderRadius.circular(radiusSm),
      child: Padding(
        padding: const EdgeInsets.symmetric(vertical: 6),
        child: Row(
          children: [
            Icon(
              isSelected ? Icons.radio_button_checked : Icons.radio_button_off,
              color: isSelected ? cicadaPrimary : cicadaOnSurfaceMuted,
              size: 18,
            ),
            const SizedBox(width: space3),
            Icon(iconData,
                color: isSelected ? cicadaPrimary : cicadaOnSurfaceMuted,
                size: 18),
            const SizedBox(width: space2),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    label,
                    style: TextStyle(
                      color: isSelected ? cicadaOnSurface : cicadaOnSurfaceMuted,
                      fontSize: 13,
                      fontWeight: isSelected ? FontWeight.w600 : FontWeight.w400,
                    ),
                  ),
                  Text(desc,
                      style: TextStyle(
                          color: cicadaOnSurfaceMuted.withValues(alpha: 0.6),
                          fontSize: 10)),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  // ── Vibration radio tile ───────────────────────────────────────────────────
  Widget _vibrationRadio(String pattern) {
    final isSelected = _settings!.vibrationPattern == pattern;
    final labels = {
      'urgent': ('Urgent', 'Short, rapid bursts'),
      'standard': ('Standard', 'Default system pattern'),
      'persistent': ('Persistent', 'Long continuous vibration'),
      'none': ('None', 'No vibration'),
    };
    final (label, desc) = labels[pattern] ?? (pattern, '');

    return InkWell(
      onTap: () => _update(
          () => NotificationSettingsService.setVibrationPattern(pattern)),
      borderRadius: BorderRadius.circular(radiusSm),
      child: Padding(
        padding: const EdgeInsets.symmetric(vertical: 6),
        child: Row(
          children: [
            Icon(
              isSelected ? Icons.radio_button_checked : Icons.radio_button_off,
              color: isSelected ? cicadaPrimary : cicadaOnSurfaceMuted,
              size: 18,
            ),
            const SizedBox(width: space3),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    label,
                    style: TextStyle(
                      color: isSelected ? cicadaOnSurface : cicadaOnSurfaceMuted,
                      fontSize: 13,
                      fontWeight: isSelected ? FontWeight.w600 : FontWeight.w400,
                    ),
                  ),
                  Text(desc,
                      style: TextStyle(
                          color: cicadaOnSurfaceMuted.withValues(alpha: 0.6),
                          fontSize: 10)),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  // ── Reset confirmation dialog ──────────────────────────────────────────────
  Future<void> _confirmReset(BuildContext context) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: cicadaSurface,
        title: Text('Reset Alert Settings?',
            style: headlineStyle(fontSize: 18)),
        content: Text(
          'This will restore all notification settings to their defaults. '
          'Wake screen will be enabled, sound will be set to emergency siren, '
          'and volume override will be turned off.',
          style:
              TextStyle(color: cicadaOnSurfaceMuted, fontSize: 14, height: 1.5),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: const Text('Cancel',
                style: TextStyle(color: cicadaOnSurfaceMuted)),
          ),
          TextButton(
            onPressed: () => Navigator.pop(ctx, true),
            child:
                const Text('Reset', style: TextStyle(color: cicadaPrimary)),
          ),
        ],
      ),
    );
    if (confirmed != true || !mounted) return;
    await NotificationSettingsService.resetToDefaults();
    await _loadSettings();
  }
}
