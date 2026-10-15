// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import 'package:shared_preferences/shared_preferences.dart';

/// Persistent notification settings for the Aegis companion app.
///
/// These settings directly impact the reliability of the 120-second CIBA
/// timeout window. A missed notification means a missed HITL decision,
/// which fails the request closed and undermines the entire governance model.
///
/// All values are stored locally via SharedPreferences. No sensitive data
/// is persisted here — these are purely UX/operational preferences.
class NotificationSettingsService {
  NotificationSettingsService._();

  // ── SharedPreferences keys ─────────────────────────────────────────────────
  static const String _keyWakeScreen = 'aegis_wake_screen_on_alert';
  static const String _keyKeepAwake = 'aegis_keep_awake_during_alert';
  static const String _keyOverrideVolume = 'aegis_override_volume';
  static const String _keyVolumeLevel = 'aegis_volume_level';
  static const String _keyForceMaxCritical = 'aegis_force_max_critical';
  static const String _keyAlertSound = 'aegis_alert_sound';
  static const String _keySmartwatch = 'aegis_smartwatch_forwarding';
  static const String _keyVibrationPattern = 'aegis_vibration_pattern';

  // ── Available alert sounds ─────────────────────────────────────────────────
  // These map to audio files in assets/audio/ and raw resource names
  // used by the Android notification channel.
  static const List<String> availableSounds = [
    'siren',      // Default: looping emergency siren
    'klaxon',     // Short, sharp alarm horn
    'pulse',      // Rhythmic pulse tone
    'chime',      // Softer chime (for non-critical environments)
    'silent',     // No sound — vibration only
  ];

  // ── Available vibration patterns ───────────────────────────────────────────
  static const List<String> availableVibrationPatterns = [
    'urgent',     // Short, rapid bursts
    'standard',   // Default Android pattern
    'persistent', // Long continuous vibration
    'none',       // No vibration
  ];

  // ── Defaults ───────────────────────────────────────────────────────────────
  // Conservative defaults: wake screen ON, volume override OFF (respect user).
  // These are chosen so the app works out of the box but doesn't
  // surprise the operator with unexpected volume changes.
  static const bool defaultWakeScreen = true;
  static const bool defaultKeepAwake = false;
  static const bool defaultOverrideVolume = false;
  static const double defaultVolumeLevel = 0.8; // 80% when override is ON
  static const bool defaultForceMaxCritical = true;
  static const String defaultAlertSound = 'siren';
  static const bool defaultSmartwatch = true;
  static const String defaultVibrationPattern = 'urgent';

  // ── Load all settings ──────────────────────────────────────────────────────
  /// Returns the current notification settings as a map.
  /// Call this at app init and when displaying the settings screen.
  static Future<NotificationSettings> load() async {
    final prefs = await SharedPreferences.getInstance();
    return NotificationSettings(
      wakeScreenOnAlert: prefs.getBool(_keyWakeScreen) ?? defaultWakeScreen,
      keepAwakeDuringAlert: prefs.getBool(_keyKeepAwake) ?? defaultKeepAwake,
      overrideVolume: prefs.getBool(_keyOverrideVolume) ?? defaultOverrideVolume,
      volumeLevel: prefs.getDouble(_keyVolumeLevel) ?? defaultVolumeLevel,
      forceMaxCritical: prefs.getBool(_keyForceMaxCritical) ?? defaultForceMaxCritical,
      alertSound: prefs.getString(_keyAlertSound) ?? defaultAlertSound,
      smartwatchForwarding: prefs.getBool(_keySmartwatch) ?? defaultSmartwatch,
      vibrationPattern: prefs.getString(_keyVibrationPattern) ?? defaultVibrationPattern,
    );
  }

  // ── Individual setters ─────────────────────────────────────────────────────
  // Each setter persists immediately. No batching needed — these are
  // infrequent writes (user tapping toggles in settings).

  static Future<void> setWakeScreen(bool value) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setBool(_keyWakeScreen, value);
  }

  static Future<void> setKeepAwake(bool value) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setBool(_keyKeepAwake, value);
  }

  static Future<void> setOverrideVolume(bool value) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setBool(_keyOverrideVolume, value);
  }

  static Future<void> setVolumeLevel(double value) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setDouble(_keyVolumeLevel, value.clamp(0.0, 1.0));
  }

  static Future<void> setForceMaxCritical(bool value) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setBool(_keyForceMaxCritical, value);
  }

  static Future<void> setAlertSound(String value) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(_keyAlertSound, value);
  }

  static Future<void> setSmartwatch(bool value) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setBool(_keySmartwatch, value);
  }

  static Future<void> setVibrationPattern(String value) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(_keyVibrationPattern, value);
  }

  /// Resets all notification settings to their defaults.
  /// Used by the "Reset to Defaults" button on the settings screen.
  static Future<void> resetToDefaults() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove(_keyWakeScreen);
    await prefs.remove(_keyKeepAwake);
    await prefs.remove(_keyOverrideVolume);
    await prefs.remove(_keyVolumeLevel);
    await prefs.remove(_keyForceMaxCritical);
    await prefs.remove(_keyAlertSound);
    await prefs.remove(_keySmartwatch);
    await prefs.remove(_keyVibrationPattern);
  }
}

/// Immutable snapshot of the operator's notification preferences.
///
/// This is read by [AlarmService] before triggering the siren and by
/// [PushService] when displaying HITL alert notifications.
class NotificationSettings {
  final bool wakeScreenOnAlert;
  final bool keepAwakeDuringAlert;
  final bool overrideVolume;
  final double volumeLevel;
  final bool forceMaxCritical;
  final String alertSound;
  final bool smartwatchForwarding;
  final String vibrationPattern;

  const NotificationSettings({
    required this.wakeScreenOnAlert,
    required this.keepAwakeDuringAlert,
    required this.overrideVolume,
    required this.volumeLevel,
    required this.forceMaxCritical,
    required this.alertSound,
    required this.smartwatchForwarding,
    required this.vibrationPattern,
  });

  /// Whether the siren should play (any sound except 'silent').
  bool get shouldPlaySound => alertSound != 'silent';

  /// The effective volume level for the siren.
  /// If override is OFF, returns 1.0 (system default via SoLoud).
  /// If force-max-critical is ON, always returns 1.0.
  double get effectiveVolume {
    if (forceMaxCritical) return 1.0;
    if (overrideVolume) return volumeLevel;
    return 1.0;
  }
}
