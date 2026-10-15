// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import 'package:flutter_soloud/flutter_soloud.dart';
import 'notification_settings_service.dart';

/// Emergency siren player for critical HITL alerts.
///
/// Uses a SINGLETON pattern so that any code path (AlertBloc, DecisionBloc,
/// DecisionScreen) can stop the same siren instance. Previously, each bloc
/// created its own AlarmService with separate SoundHandle references, so
/// the "silence" button was stopping a null handle while the real siren
/// kept playing from a different instance.
///
/// Audio assets live in `assets/audio/` and are registered in pubspec.yaml.
/// The default 'siren.wav' loops continuously until [stopSiren] is called
/// (typically after the operator makes a decision or the hold times out).
class AlarmService {
  // ── Singleton ────────────────────────────────────────────────────────────
  static final AlarmService _instance = AlarmService._internal();
  factory AlarmService() => _instance;
  AlarmService._internal();

  SoundHandle? _handle;
  AudioSource? _source;

  /// Triggers the emergency siren using the operator's preferred settings.
  ///
  /// Reads [NotificationSettings] to determine:
  ///   - Which sound to play (siren, klaxon, pulse, chime, or silent)
  ///   - Volume level (respects override slider and force-max-critical)
  ///   - Whether to play at all (silent mode = vibration only)
  Future<void> triggerSiren() async {
    try {
      // Load the operator's notification preferences
      final settings = await NotificationSettingsService.load();

      // If the operator chose 'silent', skip audio entirely.
      // The notification channel still vibrates per the vibration pattern.
      if (!settings.shouldPlaySound) return;

      final soloud = SoLoud.instance;
      if (!soloud.isInitialized) {
        await soloud.init();
      }

      // Resolve the audio file based on the selected alert sound.
      // Falls back to 'siren.wav' if the selected file doesn't exist.
      final soundFile = 'assets/audio/${settings.alertSound}.wav';
      try {
        _source = await soloud.loadAsset(soundFile);
      } catch (_) {
        // Fallback to the default siren if the selected sound is missing
        _source = await soloud.loadAsset('assets/audio/siren.wav');
      }

      // Play at the operator's configured volume level.
      // effectiveVolume respects: force-max-critical > override slider > 1.0
      _handle = await soloud.play(
        _source!,
        volume: settings.effectiveVolume,
        looping: true,
      );
    } catch (e) {
      // Device may not support audio or asset is missing.
      // Fail silently — the notification + vibration still fire.
      print('ALARM ERROR: $e');
    }
  }

  /// Stops the currently playing siren and releases audio resources.
  ///
  /// Called when the operator approves/denies a decision, or when the
  /// HITL hold times out (120-second CIBA window).
  ///
  /// Uses a two-stage approach:
  ///   1. Stop the specific handle if we have one
  ///   2. Nuclear fallback: dispose ALL active sounds via SoLoud
  /// This guarantees silence even if the handle reference was lost.
  Future<void> stopSiren() async {
    try {
      final soloud = SoLoud.instance;
      if (!soloud.isInitialized) return;

      // Stage 1: Stop the specific handle
      if (_handle != null) {
        soloud.stop(_handle!);
        _handle = null;
      }

      // Stage 2: Dispose the source (stops any leftover playback)
      if (_source != null) {
        soloud.disposeSource(_source!);
        _source = null;
      }

      // Stage 3: Nuclear — stop ALL active sounds as a guaranteed fallback
      soloud.disposeAllSources();
    } catch (e) {
      // Last resort — try to re-init which implicitly stops everything
      try {
        SoLoud.instance.deinit();
      } catch (_) {}
    }
  }
}
