// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import 'dart:typed_data';
import 'package:flutter/material.dart';
import 'package:firebase_messaging/firebase_messaging.dart';
import 'package:flutter_local_notifications/flutter_local_notifications.dart';
import '../storage/secure_storage.dart';
import '../network/dio_client.dart';
import '../alerts/notification_settings_service.dart';
import '../../config/constants.dart';
import '../../features/alerts/alert_list_screen.dart';

/// Global navigator key — used to push routes from notification tap handlers
/// which execute outside the widget tree (e.g. background FCM handler).
final GlobalKey<NavigatorState> navigatorKey = GlobalKey<NavigatorState>();

/// The high-priority Android notification channel for HITL alerts.
/// Channel ID is bumped to v3 to force Android to re-register with alarm
/// audio attributes (Android never updates existing channel settings).
const AndroidNotificationChannel hitlChannel = AndroidNotificationChannel(
  'hitl_alerts_v3', // Bumped to force re-registration with alarm audio
  'HITL Security Alerts',
  description: 'Critical AI agent decision requests requiring immediate operator action',
  importance: Importance.max,
  playSound: true,
  sound: RawResourceAndroidNotificationSound('siren'),
  enableVibration: true,
  showBadge: true,
  audioAttributesUsage: AudioAttributesUsage.alarm,
);

final FlutterLocalNotificationsPlugin localNotifications =
    FlutterLocalNotificationsPlugin();

/// Handles notification taps — navigates to the alert list screen.
void _onNotificationTapped(NotificationResponse response) {
  // The payload contains the hold_ref from the CIBA hold.
  // Navigate to the alert list so the operator can act on it.
  navigatorKey.currentState?.push(
    MaterialPageRoute(builder: (_) => const AlertListScreen()),
  );
}

@pragma('vm:entry-point')
Future<void> firebaseMessagingBackgroundHandler(RemoteMessage message) async {
  if (message.data['type'] == 'hitl_alert') {
    final flutterLocalNotificationsPlugin = FlutterLocalNotificationsPlugin();
    
    await flutterLocalNotificationsPlugin.initialize(
      const InitializationSettings(
        android: AndroidInitializationSettings('@mipmap/ic_launcher'),
      ),
      onDidReceiveNotificationResponse: _onNotificationTapped,
    );

    // CRITICAL: Create the notification channel in the background isolate.
    // The foreground PushService.initialize() creates it too, but the
    // background isolate is a separate Dart VM with no shared state.
    // Without this, Android silently drops the notification.
    final androidImpl = flutterLocalNotificationsPlugin
        .resolvePlatformSpecificImplementation<AndroidFlutterLocalNotificationsPlugin>();
    await androidImpl?.createNotificationChannel(hitlChannel);

    await flutterLocalNotificationsPlugin.show(
      message.data['hold_ref'].hashCode,
      '🚨 HITL Decision Required',
      'An AI agent action requires your immediate approval. Tap to respond.',
      NotificationDetails(
        android: AndroidNotificationDetails(
          hitlChannel.id,
          hitlChannel.name,
          importance: Importance.max,
          priority: Priority.max,
          fullScreenIntent: true,
          category: AndroidNotificationCategory.alarm,
          visibility: NotificationVisibility.public,
          playSound: true,
          sound: const RawResourceAndroidNotificationSound('siren'),
          enableVibration: true,
          ongoing: true,
          autoCancel: false,
          ticker: 'HITL Alert — AI agent requires your approval',
          colorized: true,
          color: Color(0xFFFF0000),
          audioAttributesUsage: AudioAttributesUsage.alarm,
        ),
      ),
      payload: message.data['hold_ref'],
    );
  }
}

class PushService {
  static final _messaging = FirebaseMessaging.instance;

  static Future<void> initialize({
    required SecureStorage storage,
    DioClient? dioClient,
  }) async {
    final settings = await _messaging.requestPermission(
      alert: true,
      badge: true,
      sound: true,
    );

    if (settings.authorizationStatus == AuthorizationStatus.denied) return;

    // Register the notification channel so Android uses our high-priority config
    await localNotifications.initialize(
      const InitializationSettings(
        android: AndroidInitializationSettings('@mipmap/ic_launcher'),
      ),
      onDidReceiveNotificationResponse: _onNotificationTapped,
    );

    final androidImpl = localNotifications
        .resolvePlatformSpecificImplementation<AndroidFlutterLocalNotificationsPlugin>();

    await androidImpl?.createNotificationChannel(hitlChannel);

    // Request full-screen intent permission (Android 14+)
    await androidImpl?.requestFullScreenIntentPermission();

    // When app is in foreground and FCM arrives, show a local heads-up notification.
    // We read the operator's notification preferences to apply their chosen
    // vibration pattern and sound settings. The 120-second CIBA window
    // means we must be aggressive about getting the operator's attention.
    FirebaseMessaging.onMessage.listen((message) async {
      if (message.data['type'] == 'hitl_alert') {
        // Load the operator's notification preferences
        final settings = await NotificationSettingsService.load();

        // Map the vibration pattern preference to Android vibration timing.
        // These patterns are designed to cut through ambient noise:
        //   urgent:     100ms on, 100ms off, 100ms on, 100ms off (rapid)
        //   standard:   default Android vibration
        //   persistent: 1000ms continuous
        //   none:       no vibration
        final enableVibration = settings.vibrationPattern != 'none';
        final Int64List? vibrationPattern = switch (settings.vibrationPattern) {
          'urgent'     => Int64List.fromList([0, 100, 100, 100, 100, 100, 100, 100]),
          'persistent' => Int64List.fromList([0, 1000, 200, 1000, 200, 1000]),
          'none'       => null,
          _            => null, // 'standard' uses Android default
        };

        await localNotifications.show(
          message.data['hold_ref'].hashCode,
          message.notification?.title ?? 'HITL Decision Required',
          message.notification?.body ?? 'An AI agent action requires your immediate approval.',
          NotificationDetails(
            android: AndroidNotificationDetails(
              hitlChannel.id,
              hitlChannel.name,
              importance: Importance.max,
              priority: Priority.max,
              fullScreenIntent: settings.wakeScreenOnAlert,
              category: AndroidNotificationCategory.alarm,
              visibility: NotificationVisibility.public,
              playSound: settings.shouldPlaySound,
              enableVibration: enableVibration,
              vibrationPattern: vibrationPattern,
            ),
          ),
        );
      }
    });

    // Handle notification taps when app was terminated and opened via FCM
    final initialMessage = await FirebaseMessaging.instance.getInitialMessage();
    if (initialMessage != null && initialMessage.data['type'] == 'hitl_alert') {
      // App was launched from a killed state by tapping the notification.
      // Navigate to alerts after the first frame renders.
      WidgetsBinding.instance.addPostFrameCallback((_) {
        navigatorKey.currentState?.push(
          MaterialPageRoute(builder: (_) => const AlertListScreen()),
        );
      });
    }

    // Handle notification taps when app was backgrounded (not killed)
    FirebaseMessaging.onMessageOpenedApp.listen((message) {
      if (message.data['type'] == 'hitl_alert') {
        navigatorKey.currentState?.push(
          MaterialPageRoute(builder: (_) => const AlertListScreen()),
        );
      }
    });

    final token = await _messaging.getToken();
    if (token != null) {
      await _registerToken(token, storage, dioClient);
    }

    _messaging.onTokenRefresh.listen((token) async {
      await _registerToken(token, storage, dioClient);
    });
  }

  static Future<void> registerAfterPairing({
    required SecureStorage storage,
    required DioClient dioClient,
  }) async {
    final token = await _messaging.getToken();
    if (token != null) {
      await _registerToken(token, storage, dioClient);
    }
  }

  static Future<void> _registerToken(
    String token,
    SecureStorage storage,
    DioClient? dioClient,
  ) async {
    await storage.write(AppConstants.keyPushToken, token);

    if (dioClient == null) return;

    final fingerprint = await storage.read(AppConstants.keyEd25519Public);
    if (fingerprint == null) return;

    try {
      await dioClient.post(
        AppConstants.pushTokenEndpoint,
        data: {
          'push_token': token,
          'platform': 'android',
          'ed25519_pub_fingerprint': fingerprint,
        },
      );
    } catch (_) {}
  }
}
