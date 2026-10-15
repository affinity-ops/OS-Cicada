// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:firebase_core/firebase_core.dart';
import 'package:firebase_messaging/firebase_messaging.dart';
import 'package:flutter_soloud/flutter_soloud.dart';
import 'config/theme.dart';
import 'firebase_options.dart';
import 'app.dart';
import 'core/storage/offline_queue.dart';
import 'core/push/push_service.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();

  // Initialise Firebase before anything else
  await Firebase.initializeApp(options: DefaultFirebaseOptions.currentPlatform);

  // Initialise SoLoud audio engine for the emergency siren
  await SoLoud.instance.init();

  // Register the background message handler — must be top-level, called before runApp
  FirebaseMessaging.onBackgroundMessage(firebaseMessagingBackgroundHandler);

  await SystemChrome.setPreferredOrientations([
    DeviceOrientation.portraitUp,
    DeviceOrientation.portraitDown,
  ]);

  SystemChrome.setSystemUIOverlayStyle(
    const SystemUiOverlayStyle(
      statusBarColor: Colors.transparent,
      statusBarIconBrightness: Brightness.light,
      systemNavigationBarColor: cicadaBackground,
      systemNavigationBarIconBrightness: Brightness.light,
    ),
  );

  final offlineQueue = OfflineQueue();
  await offlineQueue.init();

  runApp(AegisApp(offlineQueue: offlineQueue));
}
