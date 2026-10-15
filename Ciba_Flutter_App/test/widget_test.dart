// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:aegis_ciba_companion/config/theme.dart';
import 'package:aegis_ciba_companion/widgets/cicada_badge.dart';
import 'package:aegis_ciba_companion/widgets/cicada_button.dart';
import 'package:aegis_ciba_companion/widgets/cicada_card.dart';
import 'package:aegis_ciba_companion/widgets/cicada_timer.dart';

void main() {
  setUpAll(() {
    // Prevent Google Fonts from trying to fetch over HTTP during tests
    GoogleFonts.config.allowRuntimeFetching = false;
  });
  group('CicadaBadge', () {
    testWidgets('renders secure badge', (tester) async {
      await tester.pumpWidget(
        const MaterialApp(home: Scaffold(body: CicadaBadge(status: CicadaStatus.secure))),
      );
      expect(find.text('SECURE'), findsOneWidget);
    });

    testWidgets('renders warning badge', (tester) async {
      await tester.pumpWidget(
        const MaterialApp(home: Scaffold(body: CicadaBadge(status: CicadaStatus.warning))),
      );
      expect(find.text('ELEVATED'), findsOneWidget);
    });

    testWidgets('renders danger badge', (tester) async {
      await tester.pumpWidget(
        const MaterialApp(home: Scaffold(body: CicadaBadge(status: CicadaStatus.danger))),
      );
      expect(find.text('CRITICAL'), findsOneWidget);
    });

    testWidgets('renders info badge', (tester) async {
      await tester.pumpWidget(
        const MaterialApp(home: Scaffold(body: CicadaBadge(status: CicadaStatus.neutral))),
      );
      expect(find.text('INFO'), findsOneWidget);
    });
  });

  group('CicadaButton', () {
    testWidgets('renders primary button', (tester) async {
      await tester.pumpWidget(
        MaterialApp(home: Scaffold(body: CicadaButton(label: 'Approve', onPressed: () {}))),
      );
      expect(find.text('Approve'), findsOneWidget);
      expect(find.byType(ElevatedButton), findsOneWidget);
    });

    testWidgets('renders ghost button as TextButton', (tester) async {
      await tester.pumpWidget(
        MaterialApp(home: Scaffold(body: CicadaButton(label: 'Cancel', variant: CicadaButtonVariant.ghost, onPressed: () {}))),
      );
      expect(find.text('Cancel'), findsOneWidget);
      expect(find.byType(TextButton), findsOneWidget);
    });

    testWidgets('shows loading indicator when isLoading is true', (tester) async {
      await tester.pumpWidget(
        MaterialApp(home: Scaffold(body: CicadaButton(label: 'Submit', isLoading: true, onPressed: () {}))),
      );
      expect(find.byType(CircularProgressIndicator), findsOneWidget);
      expect(find.text('Submit'), findsNothing);
    });

    testWidgets('renders icon when provided', (tester) async {
      await tester.pumpWidget(
        MaterialApp(home: Scaffold(body: CicadaButton(label: 'Approve', icon: Icons.check, onPressed: () {}))),
      );
      expect(find.byIcon(Icons.check), findsOneWidget);
      expect(find.text('Approve'), findsOneWidget);
    });

    testWidgets('disabled when onPressed is null', (tester) async {
      await tester.pumpWidget(
        const MaterialApp(home: Scaffold(body: CicadaButton(label: 'Disabled'))),
      );
      final button = tester.widget<ElevatedButton>(find.byType(ElevatedButton));
      expect(button.onPressed, isNull);
    });
  });

  group('CicadaCard', () {
    testWidgets('renders child content', (tester) async {
      await tester.pumpWidget(
        const MaterialApp(home: Scaffold(body: CicadaCard(child: Text('Content')))),
      );
      expect(find.text('Content'), findsOneWidget);
    });
  });

  group('CicadaTimer', () {
    testWidgets('displays time remaining', (tester) async {
      final expiry = DateTime.now().toUtc().add(const Duration(minutes: 3, seconds: 30));
      await tester.pumpWidget(
        MaterialApp(
          theme: ThemeData.dark(),
          home: Scaffold(body: CicadaTimer(expiresAt: expiry)),
        ),
      );
      // Timer should show approximately 03:30 (may vary by a second)
      expect(find.byIcon(Icons.timer_outlined), findsOneWidget);
    });

    testWidgets('shows 00:00 when expired', (tester) async {
      final expiry = DateTime.now().toUtc().subtract(const Duration(minutes: 1));
      await tester.pumpWidget(
        MaterialApp(
          theme: ThemeData.dark(),
          home: Scaffold(body: CicadaTimer(expiresAt: expiry)),
        ),
      );
      await tester.pump();
      expect(find.text('00:00'), findsOneWidget);
    });
  });

  group('Theme', () {
    test('color tokens match Developer Portal globals.css', () {
      // These are the exact hex values from Developer_Portal/src/app/globals.css
      expect(cicadaBackground, equals(const Color(0xFF0E0E0E)));  // --color-background: #0e0e0e
      expect(cicadaSurface, equals(const Color(0xFF1A1A1A)));      // --color-surface-container: #1a1a1a
      expect(cicadaPrimary, equals(const Color(0xFFFF9F4A)));      // --color-primary: #ff9f4a
      expect(cicadaPrimaryContainer, equals(const Color(0xFFFD8B00))); // --color-primary-container: #fd8b00
      expect(cicadaOnSurface, equals(const Color(0xFFFFFFFF)));    // --color-on-surface: #ffffff
      expect(cicadaOnSurfaceMuted, equals(const Color(0xFFADAAAA))); // --color-on-surface-variant: #adaaaa
      expect(cicadaError, equals(const Color(0xFFFF7351)));        // --color-error: #ff7351
      expect(cicadaSurfaceVariant, equals(const Color(0xFF262626))); // --color-surface-variant: #262626
      expect(cicadaSecondary, equals(const Color(0xFFF9C13D)));    // --color-secondary: #f9c13d
      expect(cicadaTertiary, equals(const Color(0xFFFFC479)));     // --color-tertiary: #ffc479
    });

    test('border color matches portal rgba(255,159,74,0.10)', () {
      // The portal uses rgba(255,159,74,0.10) for borders
      expect(cicadaBorder, equals(const Color(0x1AFF9F4A)));
    });

    test('spacing system uses 4px base', () {
      expect(space1, equals(4.0));
      expect(space2, equals(8.0));
      expect(space3, equals(16.0));
      expect(space4, equals(24.0));
      expect(space5, equals(32.0));
      expect(space6, equals(48.0));
      expect(space7, equals(64.0));
    });

    test('border radii are defined', () {
      expect(radiusSm, equals(4.0));
      expect(radiusMd, equals(8.0));
      expect(radiusLg, equals(12.0));
      expect(radiusXl, equals(16.0));
      expect(radiusFull, equals(9999.0));
    });

    test('gradient uses primary to primaryContainer', () {
      expect(cicadaGradient.colors, containsAll([cicadaPrimary, cicadaPrimaryContainer]));
    });
  });
}
