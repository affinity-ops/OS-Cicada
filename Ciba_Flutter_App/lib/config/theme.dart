// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';

// ─── Color Tokens (matching Developer Portal globals.css) ────────────────────
const Color cicadaBackground = Color(0xFF0E0E0E);
const Color cicadaSurface = Color(0xFF1A1A1A);
const Color cicadaSurfaceLow = Color(0xFF131313);
const Color cicadaSurfaceVariant = Color(0xFF262626);
const Color cicadaBorder = Color(0x1AFF9F4A); // rgba(255,159,74,0.10)
const Color cicadaBorderStrong = Color(0x33FF9F4A); // rgba(255,159,74,0.20)
const Color cicadaOnSurface = Color(0xFFFFFFFF);
const Color cicadaOnSurfaceMuted = Color(0xFFADAAAA);
const Color cicadaPrimary = Color(0xFFFF9F4A);
const Color cicadaPrimaryContainer = Color(0xFFFD8B00);
const Color cicadaSecondary = Color(0xFFF9C13D);
const Color cicadaTertiary = Color(0xFFFFC479);
const Color cicadaError = Color(0xFFFF7351);
const Color cicadaSuccess = Color(0xFF00C853);
const Color cicadaWarning = Color(0xFFFFB300);
const Color cicadaDanger = Color(0xFFFF1744);
const Color cicadaInfo = Color(0xFF2979FF);

// ─── Spacing System (8px base) ───────────────────────────────────────────────
const double space1 = 4.0;
const double space2 = 8.0;
const double space3 = 16.0;
const double space4 = 24.0;
const double space5 = 32.0;
const double space6 = 48.0;
const double space7 = 64.0;

// ─── Border Radius ───────────────────────────────────────────────────────────
const double radiusSm = 4.0;
const double radiusMd = 8.0;
const double radiusLg = 12.0;
const double radiusXl = 16.0;
const double radiusFull = 9999.0;

// ─── Gradient ────────────────────────────────────────────────────────────────
const LinearGradient cicadaGradient = LinearGradient(
  begin: Alignment.topLeft,
  end: Alignment.bottomRight,
  colors: [cicadaPrimary, cicadaPrimaryContainer],
);

// ─── Theme Data ──────────────────────────────────────────────────────────────
ThemeData buildCicadaTheme() {
  final headline = GoogleFonts.spaceGroteskTextTheme(
    const TextTheme(
      displayLarge: TextStyle(fontSize: 32, fontWeight: FontWeight.w900, color: cicadaOnSurface, letterSpacing: -1.5),
      displayMedium: TextStyle(fontSize: 28, fontWeight: FontWeight.w800, color: cicadaOnSurface, letterSpacing: -1.2),
      headlineLarge: TextStyle(fontSize: 24, fontWeight: FontWeight.w700, color: cicadaOnSurface, letterSpacing: -1.0),
      headlineMedium: TextStyle(fontSize: 20, fontWeight: FontWeight.w700, color: cicadaOnSurface, letterSpacing: -0.8),
      headlineSmall: TextStyle(fontSize: 18, fontWeight: FontWeight.w600, color: cicadaOnSurface, letterSpacing: -0.5),
      titleLarge: TextStyle(fontSize: 16, fontWeight: FontWeight.w600, color: cicadaOnSurface),
      titleMedium: TextStyle(fontSize: 14, fontWeight: FontWeight.w600, color: cicadaOnSurface),
      titleSmall: TextStyle(fontSize: 12, fontWeight: FontWeight.w600, color: cicadaOnSurfaceMuted),
    ),
  );

  final body = GoogleFonts.manropeTextTheme(
    const TextTheme(
      bodyLarge: TextStyle(fontSize: 16, fontWeight: FontWeight.w400, color: cicadaOnSurface),
      bodyMedium: TextStyle(fontSize: 14, fontWeight: FontWeight.w400, color: cicadaOnSurface),
      bodySmall: TextStyle(fontSize: 12, fontWeight: FontWeight.w400, color: cicadaOnSurfaceMuted),
      labelLarge: TextStyle(fontSize: 14, fontWeight: FontWeight.w600, color: cicadaOnSurface),
      labelMedium: TextStyle(fontSize: 12, fontWeight: FontWeight.w500, color: cicadaOnSurfaceMuted),
      labelSmall: TextStyle(fontSize: 9, fontWeight: FontWeight.w600, color: cicadaOnSurfaceMuted, letterSpacing: 1.5),
    ),
  );

  // Merge headline and body themes
  final merged = headline.merge(body);

  return ThemeData(
    brightness: Brightness.dark,
    scaffoldBackgroundColor: cicadaBackground,
    primaryColor: cicadaPrimary,
    colorScheme: const ColorScheme.dark(
      primary: cicadaPrimary,
      secondary: cicadaSecondary,
      tertiary: cicadaTertiary,
      surface: cicadaSurface,
      error: cicadaError,
      onPrimary: Color(0xFF000000),
      onSurface: cicadaOnSurface,
      onError: cicadaOnSurface,
    ),
    textTheme: merged,
    appBarTheme: AppBarTheme(
      backgroundColor: cicadaBackground,
      foregroundColor: cicadaOnSurface,
      elevation: 0,
      centerTitle: false,
      titleTextStyle: GoogleFonts.spaceGrotesk(
        fontSize: 18,
        fontWeight: FontWeight.w700,
        color: cicadaOnSurface,
        letterSpacing: -0.5,
      ),
    ),
    dividerTheme: const DividerThemeData(color: cicadaBorder, thickness: 1),
    cardTheme: CardThemeData(
      color: cicadaSurface,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(radiusLg),
        side: const BorderSide(color: cicadaBorder),
      ),
      elevation: 0,
    ),
    bottomNavigationBarTheme: const BottomNavigationBarThemeData(
      backgroundColor: Color(0xFF0A0A0A),
      selectedItemColor: cicadaPrimary,
      unselectedItemColor: cicadaOnSurfaceMuted,
    ),
    snackBarTheme: SnackBarThemeData(
      backgroundColor: cicadaSurfaceVariant,
      contentTextStyle: GoogleFonts.manrope(color: cicadaOnSurface, fontSize: 14),
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(radiusMd)),
      behavior: SnackBarBehavior.floating,
    ),
  );
}

// ─── Text Style Helpers ──────────────────────────────────────────────────────
TextStyle technicalStyle({double fontSize = 12, Color? color}) =>
    GoogleFonts.jetBrainsMono(
      fontSize: fontSize,
      fontWeight: FontWeight.w400,
      color: color ?? cicadaOnSurfaceMuted,
    );

TextStyle headlineStyle({double fontSize = 18, FontWeight? weight, Color? color}) =>
    GoogleFonts.spaceGrotesk(
      fontSize: fontSize,
      fontWeight: weight ?? FontWeight.w700,
      color: color ?? cicadaOnSurface,
      letterSpacing: -0.5,
    );