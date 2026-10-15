// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import 'package:flutter/material.dart';
import '../config/theme.dart';
import '../features/auth/scanner_screen.dart';

class AuthorizeButton extends StatelessWidget {
  const AuthorizeButton({super.key});

  @override
  Widget build(BuildContext context) {
    return SizedBox(
      width: double.infinity,
      height: 60,
      child: ElevatedButton(
        style: ElevatedButton.styleFrom(
          backgroundColor: SentinelTheme.accent,
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(SentinelTheme.radiusLg)),
          elevation: 8,
        ),
        onPressed: () {
          Navigator.of(context).push(
            MaterialPageRoute(builder: (context) => const ScannerScreen()),
          );
        },
        child: const Row(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(Icons.qr_code_scanner, color: Colors.black, size: 28),
            SizedBox(width: SentinelTheme.space3 - 4),
            Text(
              'AUTHORIZE LOGIN',
              style: TextStyle(
                color: Colors.black,
                fontSize: 18,
                fontWeight: FontWeight.w900,
                letterSpacing: 2.0,
              ),
            ),
          ],
        ),
      ),
    );
  }
}
