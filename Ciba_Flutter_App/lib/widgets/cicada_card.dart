// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import 'package:flutter/material.dart';
import '../config/theme.dart';

class CicadaCard extends StatelessWidget {
  final Widget child;
  final Color? backgroundColor;
  final EdgeInsets? padding;

  const CicadaCard({Key? key, required this.child, this.backgroundColor, this.padding}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return Container(
      decoration: BoxDecoration(
        color: backgroundColor ?? cicadaSurface,
        borderRadius: BorderRadius.circular(radiusLg),
        border: Border.all(color: cicadaBorder),
      ),
      padding: padding ?? const EdgeInsets.all(space4),
      child: child,
    );
  }
}