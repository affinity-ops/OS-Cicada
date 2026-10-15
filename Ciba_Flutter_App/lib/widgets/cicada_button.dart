// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import 'package:flutter/material.dart';
import '../config/theme.dart';

enum CicadaButtonVariant { primary, secondary, danger, ghost }

class CicadaButton extends StatelessWidget {
  final String label;
  final VoidCallback? onPressed;
  final CicadaButtonVariant variant;
  final bool isLoading;
  final IconData? icon;

  const CicadaButton({
    Key? key,
    required this.label,
    this.onPressed,
    this.variant = CicadaButtonVariant.primary,
    this.isLoading = false,
    this.icon,
  }) : super(key: key);

  Color get _backgroundColor {
    switch (variant) {
      case CicadaButtonVariant.primary:
        return cicadaPrimary;
      case CicadaButtonVariant.secondary:
        return cicadaSurfaceVariant;
      case CicadaButtonVariant.danger:
        return cicadaDanger;
      case CicadaButtonVariant.ghost:
        return Colors.transparent;
    }
  }

  Color get _foregroundColor {
    switch (variant) {
      case CicadaButtonVariant.primary:
        return Colors.black;
      case CicadaButtonVariant.secondary:
        return cicadaOnSurface;
      case CicadaButtonVariant.danger:
        return cicadaOnSurface;
      case CicadaButtonVariant.ghost:
        return cicadaOnSurfaceMuted;
    }
  }

  @override
  Widget build(BuildContext context) {
    if (variant == CicadaButtonVariant.ghost) {
      return TextButton(
        onPressed: isLoading ? null : onPressed,
        style: TextButton.styleFrom(
          foregroundColor: _foregroundColor,
          padding: const EdgeInsets.symmetric(horizontal: space3, vertical: space2),
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(radiusMd)),
        ),
        child: _buildChild(),
      );
    }

    return ElevatedButton(
      style: ElevatedButton.styleFrom(
        backgroundColor: _backgroundColor,
        foregroundColor: _foregroundColor,
        padding: const EdgeInsets.symmetric(horizontal: space4, vertical: space3),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(radiusMd)),
        disabledBackgroundColor: cicadaSurfaceVariant.withValues(alpha: 0.5),
        elevation: 0,
      ),
      onPressed: isLoading ? null : onPressed,
      child: _buildChild(),
    );
  }

  Widget _buildChild() {
    if (isLoading) {
      return SizedBox(
        width: 20,
        height: 20,
        child: CircularProgressIndicator(
          strokeWidth: 2,
          color: _foregroundColor,
        ),
      );
    }
    if (icon != null) {
      return Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(icon, size: 18),
          const SizedBox(width: 8),
          Text(label, style: headlineStyle(fontSize: 14, weight: FontWeight.w700, color: _foregroundColor)),
        ],
      );
    }
    return Text(label, style: headlineStyle(fontSize: 14, weight: FontWeight.w700, color: _foregroundColor));
  }
}