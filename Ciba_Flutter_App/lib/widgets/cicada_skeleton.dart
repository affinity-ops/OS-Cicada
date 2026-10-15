// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import 'package:flutter/material.dart';
import 'package:shimmer/shimmer.dart';
import '../config/theme.dart';

/// Shimmer loading skeleton matching the Cicada dark theme.
class CicadaSkeleton extends StatelessWidget {
  final double width;
  final double height;
  final double borderRadius;

  const CicadaSkeleton({
    Key? key,
    this.width = double.infinity,
    this.height = 20,
    this.borderRadius = radiusMd,
  }) : super(key: key);

  /// Pre-built card skeleton for alert list loading state.
  static Widget card() => const _SkeletonCard();

  @override
  Widget build(BuildContext context) {
    return Shimmer.fromColors(
      baseColor: cicadaSurfaceVariant,
      highlightColor: cicadaSurface,
      child: Container(
        width: width,
        height: height,
        decoration: BoxDecoration(
          color: cicadaSurfaceVariant,
          borderRadius: BorderRadius.circular(borderRadius),
        ),
      ),
    );
  }
}

class _SkeletonCard extends StatelessWidget {
  const _SkeletonCard();

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(space4),
      margin: const EdgeInsets.only(bottom: space3),
      decoration: BoxDecoration(
        color: cicadaSurface,
        borderRadius: BorderRadius.circular(radiusLg),
        border: Border.all(color: cicadaBorder),
      ),
      child: Shimmer.fromColors(
        baseColor: cicadaSurfaceVariant,
        highlightColor: cicadaSurface,
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Container(width: 80, height: 20, decoration: BoxDecoration(color: cicadaSurfaceVariant, borderRadius: BorderRadius.circular(radiusFull))),
            const SizedBox(height: space3),
            Container(width: double.infinity, height: 16, decoration: BoxDecoration(color: cicadaSurfaceVariant, borderRadius: BorderRadius.circular(radiusSm))),
            const SizedBox(height: space2),
            Container(width: 200, height: 14, decoration: BoxDecoration(color: cicadaSurfaceVariant, borderRadius: BorderRadius.circular(radiusSm))),
            const SizedBox(height: space3),
            Row(
              children: [
                Container(width: 120, height: 12, decoration: BoxDecoration(color: cicadaSurfaceVariant, borderRadius: BorderRadius.circular(radiusSm))),
                const Spacer(),
                Container(width: 80, height: 28, decoration: BoxDecoration(color: cicadaSurfaceVariant, borderRadius: BorderRadius.circular(radiusMd))),
              ],
            ),
          ],
        ),
      ),
    );
  }
}
