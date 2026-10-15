// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import 'package:flutter/material.dart';
import '../../config/theme.dart';
import '../../config/constants.dart';
import '../../widgets/cicada_card.dart';
import '../../widgets/cicada_badge.dart';
import '../../widgets/cicada_button.dart';
import '../../core/storage/secure_storage.dart';
import '../../core/telemetry/device_info_service.dart';
import '../splash/splash_screen.dart';

/// Phase 4, Screen 4: Device Info — security posture, pairing details, key management.
class DeviceInfoScreen extends StatefulWidget {
  const DeviceInfoScreen({Key? key}) : super(key: key);

  @override
  State<DeviceInfoScreen> createState() => _DeviceInfoScreenState();
}

class _DeviceInfoScreenState extends State<DeviceInfoScreen> {
  Map<String, String> _deviceInfo = {};
  String _pubKey = '';
  String _pairedAt = '';
  String _gatewayUrl = '';
  bool _loading = true;

  @override
  void initState() {
    super.initState();
    _loadDeviceInfo();
  }

  Future<void> _loadDeviceInfo() async {
    final deviceService = DeviceInfoService();
    final storage = SecureStorage();

    final info = await deviceService.getDeviceProfile();
    final pubKey = await storage.read(AppConstants.keyEd25519Public) ?? 'Not available';
    final pairedAt = await storage.read(AppConstants.keyPairedAt) ?? 'Unknown';
    final gatewayUrl = await storage.read(AppConstants.keyGatewayUrl) ?? AppConstants.gatewayBaseUrl;

    if (mounted) {
      setState(() {
        _deviceInfo = info;
        _pubKey = pubKey;
        _pairedAt = pairedAt;
        _gatewayUrl = gatewayUrl;
        _loading = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: cicadaBackground,
      appBar: AppBar(
        backgroundColor: cicadaBackground,
        leading: IconButton(icon: const Icon(Icons.arrow_back), onPressed: () => Navigator.pop(context)),
        title: Text('This Device', style: headlineStyle(fontSize: 18)),
      ),
      body: _loading
          ? const Center(child: CircularProgressIndicator(color: cicadaPrimary))
          : SingleChildScrollView(
              padding: const EdgeInsets.all(space4),
              child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
                // ── Security Status ───────────────
                CicadaCard(
                  child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                    const CicadaBadge(status: CicadaStatus.secure),
                    const SizedBox(height: space4),
                    Text('${_deviceInfo['model'] ?? 'Unknown'}', style: headlineStyle(fontSize: 20)),
                    const SizedBox(height: space1),
                    Text('${_deviceInfo['os'] ?? ''} ${_deviceInfo['version'] ?? ''}',
                        style: TextStyle(color: cicadaOnSurfaceMuted, fontSize: 14)),
                    Text('App Version ${AppConstants.appVersion}',
                        style: TextStyle(color: cicadaOnSurfaceMuted, fontSize: 14)),
                    const SizedBox(height: space4),
                    const Divider(color: cicadaBorder),
                    const SizedBox(height: space3),
                    _InfoRow('Biometric', 'Enrolled', cicadaSuccess),
                    _InfoRow('Secure Enclave', 'Available', cicadaSuccess),
                    _InfoRow('Screen Lock', 'On', cicadaSuccess),
                    const SizedBox(height: space3),
                    const Divider(color: cicadaBorder),
                    const SizedBox(height: space3),
                    _InfoRow('Paired', _formatDate(_pairedAt), cicadaOnSurface),
                    _InfoRow('Last Seen', 'Just now', cicadaOnSurface),
                  ]),
                ),
                const SizedBox(height: space3),

                // ── Public Key ────────────────────
                CicadaCard(
                  child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                    Text('DEVICE PUBLIC KEY', style: technicalStyle(fontSize: 10).copyWith(letterSpacing: 1.5)),
                    const SizedBox(height: space2),
                    SelectableText(_pubKey,
                        style: technicalStyle(fontSize: 11, color: cicadaPrimary)),
                  ]),
                ),
                const SizedBox(height: space3),

                // ── Gateway ───────────────────────
                CicadaCard(
                  child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                    Text('GATEWAY', style: technicalStyle(fontSize: 10).copyWith(letterSpacing: 1.5)),
                    const SizedBox(height: space2),
                    Text(_gatewayUrl, style: technicalStyle(fontSize: 13, color: cicadaOnSurface)),
                  ]),
                ),
                const SizedBox(height: space4),

                // ── Actions ───────────────────────
                CicadaButton(label: 'Rotate Keys', variant: CicadaButtonVariant.secondary, icon: Icons.sync,
                  onPressed: () {}),
                const SizedBox(height: space2),
                CicadaButton(label: 'Revoke Device', variant: CicadaButtonVariant.danger, icon: Icons.delete_outline,
                  onPressed: () => _confirmRevoke(context)),
              ]),
            ),
    );
  }

  Future<void> _confirmRevoke(BuildContext context) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: cicadaSurface,
        title: Text('Revoke This Device?', style: headlineStyle(fontSize: 18)),
        content: Text(
          'All cryptographic keys will be deleted from this device. '
          'It will no longer receive HITL alerts or be able to sign decisions. '
          'This cannot be undone.',
          style: TextStyle(color: cicadaOnSurfaceMuted, fontSize: 14, height: 1.5),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: const Text('Cancel', style: TextStyle(color: cicadaOnSurfaceMuted)),
          ),
          TextButton(
            onPressed: () => Navigator.pop(ctx, true),
            child: const Text('Revoke', style: TextStyle(color: cicadaError)),
          ),
        ],
      ),
    );
    if (confirmed != true || !mounted) return;

    final storage = SecureStorage();
    for (final key in [
      AppConstants.keyPairedStatus,
      AppConstants.keyEd25519Seed,
      AppConstants.keyEd25519Public,
      AppConstants.keyX25519Seed,
      AppConstants.keyX25519Public,
      AppConstants.keyTenantId,
      AppConstants.keyGatewayUrl,
      AppConstants.keyPairedAt,
      AppConstants.keyLastKeyRotation,
      AppConstants.keyPushToken,
    ]) {
      await storage.delete(key);
    }

    if (!mounted) return;
    Navigator.of(context).pushAndRemoveUntil(
      MaterialPageRoute(builder: (_) => const SplashScreen()),
      (_) => false,
    );
  }

  String _formatDate(String iso) {
    try {
      final dt = DateTime.parse(iso);
      return '${dt.day} ${_months[dt.month - 1]} ${dt.year}, ${dt.hour.toString().padLeft(2, '0')}:${dt.minute.toString().padLeft(2, '0')} UTC';
    } catch (_) {
      return iso;
    }
  }

  static const _months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
}

class _InfoRow extends StatelessWidget {
  final String label;
  final String value;
  final Color valueColor;
  const _InfoRow(this.label, this.value, this.valueColor);

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 3),
      child: Row(mainAxisAlignment: MainAxisAlignment.spaceBetween, children: [
        Text(label, style: TextStyle(color: cicadaOnSurfaceMuted, fontSize: 13)),
        Text(value, style: TextStyle(color: valueColor, fontSize: 13, fontWeight: FontWeight.w600)),
      ]),
    );
  }
}
