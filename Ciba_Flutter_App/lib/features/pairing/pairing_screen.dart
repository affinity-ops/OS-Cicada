// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import 'package:flutter/material.dart';
import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:mobile_scanner/mobile_scanner.dart';
import '../../config/theme.dart';
import '../../widgets/cicada_card.dart';
import 'bloc/pairing_bloc.dart';
import '../alerts/alert_list_screen.dart';

class PairingScreen extends StatefulWidget {
  const PairingScreen({Key? key}) : super(key: key);

  @override
  State<PairingScreen> createState() => _PairingScreenState();
}

class _PairingScreenState extends State<PairingScreen> with WidgetsBindingObserver {
  late final MobileScannerController _scannerController;
  bool _hasPermissionError = false;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _scannerController = MobileScannerController(
      detectionSpeed: DetectionSpeed.normal,
      facing: CameraFacing.back,
    );
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    // When the app resumes from lock screen or background, restart the scanner
    // so Android re-evaluates camera permission in the current session.
    if (state == AppLifecycleState.resumed) {
      setState(() => _hasPermissionError = false);
      _scannerController.start();
    } else if (state == AppLifecycleState.paused) {
      _scannerController.stop();
    }
  }

  void _retryCamera() {
    setState(() => _hasPermissionError = false);
    _scannerController.start();
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _scannerController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: cicadaBackground,
      appBar: AppBar(
        title: Text('Pair with Gateway', style: headlineStyle(fontSize: 18)),
        backgroundColor: cicadaBackground,
      ),
      body: BlocConsumer<PairingBloc, PairingState>(
        listener: (context, state) {
          if (state is PairingSuccess) {
            ScaffoldMessenger.of(context).showSnackBar(
              SnackBar(
                content: Row(children: [
                  const Icon(Icons.check_circle, color: cicadaSuccess, size: 18),
                  const SizedBox(width: 8),
                  Text('Device paired successfully', style: headlineStyle(fontSize: 14)),
                ]),
                backgroundColor: cicadaSurface,
              ),
            );
            Future.delayed(const Duration(seconds: 1), () {
              if (!context.mounted) return;
              Navigator.of(context).pushReplacement(PageRouteBuilder(
                pageBuilder: (_, __, ___) => const AlertListScreen(),
                transitionsBuilder: (_, animation, __, child) =>
                    FadeTransition(opacity: animation, child: child),
                transitionDuration: const Duration(milliseconds: 400),
              ));
            });
          } else if (state is PairingError) {
            ScaffoldMessenger.of(context).showSnackBar(
              SnackBar(content: Text(state.message), backgroundColor: cicadaError),
            );
          }
        },
        builder: (context, state) {
          if (state is PairingProcessing) {
            return Center(child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                const CircularProgressIndicator(color: cicadaPrimary),
                const SizedBox(height: space4),
                Text(state.statusMessage, style: headlineStyle(fontSize: 16)),
                const SizedBox(height: space2),
                Text('Do not close the app',
                    style: technicalStyle(fontSize: 12, color: cicadaOnSurfaceMuted)),
              ],
            ));
          }
          return _buildScannerView(context);
        },
      ),
    );
  }

  Widget _buildScannerView(BuildContext context) {
    return SingleChildScrollView(
      padding: const EdgeInsets.all(space4),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Container(
            height: 320,
            decoration: BoxDecoration(
              border: Border.all(color: cicadaPrimary.withValues(alpha: 0.4), width: 2),
              borderRadius: BorderRadius.circular(radiusLg),
            ),
            clipBehavior: Clip.hardEdge,
            child: _hasPermissionError
                ? _buildPermissionDenied()
                : Stack(children: [
                    MobileScanner(
                      controller: _scannerController,
                      onDetect: (capture) {
                        final barcodes = capture.barcodes;
                        if (barcodes.isNotEmpty && barcodes.first.rawValue != null) {
                          context.read<PairingBloc>().pairWithGateway(
                              barcodes.first.rawValue!);
                        }
                      },
                      errorBuilder: (context, error) {
                        // Permission denied after lock screen — show retry, not crash
                        WidgetsBinding.instance.addPostFrameCallback((_) {
                          if (mounted) setState(() => _hasPermissionError = true);
                        });
                        return const SizedBox.shrink();
                      },
                    ),
                    Center(
                      child: Container(
                        width: 200,
                        height: 200,
                        decoration: BoxDecoration(
                          border: Border.all(color: cicadaPrimary, width: 2),
                          borderRadius: BorderRadius.circular(radiusMd),
                        ),
                      ),
                    ),
                  ]),
          ),
          const SizedBox(height: space3),
          Center(
            child: Text('Align QR code within frame',
                style: technicalStyle(fontSize: 12, color: cicadaOnSurfaceMuted)),
          ),
          const SizedBox(height: space4),
          CicadaCard(
            backgroundColor: cicadaPrimary.withValues(alpha: 0.05),
            child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Icon(Icons.security, color: cicadaPrimary, size: 20),
              const SizedBox(width: space3),
              Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Text('Zero-Trust Device Binding', style: headlineStyle(fontSize: 14)),
                const SizedBox(height: space1),
                Text(
                  'Scanning this QR code will generate a private key inside your device\'s Secure Enclave. This key never leaves your device.',
                  style: TextStyle(color: cicadaOnSurfaceMuted, fontSize: 12, height: 1.5),
                ),
              ])),
            ]),
          ),
        ],
      ),
    );
  }

  Widget _buildPermissionDenied() {
    return Container(
      color: cicadaSurface,
      child: Center(
        child: Column(mainAxisAlignment: MainAxisAlignment.center, children: [
          Icon(Icons.camera_alt_outlined, color: cicadaOnSurfaceMuted, size: 40),
          const SizedBox(height: space3),
          Text('Camera Access Required',
              style: headlineStyle(fontSize: 16)),
          const SizedBox(height: space2),
          Text('Tap below to enable camera access.',
              style: TextStyle(color: cicadaOnSurfaceMuted, fontSize: 13),
              textAlign: TextAlign.center),
          const SizedBox(height: space4),
          ElevatedButton.icon(
            onPressed: _retryCamera,
            icon: const Icon(Icons.refresh, size: 18),
            label: const Text('Enable Camera'),
            style: ElevatedButton.styleFrom(
              backgroundColor: cicadaPrimary,
              foregroundColor: Colors.black,
              padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 12),
              shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(radiusMd)),
              textStyle: headlineStyle(fontSize: 14),
            ),
          ),
        ]),
      ),
    );
  }
}
