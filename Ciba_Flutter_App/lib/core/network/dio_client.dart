// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import 'package:dio/dio.dart';
import '../../config/constants.dart';

/// Dio HTTP client configured for the Sentry Gateway mobile API.
///
/// All requests carry the device's Ed25519 public key fingerprint
/// in the X-Device-Fingerprint header for device identification.
class DioClient {
  late final Dio dio;
  String? _deviceFingerprint;

  DioClient({String? baseUrl}) {
    dio = Dio(BaseOptions(
      baseUrl: baseUrl ?? AppConstants.gatewayBaseUrl,
      connectTimeout: AppConstants.connectTimeout,
      receiveTimeout: AppConstants.receiveTimeout,
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
    ));

    // ── Request interceptor: inject device fingerprint ────────────────────
    dio.interceptors.add(InterceptorsWrapper(
      onRequest: (options, handler) {
        if (_deviceFingerprint != null) {
          options.headers['X-Device-Fingerprint'] = _deviceFingerprint;
        }
        handler.next(options);
      },
      onError: (error, handler) {
        // Log errors for debugging; retry logic is in RetryPolicy
        handler.next(error);
      },
    ));
  }

  /// Set the device fingerprint (Ed25519 public key) for all requests.
  void setDeviceFingerprint(String fingerprint) {
    _deviceFingerprint = fingerprint;
  }

  /// Reconfigure the base URL (e.g. after pairing provides the Gateway's LAN IP).
  void setBaseUrl(String url) {
    dio.options.baseUrl = url;
  }

  /// POST request with JSON body.
  Future<Response> post(String path, {Map<String, dynamic>? data}) =>
      dio.post(path, data: data);

  /// GET request.
  Future<Response> get(String path, {Map<String, dynamic>? queryParams}) =>
      dio.get(path, queryParameters: queryParams);
}