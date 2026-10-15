// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import 'dart:convert';
import 'package:http/http.dart' as http;
import '../../config/constants.dart';

class AuthClient {
  final http.Client _client = http.Client();

  Future<http.Response> verifyChallenge({
    required String host,
    required String sessionId,
    required String challengeId,
    required String ed25519Signature,
    required String mldsaSignature,
    required String ed25519PubKey,
    required String mldsaPubKey,
    required String osName,
  }) async {
    final dynamicApiUrl = 'http://$host${SentinelConstants.verifyEndpoint}';
    
    return await _client.post(
      Uri.parse(dynamicApiUrl),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'session_id': sessionId,
        'challenge_id': challengeId,
        'ed25519_signature': ed25519Signature,
        'mldsa_signature': mldsaSignature,
        'public_keys': {
          'ed25519': ed25519PubKey,
          'mldsa': mldsaPubKey,
        },
        'device_metadata': {
          'name': 'Sentinel Hardware Auth',
          'os': osName,
        }
      }),
    ).timeout(SentinelConstants.verifyTimeout);
  }
}
