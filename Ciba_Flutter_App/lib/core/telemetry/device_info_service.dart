// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import 'package:device_info_plus/device_info_plus.dart';
import 'dart:io';

class DeviceInfoService {
  final DeviceInfoPlugin _plugin = DeviceInfoPlugin();

  Future<Map<String, String>> getDeviceProfile() async {
    if (Platform.isAndroid) {
      var info = await _plugin.androidInfo;
      return {'os': 'Android', 'model': info.model, 'version': info.version.release};
    } else if (Platform.isIOS) {
      var info = await _plugin.iosInfo;
      return {'os': 'iOS', 'model': info.model, 'version': info.systemVersion};
    }
    return {'os': 'Unknown', 'model': 'Unknown', 'version': 'Unknown'};
  }
}