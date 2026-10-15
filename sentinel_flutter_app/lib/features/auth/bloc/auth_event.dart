// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

abstract class AuthEvent {}

class AuthInitializeRequested extends AuthEvent {}

class AuthKeysRevealed extends AuthEvent {}

class AuthScanRequested extends AuthEvent {
  final String sessionUrl;
  AuthScanRequested(this.sessionUrl);
}
