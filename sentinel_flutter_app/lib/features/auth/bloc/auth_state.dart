// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

abstract class AuthState {}

class AuthInitial extends AuthState {}

class AuthLoading extends AuthState {
  final String message;
  AuthLoading(this.message);
}

class AuthReady extends AuthState {
  final String ed25519PubKey;
  final String mldsaPubKey;
  final bool keysVisible;

  AuthReady({
    required this.ed25519PubKey,
    required this.mldsaPubKey,
    this.keysVisible = false,
  });

  AuthReady copyWith({
    String? ed25519PubKey,
    String? mldsaPubKey,
    bool? keysVisible,
  }) {
    return AuthReady(
      ed25519PubKey: ed25519PubKey ?? this.ed25519PubKey,
      mldsaPubKey: mldsaPubKey ?? this.mldsaPubKey,
      keysVisible: keysVisible ?? this.keysVisible,
    );
  }
}

class AuthScanSuccess extends AuthState {
  // To navigate back after successful scan
}

class AuthFailure extends AuthState {
  final String error;
  AuthFailure(this.error);
}
