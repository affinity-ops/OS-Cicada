# Aegis CIBA Companion App (Flutter)

The Aegis companion app is the mobile endpoint of Cicada's zero-trust HITL (Human-in-the-Loop) pipeline. When the Sentry Gateway flags a high-risk agent action, Aegis delivers the alert to the operator's device for biometric-gated approval or denial.

## Status: **Operational**

The app is fully built and deployed. It communicates directly with the Sentry Gateway — not the Core API.

## Core Architecture

```
Developer Portal ──▶ Sentry Gateway ──▶ PostgreSQL
  (QR generation)    (pairing, holds)   (mobile_devices, aegis_devices)
                          ▲
                          │ HTTPS
                          ▼
                    Aegis Mobile App
                     (Ed25519 + PQC)
```

### Pairing Flow (Zero-Secret QR Handshake)

1. Operator clicks "Generate Pairing QR" in the Developer Portal
2. Gateway creates a challenge nonce, signs it with its Ed25519 key, inserts into `mobile_pairing_challenges`
3. QR payload: `{"v":1,"tid":"...","n":"...","exp":...,"gw":"http://192.168.x.x:8080","sig":"...","pk":"..."}`
4. App scans QR, verifies the Gateway's signature using the embedded public key
5. App generates Ed25519 + X25519 keypairs (+ ML-DSA-65 / ML-KEM-768 if available)
6. App signs the nonce with its new Ed25519 key and sends handshake to `gw` URL
7. Gateway verifies signature, revokes any existing devices for the tenant, inserts new device
8. App persists gateway URL, tenant ID, and paired status to Secure Storage

### Cryptographic Keys

| Key Type | Purpose | Algorithm |
|----------|---------|-----------|
| **Ed25519** | Device identity, decision signing | Classical — always available |
| **X25519** | Hold payload encryption (ECDH) | Classical — always available |
| **ML-DSA-65** | Post-quantum decision signatures | PQC — optional (NIST FIPS 204) |
| **ML-KEM-768** | Post-quantum key encapsulation | PQC — optional (NIST FIPS 203) |

### Alert Pipeline

1. Gateway suspends a high-risk agent action → creates CIBA hold
2. App heartbeat (`POST /v1/mobile/heartbeat`) returns pending hold references
3. App fetches encrypted hold payload, decrypts with X25519
4. Operator reviews action details, approves/denies with biometric gate
5. App signs decision with Ed25519 private key → `POST /v1/mobile/decisions`
6. Gateway verifies signature, records to action ledger, unblocks agent

## API Integration (Sentry Gateway Endpoints)

### Pairing
- **Handshake:** `POST /v1/mobile/pair/handshake` — device sends public keys + signed nonce
- **Push Token:** `POST /v1/mobile/push-token` — register FCM/APNs token for push alerts

### Operations
- **Heartbeat:** `POST /v1/mobile/heartbeat` — periodic check-in, returns pending holds + device status
- **Hold Payload:** `GET /v1/mobile/hold/{ref}` — fetch encrypted hold details
- **Decisions:** `POST /v1/mobile/decisions` — submit signed approve/deny decisions

### Telemetry
- **Enrollment:** `POST /v1/device/enroll` — register device model, OS, security posture

## App Screens

| Screen | Purpose |
|--------|---------|
| **Splash** | Checks pairing status → routes to Scanner or Biometric gate |
| **Pairing** | QR scanner with camera permission handling |
| **Alert List** | Active HITL holds requiring operator decision |
| **Alert Detail** | Full action context + approve/deny buttons |
| **Settings** | Device info, security posture, key management, re-pairing |

## APK Distribution

The APK is served via a Python HTTP server on port 3004:

```
http://<LAN_IP>:3004/aegis-app-v5.apk
```

The Developer Portal's Aegis page auto-detects the host IP for the download link.

## Build

```bash
cd Ciba_Flutter_App
flutter pub get
flutter build apk --release
```

## Directory Structure

```
Ciba_Flutter_App/
├── lib/
│   ├── app.dart                    App root with BLoC providers
│   ├── config/
│   │   └── constants.dart          Endpoints, timeouts, storage keys
│   ├── core/
│   │   ├── crypto/
│   │   │   ├── ed25519_service.dart    Ed25519 key generation + signing
│   │   │   ├── x25519_service.dart     X25519 key exchange
│   │   │   ├── ml_dsa_service.dart     ML-DSA-65 PQC signing
│   │   │   └── ml_kem_service.dart     ML-KEM-768 PQC encapsulation
│   │   ├── network/
│   │   │   └── dio_client.dart     HTTP client with auth headers
│   │   ├── push/
│   │   │   └── push_service.dart   FCM token registration
│   │   ├── storage/
│   │   │   └── secure_storage.dart Flutter Secure Storage wrapper
│   │   └── telemetry/
│   │       └── device_info_service.dart  Device model/OS detection
│   └── features/
│       ├── alerts/                 Alert list + detail screens
│       ├── pairing/               QR scanner + pairing BLoC
│       ├── settings/              Device info, key management
│       └── splash/                Biometric gate, status check
└── apk_server/                    Python HTTP server for APK downloads
```
