# Developer Portal

The Developer Portal is the primary workspace for agent developers and platform administrators. Built with Next.js 15, it provides agent registration, Aegis mobile device pairing, and device management.

## Port

**3001**

## Features

| Section | Purpose |
|---------|---------|
| **Agent Registration** | Register new AI agents, configure `cicada.yaml` policies |
| **Aegis Pairing** | Generate QR codes for zero-trust device binding |
| **Device Management** | View enrolled devices, revoke compromised devices |
| **Account / Company** | Tenant information, onboarding guide |

## Aegis Device Pairing

The Developer Portal generates QR pairing codes via the Sentry Gateway:

1. Operator clicks "Generate Pairing QR Code" on the Aegis page
2. Portal calls `POST /v1/portal/pair/generate` on the Sentry Gateway
3. Gateway returns a signed JSON QR payload containing a challenge nonce
4. The QR is rendered on screen for the operator to scan with the Aegis mobile app
5. The app completes the handshake directly with the Gateway — the Portal is not involved after QR generation

### APK Distribution

The Aegis page includes a download link for the Android APK. The URL auto-detects the host's LAN IP:

```
http://<LAN_IP>:3004/aegis-app-v5.apk
```

## Data Sources

| Endpoint | Source | Purpose |
|----------|--------|---------|
| `/v1/portal/pair/generate` | Sentry Gateway (:8080) | Generate QR challenge |
| `/v1/portal/devices` | Sentry Gateway (:8080) | List enrolled devices |
| `/v1/portal/devices/{id}/revoke` | Sentry Gateway (:8080) | Revoke a device |
| `/api/v1/auth/me` | Core API (:8000) | Session authentication |

## Authentication

Laravel Sanctum bearer token stored in `localStorage` under `cicada_token`.

## Run

```bash
cd Developer_Portal
npm install
npm run build
npm start
```

Or via the fleet startup script:

```bash
./start_fleet.sh
```

## Environment

| Variable | Default | Purpose |
|----------|---------|---------|
| `NEXT_PUBLIC_CORE_API_URL` | `http://localhost:8000` | Core API for auth |
| `NEXT_PUBLIC_GATEWAY_URL` | `http://localhost:8080` | Sentry Gateway for pairing + devices |
| `PORT` | `3001` | Portal listen port |
