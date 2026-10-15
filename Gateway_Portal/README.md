# Gateway Portal

The Gateway Portal is the operator-facing control plane for the Sentry Gateway. Built with Next.js 15, it provides real-time visibility into gateway traffic, CIBA approvals, threat intelligence, policy management, and Aegis device status.

## Port

**3002**

## Features

| Section | Purpose |
|---------|---------|
| **Overview** | Gateway health status, online/offline indicator, system metrics |
| **Gateway Health** | Detailed health telemetry — PostgreSQL, Redis, OPA, ledger integrity |
| **Inbound Agents** | Live feed of inbound agent requests passing through the gateway |
| **Outbound Agents** | Live feed of outbound proxied API calls |
| **Threat Intelligence** | Aggregated threat signals — injection attempts, anomaly patterns |
| **Policy Management** | OPA Rego policy viewer, version history, activation controls |
| **CIBA Approvals** | Pending HITL authorization requests with approve/deny actions |
| **Identity Federation** | OIDC/SAML 2.0 provider configuration |
| **Revocation Webhooks** | CAEP webhook management for cross-platform agent revocation |
| **Certified Agents** | Agent registry with trust tiers and scope details |
| **Licence & Company** | Tenant and licence information |

## CIBA Device Integration

The CIBA Approvals page shows a device status banner:
- **Active** (green) — paired Aegis device detected, HITL push notifications will be delivered
- **Not Paired** (amber) — no device enrolled, links to Developer Portal for pairing

Device data is fetched from the **Sentry Gateway** (`GET /v1/portal/devices`), not the Core API, because the `mobile_devices` table lives in the Gateway's PostgreSQL database.

## Data Sources

| Endpoint | Source | Purpose |
|----------|--------|---------|
| `/health` | Sentry Gateway (:8080) | Gateway online status |
| `/v1/portal/devices` | Sentry Gateway (:8080) | Aegis device status |
| `/api/v1/admin/ciba/pending` | Core API (:8000) | Pending CIBA holds |
| `/api/v1/auth/me` | Core API (:8000) | Session authentication |

## Authentication

The Gateway Portal uses the same Laravel Sanctum bearer token as the Developer Portal. Session tokens are stored in `localStorage` under `cicada_gw_token`.

## Run

```bash
cd Gateway_Portal
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
| `NEXT_PUBLIC_CORE_API_URL` | `http://localhost:8000` | Core API for auth + CIBA |
| `NEXT_PUBLIC_GATEWAY_URL` | `http://localhost:8080` | Sentry Gateway for devices + health |
| `NEXT_PUBLIC_DEVELOPER_PORTAL_URL` | `http://localhost:3001` | Link to Developer Portal for pairing |
| `PORT` | `3002` | Portal listen port |
