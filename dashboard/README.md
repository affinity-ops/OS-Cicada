# Operator Dashboard

The Operator Dashboard is the internal admin interface for the Cicada platform. Built with Next.js 15, it provides real-time visibility into platform KPIs, agent telemetry, and operational metrics.

## Port

**3000**

## Features

- **KPI Cards** — live metrics: active agents, pending holds, throughput, risk scores
- **Agent Registry** — registered agents with trust tiers, scope entitlements, and status
- **Telemetry** — real-time agent activity monitoring
- **Action Ledger** — searchable audit trail of all agent actions
- **Threat Intelligence** — aggregated threat signals and anomaly detection

## Data Sources

The dashboard fetches data exclusively from the Core API:

| Endpoint | Purpose |
|----------|---------|
| `GET /api/v1/dashboard/summary` | KPI aggregates |
| `GET /api/v1/agents` | Agent list |
| `GET /api/v1/admin/ciba/pending` | Pending HITL holds |
| `GET /api/v1/admin/threat-signals` | Threat feed |

## Run

```bash
cd dashboard
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
| `NEXT_PUBLIC_CORE_API_URL` | `http://localhost:8000` | Core API endpoint |
| `PORT` | `3000` | Dashboard listen port |
