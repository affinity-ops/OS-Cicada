# Core API

The Core API is the tenant management and authentication backend for the Cicada platform. Built with Laravel 12 and PHP 8.2+, it handles user authentication, agent registration, CIBA authorization records, and serves as the identity provider for the Developer Portal and Gateway Portal.

## Port

**8000** (via `php artisan serve --port=8000`)

## Authentication

Laravel Sanctum — Bearer token authentication. All portal requests include `Authorization: Bearer <token>`.

### Auth Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/api/v1/auth/login` | Authenticate and receive Bearer token |
| POST | `/api/v1/auth/logout` | Invalidate session |
| GET | `/api/v1/auth/me` | Verify session, returns contact + tenant info |

## Key Endpoints

### Dashboard & Admin
| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/v1/dashboard/summary` | KPI summary for Operator Dashboard |
| GET | `/api/v1/admin/ciba/pending` | List pending CIBA authorization requests |
| POST | `/api/v1/admin/ciba/{traceId}/respond` | Approve or deny a CIBA request |
| GET | `/api/v1/admin/threat-signals` | Threat intelligence feed |

### Agent Management
| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/v1/agents` | List registered agents |
| POST | `/api/v1/agents` | Register a new agent |
| GET | `/api/v1/agents/{id}` | Agent detail |

### Portal (used by Gateway to verify portal sessions)
| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/v1/portal/mobile/devices` | List devices (Core API view) |

## Data Model

The Core API owns the following key tables (MySQL/SQLite via Laravel migrations):

- **tenants** — multi-tenant organisation records
- **contacts** — operator/admin users within a tenant
- **personal_access_tokens** — Sanctum session tokens
- **agents** — registered AI agent records
- **ciba_authorization_requests** — HITL hold records created by the Sentry Gateway

## Relationship to Sentry Gateway

The Sentry Gateway validates portal bearer tokens by calling `GET /api/v1/auth/me` on the Core API. This allows the Gateway to authenticate Developer Portal and Gateway Portal requests without duplicating session management.

The Sentry Gateway also writes CIBA authorization requests to the Core API's database so both the Gateway Portal and the Operator Dashboard can display pending approvals.

## Run

```bash
cd Core_API
php artisan serve --port=8000
```

Or via the fleet startup script (recommended):

```bash
./start_fleet.sh
```

## Environment

Configuration is managed via `.env` in the Core API directory. Key variables:

| Variable | Purpose |
|----------|---------|
| `DB_CONNECTION` | Database driver (mysql, sqlite, pgsql) |
| `DB_HOST` / `DB_PORT` | Database connection |
| `DB_DATABASE` | Database name |
| `APP_KEY` | Laravel application key |
| `SANCTUM_STATEFUL_DOMAINS` | Allowed Sanctum domains |
