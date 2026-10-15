# Sentry Gateway

The Sentry Gateway is the core enforcement engine of the Cicada platform. Written in Go, it sits between AI agents and the APIs they call, enforcing a 7-layer security pipeline on every request.

## Port

**8080** (configurable via `PORT` env var)

## 7-Layer Enforcement Pipeline

Every agent request passes through these layers in order:

| Layer | Name | What It Does |
|-------|------|-------------|
| 1 | **Ed25519 Authentication** | Verifies the agent's EVAR JWT (Ed25519-signed session token) |
| 2 | **URL Allowlist** | Blocks requests to URLs not declared in the agent's `cicada.yaml` policy |
| 3 | **Semantic Intent Alignment** | Scores the agent's action against its declared purpose using embedding similarity |
| 4 | **OPA Policy Evaluation** | Evaluates the request against Rego policies (tenant-specific, versioned) |
| 5 | **Velocity Limits** | Enforces per-agent rate limits (writes/minute, deletes/minute) |
| 6 | **Circuit Breaker** | Trips on anomalous burst patterns to prevent runaway agents |
| 7 | **HITL Gate** | Suspends high-risk actions for human approval via Aegis mobile companion |

## Cryptographic Identity

- **Ed25519 keypair** — loaded from `sentry_ed25519.key` on startup (auto-generated if missing)
- **EVAR tokens** — Ed25519-signed JWTs issued to agents at registration
- **QR pairing signatures** — the Gateway signs QR payloads so the mobile app can verify authenticity

## Database

PostgreSQL — 15 migrations applied automatically on startup:

```
001_multi_tenant_schema      007_mobile_devices          012_role_mappings
002_ghost_mode_consent       007_swarm_verification      013_scim_operators
003_policy_governance        008_aegis_devices           014_mobile_pqc_columns
004_reasoning_trace          009_pairing_challenges
005_gateway_instances        009_quorum_enforcement
006_semantic_alignment       010_credential_rotation
                             011_federation_config
```

## Key Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/health` | Health check |
| POST | `/v1/agent/register` | Register an agent (returns EVAR token) |
| POST | `/v1/agent/proxy` | Proxy an agent's API call through the 7-layer pipeline |
| POST | `/v1/llm/proxy` | Proxy an agent's LLM call (reasoning trace capture + IPI scan) |
| POST | `/v1/portal/pair/generate` | Generate a QR pairing challenge for Aegis mobile app |
| POST | `/v1/mobile/pair/handshake` | Complete device pairing (Ed25519 + PQC key exchange) |
| POST | `/v1/mobile/heartbeat` | Device heartbeat (returns pending HITL holds) |
| GET | `/v1/portal/devices` | List enrolled devices for a tenant |
| POST | `/v1/mcp` | MCP JSON-RPC 2.0 endpoint for Aegis-0 |

## Build & Run

```bash
cd Sentry_Gateway
go build -o sentry ./cmd/sentry/
./sentry
```

Or via the fleet startup script (recommended):

```bash
./start_fleet.sh
```

## Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `PORT` | `8080` | HTTP listen port |
| `CICADA_POSTGRES_URL` | — | PostgreSQL connection string |
| `CICADA_REDIS_URL` | — | Redis connection string |
| `CICADA_KEY_PATH` | `sentry_ed25519.key` | Path to Ed25519 private key |
| `CICADA_CORE_API_URL` | `http://localhost:8000` | Core API URL for portal auth |
| `GATEWAY_PUBLIC_URL` | auto-detected LAN IP | Public URL embedded in QR codes |
| `CICADA_AES_MASTER_KEY` | — | 256-bit hex key for EVAR encryption |
| `CICADA_MOCK_MODE` | `false` | Skip real LLM calls in development |

## Logs

When run via `start_fleet.sh`, logs are written to `logs/sentry.log`.
