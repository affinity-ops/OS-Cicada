# Shadow Sandbox

The Shadow Sandbox is a Go binary that provides a **deceptive isolation environment** for agents placed into Ghost Mode by the Sentry Gateway. When an agent is flagged as suspicious — via Aegis-0 MCP command, operator dashboard action, or automatic violation threshold (≥3 violations in 5 minutes) — its outbound API calls are silently rerouted to this sandbox instead of the real target API.

The agent receives **plausible-looking synthetic responses** shaped to match the target API (Stripe, OpenAI, SendGrid, GitHub, Slack, Twilio, HubSpot) and cannot detect it has been diverted. Every intercepted request is recorded and analysed for behavioural anomalies.

## Port

**9090**

## Purpose

- Receives diverted requests from ghost-mode agents via the Gateway's `handleGhostProxy()` function
- Returns API-specific synthetic responses (7 built-in generators + generic fallback) so the agent never knows it is being observed
- Scores every intercepted request against 7 deterministic anomaly detection rules (destructive SQL, SQL injection, credential exfiltration, prompt injection, bulk email extraction, base64 exfiltration, oversized body)
- Records all intercepted traffic to an append-only SQLite database for operator review
- Reports high-scoring anomalies (≥0.70) to the Sentry Gateway's gossip endpoint for real-time operator visibility; scores ≥0.85 trigger automatic quarantine via the gossip mesh

## Activation Methods

1. **Manual (Aegis-0 MCP):** The `engage_ghost_mode` tool sets a Redis key `cicada:ghost:{agentID}` with a 4-hour TTL
2. **Manual (Operator Dashboard):** The `toggleShadowMode` API endpoint activates/releases ghost mode for selected agents
3. **Automatic (Violation Threshold):** `ghostmode.RecordViolation()` auto-activates when an agent accumulates ≥3 violations within 5 minutes

## Run

```bash
cd Shadow_Sandbox
go build -o sandbox ./cmd/server
SANDBOX_PORT=9090 ./sandbox
```

Or via the fleet startup script:

```bash
./start_fleet.sh
```

## Environment

| Variable | Default | Purpose |
|---|---|---|
| `SANDBOX_PORT` | `9090` | HTTP listen port |
| `SANDBOX_DB_PATH` | `/data/sandbox.db` | SQLite database for observation records |
| `CICADA_GATEWAY_GOSSIP_URL` | `http://localhost:8080/v1/sandbox/report` | Gateway endpoint for anomaly reports |

## Endpoints

| Endpoint | Method | Purpose |
|---|---|---|
| `/health` | GET | Health check (used by `start_fleet.sh` and Docker) |
| `/sandbox/proxy` | POST | Receives diverted agent requests, analyses them, returns fake responses |
| `/sandbox/events` | GET | Returns last 100 sandbox events for the operator dashboard |

## Logs

When run via `start_fleet.sh`, logs are written to `logs/shadow_sandbox.log`.
