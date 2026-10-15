# Saga Executor

The Saga Executor is a Python worker that handles compensating transactions (rollbacks) for the Cicada platform. When an agent action needs to be reversed — due to policy violation, failed verification, or operator denial — the Saga Executor processes the rollback job from the Redis queue.

## Architecture

```
Sentry Gateway ──▶ Redis Queue ──▶ Saga Executor
      │                                  │
      ▼                                  ▼
  Action Ledger ◀────────── Rollback recorded
```

## Run

```bash
cd Saga_Executor
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python saga_worker.py
```

Or via the fleet startup script:

```bash
./start_fleet.sh
```

## Logs

When run via `start_fleet.sh`, logs are written to `logs/saga.log`.
