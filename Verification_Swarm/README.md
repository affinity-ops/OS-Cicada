# Verification Swarm

The Verification Swarm is a Python LangGraph pipeline that performs multi-agent semantic verification of AI agent actions. It consumes jobs from the Redis queue, evaluates them using OpenAI-powered LLM agents, and reports verification results back to the Sentry Gateway.

## Architecture

```
Sentry Gateway ──▶ Redis Queue ──▶ Verification Swarm (3 LLM agents)
                                          │
                                          ▼
                                   Sentry Gateway (verdict recorded to action ledger)
```

### Swarm Agents

| Agent | Role |
|-------|------|
| **Semantic Analyst** | Evaluates whether the agent's action aligns with its declared purpose |
| **Risk Assessor** | Scores the action's potential for harm based on target, method, and payload |
| **Consensus Judge** | Synthesises the other agents' assessments into a final approve/flag/block verdict |

## Prerequisites

- Python 3.11+
- OpenAI API key (`OPENAI_API_KEY` env var)
- Redis running and accessible

## Run

```bash
cd Verification_Swarm
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python worker.py
```

Or via the fleet startup script (recommended):

```bash
./start_fleet.sh
```

## Logs

When run via `start_fleet.sh`, logs are written to `logs/swarm.log`.
