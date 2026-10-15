# © 2026 Affinity Ops Ltd. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""
DevOps Automation Agent — Raw Python + Cicada Guard

Infrastructure automation agent with shell access. All destructive
operations (container management, deployments, shell commands) require
HITL approval through the Cicada Gateway.

Setup:
    1. pip install cicada-guard python-dotenv
    2. Copy .env.template to .env and fill in your credentials
    3. python agent.py

Architecture:
    Agent → Cicada SDK → Sentry Gateway (mandatory HITL) → Infrastructure APIs
                              ↓
                    Human Approval (Operator Dashboard)
                              ↓
                    Action Ledger (3-year retention)
"""

import os
import json
import logging
from dotenv import load_dotenv

from cicada_guard import CicadaClient

load_dotenv()
logging.basicConfig(level=logging.INFO)

# ── Initialize Cicada client ────────────────────────────────────────────────
client = CicadaClient.from_yaml("cicada.yaml")
health = client.health_check()
print(f"🛡️  Cicada Gateway: {health.get('status', 'unknown')}")


# ── DevOps operations (all routed through Cicada) ───────────────────────────

def check_system_health() -> dict:
    """Query monitoring API for system health metrics."""
    response = client.proxy_call(
        method="GET",
        target_url="https://api.internal.acme.com/v1/monitoring/health",
        provenance="developer",
    )
    return response.json() if response.status_code == 200 else {"error": response.text}


def list_containers() -> list:
    """List running Docker containers."""
    response = client.proxy_call(
        method="GET",
        target_url="https://api.internal.acme.com/v1/containers/",
        provenance="developer",
    )
    return response.json() if response.status_code == 200 else []


def restart_container(container_id: str) -> str:
    """
    Restart a Docker container.
    ⚠️  This is a destructive operation — requires HITL approval.
    """
    response = client.proxy_call(
        method="POST",
        target_url=f"https://api.internal.acme.com/v1/containers/{container_id}/restart",
        provenance="developer",
    )

    if response.status_code == 202:
        return f"⏳ Container restart submitted for human approval (HITL pending)"
    elif response.status_code == 403:
        return f"❌ Blocked by Cicada: {response.text[:200]}"
    elif response.status_code == 200:
        return f"✅ Container {container_id} restarted successfully"
    else:
        return f"❌ Error: {response.status_code} — {response.text[:200]}"


def execute_command(command: str) -> str:
    """
    Execute a shell command on managed infrastructure.
    ⚠️  This is a CRITICAL destructive operation — always requires HITL.
    """
    response = client.proxy_call(
        method="POST",
        target_url="https://api.internal.acme.com/v1/exec/run",
        body={"command": command, "timeout": 30},
        provenance="developer",
    )

    if response.status_code == 202:
        return f"⏳ Command submitted for human approval: '{command}'"
    elif response.status_code == 403:
        return f"❌ Command blocked by Cicada: {response.text[:200]}"
    elif response.status_code == 200:
        data = response.json()
        return f"✅ Output:\n{data.get('stdout', '')}\n{data.get('stderr', '')}"
    else:
        return f"❌ Error: {response.status_code}"


def trigger_deployment(repo: str, ref: str = "main", environment: str = "staging") -> str:
    """
    Trigger a GitHub deployment.
    ⚠️  Requires HITL approval for production deployments.
    """
    response = client.proxy_call(
        method="POST",
        target_url=f"https://api.github.com/repos/{repo}/deployments",
        body={
            "ref": ref,
            "environment": environment,
            "auto_merge": False,
            "required_contexts": [],
        },
        provenance="developer",
    )

    if response.status_code == 202:
        return f"⏳ Deployment to {environment} submitted for HITL approval"
    elif response.status_code == 201:
        data = response.json()
        return f"✅ Deployment triggered: {data.get('url', 'N/A')}"
    else:
        return f"❌ Deployment failed: {response.text[:200]}"


# ── Interactive CLI ─────────────────────────────────────────────────────────

COMMANDS = {
    "health": ("Check system health", check_system_health),
    "containers": ("List running containers", list_containers),
    "restart": ("Restart a container (requires HITL)", lambda: restart_container(input("  Container ID: "))),
    "exec": ("Execute a shell command (requires HITL)", lambda: execute_command(input("  Command: "))),
    "deploy": ("Trigger a deployment (requires HITL)", lambda: trigger_deployment(
        input("  Repo (owner/repo): "),
        input("  Ref (default: main): ") or "main",
        input("  Environment (staging/production): ") or "staging",
    )),
}


if __name__ == "__main__":
    print("\n⚙️  DevOps Automation Agent (Cicada-governed)")
    print("   ⚠️  Destructive operations require human approval")
    print("=" * 50)

    while True:
        print("\nCommands:")
        for cmd, (desc, _) in COMMANDS.items():
            print(f"  {cmd:12s} — {desc}")
        print(f"  {'quit':12s} — Exit")

        user_input = input("\n> ").strip().lower()
        if user_input in ("quit", "exit", "q"):
            break

        if user_input in COMMANDS:
            _, func = COMMANDS[user_input]
            result = func()
            print(f"\n{json.dumps(result, indent=2) if isinstance(result, (dict, list)) else result}")
        else:
            print(f"❌ Unknown command: {user_input}")
