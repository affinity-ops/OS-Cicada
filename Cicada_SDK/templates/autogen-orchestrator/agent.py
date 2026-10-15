# © 2026 Affinity Ops Ltd. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""
AutoGen Multi-Agent Orchestrator — AutoGen + Cicada Guard

Multi-agent orchestration hub that coordinates sub-agents for complex
data analysis tasks. All HTTP calls from all agents route through the
Cicada Sentry Gateway for unified enforcement and audit.

Setup:
    1. pip install cicada-guard pyautogen python-dotenv
    2. Copy .env.template to .env and fill in your credentials
    3. python agent.py "Analyze Q1 revenue trends"

Architecture:
    Orchestrator → Sub-agents → Cicada SDK → Sentry Gateway → APIs
         ↓              ↓             ↓
    Task coordination   Tool calls   7-layer enforcement
                                          ↓
                              Unified Action Ledger (all agents)
"""

import os
import sys
import logging
from dotenv import load_dotenv

from cicada_guard import CicadaClient

load_dotenv()
logging.basicConfig(level=logging.INFO)

# ── Initialize Cicada client ────────────────────────────────────────────────
client = CicadaClient.from_yaml("cicada.yaml")
health = client.health_check()
print(f"🛡️  Cicada Gateway: {health.get('status', 'unknown')}")

# ── Cicada-governed tool functions ──────────────────────────────────────────

def execute_code(code: str) -> str:
    """Execute Python code in a sandboxed environment via Cicada."""
    response = client.proxy_call(
        method="POST",
        target_url="https://api.internal.acme.com/v1/sandbox/execute",
        body={"code": code, "language": "python", "timeout": 30},
        provenance="developer",
    )
    if response.status_code == 202:
        return "⏳ Code execution submitted for HITL review"
    elif response.status_code == 403:
        return f"❌ Blocked: {response.text[:200]}"
    return response.json().get("output", response.text)


def query_warehouse(sql: str) -> str:
    """Query the data warehouse via Cicada."""
    response = client.proxy_call(
        method="POST",
        target_url="https://api.internal.acme.com/v1/warehouse/query",
        body={"query": sql, "format": "json", "limit": 1000},
        provenance="developer",
    )
    if response.status_code == 403:
        return f"❌ Blocked: {response.text[:200]}"
    return response.text


def save_artifact(name: str, content: str, artifact_type: str = "report") -> str:
    """Save an analysis artifact via Cicada."""
    response = client.proxy_call(
        method="POST",
        target_url="https://api.internal.acme.com/v1/artifacts/",
        body={"name": name, "content": content, "type": artifact_type},
        provenance="developer",
    )
    if response.status_code in (200, 201):
        return f"✅ Artifact saved: {name}"
    return f"❌ Save failed: {response.text[:200]}"


def fetch_external_data(source: str, endpoint: str) -> str:
    """Fetch data from external APIs with 'retrieved' provenance."""
    url_map = {
        "worldbank": f"https://api.worldbank.org/v2/{endpoint}?format=json",
        "census": f"https://api.census.gov/{endpoint}",
    }
    url = url_map.get(source, endpoint)

    response = client.proxy_call(
        method="GET",
        target_url=url,
        provenance="retrieved",  # External data — elevated scan sensitivity
    )
    if response.status_code == 403:
        return f"❌ Blocked: {response.text[:200]}"
    return response.text


# ── AutoGen configuration ─────────────────────────────────────────────────

try:
    import autogen

    # LLM configuration — routed through Cicada's LLM proxy
    llm_config = {
        "config_list": [{
            "model": "gpt-4",
            "base_url": f"{client.gateway_url}/v1/llm/proxy",
            "api_key": os.environ.get("OPENAI_API_KEY", ""),
        }],
        "timeout": 120,
    }

    # ── Define agents ────────────────────────────────────────────────────

    orchestrator = autogen.AssistantAgent(
        name="orchestrator",
        system_message="""You are the lead analyst orchestrating a data analysis team.
Your responsibilities:
- Break down complex analysis tasks into sub-tasks
- Assign sub-tasks to the appropriate specialist agent
- Synthesize results into a coherent final report
- Ensure all findings are data-driven and properly sourced

GOVERNANCE: All your actions are logged to Cicada's immutable audit ledger.""",
        llm_config=llm_config,
    )

    data_analyst = autogen.AssistantAgent(
        name="data_analyst",
        system_message="""You are a data analyst specializing in SQL queries and statistical analysis.
Use the query_warehouse function to run SQL queries.
Use the execute_code function to run Python analysis code.
Always validate your results before reporting.""",
        llm_config=llm_config,
    )

    report_writer = autogen.AssistantAgent(
        name="report_writer",
        system_message="""You are a report writer who creates clear, executive-ready analysis reports.
Synthesize the team's findings into a structured report with:
- Executive summary
- Key metrics and trends
- Data visualizations (describe them)
- Recommendations
Use save_artifact to store the final report.""",
        llm_config=llm_config,
    )

    user_proxy = autogen.UserProxyAgent(
        name="user",
        human_input_mode="NEVER",
        max_consecutive_auto_reply=10,
        code_execution_config=False,
        function_map={
            "execute_code": execute_code,
            "query_warehouse": query_warehouse,
            "save_artifact": save_artifact,
            "fetch_external_data": fetch_external_data,
        },
    )

    def run_analysis(task: str):
        """Run a multi-agent analysis task."""
        print(f"\n🔬 AutoGen Orchestrator (Cicada-governed)")
        print(f"   Task: {task}")
        print("=" * 50)

        group_chat = autogen.GroupChat(
            agents=[user_proxy, orchestrator, data_analyst, report_writer],
            messages=[],
            max_round=15,
        )
        manager = autogen.GroupChatManager(groupchat=group_chat, llm_config=llm_config)
        user_proxy.initiate_chat(manager, message=task)


except ImportError:
    def run_analysis(task: str):
        print("❌ AutoGen is not installed. Install with: pip install pyautogen")
        print(f"\nTask was: {task}")
        print("\nIn the meantime, here's what the Cicada-governed tools can do:")
        print(f"  query_warehouse: {query_warehouse('SELECT 1')}")
        print(f"  save_artifact: {save_artifact('test', 'hello world')}")


# ── Run ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    task = " ".join(sys.argv[1:]) or "Analyze Q1 2026 revenue trends across all product lines"
    run_analysis(task)
