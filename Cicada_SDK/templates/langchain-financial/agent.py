# © 2026 Affinity Ops Ltd. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Billing Reconciliation Agent — LangChain + Cicada Guard

This agent processes billing reconciliation tasks using Stripe and internal
APIs. All HTTP calls route through the Cicada Sentry Gateway for seven-layer
enforcement, and HITL approval is required for all write operations.

Setup:
    1. pip install cicada-guard[langchain] langchain-openai
    2. Copy .env.template to .env and fill in your credentials
    3. python agent.py

Architecture:
    Agent → Cicada SDK → Sentry Gateway (7 layers) → Stripe/Internal APIs
                              ↓
                    Action Ledger (PostgreSQL)
                              ↓
                    Operator Dashboard (real-time)
"""

import os
import logging
from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from langchain.agents import AgentExecutor, create_openai_tools_agent
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.tools import tool

from cicada_guard import CicadaClient
from cicada_guard.provenance import tag_retrieved, tag_tool_result

# Load environment
load_dotenv()
logging.basicConfig(level=logging.INFO)

# ── Initialize Cicada client from policy ────────────────────────────────────
client = CicadaClient.from_yaml("cicada.yaml")

# Verify gateway connectivity
health = client.health_check()
print(f"🛡️  Cicada Gateway: {health.get('status', 'unknown')}")


# ── Define tools that route through Cicada ──────────────────────────────────

@tool
def get_charge(charge_id: str) -> str:
    """Retrieve a Stripe charge by ID."""
    response = client.proxy_call(
        method="GET",
        target_url=f"https://api.stripe.com/v1/charges/{charge_id}",
        provenance="developer",
    )
    return response.text


@tool
def create_refund(charge_id: str, amount: int, reason: str = "requested_by_customer") -> str:
    """
    Create a refund for a Stripe charge. This is a destructive operation
    that requires HITL approval via the Cicada Gateway.
    """
    response = client.proxy_call(
        method="POST",
        target_url="https://api.stripe.com/v1/refunds",
        body={
            "charge": charge_id,
            "amount": amount,
            "reason": reason,
        },
        provenance="developer",
    )

    if response.status_code == 202:
        return "⏳ Refund submitted for human approval. Awaiting HITL review."
    elif response.status_code == 403:
        return f"❌ Refund blocked by Cicada: {response.text}"

    return response.text


@tool
def get_invoices(customer_id: str) -> str:
    """Query internal invoice database for a customer."""
    response = client.proxy_call(
        method="GET",
        target_url=f"https://api.internal.acme.com/v1/invoices/?customer={customer_id}",
        provenance="developer",
    )
    return response.text


@tool
def generate_report(report_type: str, period: str) -> str:
    """Generate a financial reconciliation report."""
    response = client.proxy_call(
        method="POST",
        target_url="https://api.internal.acme.com/v1/reports/",
        body={
            "type": report_type,
            "period": period,
        },
        provenance="developer",
    )
    return response.text


# ── Configure LangChain agent ──────────────────────────────────────────────

# Route LLM calls through Cicada's LLM proxy for context window scanning
# and reasoning trace extraction.
llm = ChatOpenAI(
    model="gpt-4",
    openai_api_base=f"{client.gateway_url}/v1/llm/proxy",
    openai_api_key=os.environ.get("OPENAI_API_KEY", ""),
)

prompt = ChatPromptTemplate.from_messages([
    ("system", """You are a billing reconciliation assistant for Acme Corp.
Your responsibilities:
- Look up charges and invoices when asked
- Process refunds when authorized (requires human approval)
- Generate financial reports

Always verify charge details before processing refunds.
Never process refunds over $1,000 without explicit manager authorization.
Report any suspicious billing patterns immediately."""),
    ("human", "{input}"),
    ("placeholder", "{agent_scratchpad}"),
])

tools = [get_charge, create_refund, get_invoices, generate_report]
agent = create_openai_tools_agent(llm, tools, prompt)
executor = AgentExecutor(agent=agent, tools=tools, verbose=True)


# ── Run ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n🏦 Billing Reconciliation Agent (Cicada-governed)")
    print("=" * 50)

    while True:
        user_input = input("\n> ")
        if user_input.lower() in ("quit", "exit", "q"):
            break

        result = executor.invoke({"input": user_input})
        print(f"\n📋 {result['output']}")
