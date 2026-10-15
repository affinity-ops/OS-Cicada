# © 2026 Affinity Ops Ltd. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Research Analyst Crew — CrewAI + Cicada Guard

Multi-agent research team that retrieves information from web sources,
analyzes documents, and produces research reports. All HTTP calls route
through the Cicada Sentry Gateway, and retrieved content is automatically
tagged with provenance metadata for elevated IPI scanning.

Setup:
    1. pip install cicada-guard[crewai] crewai crewai-tools
    2. Copy .env.template to .env and fill in your credentials
    3. python agent.py "Research topic"

Architecture:
    Crew (3 agents) → Cicada SDK → Sentry Gateway → External APIs
         ↓                              ↓
    Research Report            Action Ledger (audit)
"""

import os
import sys
import logging
from dotenv import load_dotenv
from crewai import Agent, Task, Crew, Process

from cicada_guard import CicadaClient
from cicada_guard.adapters.crewai import CicadaCrewTool, CicadaWebScrapeTool, cicada_crew_config

# Load environment
load_dotenv()
logging.basicConfig(level=logging.INFO)

# ── Initialize Cicada client ────────────────────────────────────────────────
client = CicadaClient.from_yaml("cicada.yaml")
health = client.health_check()
print(f"🛡️  Cicada Gateway: {health.get('status', 'unknown')}")

# ── Define tools ────────────────────────────────────────────────────────────

search_tool = CicadaCrewTool(
    name="web-search",
    description="Search the web for information on a topic",
    client=client,
    target_url="https://serpapi.com/search?q={query}",
    method="GET",
    provenance="retrieved",  # Search results are external content
)

scrape_tool = CicadaWebScrapeTool(client=client)

save_document = CicadaCrewTool(
    name="save-document",
    description="Save a document to the internal store",
    client=client,
    target_url="https://api.internal.acme.com/v1/documents/",
    method="POST",
)

# ── Define agents ───────────────────────────────────────────────────────────

researcher = Agent(
    role="Senior Research Analyst",
    goal="Discover and synthesize comprehensive information on the given topic",
    backstory=(
        "You are a meticulous research analyst with expertise in finding "
        "and synthesizing information from diverse sources. You verify claims "
        "against multiple sources before including them in your findings."
    ),
    tools=[search_tool, scrape_tool],
    verbose=True,
    **cicada_crew_config(client),
)

writer = Agent(
    role="Technical Writer",
    goal="Transform research findings into a clear, well-structured report",
    backstory=(
        "You are an experienced technical writer who transforms complex "
        "research into clear, actionable reports. You cite sources and "
        "distinguish between confirmed facts and analysis."
    ),
    tools=[save_document],
    verbose=True,
)

reviewer = Agent(
    role="Quality Reviewer",
    goal="Review reports for accuracy, completeness, and bias",
    backstory=(
        "You are a critical reviewer who checks research reports for "
        "factual errors, logical gaps, and potential bias. You flag "
        "unsupported claims and suggest improvements."
    ),
    verbose=True,
)

# ── Define tasks ────────────────────────────────────────────────────────────

def create_crew(topic: str) -> Crew:
    research_task = Task(
        description=f"Research the following topic thoroughly: {topic}",
        expected_output="A comprehensive research brief with key findings, sources, and data points",
        agent=researcher,
    )

    writing_task = Task(
        description="Write a detailed research report based on the research findings",
        expected_output="A well-structured report with executive summary, key findings, analysis, and recommendations",
        agent=writer,
    )

    review_task = Task(
        description="Review the report for accuracy, completeness, and quality",
        expected_output="A reviewed report with quality assessment and any corrections applied",
        agent=reviewer,
    )

    return Crew(
        agents=[researcher, writer, reviewer],
        tasks=[research_task, writing_task, review_task],
        process=Process.sequential,
        verbose=True,
    )


# ── Run ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    topic = " ".join(sys.argv[1:]) if len(sys.argv) > 1 else "AI agent security in enterprise environments"

    print(f"\n🔬 Research Analyst Crew (Cicada-governed)")
    print(f"   Topic: {topic}")
    print("=" * 50)

    crew = create_crew(topic)
    result = crew.kickoff()

    print(f"\n📋 Report:\n{result}")
