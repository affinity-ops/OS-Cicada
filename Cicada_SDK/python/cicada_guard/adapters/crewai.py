# © 2026 Affinity Ops Ltd. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""
cicada_guard.adapters.crewai — CrewAI integration adapter.

This adapter wraps CrewAI's agent and task execution to route HTTP calls
through the Cicada Sentry Gateway. It provides:

    1. CicadaCrewTool — wraps any CrewAI tool so HTTP calls route through
       the Gateway with full seven-layer enforcement.

    2. cicada_crew_config — helper that generates CrewAI agent configuration
       from a cicada.yaml policy file, ensuring the agent's declared tools
       and permissions align with the governance policy.

Usage:
    from crewai import Agent, Task, Crew
    from cicada_guard import CicadaClient
    from cicada_guard.adapters.crewai import CicadaCrewTool, cicada_crew_config

    client = CicadaClient.from_yaml("cicada.yaml")

    # Wrap tools
    search_tool = CicadaCrewTool(
        name="web-search",
        description="Search the web for information",
        client=client,
        target_url="https://api.search.com/v1/search",
    )

    # Create agent with Cicada governance
    agent = Agent(
        role="Research Analyst",
        tools=[search_tool],
        **cicada_crew_config(client)
    )
"""

import json
import logging
from typing import Any, Optional

from cicada_guard.client import CicadaClient
from cicada_guard.provenance import tag_retrieved, tag_tool_result

logger = logging.getLogger("cicada_guard.crewai")


class CicadaCrewTool:
    """
    A CrewAI-compatible tool that routes HTTP calls through Cicada.

    Each tool wraps a single API endpoint. When the agent invokes the tool,
    the HTTP call routes through the Sentry Gateway's proxy, passing through
    all seven enforcement layers before reaching the target API.

    Usage:
        tool = CicadaCrewTool(
            name="stripe-charges",
            description="Retrieve Stripe charge details",
            client=cicada_client,
            target_url="https://api.stripe.com/v1/charges/{charge_id}",
            method="GET",
        )
        result = tool.run(charge_id="ch_123")
    """

    def __init__(
        self,
        name: str,
        description: str,
        client: CicadaClient,
        target_url: str,
        method: str = "GET",
        provenance: str = "developer",
    ):
        self.name = name
        self.description = description
        self._client = client
        self._target_url = target_url
        self._method = method
        self._provenance = provenance

    def run(self, **kwargs: Any) -> str:
        """Execute the tool through Cicada's enforcement pipeline."""
        # Build the target URL with path parameters
        url = self._target_url
        for key, value in kwargs.items():
            url = url.replace(f"{{{key}}}", str(value))

        # Determine body for write operations
        body = None
        if self._method.upper() in ("POST", "PUT", "PATCH"):
            body = kwargs

        logger.info("Cicada CrewAI tool '%s': %s %s", self.name, self._method, url)

        response = self._client.proxy_call(
            method=self._method,
            target_url=url,
            body=body,
            provenance=self._provenance,
        )

        # Handle Gateway enforcement responses
        if response.status_code == 403:
            return f"[BLOCKED] Cicada Gateway denied this action: {response.text[:200]}"
        elif response.status_code == 429:
            return "[RATE LIMITED] Velocity limit exceeded. Try again later."
        elif response.status_code == 202:
            return "[PENDING] Action submitted for human approval. Awaiting HITL review."

        # Tag the response as tool_result for downstream provenance tracking
        result_text = response.text
        _, tag = tag_tool_result(result_text, tool_name=self.name, source_url=url)
        logger.debug("Tool result tagged: %s (hash: %s)", tag.trust_level, tag.content_hash[:16])

        return result_text

    def __str__(self) -> str:
        return f"CicadaCrewTool({self.name})"


class CicadaWebScrapeTool:
    """
    CrewAI tool for web scraping with automatic content provenance tagging.

    Retrieved web content is automatically tagged as 'retrieved' provenance,
    triggering elevated scan sensitivity at the Gateway. This is critical
    for defending against IPI payloads embedded in web pages.

    Usage:
        scraper = CicadaWebScrapeTool(client=cicada_client)
        content = scraper.run(url="https://example.com/article")
    """

    def __init__(self, client: CicadaClient):
        self.name = "cicada-web-scrape"
        self.description = (
            "Scrape a web page and retrieve its content. Content is automatically "
            "tagged with 'retrieved' provenance for elevated security scanning."
        )
        self._client = client

    def run(self, url: str) -> str:
        """Scrape a URL through Cicada with retrieved provenance tagging."""
        logger.info("Scraping %s with retrieved provenance", url)

        response = self._client.proxy_call(
            method="GET",
            target_url=url,
            provenance="retrieved",  # Elevated scan sensitivity
        )

        if response.status_code == 403:
            return f"[BLOCKED] Content blocked by Cicada: {response.text[:200]}"

        content = response.text
        _, tag = tag_retrieved(content, source_url=url, source_type="web")
        logger.info(
            "Retrieved content tagged: source=%s hash=%s",
            url, tag.content_hash[:16],
        )

        return content


def cicada_crew_config(client: CicadaClient) -> dict[str, Any]:
    """
    Generate CrewAI agent configuration from a CicadaClient's policy.

    Returns a dict of keyword arguments that can be spread into the
    CrewAI Agent constructor to ensure alignment with governance policy.

    Usage:
        agent = Agent(
            role="Analyst",
            tools=[...],
            **cicada_crew_config(client)
        )
    """
    config: dict[str, Any] = {}

    if client.policy:
        policy = client.policy

        # Map agent type to CrewAI verbosity
        if policy.identity.type in ("supervised", "semi-autonomous"):
            config["verbose"] = True

        # Set max iterations based on velocity limits
        if policy.enforcement.velocity.max_writes_per_minute > 0:
            config["max_iter"] = min(
                policy.enforcement.velocity.max_writes_per_minute * 2,
                25,  # CrewAI default max
            )

        # Add governance context to backstory
        governance_note = (
            f"\n\nGOVERNANCE: This agent operates under Cicada governance policy "
            f"'{policy.identity.name}'. All actions are logged to an immutable audit "
            f"ledger. Compliance frameworks: {', '.join(policy.compliance.frameworks) or 'none'}. "
            f"Budget cap: ${policy.compliance.budget_cap_usd or 'unlimited'}."
        )
        config["backstory"] = governance_note

    return config
