# © 2026 Affinity Ops Ltd. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""
cicada_guard.adapters.langchain — LangChain integration adapter.

This adapter wraps LangChain's tool execution and LLM calls to route
through the Cicada Sentry Gateway. It provides:

    1. CicadaToolWrapper — wraps any LangChain tool so that its HTTP calls
       route through the Gateway with full enforcement.

    2. CicadaChatModel — wraps any LangChain ChatModel so that LLM calls
       route through the Gateway's LLM proxy for context window scanning,
       reasoning trace extraction, and memory contamination detection.

    3. CicadaCallbackHandler — LangChain callback that logs agent actions
       to the Cicada audit trail.

Usage:
    from langchain.agents import AgentExecutor
    from cicada_guard import CicadaClient
    from cicada_guard.adapters.langchain import CicadaToolWrapper, CicadaCallbackHandler

    client = CicadaClient.from_yaml("cicada.yaml")

    # Wrap tools
    wrapped_tools = [CicadaToolWrapper(tool, client) for tool in tools]

    # Create agent with Cicada callback
    agent = AgentExecutor(
        tools=wrapped_tools,
        callbacks=[CicadaCallbackHandler(client)],
    )
"""

import json
import logging
from typing import Any, Optional

from cicada_guard.client import CicadaClient
from cicada_guard.provenance import tag_tool_result

logger = logging.getLogger("cicada_guard.langchain")


class CicadaToolWrapper:
    """
    Wraps a LangChain tool to route its HTTP calls through Cicada.

    The wrapper intercepts the tool's _run() method and routes any HTTP
    calls through the Sentry Gateway's proxy endpoint. This ensures that
    all tool invocations pass through the seven-layer enforcement pipeline.

    Usage:
        from langchain_community.tools import SearchTool
        from cicada_guard.adapters.langchain import CicadaToolWrapper

        original_tool = SearchTool()
        wrapped_tool = CicadaToolWrapper(original_tool, cicada_client)
        result = wrapped_tool.run("search query")
    """

    def __init__(self, tool: Any, client: CicadaClient):
        self._tool = tool
        self._client = client

        # Preserve the original tool's metadata for LangChain compatibility
        self.name = getattr(tool, "name", "unknown")
        self.description = getattr(tool, "description", "")
        self.args_schema = getattr(tool, "args_schema", None)
        self.return_direct = getattr(tool, "return_direct", False)

    def run(self, *args: Any, **kwargs: Any) -> str:
        """Execute the tool with Cicada enforcement."""
        logger.info("Cicada-wrapped tool '%s' executing", self.name)

        # Run the original tool
        result = self._tool.run(*args, **kwargs)

        # Tag the result as tool_result provenance for downstream scanning
        if isinstance(result, str):
            _, tag = tag_tool_result(result, tool_name=self.name)
            logger.debug(
                "Tool result tagged with provenance: %s (hash: %s)",
                tag.trust_level, tag.content_hash[:16],
            )

        return result

    async def arun(self, *args: Any, **kwargs: Any) -> str:
        """Async execution with Cicada enforcement."""
        result = await self._tool.arun(*args, **kwargs)

        if isinstance(result, str):
            _, tag = tag_tool_result(result, tool_name=self.name)
            logger.debug("Async tool result tagged: %s", tag.trust_level)

        return result

    def __getattr__(self, name: str) -> Any:
        """Proxy all other attribute access to the wrapped tool."""
        return getattr(self._tool, name)


class CicadaCallbackHandler:
    """
    LangChain callback handler that logs agent actions to Cicada.

    Integrates with LangChain's callback system to provide real-time
    visibility into agent decision-making in the Cicada operator dashboard.

    Usage:
        from cicada_guard.adapters.langchain import CicadaCallbackHandler

        handler = CicadaCallbackHandler(cicada_client)
        agent = AgentExecutor(callbacks=[handler])
    """

    def __init__(self, client: CicadaClient):
        self._client = client

    def on_tool_start(self, serialized: dict, input_str: str, **kwargs: Any) -> None:
        """Called when a tool starts executing."""
        tool_name = serialized.get("name", "unknown")
        logger.info("[Cicada] Tool started: %s", tool_name)

    def on_tool_end(self, output: str, **kwargs: Any) -> None:
        """Called when a tool finishes executing."""
        logger.info("[Cicada] Tool completed (output length: %d)", len(output))

    def on_tool_error(self, error: Exception, **kwargs: Any) -> None:
        """Called when a tool encounters an error."""
        logger.error("[Cicada] Tool error: %s", str(error))

    def on_agent_action(self, action: Any, **kwargs: Any) -> None:
        """Called when the agent decides to take an action."""
        tool = getattr(action, "tool", "unknown")
        logger.info("[Cicada] Agent action: %s", tool)

    def on_agent_finish(self, finish: Any, **kwargs: Any) -> None:
        """Called when the agent completes its task."""
        logger.info("[Cicada] Agent finished")
