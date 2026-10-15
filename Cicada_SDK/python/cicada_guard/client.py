# © 2026 Affinity Ops Ltd. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""
cicada_guard.client — Core SDK client for the Cicada Sentry Gateway.

This module provides the main CicadaClient class that wraps all HTTP
communication to route through the Cicada enforcement pipeline.

The client handles:
    - Ed25519 JWT session authentication
    - Automatic X-Cicada-* header injection
    - Content provenance tagging
    - Gateway health checking
    - Shadow Mode testing support
"""

import json
import logging
import os
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urljoin

import requests

from cicada_guard.policy import CicadaPolicy, load_policy
from cicada_guard.retry import (
    CicadaBlockedError,
    CicadaConnectionError,
    CicadaGatewayError,
    CicadaHITLPendingError,
    CicadaRateLimitedError,
    RetryConfig,
    retry_request,
)
from cicada_guard.user_context import UserContext

logger = logging.getLogger("cicada_guard")


class CicadaClient:
    """
    Client for the Cicada Sentry Gateway.

    All outbound HTTP calls are routed through the Gateway, which applies
    the seven-layer enforcement pipeline before proxying to the target API.

    Usage:
        client = CicadaClient.from_yaml("cicada.yaml")
        response = client.proxy_call("POST", "https://api.stripe.com/v1/charges", body={...})
    """

    def __init__(
        self,
        gateway_url: str,
        session_token: str,
        agent_id: str = "",
        tenant_id: str = "",
        policy: Optional[CicadaPolicy] = None,
        timeout: float = 30.0,
        verify_ssl: bool = True,
        retry_config: Optional[RetryConfig] = None,
        default_user_context: Optional[UserContext] = None,
        memory_context: Optional[object] = None,
    ):
        """
        Initialize the Cicada client.

        Args:
            gateway_url: Base URL of the Sentry Gateway (e.g. http://localhost:8080).
            session_token: Ed25519 JWT session token issued during agent registration.
            agent_id: Agent ID from the registry. Auto-extracted from token if empty.
            tenant_id: Tenant ID for multi-tenant isolation.
            policy: Parsed CicadaPolicy object. If provided, enables automatic
                    content provenance tagging and URL validation.
            timeout: Request timeout in seconds.
            verify_ssl: Whether to verify SSL certificates.
            retry_config: Retry configuration for transient failures.
                         Defaults to 3 retries with exponential backoff.
            default_user_context: Default user context to attach to all requests.
                                 Can be overridden per-call.
        """
        self.gateway_url = gateway_url.rstrip("/")
        self.session_token = session_token
        self.agent_id = agent_id
        self.tenant_id = tenant_id
        self.policy = policy
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.retry_config = retry_config or RetryConfig()
        self.default_user_context = default_user_context
        self.memory_context = memory_context

        # Persistent session for connection pooling
        self._session = requests.Session()
        self._session.verify = verify_ssl
        self._session.headers.update(self._base_headers())

    @classmethod
    def from_yaml(
        cls,
        policy_path: str | Path = "cicada.yaml",
        gateway_url: Optional[str] = None,
        session_token: Optional[str] = None,
    ) -> "CicadaClient":
        """
        Create a CicadaClient from a cicada.yaml policy file.

        Reads gateway URL and session token from environment variables
        if not provided explicitly:
            CICADA_GATEWAY_URL (default: http://localhost:8080)
            CICADA_SESSION_TOKEN (required)

        Args:
            policy_path: Path to cicada.yaml file.
            gateway_url: Override gateway URL.
            session_token: Override session token.

        Returns:
            Configured CicadaClient instance.
        """
        policy = load_policy(policy_path)

        gw_url = gateway_url or os.environ.get("CICADA_GATEWAY_URL", "http://localhost:8080")
        token = session_token or os.environ.get("CICADA_SESSION_TOKEN", "")
        if not token:
            raise ValueError(
                "Session token is required. Set CICADA_SESSION_TOKEN environment variable "
                "or pass session_token to from_yaml()."
            )

        # Validate policy and warn on issues
        issues = policy.validate()
        for issue in issues:
            logger.warning("Policy validation: %s", issue)

        return cls(
            gateway_url=gw_url,
            session_token=token,
            agent_id=policy.identity.name,
            policy=policy,
        )

    def _base_headers(self) -> dict[str, str]:
        """Build the standard Cicada headers for every request."""
        headers = {
            "Authorization": f"Bearer {self.session_token}",
            "X-Cicada-Agent-ID": self.agent_id,
            "User-Agent": f"cicada-guard-python/0.1.0",
        }
        if self.tenant_id:
            headers["X-Cicada-Tenant-ID"] = self.tenant_id
        return headers

    def proxy_call(
        self,
        method: str,
        target_url: str,
        body: Optional[dict | str | bytes] = None,
        headers: Optional[dict[str, str]] = None,
        provenance: str = "developer",
        timeout: Optional[float] = None,
        user_context: Optional[UserContext] = None,
        raise_on_block: bool = False,
    ) -> requests.Response:
        """
        Route an HTTP call through the Cicada Sentry Gateway.

        The Gateway applies all seven enforcement layers before proxying
        the call to the target API. The response is inspected by output
        controls before being returned.

        Args:
            method: HTTP method (GET, POST, PUT, PATCH, DELETE).
            target_url: The actual target API URL.
            body: Request body (dict for JSON, str/bytes for raw).
            headers: Additional headers to forward to the target.
            provenance: Content provenance level for the request body.
                        One of: 'system', 'developer', 'user', 'tool_result',
                        'retrieved'. Affects scan sensitivity at the Gateway.
            timeout: Override request timeout.
            user_context: User acting through this agent. Overrides
                         default_user_context for this call.
            raise_on_block: If True, raise CicadaBlockedError on 403
                           and CicadaRateLimitedError on 429 instead of
                           returning the response.

        Returns:
            The response from the target API (after Gateway inspection).

        Raises:
            CicadaBlockedError: If raise_on_block=True and Gateway blocks (403).
            CicadaRateLimitedError: If raise_on_block=True and velocity cap hit (429).
            CicadaConnectionError: If Gateway is unreachable after retries.
        """
        proxy_url = f"{self.gateway_url}/v1/proxy"

        req_headers = {
            "X-Cicada-Target-URL": target_url,
            "X-Cicada-Content-Provenance": provenance,
        }

        # Auto-tag retrieved content if policy has content_tagging enabled
        if self.policy and self.policy.provenance.content_tagging:
            if provenance in ("retrieved", "tool_result", "external", "rag"):
                req_headers["X-Cicada-Content-Provenance"] = provenance

        # Inject user context header
        ctx = user_context or self.default_user_context
        if ctx:
            req_headers.update(ctx.to_headers())

        if headers:
            req_headers.update(headers)

        # Serialize body
        data = None
        if body is not None:
            if isinstance(body, dict):
                data = json.dumps(body)
                req_headers.setdefault("Content-Type", "application/json")
            elif isinstance(body, str):
                data = body.encode("utf-8")
            else:
                data = body

        response = retry_request(
            self._session,
            method=method.upper(),
            url=proxy_url,
            config=self.retry_config,
            data=data,
            headers=req_headers,
            timeout=timeout or self.timeout,
        )

        # Log Gateway enforcement decisions
        if response.status_code == 403:
            logger.warning(
                "Gateway blocked call: %s %s → %s",
                method, target_url, response.text[:200],
            )
            if raise_on_block:
                raise CicadaBlockedError(response)
        elif response.status_code == 429:
            logger.warning(
                "Gateway velocity limit hit: %s %s",
                method, target_url,
            )
            if raise_on_block:
                raise CicadaRateLimitedError(response)
        elif response.status_code == 202:
            logger.info(
                "Gateway HITL suspended: %s %s — awaiting human approval",
                method, target_url,
            )

        # ── Context Rot Prevention: Gateway-to-SDK Flush Feedback Loop ────────
        # When the Sentry Gateway detects a memory-degrading event (injection,
        # skill boundary breach, schema mutation), it signals the SDK to purge
        # contaminated context frames via X-Cicada-Memory-Action response header.
        memory_action = response.headers.get("X-Cicada-Memory-Action")
        if memory_action == "flush":
            flush_reason = response.headers.get(
                "X-Cicada-Flush-Reason", "unknown_governance_trigger"
            )
            logger.warning(
                "Anti-Rot: Gateway commanded memory flush. Reason: %s",
                flush_reason,
            )
            if (
                self.memory_context is not None
                and hasattr(self.memory_context, "flush_active_window")
            ):
                try:
                    self.memory_context.flush_active_window(flush_reason)
                except Exception as flush_err:
                    logger.error("Memory flush error: %s", flush_err)

        return response

    def invoke_skill(
        self,
        skill_name: str,
        target_url: str,
        payload: dict,
        headers: Optional[dict[str, str]] = None,
        user_context: Optional[UserContext] = None,
        raise_on_block: bool = False,
        timeout: Optional[float] = None,
    ) -> requests.Response:
        """
        Execute an agent operation bound to a specific declarative skill contract.

        Injects the X-Cicada-Target-Skill header so the Sentry Gateway resolves
        the target capability against the agent's cached skill graph (Layer 1d).
        The gateway verifies: (1) the skill is declared in cicada.yaml,
        (2) the upstream agent chain is authorised, (3) the payload matches the
        input_schema, and (4) high-criticality skills trigger CIBA holds.

        Args:
            skill_name: The target capability name registered in cicada.yaml tools[].name.
            target_url: Target API URL.
            payload: Structured data payload to forward (validated against input_schema).
            headers: Additional headers.
            user_context: User acting through this agent.
            raise_on_block: If True, raise on 403/429/202.
            timeout: Override request timeout.

        Returns:
            The response from the target API (after Layer 1d skill verification).
        """
        skill_headers = {"X-Cicada-Target-Skill": skill_name}
        if headers:
            skill_headers.update(headers)

        return self.proxy_call(
            method="POST",
            target_url=target_url,
            body=payload,
            headers=skill_headers,
            user_context=user_context,
            raise_on_block=raise_on_block,
            timeout=timeout,
        )

    def proxy_llm_call(
        self,
        messages: list[dict[str, str]],
        model: str = "gpt-4",
        provider_base_url: str = "https://api.openai.com",
        user_context: Optional[UserContext] = None,
        **kwargs: Any,
    ) -> requests.Response:
        """
        Route an LLM API call through the Cicada LLM proxy.

        This enables context window scanning, reasoning trace extraction,
        and memory contamination detection.

        Args:
            messages: LLM messages array (list of {role, content} dicts).
            model: Model identifier.
            provider_base_url: LLM provider base URL.
            user_context: User acting through this agent.
            **kwargs: Additional parameters for the LLM API.

        Returns:
            The LLM response (after Gateway inspection and trace extraction).
        """
        proxy_url = f"{self.gateway_url}/v1/llm/proxy"

        body = {
            "model": model,
            "messages": messages,
            **kwargs,
        }

        headers = {
            "X-Cicada-LLM-Provider": provider_base_url,
            "Content-Type": "application/json",
        }

        # Inject user context header
        ctx = user_context or self.default_user_context
        if ctx:
            headers.update(ctx.to_headers())

        # Use retry with extended timeout for LLM calls
        llm_retry = RetryConfig(
            max_retries=self.retry_config.max_retries,
            backoff_base=self.retry_config.backoff_base * 2,  # LLM calls need longer backoff
            backoff_max=self.retry_config.backoff_max,
        )

        response = retry_request(
            self._session,
            method="POST",
            url=proxy_url,
            config=llm_retry,
            json=body,
            headers=headers,
            timeout=self.timeout * 3,  # LLM calls are slower
        )

        return response

    def health_check(self) -> dict[str, Any]:
        """
        Check the Gateway's health status.

        Returns:
            Dict with gateway status, version, and uptime.
        """
        try:
            response = self._session.get(
                f"{self.gateway_url}/healthz",
                timeout=5.0,
            )
            return response.json()
        except Exception as e:
            return {"status": "unreachable", "error": str(e)}

    def get_agent_status(self) -> dict[str, Any]:
        """
        Retrieve the agent's current status from the Gateway.

        Returns trust score, recent violations, and enforcement state.
        """
        response = self._session.get(
            f"{self.gateway_url}/v1/agent/{self.agent_id}/status",
            timeout=10.0,
        )
        response.raise_for_status()
        return response.json()
