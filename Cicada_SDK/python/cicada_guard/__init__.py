# © 2026 Affinity Ops Ltd. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Cicada Guard — Python SDK for the Cicada Governance Platform.

This package provides everything a Python-based AI agent needs to operate
within Cicada's seven-layer enforcement pipeline:

    pip install cicada-guard

Quick start:

    from cicada_guard import CicadaClient

    client = CicadaClient.from_yaml("cicada.yaml")
    
    # All subsequent HTTP calls route through the Sentry Gateway
    response = client.proxy_call(
        method="POST",
        target_url="https://api.stripe.com/v1/charges",
        body={"amount": 2000, "currency": "usd"},
        provenance="developer",  # auto-sets X-Cicada-Content-Provenance
    )

User context (delegated actions):

    from cicada_guard import CicadaClient, UserContext

    client = CicadaClient.from_yaml("cicada.yaml")
    user = UserContext.from_oauth_token(user_access_token)

    # "Agent X on behalf of User Y" in the action ledger
    response = client.proxy_call(
        method="POST",
        target_url="https://api.stripe.com/v1/charges",
        body={"amount": 2000, "currency": "usd"},
        user_context=user,
    )

Architecture:
    This SDK does NOT replace the agent's LLM framework (LangChain, CrewAI, etc.).
    It wraps the HTTP layer so that all outbound calls route through the Cicada
    Sentry Gateway, carrying the agent's Ed25519 session token, content provenance
    headers, and EVAR identity metadata.

    Framework-specific adapters (langchain, crewai) are in the adapters/ directory.
"""

__version__ = "0.2.0"

from cicada_guard.client import CicadaClient
from cicada_guard.policy import CicadaPolicy, load_policy
from cicada_guard.retry import (
    CicadaBlockedError,
    CicadaConnectionError,
    CicadaGatewayError,
    CicadaHITLPendingError,
    CicadaRateLimitedError,
    RetryConfig,
)
from cicada_guard.user_context import UserContext

__all__ = [
    "CicadaClient",
    "CicadaPolicy",
    "load_policy",
    "RetryConfig",
    "UserContext",
    "CicadaGatewayError",
    "CicadaBlockedError",
    "CicadaRateLimitedError",
    "CicadaHITLPendingError",
    "CicadaConnectionError",
]
