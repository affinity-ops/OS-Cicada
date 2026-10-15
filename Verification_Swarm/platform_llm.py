# © 2026 Affinity Ops Ltd. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Platform LLM Provider — Cicada's own internal monitoring agent key only.

Cicada is a fully BYOK platform. All tenant workloads — including the
Verification Swarm — run against the tenant's own stored API key via
byok_provider.py. Cicada incurs zero LLM costs from tenant operations.

This module exists for ONE purpose only: Aegis-0, Cicada's own internal
monitoring agent that watches the platform for the operator. Aegis-0 is
Cicada's infrastructure, not a tenant workload, so Cicada pays for it.

OpenRouter gives a single endpoint with ordered model fallback:
  Primary:  openai/gpt-4o-mini
  Fallback: anthropic/claude-haiku-4-5-20251001
If the primary model is unavailable, OpenRouter routes to the fallback
automatically without the caller changing anything.

DO NOT use this for tenant verification jobs. Use byok_provider.py for those.
"""
import logging
import os
from openai import OpenAI

logger = logging.getLogger("PlatformLLM")

OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"

# Ordered model preference. OpenRouter routes to the first available model.
# Override via env vars to swap models without a code change.
PRIMARY_MODEL  = os.environ.get("CICADA_LLM_PRIMARY_MODEL",  "openai/gpt-4o-mini")
FALLBACK_MODEL = os.environ.get("CICADA_LLM_FALLBACK_MODEL", "anthropic/claude-haiku-4-5-20251001")


def get_platform_client() -> OpenAI:
    """
    Return a short-lived OpenAI-compatible client pointed at OpenRouter.
    Uses Cicada's own platform API key — never a tenant key.
    """
    api_key = os.environ.get("CICADA_OPENROUTER_API_KEY", "")
    if not api_key:
        raise RuntimeError(
            "CICADA_OPENROUTER_API_KEY is not set. "
            "Set this in the platform .env to enable the Verification Swarm."
        )
    return OpenAI(
        api_key=api_key,
        base_url=OPENROUTER_BASE_URL,
        default_headers={
            # OpenRouter uses these headers for routing analytics — optional but useful
            "HTTP-Referer": "https://cicada.ai",
            "X-Title": "Cicada Verification Swarm",
        },
    )


def get_model() -> str:
    """
    Returns the primary model name for chat completions.
    Pass this as the `model` parameter. If it fails, OpenRouter
    automatically tries FALLBACK_MODEL before returning an error.
    """
    return PRIMARY_MODEL


def get_models_with_fallback() -> list[str]:
    """
    Returns the ordered [primary, fallback] list for use with OpenRouter's
    `models` extra_body parameter, which enables explicit multi-model routing.
    Use this when you want guaranteed fallback behaviour declared at call time.
    """
    return [PRIMARY_MODEL, FALLBACK_MODEL]
