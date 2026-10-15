# © 2026 Affinity Ops Ltd. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import logging
import json
from openai import OpenAI

logger = logging.getLogger("ClaimExtractor")


def claim_extraction_node(state: dict) -> dict:
    """
    Extracts atomic, verifiable claims from an agent's capability
    declaration using the TENANT'S OWN API key (BYOK model).

    The OpenAI client is injected into state by the worker before
    the pipeline starts. Cicada never holds a global LLM key.
    """
    client: OpenAI = state.get("openai_client")
    if not client:
        raise RuntimeError("No OpenAI client in state. BYOK client must be injected by the worker.")

    model = state.get("llm_model", "gpt-4o-mini")
    payload = state.get("payload", {})

    prompt = f"""You are a Claim Extraction Agent for an AI agent verification system.
Analyze this agent's capability declaration and extract discrete, testable claims.
Each claim must be independently verifiable.

Agent payload:
{json.dumps(payload, indent=2)}

Return a JSON array of claim strings. Each claim should be a short, specific statement
about what this agent claims to do, what constraints it respects, or what safety
boundaries it operates within. Maximum 15 claims."""

    state.setdefault("reasons", [])

    try:
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": "You are a precise claim extraction system. Extract only factual, testable claims. Return valid JSON array of strings."},
                {"role": "user", "content": prompt},
            ],
            temperature=0.2,
            max_tokens=1000,
        )

        claims = json.loads(response.choices[0].message.content)
        if isinstance(claims, list):
            state["extracted_claims"] = claims
            state["reasons"].append(f"Extracted {len(claims)} atomic claims from capability declaration.")
        else:
            state["extracted_claims"] = []
            state["reasons"].append("Claim extraction returned non-list format.")

    except Exception as e:
        logger.error(f"Claim extraction failed: {e}")
        state["extracted_claims"] = []
        state["reasons"].append(f"Claim extraction error: {str(e)}")

    return state
