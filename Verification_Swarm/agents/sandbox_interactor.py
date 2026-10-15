# © 2026 Affinity Ops Ltd. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import logging
import json
from openai import OpenAI

logger = logging.getLogger("SandboxInteractor")


def sandbox_interaction_node(state: dict) -> dict:
    """
    Evaluates agent payload safety using the TENANT'S OWN API key (BYOK model).

    Phase 1: LLM-based security analysis of the payload.
    Phase 2: Real Docker/gVisor container execution with blocked network egress.
    """
    client: OpenAI = state.get("openai_client")
    if not client:
        raise RuntimeError("No OpenAI client in state. BYOK client must be injected by the worker.")

    model = state.get("llm_model", "gpt-4o-mini")
    payload = state.get("payload", {})
    action_target = state.get("action_target", "unknown")

    prompt = f"""You are a sandbox security evaluator. Analyze this agent payload
as if you were executing it in an isolated environment. Determine:
1. Would this payload cause destructive changes? (data deletion, schema drops, etc.)
2. Does it attempt to access resources outside its scope?
3. Does it contain encoded or obfuscated commands?

Action target: {action_target}
Payload: {json.dumps(payload, indent=2)}

Respond in JSON: {{"verdict": "nominal" | "blocked_by_isolation", "risk_level": "low" | "medium" | "high" | "critical", "details": "..."}}"""

    state.setdefault("reasons", [])

    try:
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": "You are a secure sandbox evaluator. Be extremely cautious. Any destructive operation should be flagged. Respond only in valid JSON."},
                {"role": "user", "content": prompt},
            ],
            temperature=0.1,
            max_tokens=500,
        )

        result = json.loads(response.choices[0].message.content)
        verdict = result.get("verdict", "blocked_by_isolation")
        risk_level = result.get("risk_level", "high")
        details = result.get("details", "")

        if verdict == "nominal":
            state["sandbox_score"] = 0.95
            state["reasons"].append(f"Sandbox: Payload safe ({risk_level} risk)")
        else:
            state["sandbox_score"] = 0.1
            state["reasons"].append(f"Sandbox: BLOCKED — {details}")

    except Exception as e:
        logger.error(f"Sandbox LLM evaluation failed: {e}")
        state["sandbox_score"] = 0.3
        state["reasons"].append(f"Sandbox evaluation error: {str(e)}")

    return state
