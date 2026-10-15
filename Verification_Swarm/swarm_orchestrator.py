# © 2026 Affinity Ops Ltd. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import logging
import os
import json
from langgraph.graph import StateGraph, END
from openai import OpenAI

from agents.claim_extractor import claim_extraction_node
from agents.sandbox_interactor import sandbox_interaction_node
from agents.adversarial_editor import adversarial_evaluation_node
from agents.meta_cognitive import intention_evaluator_node
from agents.model_vulnerability_scanner import model_vulnerability_node

logger = logging.getLogger("SwarmOrchestrator")
logging.basicConfig(level=logging.INFO, format="%(asctime)s - [%(name)s] %(message)s")

# Confidence threshold — below this, the agent action is blocked.
CONFIDENCE_THRESHOLD = float(os.environ.get("CICADA_SWARM_THRESHOLD", "0.6"))

# Whether to include model vulnerability scanning in the DAG.
# Disabled by default to avoid extra LLM calls unless opted-in.
VULN_SCANNING_ENABLED = os.environ.get("CICADA_SWARM_VULN_SCANNING", "true").lower() == "true"


def factual_verification_node(state: dict) -> dict:
    """
    Cross-references extracted claims against known factual constraints.

    Phase 1: Rule-based heuristics for known dangerous patterns.
    Phase 2: RAG pipeline with enterprise knowledge base lookups.
    """
    claims = state.get("extracted_claims", [])
    state.setdefault("reasons", [])

    dangerous_claims = {"admin_override", "root_access", "schema_modify", "delete_all", "truncate"}
    flagged = [c for c in claims if c.lower().replace(" ", "_") in dangerous_claims]

    if flagged:
        state["factual_score"] = 0.2
        state["reasons"].append(f"Factual: Dangerous claims detected: {flagged}")
    elif len(claims) == 0:
        state["factual_score"] = 0.5
        state["reasons"].append("Factual: No claims extracted — cannot verify.")
    else:
        state["factual_score"] = 0.85
        state["reasons"].append(f"Factual: {len(claims)} claims verified against ruleset.")

    return state


def judge_node(state: dict) -> dict:
    """
    Final arbitration. Weighted composite score from all verification agents.

    When model vulnerability scanning is enabled, the judge includes the
    vulnerability_score with its own weight. Weights are rebalanced to sum to 1.0.
    """
    # Base weights (without vulnerability scanning) — sum to 1.0
    base_weights = {
        "adversarial_score": 0.30,
        "sandbox_score": 0.25,
        "factual_score": 0.25,
        "intent_score": 0.20,
    }

    # Extended weights (with vulnerability scanning) — sum to 1.0
    # Adversarial remains highest. Vulnerability scanner gets meaningful weight
    # because it tests the model itself, not just the agent's payload.
    extended_weights = {
        "adversarial_score": 0.25,
        "sandbox_score": 0.20,
        "factual_score": 0.20,
        "intent_score": 0.15,
        "vulnerability_score": 0.20,
    }

    # Use extended weights if vulnerability scanning ran
    weights = extended_weights if "vulnerability_score" in state else base_weights

    composite = 0.0
    for key, weight in weights.items():
        score = state.get(key, 0.5)
        composite += score * weight

    state["composite_confidence_score"] = round(composite, 4)
    state["verdict"] = "ALLOW" if composite >= CONFIDENCE_THRESHOLD else "BLOCK"

    state.setdefault("reasons", []).append(
        f"Judge: Composite={composite:.4f} (threshold={CONFIDENCE_THRESHOLD}) -> {state['verdict']}"
        + (f" [vuln_scanning={'ON' if 'vulnerability_score' in state else 'OFF'}]" if VULN_SCANNING_ENABLED else "")
    )

    logger.info(f"Verdict: {state['verdict']} (score={composite:.4f})")
    return state


def build_verification_graph() -> StateGraph:
    """Constructs the LangGraph DAG for the multi-agent verification swarm."""
    graph = StateGraph(dict)

    graph.add_node("claim", claim_extraction_node)
    graph.add_node("sandbox", sandbox_interaction_node)
    graph.add_node("adversarial", adversarial_evaluation_node)
    graph.add_node("factual", factual_verification_node)
    graph.add_node("intent", intention_evaluator_node)
    graph.add_node("judge", judge_node)

    graph.set_entry_point("claim")
    graph.add_edge("claim", "sandbox")
    graph.add_edge("sandbox", "adversarial")
    graph.add_edge("adversarial", "factual")
    graph.add_edge("factual", "intent")

    if VULN_SCANNING_ENABLED:
        graph.add_node("vulnerability", model_vulnerability_node)
        graph.add_edge("intent", "vulnerability")
        graph.add_edge("vulnerability", "judge")
        logger.info("Model vulnerability scanning node ENABLED in DAG")
    else:
        graph.add_edge("intent", "judge")
        logger.info("Model vulnerability scanning node DISABLED")

    graph.add_edge("judge", END)

    return graph.compile()


# Pre-compile the graph at module load
verification_pipeline = build_verification_graph()


def run_verification_cycle(payload: dict, openai_client: OpenAI, llm_model: str = "gpt-4o-mini") -> dict:
    """
    Execute the full swarm verification pipeline on an agent payload.

    Args:
        payload: The agent's action payload to verify
        openai_client: A tenant-scoped BYOK OpenAI client (short-lived)
        llm_model: The LLM model to use for this verification cycle

    Returns:
        Verification result dict with verdict, scores, and reasons
    """
    initial_state = {
        "payload": payload,
        "openai_client": openai_client,
        "llm_model": llm_model,
        "reasons": [],
    }

    result = verification_pipeline.invoke(initial_state)

    scores = {
        "adversarial": result.get("adversarial_score"),
        "sandbox": result.get("sandbox_score"),
        "factual": result.get("factual_score"),
        "intent": result.get("intent_score"),
    }

    # Include vulnerability score and findings if scanning was enabled
    if "vulnerability_score" in result:
        scores["vulnerability"] = result.get("vulnerability_score")

    output = {
        "verdict": result.get("verdict", "BLOCK"),
        "composite_confidence_score": result.get("composite_confidence_score", 0.0),
        "reasons": result.get("reasons", []),
        "scores": scores,
    }

    if "vulnerability_findings" in result:
        output["vulnerability_findings"] = result.get("vulnerability_findings", [])

    return output

