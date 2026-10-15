# © 2026 Affinity Ops Ltd. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import logging
import json
import numpy as np
from openai import OpenAI

logger = logging.getLogger("MetaCognitive")

ANOMALY_THRESHOLD = 0.35


def intention_evaluator_node(state: dict) -> dict:
    """
    Meta-Cognitive agent that monitors the verification swarm for
    groupthink and convergence artifacts using embedding similarity.

    Uses the TENANT'S OWN API key (BYOK model) for embedding generation.

    If attack strategy diversity drops below the anomaly threshold,
    this agent flags the swarm for intervention and recommends
    diversifying the adversarial approach.
    """
    client: OpenAI = state.get("openai_client")
    if not client:
        raise RuntimeError("No OpenAI client in state. BYOK client must be injected by the worker.")

    reasons_so_far = state.get("reasons", [])

    if len(reasons_so_far) < 2:
        state["intent_score"] = 0.5
        state.setdefault("reasons", []).append("Meta-Cognitive: Insufficient data for convergence analysis.")
        return state

    try:
        response = client.embeddings.create(
            model="text-embedding-3-small",
            input=reasons_so_far,
        )

        vectors = [np.array(d.embedding) for d in response.data]

        # Compute pairwise cosine similarity to detect groupthink
        similarities = []
        for i in range(len(vectors)):
            for j in range(i + 1, len(vectors)):
                cos_sim = np.dot(vectors[i], vectors[j]) / (
                    np.linalg.norm(vectors[i]) * np.linalg.norm(vectors[j])
                )
                similarities.append(cos_sim)

        avg_similarity = float(np.mean(similarities)) if similarities else 0.0
        diversity_score = 1.0 - avg_similarity

        if diversity_score < ANOMALY_THRESHOLD:
            state["intent_score"] = 0.4
            state.setdefault("reasons", []).append(
                f"Meta-Cognitive: WARNING — Swarm convergence detected "
                f"(diversity={diversity_score:.3f}, threshold={ANOMALY_THRESHOLD}). "
                f"Recommend diversifying adversarial strategy."
            )
        else:
            state["intent_score"] = 0.85
            state.setdefault("reasons", []).append(
                f"Meta-Cognitive: Strategy diversity healthy "
                f"(diversity={diversity_score:.3f})."
            )

    except Exception as e:
        logger.error(f"Meta-cognitive evaluation failed: {e}")
        state["intent_score"] = 0.5
        state.setdefault("reasons", []).append(f"Meta-cognitive error: {str(e)}")

    return state
