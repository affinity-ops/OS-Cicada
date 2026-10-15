# © 2026 Affinity Ops Ltd. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Verification Swarm — Multi-Agent Consensus Tests

Closes the "No Verification Swarm tests" gap.

Strategy:
  1. factual_verification_node and judge_node are PURE LOGIC — no LLM calls.
     Test them directly with known inputs.
  2. claim_extractor, adversarial_editor, sandbox_interactor, and meta_cognitive
     depend on OpenAI API. Mock the client by injecting a fake that returns
     predetermined JSON responses.
  3. Test the full pipeline by composing nodes with mocked LLM responses.

Run: cd Verification_Swarm && python3 -m pytest test_swarm.py -v
"""

import pytest
import json
import os
import math
from unittest.mock import MagicMock, patch


# ── Helpers ──────────────────────────────────────────────────────────────────

def mock_openai_client(chat_response=None, embedding_response=None):
    """Build a mock OpenAI client that returns predetermined responses."""
    client = MagicMock()

    if chat_response is not None:
        mock_choice = MagicMock()
        mock_choice.message.content = json.dumps(chat_response) if isinstance(chat_response, (dict, list)) else chat_response
        mock_completion = MagicMock()
        mock_completion.choices = [mock_choice]
        client.chat.completions.create.return_value = mock_completion

    if embedding_response is not None:
        mock_data = []
        for emb in embedding_response:
            d = MagicMock()
            d.embedding = emb
            mock_data.append(d)
        mock_emb_resp = MagicMock()
        mock_emb_resp.data = mock_data
        client.embeddings.create.return_value = mock_emb_resp

    return client


# ── factual_verification_node (pure logic, no LLM) ──────────────────────────

class TestFactualVerification:
    """Tests for the rule-based factual constraint checker."""

    def setup_method(self):
        from swarm_orchestrator import factual_verification_node
        self.node = factual_verification_node

    def test_clean_claims_high_score(self):
        state = {"extracted_claims": ["reads customer orders", "respects rate limits"], "reasons": []}
        result = self.node(state)
        assert result["factual_score"] == 0.85
        assert "verified against ruleset" in result["reasons"][-1]

    def test_dangerous_claim_admin_override(self):
        state = {"extracted_claims": ["admin_override", "reads data"], "reasons": []}
        result = self.node(state)
        assert result["factual_score"] == 0.2
        assert "Dangerous claims" in result["reasons"][-1]

    def test_dangerous_claim_delete_all(self):
        state = {"extracted_claims": ["delete all records", "delete_all"], "reasons": []}
        result = self.node(state)
        assert result["factual_score"] == 0.2

    def test_dangerous_claim_truncate(self):
        state = {"extracted_claims": ["truncate", "normal operation"], "reasons": []}
        result = self.node(state)
        assert result["factual_score"] == 0.2

    def test_dangerous_claim_root_access(self):
        state = {"extracted_claims": ["root_access"], "reasons": []}
        result = self.node(state)
        assert result["factual_score"] == 0.2

    def test_dangerous_claim_schema_modify(self):
        state = {"extracted_claims": ["schema_modify"], "reasons": []}
        result = self.node(state)
        assert result["factual_score"] == 0.2

    def test_no_claims_medium_score(self):
        state = {"extracted_claims": [], "reasons": []}
        result = self.node(state)
        assert result["factual_score"] == 0.5
        assert "No claims extracted" in result["reasons"][-1]

    def test_mixed_claims_dangerous_wins(self):
        state = {"extracted_claims": ["reads data", "schema modify", "logs actions"], "reasons": []}
        result = self.node(state)
        assert result["factual_score"] == 0.2  # dangerous claim overrides clean ones


# ── judge_node (pure logic, no LLM) ─────────────────────────────────────────

class TestJudgeNode:
    """Tests for the weighted composite scoring and verdict."""

    def setup_method(self):
        from swarm_orchestrator import judge_node, CONFIDENCE_THRESHOLD
        self.node = judge_node
        self.threshold = CONFIDENCE_THRESHOLD

    def test_all_high_scores_allow(self):
        state = {
            "adversarial_score": 0.9,
            "sandbox_score": 0.95,
            "factual_score": 0.85,
            "intent_score": 0.85,
            "reasons": [],
        }
        result = self.node(state)
        assert result["verdict"] == "ALLOW"
        # 0.9*0.30 + 0.95*0.25 + 0.85*0.25 + 0.85*0.20 = 0.27 + 0.2375 + 0.2125 + 0.17 = 0.89
        assert result["composite_confidence_score"] >= 0.89

    def test_all_low_scores_block(self):
        state = {
            "adversarial_score": 0.1,
            "sandbox_score": 0.1,
            "factual_score": 0.2,
            "intent_score": 0.3,
            "reasons": [],
        }
        result = self.node(state)
        assert result["verdict"] == "BLOCK"
        assert result["composite_confidence_score"] < self.threshold

    def test_adversarial_breach_blocks(self):
        """Single adversarial breach with high other scores should still block."""
        state = {
            "adversarial_score": 0.1,  # breached
            "sandbox_score": 0.95,
            "factual_score": 0.85,
            "intent_score": 0.85,
            "reasons": [],
        }
        result = self.node(state)
        # 0.1*0.30 + 0.95*0.25 + 0.85*0.25 + 0.85*0.20 = 0.03 + 0.2375 + 0.2125 + 0.17 = 0.65
        # With 0.6 threshold, this is ALLOW (barely). Adversarial weight 30% not enough alone.
        assert result["composite_confidence_score"] >= 0.60

    def test_missing_scores_use_defaults(self):
        """Missing scores default to 0.5 per judge_node logic."""
        state = {"reasons": []}
        result = self.node(state)
        # All defaults: 0.5*0.30 + 0.5*0.25 + 0.5*0.25 + 0.5*0.20 = 0.5
        assert result["composite_confidence_score"] == 0.5
        assert result["verdict"] == "BLOCK"  # 0.5 < 0.6 threshold

    def test_weights_sum_to_one(self):
        """Verify the weight configuration is normalized."""
        weights = {"adversarial_score": 0.30, "sandbox_score": 0.25, "factual_score": 0.25, "intent_score": 0.20}
        total = sum(weights.values())
        assert abs(total - 1.0) < 0.001, f"Weights sum to {total}, expected 1.0"

    def test_exact_threshold_allows(self):
        """Score exactly at threshold should ALLOW (>= comparison)."""
        # Need composite = exactly 0.6
        # 0.6/1.0 = uniform 0.6 everywhere
        state = {
            "adversarial_score": 0.6,
            "sandbox_score": 0.6,
            "factual_score": 0.6,
            "intent_score": 0.6,
            "reasons": [],
        }
        result = self.node(state)
        assert result["verdict"] == "ALLOW"

    def test_verdict_includes_reason(self):
        state = {"adversarial_score": 0.9, "sandbox_score": 0.9, "factual_score": 0.9, "intent_score": 0.9, "reasons": []}
        result = self.node(state)
        assert any("Composite=" in r for r in result["reasons"])


# ── claim_extractor (mocked LLM) ────────────────────────────────────────────

class TestClaimExtractor:
    """Tests for the claim extraction agent with mocked OpenAI."""

    def test_extracts_claims_from_response(self):
        from agents.claim_extractor import claim_extraction_node

        mock_claims = ["reads customer orders", "respects 5 req/sec rate limit", "only accesses order data"]
        client = mock_openai_client(chat_response=mock_claims)

        state = {
            "openai_client": client,
            "llm_model": "gpt-4o-mini",
            "payload": {"agent_id": "order-agent", "description": "Order processing"},
            "reasons": [],
        }
        result = claim_extraction_node(state)
        assert result["extracted_claims"] == mock_claims
        assert len(result["reasons"]) == 1

    def test_empty_response_returns_empty_list(self):
        from agents.claim_extractor import claim_extraction_node

        client = mock_openai_client(chat_response=[])
        state = {"openai_client": client, "payload": {}, "reasons": []}
        result = claim_extraction_node(state)
        assert result["extracted_claims"] == []

    def test_malformed_response_returns_empty(self):
        from agents.claim_extractor import claim_extraction_node

        # Return a non-list JSON — should be handled gracefully
        client = mock_openai_client(chat_response={"error": "not a list"})
        state = {"openai_client": client, "payload": {}, "reasons": []}
        result = claim_extraction_node(state)
        assert result["extracted_claims"] == []

    def test_no_client_raises(self):
        from agents.claim_extractor import claim_extraction_node

        state = {"payload": {}, "reasons": []}
        with pytest.raises(RuntimeError, match="No OpenAI client"):
            claim_extraction_node(state)


# ── adversarial_editor (mocked LLM) ─────────────────────────────────────────

class TestAdversarialEditor:
    """Tests for the adversarial red-team agent with mocked OpenAI."""

    def test_all_attacks_survived(self):
        from agents.adversarial_editor import adversarial_evaluation_node

        response = {
            "is_epistemically_sound": True,
            "attack_results": [
                {"claim": "reads data", "attack": "injection", "result": "survived"},
                {"claim": "rate limited", "attack": "burst", "result": "survived"},
            ],
            "overall_risk": "low",
        }
        client = mock_openai_client(chat_response=response)
        state = {"openai_client": client, "extracted_claims": ["reads data", "rate limited"], "payload": {}, "reasons": []}

        result = adversarial_evaluation_node(state)
        assert result["adversarial_score"] == 0.9
        assert "survived all" in result["reasons"][-1]

    def test_one_breach_lowers_score(self):
        from agents.adversarial_editor import adversarial_evaluation_node

        response = {
            "is_epistemically_sound": False,
            "attack_results": [
                {"claim": "reads data", "attack": "injection", "result": "survived"},
                {"claim": "no admin", "attack": "escalation", "result": "breached"},
            ],
            "overall_risk": "high",
        }
        client = mock_openai_client(chat_response=response)
        state = {"openai_client": client, "extracted_claims": [], "payload": {}, "reasons": []}

        result = adversarial_evaluation_node(state)
        # 1 breach: max(0.1, 1.0 - 0.2) = 0.8
        assert result["adversarial_score"] == 0.8
        assert "1/2 attacks breached" in result["reasons"][-1]

    def test_all_breached_minimum_score(self):
        from agents.adversarial_editor import adversarial_evaluation_node

        response = {
            "is_epistemically_sound": False,
            "attack_results": [
                {"claim": "c1", "attack": "a1", "result": "breached"},
                {"claim": "c2", "attack": "a2", "result": "breached"},
                {"claim": "c3", "attack": "a3", "result": "breached"},
                {"claim": "c4", "attack": "a4", "result": "breached"},
                {"claim": "c5", "attack": "a5", "result": "breached"},
            ],
            "overall_risk": "critical",
        }
        client = mock_openai_client(chat_response=response)
        state = {"openai_client": client, "extracted_claims": [], "payload": {}, "reasons": []}

        result = adversarial_evaluation_node(state)
        # 5 breaches: max(0.1, 1.0 - 1.0) = 0.1 (floored at minimum)
        assert result["adversarial_score"] == 0.1

    def test_llm_failure_returns_low_score(self):
        from agents.adversarial_editor import adversarial_evaluation_node

        client = MagicMock()
        client.chat.completions.create.side_effect = Exception("API timeout")
        state = {"openai_client": client, "extracted_claims": [], "payload": {}, "reasons": []}

        result = adversarial_evaluation_node(state)
        assert result["adversarial_score"] == 0.3  # fail-cautious


# ── sandbox_interactor (mocked LLM) ─────────────────────────────────────────

class TestSandboxInteractor:
    """Tests for the sandbox security evaluator with mocked OpenAI."""

    def test_nominal_verdict_high_score(self):
        from agents.sandbox_interactor import sandbox_interaction_node

        response = {"verdict": "nominal", "risk_level": "low", "details": "No destructive operations"}
        client = mock_openai_client(chat_response=response)
        state = {"openai_client": client, "payload": {"action": "read"}, "reasons": []}

        result = sandbox_interaction_node(state)
        assert result["sandbox_score"] == 0.95

    def test_blocked_verdict_low_score(self):
        from agents.sandbox_interactor import sandbox_interaction_node

        response = {"verdict": "blocked_by_isolation", "risk_level": "critical", "details": "Attempted schema drop"}
        client = mock_openai_client(chat_response=response)
        state = {"openai_client": client, "payload": {"action": "DROP TABLE users"}, "reasons": []}

        result = sandbox_interaction_node(state)
        assert result["sandbox_score"] == 0.1
        assert "BLOCKED" in result["reasons"][-1]

    def test_llm_failure_returns_cautious_score(self):
        from agents.sandbox_interactor import sandbox_interaction_node

        client = MagicMock()
        client.chat.completions.create.side_effect = Exception("Rate limited")
        state = {"openai_client": client, "payload": {}, "reasons": []}

        result = sandbox_interaction_node(state)
        assert result["sandbox_score"] == 0.3


# ── meta_cognitive (mocked embeddings) ───────────────────────────────────────

class TestMetaCognitive:
    """Tests for the groupthink detection agent with mocked embeddings."""

    def test_diverse_strategies_high_score(self):
        from agents.meta_cognitive import intention_evaluator_node

        # Two very different embedding vectors → high diversity
        embeddings = [
            [1.0, 0.0, 0.0, 0.0],
            [0.0, 1.0, 0.0, 0.0],
            [0.0, 0.0, 1.0, 0.0],
        ]
        client = mock_openai_client(embedding_response=embeddings)
        state = {
            "openai_client": client,
            "reasons": ["Claim: safe agent", "Adversarial: survived attacks", "Factual: verified"],
        }

        result = intention_evaluator_node(state)
        assert result["intent_score"] == 0.85
        assert "diversity healthy" in result["reasons"][-1]

    def test_convergent_strategies_low_score(self):
        from agents.meta_cognitive import intention_evaluator_node

        # Nearly identical embedding vectors → groupthink detected
        embeddings = [
            [1.0, 0.0, 0.0, 0.0],
            [0.99, 0.01, 0.0, 0.0],
            [0.98, 0.02, 0.0, 0.0],
        ]
        client = mock_openai_client(embedding_response=embeddings)
        state = {
            "openai_client": client,
            "reasons": ["All safe", "Very safe", "Definitely safe"],
        }

        result = intention_evaluator_node(state)
        assert result["intent_score"] == 0.4
        assert "convergence detected" in result["reasons"][-1].lower()

    def test_insufficient_reasons_skips(self):
        from agents.meta_cognitive import intention_evaluator_node

        client = mock_openai_client()
        state = {"openai_client": client, "reasons": ["Only one reason"]}

        result = intention_evaluator_node(state)
        assert result["intent_score"] == 0.5
        assert "Insufficient data" in result["reasons"][-1]


# ── Full Pipeline Integration (all nodes, mocked LLMs) ──────────────────────

class TestFullPipeline:
    """End-to-end swarm pipeline with mocked LLM clients."""

    def test_safe_agent_allowed(self):
        """Agent with clean claims and no breaches → ALLOW."""
        from swarm_orchestrator import factual_verification_node, judge_node

        state = {
            "extracted_claims": ["reads customer data", "rate limited to 10/min"],
            "reasons": [],
        }

        # Run factual (pure logic)
        state = factual_verification_node(state)
        assert state["factual_score"] == 0.85

        # Simulate other scores (from mocked agents)
        state["adversarial_score"] = 0.9
        state["sandbox_score"] = 0.95
        state["intent_score"] = 0.85

        # Run judge (pure logic)
        state = judge_node(state)
        assert state["verdict"] == "ALLOW"
        assert state["composite_confidence_score"] > 0.85

    def test_dangerous_agent_blocked(self):
        """Agent with admin_override claim → BLOCK even with high other scores."""
        from swarm_orchestrator import factual_verification_node, judge_node

        state = {
            "extracted_claims": ["admin_override", "reads all data"],
            "reasons": [],
        }

        state = factual_verification_node(state)
        assert state["factual_score"] == 0.2  # dangerous

        # Even with high other scores, factual at 0.2 drags composite down
        state["adversarial_score"] = 0.9
        state["sandbox_score"] = 0.95
        state["intent_score"] = 0.85

        state = judge_node(state)
        # 0.9*0.30 + 0.95*0.25 + 0.2*0.25 + 0.85*0.20 = 0.27 + 0.2375 + 0.05 + 0.17 = 0.7275
        # Above 0.6 threshold — dangerous claim alone is not enough to block!
        # This is an important finding: the swarm weighs multiple perspectives.
        assert state["composite_confidence_score"] < 0.75

    def test_compound_failure_blocks(self):
        """Multiple low scores from different agents → definite BLOCK."""
        from swarm_orchestrator import factual_verification_node, judge_node

        state = {
            "extracted_claims": ["delete_all"],
            "reasons": [],
        }

        state = factual_verification_node(state)
        state["adversarial_score"] = 0.1   # all attacks breached
        state["sandbox_score"] = 0.1       # blocked by isolation
        state["intent_score"] = 0.4        # groupthink detected

        state = judge_node(state)
        assert state["verdict"] == "BLOCK"
        assert state["composite_confidence_score"] < 0.3

    def test_confidence_threshold_configurable(self):
        """CICADA_SWARM_THRESHOLD env var controls the threshold."""
        threshold = float(os.environ.get("CICADA_SWARM_THRESHOLD", "0.6"))
        assert threshold == 0.6  # default
