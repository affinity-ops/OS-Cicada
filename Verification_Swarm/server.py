# © 2026 Affinity Ops Ltd. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Verification Swarm — HTTP API Server

Synchronous HTTP interface to the Verification Swarm for use by the Core API
during agent registration. The existing Redis-based worker.py remains for
async background re-verification; this server handles the registration-time
blocking verification where the EVAR must not be issued until the swarm
has run.

Endpoints:
    POST /verify          — Run full swarm verification on an agent payload
    GET  /health          — Health check for start_fleet.sh
"""

import logging
import os
import json
import traceback
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import Optional

from byok_provider import get_tenant_openai_client
from swarm_orchestrator import run_verification_cycle
from swarm_rate_limiter import SwarmRateLimiter, SwarmRateLimitExceeded

logger = logging.getLogger("SwarmServer")
logging.basicConfig(level=logging.INFO, format="%(asctime)s - [%(name)s] %(message)s")

DEFAULT_MODEL = os.environ.get("CICADA_DEFAULT_LLM_MODEL", "gpt-4o-mini")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Verification Swarm HTTP server starting")
    yield
    logger.info("Verification Swarm HTTP server shutting down")


app = FastAPI(
    title="Cicada Verification Swarm",
    description="Adversarial agent verification via multi-LLM consensus",
    version="1.0.0",
    lifespan=lifespan,
)


class VerificationRequest(BaseModel):
    """Payload sent by the Core API at registration time."""
    tenant_id: str = Field(..., description="UUID of the tenant who owns this agent")
    agent_id: str = Field(..., description="UUID of the agent to verify")
    agent_name: str = Field("", description="Human-readable agent name")
    description: str = Field("", description="Agent's declared purpose/description")
    scopes: list[str] = Field(default_factory=list, description="Declared scope entitlements")
    tools: list[dict] = Field(default_factory=list, description="Declared tool list")
    agent_type: str = Field("reactive", description="Agent operation type")
    role: str = Field("autonomous", description="Orchestration role")
    declared_purpose: str = Field("", description="Formal purpose statement")
    target_model: str = Field("gpt-4o", description="Target LLM model")
    llm_model: Optional[str] = Field(None, description="Model for swarm verification (defaults to gpt-4o-mini)")
    # Governance constraint fields — required for a complete trust declaration.
    # Missing values are not errors but are penalised by the deterministic judge.
    expected_velocity: Optional[int] = Field(None, description="Max calls/hour declared by the operator")
    monthly_budget_usd: Optional[float] = Field(None, description="Monthly spend cap in USD")
    ghost_mode_allowed: Optional[bool] = Field(None, description="Operator consent for Shadow Sandbox diversion")
    owner_name: Optional[str] = Field(None, description="Registered human owner of this agent")
    business_unit: Optional[str] = Field(None, description="Business unit accountable for this agent")
    regulatory_frameworks: Optional[list[str]] = Field(default_factory=list, description="Declared compliance frameworks")
    budget_exhaustion_fallback: str = Field("fail_closed", description="fail_open (deterministic fallback) or fail_closed (block)")


class VerificationResponse(BaseModel):
    """Result returned to the Core API."""
    verdict: str = Field(..., description="ALLOW or BLOCK")
    composite_confidence_score: float = Field(..., description="Weighted composite score (0.0-1.0)")
    trust_tier: str = Field(..., description="Recommended trust tier based on score")
    reasons: list[str] = Field(default_factory=list, description="Explanation from each swarm agent")
    scores: dict = Field(default_factory=dict, description="Per-agent scores")


def score_to_trust_tier(score: float) -> str:
    """Map a composite confidence score to a trust tier."""
    if score >= 0.80:
        return "nominal"
    elif score >= 0.60:
        return "provisional"
    elif score >= 0.40:
        return "restricted"
    else:
        return "unverified"


@app.get("/health")
def health():
    return {"status": "ok", "service": "verification_swarm"}


@app.get("/rate-limits/{tenant_id}")
def get_rate_limits(tenant_id: str):
    """
    Returns the current swarm rate limiter state for a tenant.
    Used by the operator dashboard to surface budget consumption.
    """
    return {
        "status": "success",
        "data": SwarmRateLimiter.get_tenant_status(tenant_id),
    }

@app.post("/verify", response_model=VerificationResponse)
def verify_agent(req: VerificationRequest):
    """
    Run the full multi-agent verification swarm against a registered agent.

    PRE-FLIGHT GATE (hard): Before any scoring or LLM call, all mandatory
    governance fields must be present. If any are missing, the agent is
    immediately BLOCKED. This is a binary gate — not a penalty. The Swarm
    cannot red-team an incomplete declaration.

    Mandatory fields:
        declared_purpose, owner_name, expected_velocity,
        monthly_budget_usd, business_unit
    """
    client = None
    try:
        # ── PRE-FLIGHT MANDATORY GOVERNANCE GATE ─────────────────────────────
        # This executes BEFORE the payload is built and BEFORE any LLM call.
        # Missing any mandatory field = immediate BLOCK. No exceptions.
        missing_fields = []

        if not (req.declared_purpose or "").strip():
            missing_fields.append(
                "declared_purpose — the agent has no declared operational purpose. "
                "The Swarm cannot verify intent alignment without this."
            )
        if not (req.owner_name or "").strip():
            missing_fields.append(
                "owner_name — no accountable human owner has been registered. "
                "Every certified agent must have a named responsible person."
            )
        if req.expected_velocity is None or req.expected_velocity <= 0:
            missing_fields.append(
                "expected_velocity — no rate limit declared. "
                "The Sentry Gateway cannot enforce velocity controls without this value. "
                "An unconstrained agent is an unacceptable operational risk."
            )
        if req.monthly_budget_usd is None or req.monthly_budget_usd <= 0:
            missing_fields.append(
                "monthly_budget_usd — no financial cap declared. "
                "An agent with unbounded spend cannot be certified under any circumstance."
            )
        if not (req.business_unit or "").strip():
            missing_fields.append(
                "business_unit — no organisational unit declared. "
                "Organisational accountability must be established before certification."
            )

        if missing_fields:
            block_reasons = [
                "⛔ PRE-FLIGHT GATE FAILED — AGENT BLOCKED",
                "Mandatory governance fields are missing. The Verification Swarm will not "
                "run adversarial tests against an incomplete declaration. Resolve all "
                "missing fields and re-submit for certification. The registered owner "
                "should be notified of this failure.",
            ] + [f"MISSING: {f}" for f in missing_fields]

            logger.warning(
                f"[PRE-FLIGHT BLOCK] agent={req.agent_id} tenant={req.tenant_id} "
                f"missing={[f.split(' — ')[0] for f in missing_fields]}"
            )

            return VerificationResponse(
                verdict="BLOCK",
                composite_confidence_score=0.0,
                trust_tier="unverified",
                reasons=block_reasons,
                scores={
                    "preflight_gate": 0.0,
                    "deterministic": None,
                    "adversarial": None,
                    "sandbox": None,
                    "factual": None,
                    "intent": None,
                },
            )
        # ── PRE-FLIGHT GATE PASSED — proceed to full swarm ───────────────────

        # Build the payload the swarm will adversarially evaluate
        payload = {
            "agent_id": req.agent_id,
            "agent_name": req.agent_name,
            "description": req.description,
            "declared_purpose": req.declared_purpose,
            "scopes": req.scopes,
            "tools": req.tools,
            "agent_type": req.agent_type,
            "role": req.role,
            "target_model": req.target_model,
            "expected_velocity": req.expected_velocity,
            "monthly_budget_usd": req.monthly_budget_usd,
            "ghost_mode_allowed": req.ghost_mode_allowed,
            "owner_name": req.owner_name,
            "business_unit": req.business_unit,
            "regulatory_frameworks": req.regulatory_frameworks or [],
        }

        # ── RATE LIMITER GATE ────────────────────────────────────────────────
        # Check per-tenant budget and concurrency limits before making any
        # LLM calls. This prevents runaway cost spikes from batch re-certification
        # or retry storms. The breaker trips after 5 consecutive LLM errors.
        rate_limit_exceeded = False
        try:
            SwarmRateLimiter.check(req.tenant_id)
        except SwarmRateLimitExceeded as rle:
            logger.warning(
                f"[RATE LIMIT] Swarm call blocked for tenant {req.tenant_id}: {rle.reason}. "
                f"Fallback policy: {req.budget_exhaustion_fallback}"
            )
            if req.budget_exhaustion_fallback == "fail_open":
                rate_limit_exceeded = True
            else:
                return VerificationResponse(
                    verdict="BLOCK",
                    composite_confidence_score=0.0,
                    trust_tier="unverified",
                    reasons=[
                        "⚡ SWARM RATE LIMIT — EVALUATION DEFERRED",
                        rle.reason,
                        "The agent cannot be certified while the rate limiter is active. "
                        "This is a protective measure against runaway LLM costs. "
                        "Retry after the cooldown period or contact your platform administrator.",
                    ],
                    scores={
                        "rate_limiter": 0.0,
                        "adversarial": None,
                        "sandbox": None,
                        "factual": None,
                        "intent": None,
                    },
                )

        model = req.llm_model or DEFAULT_MODEL

        # BYOK: Use the tenant's own API key. Cicada never pays.
        try:
            client = get_tenant_openai_client(req.tenant_id)
        except Exception as e:
            logger.warning(f"BYOK unavailable for tenant {req.tenant_id}: {e}. Running deterministic-only verification.")
            client = None

        # ── TRACKED EXECUTION — rate limiter wraps the LLM call lifecycle ────
        if rate_limit_exceeded or not client:
            # Deterministic fallback used if BYOK is unavailable OR if budget exhausted and fail_open is selected.
            if rate_limit_exceeded:
                logger.warning(f"Running deterministic fallback for tenant {req.tenant_id} due to rate limit fail_open")
            result = run_deterministic_verification(payload)
        else:
            with SwarmRateLimiter.track(req.tenant_id):
                result = run_verification_cycle(payload=payload, openai_client=client, llm_model=model)

        score = result.get("composite_confidence_score", 0.0)
        verdict = result.get("verdict", "BLOCK")
        trust_tier = score_to_trust_tier(score)

        logger.info(
            f"Verification complete: agent={req.agent_id} tenant={req.tenant_id} "
            f"verdict={verdict} score={score:.4f} tier={trust_tier}"
        )

        return VerificationResponse(
            verdict=verdict,
            composite_confidence_score=score,
            trust_tier=trust_tier,
            reasons=result.get("reasons", []),
            scores=result.get("scores", {}),
        )

    except SwarmRateLimitExceeded:
        raise  # Already handled above, but in case of re-raise

    except Exception as e:
        logger.error(f"Verification failed for agent {req.agent_id}: {e}\n{traceback.format_exc()}")
        return VerificationResponse(
            verdict="BLOCK",
            composite_confidence_score=0.0,
            trust_tier="unverified",
            reasons=[f"Swarm error: {str(e)}"],
            scores={},
        )
    finally:
        client = None



def run_deterministic_verification(payload: dict) -> dict:
    """
    Rule-based verification fallback when no BYOK key is available.

    This catches:
    - Agents with no description (unverifiable purpose)
    - Agents requesting destructive scopes without HITL
    - Agents with known-dangerous tool patterns
    - Agents with overly broad scope declarations
    """
    reasons = []
    score_penalties = 0.0
    base_score = 0.75  # Start with a passing baseline

    description = payload.get("description", "").strip()
    declared_purpose = payload.get("declared_purpose", "").strip()
    scopes = payload.get("scopes", [])
    tools = payload.get("tools", [])
    agent_type = payload.get("agent_type", "")
    role = payload.get("role", "")
    expected_velocity = payload.get("expected_velocity")
    monthly_budget_usd = payload.get("monthly_budget_usd")
    owner_name = payload.get("owner_name", "").strip() if payload.get("owner_name") else ""
    business_unit = payload.get("business_unit", "").strip() if payload.get("business_unit") else ""
    regulatory_frameworks = payload.get("regulatory_frameworks", [])

    # Penalty: No description means the platform cannot verify intent alignment
    if not description and not declared_purpose:
        score_penalties += 0.30
        reasons.append("Deterministic: No description or declared purpose — cannot verify intent alignment")
    elif not description:
        score_penalties += 0.10
        reasons.append("Deterministic: Missing agent description — limited verification possible")

    # Penalty: Destructive scopes without tools declared
    destructive_scopes = {"proxy:write", "proxy:transact"}
    has_destructive = bool(destructive_scopes & set(scopes))
    if has_destructive and len(tools) == 0:
        score_penalties += 0.20
        reasons.append("Deterministic: Destructive scopes declared but no tools specified — unverifiable attack surface")

    # Penalty: Too many scopes suggests over-privileged agent
    if len(scopes) >= 5:
        score_penalties += 0.15
        reasons.append(f"Deterministic: {len(scopes)} scopes declared — over-privileged agent profile")

    # Penalty: Autonomous role with destructive scopes is highest risk
    if role == "autonomous" and has_destructive:
        score_penalties += 0.15
        reasons.append("Deterministic: Autonomous agent with destructive scopes — highest risk profile")

    # ── Governance Completeness Checks ────────────────────────────────────────
    # An agent without a velocity declaration is operationally unconstrained.
    # The Gateway velocity circuit breaker cannot enforce anything without this
    # value, so missing velocity is a material governance deficiency.
    if expected_velocity is None:
        score_penalties += 0.20
        reasons.append(
            "Governance: No velocity limit declared — agent is operationally unconstrained. "
            "The Sentry Gateway cannot enforce rate limits without this value. "
            "Register a maximum calls/hour value to resolve this deficiency."
        )
    elif expected_velocity <= 0:
        score_penalties += 0.15
        reasons.append("Governance: Velocity limit declared as zero or negative — invalid constraint")

    if monthly_budget_usd is None:
        score_penalties += 0.10
        reasons.append(
            "Governance: No monthly budget cap declared — financial exposure is unbound. "
            "Declare a monthly_budget_usd value to establish cost accountability."
        )

    if not owner_name:
        score_penalties += 0.10
        reasons.append("Governance: No owner declared — agent has no accountable human contact")

    if not business_unit:
        score_penalties += 0.05
        reasons.append("Governance: No business unit declared — organisational accountability cannot be established")

    if not regulatory_frameworks:
        score_penalties += 0.05
        reasons.append("Governance: No regulatory frameworks declared — compliance posture is unknown")

    # Positive: Well-documented agent with full governance profile
    if description and declared_purpose and len(tools) > 0:
        score_penalties -= 0.05
        reasons.append("Deterministic: Well-documented agent with declared tools — positive signal")

    if expected_velocity and monthly_budget_usd and owner_name and business_unit:
        score_penalties -= 0.05
        reasons.append("Governance: Complete governance profile declared — positive signal")

    final_score = max(0.0, min(1.0, base_score - score_penalties))

    from swarm_orchestrator import CONFIDENCE_THRESHOLD
    verdict = "ALLOW" if final_score >= CONFIDENCE_THRESHOLD else "BLOCK"

    reasons.append(f"Deterministic Judge: Score={final_score:.4f} (threshold={CONFIDENCE_THRESHOLD}) -> {verdict}")

    return {
        "verdict": verdict,
        "composite_confidence_score": round(final_score, 4),
        "reasons": reasons,
        "scores": {
            "deterministic": round(final_score, 4),
            "adversarial": None,
            "sandbox": None,
            "factual": None,
            "intent": None,
        },
    }


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("SWARM_PORT", "9091"))
    logger.info(f"Starting Verification Swarm server on port {port}")
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")
