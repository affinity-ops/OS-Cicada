# © 2026 Affinity Ops Ltd. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import logging
import os
import json
import redis

from byok_provider import get_tenant_openai_client
from swarm_orchestrator import run_verification_cycle

logger = logging.getLogger("SwarmWorker")
logging.basicConfig(level=logging.INFO, format="%(asctime)s - [%(name)s] %(message)s")

# LLM model preference — can be overridden per-tenant in the job payload
DEFAULT_MODEL = os.environ.get("CICADA_DEFAULT_LLM_MODEL", "gpt-4o-mini")


def main():
    """
    Redis queue consumer for the Verification Swarm.

    Each job contains a tenant_id. The worker:
    1. Retrieves the tenant's encrypted API key from PostgreSQL
    2. Decrypts it via AES-256-CBC
    3. Creates a short-lived OpenAI client scoped to this job
    4. Injects it into the pipeline state
    5. Runs the verification swarm using the tenant's key and compute budget
    6. Destroys the client reference after completion

    Cicada incurs zero LLM token costs. The tenant pays.
    """
    redis_url = os.environ.get("CICADA_REDIS_URL", "redis://localhost:6379")
    r = redis.from_url(redis_url)

    try:
        r.ping()
        logger.info(f"Connected to Redis at {redis_url}")
    except redis.ConnectionError as e:
        logger.error(f"Cannot connect to Redis: {e}")
        raise

    queues = ["cicada_swarm_queue_high", "cicada_swarm_queue_low", "cicada_swarm_queue"]
    result_queue = "cicada_swarm_results"
    logger.info(f"Listening on queues {queues} for verification jobs...")

    from swarm_rate_limiter import SwarmRateLimiter, SwarmRateLimitExceeded
    from server import run_deterministic_verification

    while True:
        client = None
        try:
            # brpop correctly prioritises the first queue in the list
            queue_name, raw = r.brpop(queues, timeout=0)
            job = json.loads(raw)

            tenant_id = job.get("tenant_id")
            agent_id = job.get("agent_id", "unknown")
            payload = job.get("payload", {})
            model = job.get("llm_model", DEFAULT_MODEL)
            fallback = job.get("budget_exhaustion_fallback", "fail_closed")

            if not tenant_id:
                logger.error("Job missing tenant_id — cannot resolve BYOK key. Skipping.")
                continue

            logger.info(f"Job received from {queue_name}: tenant={tenant_id}, agent={agent_id}")

            rate_limit_exceeded = False
            try:
                SwarmRateLimiter.check(tenant_id)
            except SwarmRateLimitExceeded as rle:
                logger.warning(
                    f"[RATE LIMIT] Swarm call blocked for tenant {tenant_id}: {rle.reason}. "
                    f"Fallback policy: {fallback}"
                )
                if fallback == "fail_open":
                    rate_limit_exceeded = True
                else:
                    # fail_closed: immediately fail the verification
                    result = {
                        "verdict": "BLOCK",
                        "composite_confidence_score": 0.0,
                        "reasons": [f"Swarm rate limit exceeded. {rle.reason}"]
                    }
                    result["tenant_id"] = tenant_id
                    result["agent_id"] = agent_id
                    r.lpush(result_queue, json.dumps(result))
                    continue

            # BYOK: create a tenant-scoped client using their own stored API key.
            # Cicada never pays for this — the tenant's key is used for their calls.
            try:
                client = get_tenant_openai_client(tenant_id)
            except Exception as e:
                logger.warning(f"BYOK unavailable for tenant {tenant_id}: {e}. Running deterministic-only verification.")
                client = None

            if rate_limit_exceeded or not client:
                if rate_limit_exceeded:
                    logger.warning(f"Running deterministic fallback for tenant {tenant_id} due to rate limit fail_open")
                result = run_deterministic_verification(payload)
            else:
                with SwarmRateLimiter.track(tenant_id):
                    result = run_verification_cycle(
                        payload=payload,
                        openai_client=client,
                        llm_model=model,
                    )

            result["tenant_id"] = tenant_id
            result["agent_id"] = agent_id
            r.lpush(result_queue, json.dumps(result))

            logger.info(
                f"Verdict for tenant={tenant_id} agent={agent_id}: "
                f"{result.get('verdict')} (score={result.get('composite_confidence_score')})"
            )

        except ValueError as e:
            # Tenant has no BYOK key configured
            logger.error(f"BYOK key error: {e}")
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON from queue: {e}")
        except Exception as e:
            logger.error(f"Swarm processing error: {e}")
        finally:
            # Destroy the client reference — key must not persist in memory
            client = None
