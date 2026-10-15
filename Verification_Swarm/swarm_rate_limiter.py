# © 2026 Affinity Ops Ltd. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Swarm Rate Limiter — Per-Tenant Circuit Breaker for LLM Calls

Prevents runaway LLM costs from the Verification Swarm by enforcing
per-tenant concurrency and hourly call budgets. Uses Redis counters
with TTL expiry for distributed state.

Architecture:
    ┌────────────────────────────────────────────────────────────────┐
    │  POST /verify  →  SwarmRateLimiter.check()  →  ALLOW / DENY  │
    │                                                                │
    │  Redis Keys:                                                   │
    │    cicada:swarm:hourly:{tenant_id}  — calls in current hour    │
    │    cicada:swarm:inflight:{tenant_id} — active concurrent calls │
    └────────────────────────────────────────────────────────────────┘

Configuration (env vars):
    CICADA_SWARM_MAX_CALLS_PER_HOUR    — max swarm LLM calls per tenant per hour (default: 50)
    CICADA_SWARM_MAX_CONCURRENT        — max concurrent swarm evaluations per tenant (default: 5)
    CICADA_SWARM_CIRCUIT_BREAKER_COOL  — cooldown seconds after breaker trips (default: 300)
"""

import os
import time
import logging
import redis
from contextlib import contextmanager
from typing import Optional

logger = logging.getLogger("SwarmRateLimiter")

# Defaults are conservative — high enough that normal operations
# (10–20 agent certifications per hour) never trip, low enough that
# a runaway re-certification loop is caught before costs escalate.
MAX_CALLS_PER_HOUR = int(os.environ.get("CICADA_SWARM_MAX_CALLS_PER_HOUR", "50"))
MAX_CONCURRENT = int(os.environ.get("CICADA_SWARM_MAX_CONCURRENT", "5"))
CIRCUIT_BREAKER_COOLDOWN = int(os.environ.get("CICADA_SWARM_CIRCUIT_BREAKER_COOL", "300"))

# Redis connection — shared with the rest of the Cicada stack.
_redis_client: Optional[redis.Redis] = None


def _get_redis() -> Optional[redis.Redis]:
    """Lazy-initialise the Redis connection from CICADA_REDIS_URL."""
    global _redis_client
    if _redis_client is not None:
        return _redis_client

    redis_url = os.environ.get("CICADA_REDIS_URL")
    if not redis_url:
        logger.warning("[RATE LIMITER] CICADA_REDIS_URL not set — rate limiting disabled")
        return None

    try:
        _redis_client = redis.Redis.from_url(redis_url, decode_responses=True)
        _redis_client.ping()
        logger.info("[RATE LIMITER] Redis connection established for swarm rate limiting")
        return _redis_client
    except Exception as e:
        logger.error(f"[RATE LIMITER] Redis connection failed: {e} — rate limiting disabled")
        return None


class SwarmRateLimitExceeded(Exception):
    """Raised when a tenant has exceeded their swarm call budget."""
    def __init__(self, tenant_id: str, reason: str, retry_after: int = 0):
        self.tenant_id = tenant_id
        self.reason = reason
        self.retry_after = retry_after
        super().__init__(f"Swarm rate limit exceeded for tenant {tenant_id}: {reason}")


class SwarmRateLimiter:
    """
    Per-tenant circuit breaker for Verification Swarm LLM calls.

    Enforces:
        1. Hourly call budget — prevents runaway certification loops
        2. Concurrent call limit — prevents burst cost spikes
        3. Circuit breaker cooldown — after 5 consecutive errors, trips for 5 minutes

    All state is stored in Redis for cross-process visibility. If Redis is
    unavailable, the limiter degrades gracefully — all calls are allowed.
    """

    @staticmethod
    def _hourly_key(tenant_id: str) -> str:
        """Redis key for hourly call counter. Includes the current hour so
        counters auto-expire without manual cleanup."""
        hour_bucket = int(time.time() // 3600)
        return f"cicada:swarm:hourly:{tenant_id}:{hour_bucket}"

    @staticmethod
    def _inflight_key(tenant_id: str) -> str:
        return f"cicada:swarm:inflight:{tenant_id}"

    @staticmethod
    def _breaker_key(tenant_id: str) -> str:
        return f"cicada:swarm:breaker:{tenant_id}"

    @staticmethod
    def _error_count_key(tenant_id: str) -> str:
        return f"cicada:swarm:errors:{tenant_id}"

    @classmethod
    def check(cls, tenant_id: str) -> None:
        """
        Check whether this tenant is allowed to make a swarm LLM call.
        Raises SwarmRateLimitExceeded if any limit is breached.

        This should be called BEFORE the LLM call is made.
        """
        r = _get_redis()
        if r is None:
            return  # No Redis = no enforcement (graceful degradation)

        # 1. Check circuit breaker (tripped by consecutive errors)
        breaker_ttl = r.ttl(cls._breaker_key(tenant_id))
        if breaker_ttl and breaker_ttl > 0:
            raise SwarmRateLimitExceeded(
                tenant_id,
                f"Circuit breaker tripped — cooling down for {breaker_ttl}s after consecutive LLM errors",
                retry_after=breaker_ttl,
            )

        # 2. Check hourly budget
        hourly_key = cls._hourly_key(tenant_id)
        current_count = r.get(hourly_key)
        if current_count is not None and int(current_count) >= MAX_CALLS_PER_HOUR:
            raise SwarmRateLimitExceeded(
                tenant_id,
                f"Hourly swarm budget exhausted ({current_count}/{MAX_CALLS_PER_HOUR}). "
                f"Resets at the next hour boundary.",
                retry_after=3600 - int(time.time() % 3600),
            )

        # 3. Check concurrent call limit
        inflight = r.get(cls._inflight_key(tenant_id))
        if inflight is not None and int(inflight) >= MAX_CONCURRENT:
            raise SwarmRateLimitExceeded(
                tenant_id,
                f"Max concurrent swarm evaluations reached ({inflight}/{MAX_CONCURRENT}). "
                f"Wait for in-flight evaluations to complete.",
                retry_after=30,
            )

    @classmethod
    @contextmanager
    def track(cls, tenant_id: str):
        """
        Context manager that tracks a swarm call lifecycle:
            1. Increments hourly counter
            2. Increments inflight counter
            3. On exit: decrements inflight, handles error counting

        Usage:
            with SwarmRateLimiter.track(tenant_id):
                result = run_verification_cycle(...)
        """
        r = _get_redis()
        if r is None:
            yield
            return

        hourly_key = cls._hourly_key(tenant_id)
        inflight_key = cls._inflight_key(tenant_id)
        error_key = cls._error_count_key(tenant_id)

        try:
            # Increment counters atomically
            pipe = r.pipeline()
            pipe.incr(hourly_key)
            pipe.expire(hourly_key, 3600)  # Expire with the hour
            pipe.incr(inflight_key)
            pipe.expire(inflight_key, 600)  # Safety TTL — 10min max for any single call
            pipe.execute()

            logger.info(
                f"[RATE LIMITER] Swarm call started for tenant {tenant_id} "
                f"(hourly: {r.get(hourly_key)}/{MAX_CALLS_PER_HOUR}, "
                f"inflight: {r.get(inflight_key)}/{MAX_CONCURRENT})"
            )

            yield

            # Success — reset error counter
            r.delete(error_key)

        except SwarmRateLimitExceeded:
            raise  # Don't track rate limit errors as LLM errors

        except Exception:
            # LLM or processing error — increment error counter
            errors = r.incr(error_key)
            r.expire(error_key, 3600)

            if errors >= 5:
                # Trip the circuit breaker
                r.setex(
                    cls._breaker_key(tenant_id),
                    CIRCUIT_BREAKER_COOLDOWN,
                    f"tripped_at_{int(time.time())}"
                )
                r.delete(error_key)
                logger.error(
                    f"[CIRCUIT BREAKER] Swarm breaker TRIPPED for tenant {tenant_id} "
                    f"after {errors} consecutive errors. Cooldown: {CIRCUIT_BREAKER_COOLDOWN}s"
                )
            raise

        finally:
            # Always decrement inflight, even on error
            try:
                current = r.decr(inflight_key)
                if current < 0:
                    r.set(inflight_key, 0, ex=600)
            except Exception:
                pass  # Best-effort cleanup

    @classmethod
    def get_tenant_status(cls, tenant_id: str) -> dict:
        """
        Return the current rate limiter state for a tenant.
        Used by the dashboard API to surface swarm budget consumption.
        """
        r = _get_redis()
        if r is None:
            return {"enabled": False, "reason": "Redis not available"}

        hourly_key = cls._hourly_key(tenant_id)
        return {
            "enabled": True,
            "hourly_calls": int(r.get(hourly_key) or 0),
            "hourly_limit": MAX_CALLS_PER_HOUR,
            "inflight": int(r.get(cls._inflight_key(tenant_id)) or 0),
            "max_concurrent": MAX_CONCURRENT,
            "circuit_breaker_active": (r.ttl(cls._breaker_key(tenant_id)) or 0) > 0,
            "breaker_ttl": max(0, r.ttl(cls._breaker_key(tenant_id)) or 0),
            "consecutive_errors": int(r.get(cls._error_count_key(tenant_id)) or 0),
        }
