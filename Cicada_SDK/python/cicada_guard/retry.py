# © 2026 Affinity Ops Ltd. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""
cicada_guard.retry — Retry and resilience logic for Gateway communication.

Provides configurable retry with exponential backoff, jitter, and
circuit breaker awareness. Retries are applied to transient failures
(5xx, connection errors, timeouts) but never to 4xx policy rejections
(403 blocked, 429 rate-limited) — those are final Gateway decisions.

Usage:
    from cicada_guard.retry import RetryConfig, retry_request

    config = RetryConfig(max_retries=3, backoff_base=0.5)
    response = retry_request(session, "POST", url, config=config)
"""

import logging
import random
import time
from dataclasses import dataclass, field
from typing import Optional, Set

import requests

logger = logging.getLogger("cicada_guard.retry")


# Status codes that should never be retried — they are deliberate Gateway decisions
NON_RETRYABLE_STATUS = frozenset({
    400,  # Bad request — payload is malformed
    401,  # Unauthorized — token is invalid
    403,  # Forbidden — Gateway policy rejection (BLOCK decision)
    404,  # Not found — endpoint doesn't exist
    422,  # Unprocessable entity — validation failure
    429,  # Rate limited — velocity cap hit, wait for window reset
})


@dataclass
class RetryConfig:
    """
    Configuration for retry behaviour.

    Attributes:
        max_retries: Maximum number of retry attempts (0 = no retries).
        backoff_base: Base delay in seconds for exponential backoff.
        backoff_max: Maximum delay cap in seconds.
        jitter: Whether to add random jitter to backoff delays.
        retryable_status_codes: HTTP status codes that trigger a retry.
            Defaults to 502, 503, 504 (Gateway/upstream errors).
        retry_on_connection_error: Whether to retry on connection failures.
        retry_on_timeout: Whether to retry on request timeouts.
    """
    max_retries: int = 3
    backoff_base: float = 0.5
    backoff_max: float = 30.0
    jitter: bool = True
    retryable_status_codes: Set[int] = field(
        default_factory=lambda: {502, 503, 504}
    )
    retry_on_connection_error: bool = True
    retry_on_timeout: bool = True

    def delay_for_attempt(self, attempt: int) -> float:
        """
        Calculate the delay before the next retry attempt.

        Uses exponential backoff with optional jitter:
            delay = min(backoff_base * 2^attempt, backoff_max) + jitter

        Args:
            attempt: Zero-indexed attempt number.

        Returns:
            Delay in seconds before the next retry.
        """
        delay = min(self.backoff_base * (2 ** attempt), self.backoff_max)
        if self.jitter:
            delay += random.uniform(0, delay * 0.25)
        return delay


class CicadaGatewayError(Exception):
    """
    Raised when the Gateway returns a non-retryable error.

    Attributes:
        status_code: HTTP status code from the Gateway.
        response: The full requests.Response object.
        decision: The Gateway's enforcement decision (BLOCK/RATE_LIMITED/etc).
    """

    def __init__(
        self,
        message: str,
        status_code: int,
        response: Optional[requests.Response] = None,
        decision: str = "UNKNOWN",
    ):
        super().__init__(message)
        self.status_code = status_code
        self.response = response
        self.decision = decision


class CicadaBlockedError(CicadaGatewayError):
    """Raised when the Gateway blocks a request (403 — pipeline BLOCK decision)."""

    def __init__(self, response: requests.Response):
        body = response.text[:500]
        super().__init__(
            f"Gateway blocked request: {body}",
            status_code=403,
            response=response,
            decision="BLOCK",
        )


class CicadaRateLimitedError(CicadaGatewayError):
    """Raised when the Gateway rate-limits a request (429 — velocity cap)."""

    def __init__(self, response: requests.Response):
        retry_after = response.headers.get("Retry-After", "unknown")
        super().__init__(
            f"Gateway rate limited (retry after {retry_after}s)",
            status_code=429,
            response=response,
            decision="RATE_LIMITED",
        )
        self.retry_after = retry_after


class CicadaHITLPendingError(CicadaGatewayError):
    """Raised when a request is suspended for human review (202 — HITL hold)."""

    def __init__(self, response: requests.Response):
        super().__init__(
            "Request suspended for human-in-the-loop review",
            status_code=202,
            response=response,
            decision="HOLD",
        )


class CicadaConnectionError(CicadaGatewayError):
    """Raised when the Gateway is unreachable after all retry attempts."""

    def __init__(self, original_error: Exception):
        super().__init__(
            f"Gateway unreachable after all retries: {original_error}",
            status_code=0,
            decision="UNREACHABLE",
        )
        self.original_error = original_error


def retry_request(
    session: requests.Session,
    method: str,
    url: str,
    config: Optional[RetryConfig] = None,
    **kwargs,
) -> requests.Response:
    """
    Execute an HTTP request with retry logic.

    Retries on transient failures (5xx, connection errors, timeouts).
    Never retries on 4xx policy rejections — those are final Gateway decisions.

    Args:
        session: The requests.Session to use.
        method: HTTP method (GET, POST, etc.).
        url: Request URL.
        config: RetryConfig instance. Defaults to RetryConfig().
        **kwargs: Additional keyword arguments passed to session.request().

    Returns:
        The successful requests.Response.

    Raises:
        CicadaBlockedError: If the Gateway blocks the request (403).
        CicadaRateLimitedError: If the Gateway rate-limits the request (429).
        CicadaConnectionError: If the Gateway is unreachable after all retries.
    """
    if config is None:
        config = RetryConfig()

    last_exception: Optional[Exception] = None

    for attempt in range(config.max_retries + 1):
        try:
            response = session.request(method=method, url=url, **kwargs)

            # Non-retryable status codes — these are deliberate Gateway decisions
            if response.status_code in NON_RETRYABLE_STATUS:
                return response  # Let the caller decide how to handle

            # Retryable status codes — upstream/Gateway transient errors
            if response.status_code in config.retryable_status_codes:
                if attempt < config.max_retries:
                    delay = config.delay_for_attempt(attempt)
                    logger.warning(
                        "Retryable status %d on attempt %d/%d — retrying in %.2fs",
                        response.status_code,
                        attempt + 1,
                        config.max_retries + 1,
                        delay,
                    )
                    time.sleep(delay)
                    continue
                else:
                    logger.error(
                        "Max retries exhausted — last status %d",
                        response.status_code,
                    )
                    return response

            # Success — return immediately
            return response

        except requests.exceptions.ConnectionError as e:
            last_exception = e
            if config.retry_on_connection_error and attempt < config.max_retries:
                delay = config.delay_for_attempt(attempt)
                logger.warning(
                    "Connection error on attempt %d/%d — retrying in %.2fs: %s",
                    attempt + 1,
                    config.max_retries + 1,
                    delay,
                    e,
                )
                time.sleep(delay)
                continue
            raise CicadaConnectionError(e) from e

        except requests.exceptions.Timeout as e:
            last_exception = e
            if config.retry_on_timeout and attempt < config.max_retries:
                delay = config.delay_for_attempt(attempt)
                logger.warning(
                    "Timeout on attempt %d/%d — retrying in %.2fs",
                    attempt + 1,
                    config.max_retries + 1,
                    delay,
                )
                time.sleep(delay)
                continue
            raise CicadaConnectionError(e) from e

    # Should not reach here, but safety net
    if last_exception:
        raise CicadaConnectionError(last_exception) from last_exception
    raise CicadaConnectionError(RuntimeError("Unexpected retry exhaustion"))
