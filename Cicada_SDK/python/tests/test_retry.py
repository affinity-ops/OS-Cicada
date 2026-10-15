# © 2026 Affinity Ops Ltd. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Tests for cicada_guard.retry — Retry logic and typed exceptions.
"""

import time
from unittest.mock import MagicMock, patch

import pytest
import requests

from cicada_guard.retry import (
    NON_RETRYABLE_STATUS,
    CicadaBlockedError,
    CicadaConnectionError,
    CicadaGatewayError,
    CicadaHITLPendingError,
    CicadaRateLimitedError,
    RetryConfig,
    retry_request,
)


# ── RetryConfig ──────────────────────────────────────────────────


class TestRetryConfig:
    """Tests for RetryConfig dataclass and delay calculation."""

    def test_default_values(self):
        config = RetryConfig()
        assert config.max_retries == 3
        assert config.backoff_base == 0.5
        assert config.backoff_max == 30.0
        assert config.jitter is True
        assert 502 in config.retryable_status_codes
        assert 503 in config.retryable_status_codes
        assert 504 in config.retryable_status_codes

    def test_custom_values(self):
        config = RetryConfig(max_retries=5, backoff_base=1.0, backoff_max=60.0)
        assert config.max_retries == 5
        assert config.backoff_base == 1.0
        assert config.backoff_max == 60.0

    def test_delay_exponential_backoff_no_jitter(self):
        config = RetryConfig(backoff_base=1.0, jitter=False)
        assert config.delay_for_attempt(0) == 1.0
        assert config.delay_for_attempt(1) == 2.0
        assert config.delay_for_attempt(2) == 4.0
        assert config.delay_for_attempt(3) == 8.0

    def test_delay_respects_max(self):
        config = RetryConfig(backoff_base=1.0, backoff_max=5.0, jitter=False)
        assert config.delay_for_attempt(10) == 5.0

    def test_delay_with_jitter_is_bounded(self):
        config = RetryConfig(backoff_base=1.0, jitter=True)
        delay = config.delay_for_attempt(0)
        # delay = 1.0 + jitter(0, 0.25), so [1.0, 1.25]
        assert 1.0 <= delay <= 1.25


# ── Typed Exceptions ─────────────────────────────────────────────


class TestExceptions:
    """Tests for Gateway-specific exception classes."""

    def test_blocked_error(self):
        response = MagicMock()
        response.text = "Policy violation: injection detected"
        response.status_code = 403
        err = CicadaBlockedError(response)
        assert err.status_code == 403
        assert err.decision == "BLOCK"
        assert "injection detected" in str(err)
        assert err.response is response

    def test_rate_limited_error(self):
        response = MagicMock()
        response.headers = {"Retry-After": "60"}
        response.status_code = 429
        err = CicadaRateLimitedError(response)
        assert err.status_code == 429
        assert err.decision == "RATE_LIMITED"
        assert err.retry_after == "60"

    def test_hitl_pending_error(self):
        response = MagicMock()
        response.status_code = 202
        err = CicadaHITLPendingError(response)
        assert err.status_code == 202
        assert err.decision == "HOLD"

    def test_connection_error(self):
        original = ConnectionError("refused")
        err = CicadaConnectionError(original)
        assert err.status_code == 0
        assert err.decision == "UNREACHABLE"
        assert err.original_error is original

    def test_exception_hierarchy(self):
        """All typed exceptions should inherit from CicadaGatewayError."""
        response = MagicMock()
        response.text = "test"
        response.headers = {}
        assert isinstance(CicadaBlockedError(response), CicadaGatewayError)
        assert isinstance(CicadaRateLimitedError(response), CicadaGatewayError)
        assert isinstance(CicadaHITLPendingError(response), CicadaGatewayError)
        assert isinstance(CicadaConnectionError(Exception()), CicadaGatewayError)


# ── retry_request ────────────────────────────────────────────────


class TestRetryRequest:
    """Tests for the retry_request function."""

    def _mock_response(self, status_code=200, text="ok"):
        response = MagicMock(spec=requests.Response)
        response.status_code = status_code
        response.text = text
        response.headers = {}
        return response

    def test_successful_request_no_retry(self):
        session = MagicMock()
        session.request.return_value = self._mock_response(200)
        config = RetryConfig(max_retries=3)

        result = retry_request(session, "GET", "http://gw/v1/proxy", config=config)

        assert result.status_code == 200
        assert session.request.call_count == 1

    def test_non_retryable_status_returned_immediately(self):
        """403, 429 etc. should be returned without retry."""
        for status in [400, 401, 403, 404, 422, 429]:
            session = MagicMock()
            session.request.return_value = self._mock_response(status)
            config = RetryConfig(max_retries=3)

            result = retry_request(session, "POST", "http://gw/v1/proxy", config=config)
            assert result.status_code == status
            assert session.request.call_count == 1

    @patch("cicada_guard.retry.time.sleep")
    def test_retryable_status_triggers_retry(self, mock_sleep):
        """502/503/504 should trigger retry with backoff."""
        session = MagicMock()
        session.request.side_effect = [
            self._mock_response(503),
            self._mock_response(503),
            self._mock_response(200),
        ]
        config = RetryConfig(max_retries=3, backoff_base=0.1, jitter=False)

        result = retry_request(session, "GET", "http://gw/v1/proxy", config=config)

        assert result.status_code == 200
        assert session.request.call_count == 3
        assert mock_sleep.call_count == 2

    @patch("cicada_guard.retry.time.sleep")
    def test_max_retries_exhausted_returns_last_response(self, mock_sleep):
        session = MagicMock()
        session.request.return_value = self._mock_response(503)
        config = RetryConfig(max_retries=2, backoff_base=0.01, jitter=False)

        result = retry_request(session, "GET", "http://gw/v1/proxy", config=config)

        assert result.status_code == 503
        assert session.request.call_count == 3  # initial + 2 retries

    @patch("cicada_guard.retry.time.sleep")
    def test_connection_error_retries_then_raises(self, mock_sleep):
        session = MagicMock()
        session.request.side_effect = requests.exceptions.ConnectionError("refused")
        config = RetryConfig(max_retries=2, backoff_base=0.01, jitter=False)

        with pytest.raises(CicadaConnectionError) as exc_info:
            retry_request(session, "GET", "http://gw/v1/proxy", config=config)

        assert exc_info.value.decision == "UNREACHABLE"
        assert session.request.call_count == 3

    @patch("cicada_guard.retry.time.sleep")
    def test_timeout_retries_then_raises(self, mock_sleep):
        session = MagicMock()
        session.request.side_effect = requests.exceptions.Timeout("timed out")
        config = RetryConfig(max_retries=1, backoff_base=0.01, jitter=False)

        with pytest.raises(CicadaConnectionError):
            retry_request(session, "GET", "http://gw/v1/proxy", config=config)

        assert session.request.call_count == 2

    @patch("cicada_guard.retry.time.sleep")
    def test_connection_error_recovery(self, mock_sleep):
        """First attempt fails, second succeeds."""
        session = MagicMock()
        session.request.side_effect = [
            requests.exceptions.ConnectionError("refused"),
            self._mock_response(200),
        ]
        config = RetryConfig(max_retries=2, backoff_base=0.01, jitter=False)

        result = retry_request(session, "GET", "http://gw/v1/proxy", config=config)
        assert result.status_code == 200

    def test_no_retries_config(self):
        session = MagicMock()
        session.request.return_value = self._mock_response(503)
        config = RetryConfig(max_retries=0)

        result = retry_request(session, "GET", "http://gw/v1/proxy", config=config)
        assert result.status_code == 503
        assert session.request.call_count == 1

    def test_connection_error_no_retry_disabled(self):
        session = MagicMock()
        session.request.side_effect = requests.exceptions.ConnectionError("refused")
        config = RetryConfig(max_retries=3, retry_on_connection_error=False)

        with pytest.raises(CicadaConnectionError):
            retry_request(session, "GET", "http://gw/v1/proxy", config=config)
        assert session.request.call_count == 1


# ── NON_RETRYABLE_STATUS constant ────────────────────────────────


class TestNonRetryableStatus:
    def test_contains_expected_codes(self):
        assert 403 in NON_RETRYABLE_STATUS
        assert 429 in NON_RETRYABLE_STATUS
        assert 400 in NON_RETRYABLE_STATUS
        assert 401 in NON_RETRYABLE_STATUS

    def test_does_not_contain_retryable(self):
        assert 502 not in NON_RETRYABLE_STATUS
        assert 503 not in NON_RETRYABLE_STATUS
        assert 200 not in NON_RETRYABLE_STATUS
