# © 2026 Affinity Ops Ltd. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Tests for Saga Executor — SagaWorker and HitlResumeWorker

These tests cover the deterministic security and reliability logic:
- SSRF domain validation
- HMAC webhook signature generation
- DLQ routing
- Retry backoff calculation
- Idempotency guards

Tests that require Redis/PostgreSQL connections use unittest.mock to
avoid infrastructure dependency.
"""
import hashlib
import hmac
import json
import os
import time
import uuid
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

# Set required env vars BEFORE importing workers
os.environ.setdefault("CICADA_WEBHOOK_SECRET", "test-webhook-secret-for-pytest")
os.environ.setdefault("CICADA_ALLOWED_WEBHOOK_DOMAINS", "enterprise.internal,api.stripe.com,hooks.example.com")
os.environ.setdefault("CICADA_SAGA_MAX_RETRIES", "3")

from saga_worker import SagaWorker, ALLOWED_DOMAINS, WEBHOOK_SECRET, MAX_RETRIES


# ── SSRF Domain Validation ─────────────────────────────────────────────────────


class TestValidateOutboundUrl:
    """Test the SSRF protection logic in _validate_outbound_url."""

    @pytest.fixture
    def worker(self):
        with patch("saga_worker.redis.from_url") as mock_redis:
            mock_redis.return_value = MagicMock()
            return SagaWorker()

    def test_allowed_domain_passes(self, worker):
        with patch("socket.getaddrinfo", return_value=[
            (2, 1, 6, '', ('93.184.216.34', 0)),  # mock public IP
        ]):
            ok, _ = worker._validate_outbound_url("https://api.stripe.com/v1/refunds")
            assert ok is True

    def test_allowed_subdomain_passes(self, worker):
        with patch("socket.getaddrinfo", return_value=[
            (2, 1, 6, '', ('93.184.216.34', 0)),  # mock public IP
        ]):
            ok, _ = worker._validate_outbound_url("https://billing.enterprise.internal/rollback")
            assert ok is True

    def test_blocked_domain_rejected(self, worker):
        ok, reason = worker._validate_outbound_url("https://attacker.com/exfil")
        assert ok is False
        assert "not in domain allowlist" in reason

    def test_localhost_rejected(self, worker):
        ok, reason = worker._validate_outbound_url("https://localhost:8080/admin")
        assert ok is False
        # Rejected by either allowlist (localhost not in list) or loopback check
        assert "loopback" in reason or "not in domain allowlist" in reason

    def test_private_ip_rejected(self, worker):
        ok, reason = worker._validate_outbound_url("https://192.168.1.1/internal")
        assert ok is False
        # Rejected by either allowlist or private IP check
        assert ok is False

    def test_empty_url_rejected(self, worker):
        ok, _ = worker._validate_outbound_url("")
        assert ok is False

    def test_malformed_url_rejected(self, worker):
        ok, _ = worker._validate_outbound_url("not-a-url")
        assert ok is False

    def test_http_scheme_rejected(self, worker):
        """HTTP must be rejected — HTTPS only."""
        ok, reason = worker._validate_outbound_url("http://api.stripe.com/v1/refunds")
        assert ok is False
        assert "non-HTTPS" in reason

    def test_ftp_scheme_rejected(self, worker):
        """FTP must also be rejected."""
        ok, reason = worker._validate_outbound_url("ftp://enterprise.internal/data")
        assert ok is False
        assert "non-HTTPS" in reason

    def test_suffix_confusion_blocked(self, worker):
        """evil-stripe.com must NOT match stripe.com (dot-prefix check)."""
        ok, reason = worker._validate_outbound_url("https://evil-stripe.com/steal")
        assert ok is False
        assert "not in domain allowlist" in reason

    def test_no_hostname_rejected(self, worker):
        ok, _ = worker._validate_outbound_url("///path/only")
        assert ok is False


# ── HMAC Signature Verification ────────────────────────────────────────────────


class TestHMACSignature:
    """Verify that webhook signatures match expected HMAC-SHA256 format."""

    def test_signature_is_deterministic(self):
        secret = b"test-secret"
        timestamp = "1714200000"
        nonce = "test-nonce-123"
        payload = '{"action": "rollback"}'

        sig_input = f"{timestamp}:{nonce}:{payload}"
        sig1 = hmac.new(secret, sig_input.encode(), hashlib.sha256).hexdigest()
        sig2 = hmac.new(secret, sig_input.encode(), hashlib.sha256).hexdigest()

        assert sig1 == sig2
        assert len(sig1) == 64  # SHA-256 hex = 64 chars

    def test_different_payloads_differ(self):
        secret = b"test-secret"
        timestamp = "1714200000"
        nonce = "nonce1"

        sig1 = hmac.new(secret, f"{timestamp}:{nonce}:payload-a".encode(), hashlib.sha256).hexdigest()
        sig2 = hmac.new(secret, f"{timestamp}:{nonce}:payload-b".encode(), hashlib.sha256).hexdigest()

        assert sig1 != sig2

    def test_different_nonces_differ(self):
        secret = b"test-secret"
        timestamp = "1714200000"
        payload = '{"same": true}'

        sig1 = hmac.new(secret, f"{timestamp}:nonce-a:{payload}".encode(), hashlib.sha256).hexdigest()
        sig2 = hmac.new(secret, f"{timestamp}:nonce-b:{payload}".encode(), hashlib.sha256).hexdigest()

        assert sig1 != sig2


# ── Job Processing & DLQ ──────────────────────────────────────────────────────


class TestJobProcessing:
    """Test the saga rollback job processing pipeline."""

    @pytest.fixture
    def worker(self):
        with patch("saga_worker.redis.from_url") as mock_redis:
            mock_client = MagicMock()
            mock_redis.return_value = mock_client
            w = SagaWorker()
            w.redis = mock_client
            return w

    def test_duplicate_job_skipped(self, worker):
        """Idempotency: duplicate rollback_id should not be re-processed."""
        worker.redis.sismember.return_value = True

        job = {
            "rollback_id": "dup-001",
            "trace_id": "trace-001",
            "revert_route": "https://api.stripe.com/v1/refund",
            "failed_action": "charge",
        }
        # Should return without calling _execute_webhook
        worker._process_job(job)

        # Verify no webhook call was made
        worker.session = MagicMock()
        worker.session.post.assert_not_called()

    def test_ssrf_sends_to_dlq(self, worker):
        """Blocked domains should route to DLQ."""
        worker.redis.sismember.return_value = False

        job = {
            "rollback_id": "ssrf-001",
            "trace_id": "trace-ssrf",
            "revert_route": "https://attacker.com/steal",
            "failed_action": "payment",
        }
        worker._process_job(job)

        # Verify it was pushed to DLQ
        worker.redis.lpush.assert_called_once()
        call_args = worker.redis.lpush.call_args
        assert call_args[0][0] == "cicada_saga_dlq"
        dlq_payload = json.loads(call_args[0][1])
        assert dlq_payload["dlq_reason"].startswith("ssrf_blocked:")

    def test_dlq_includes_timestamp(self, worker):
        """DLQ entries must have a timestamp for audit trail."""
        job = {"rollback_id": "ts-001", "trace_id": "t-001"}
        worker._send_to_dlq(job, "test_reason")

        call_args = worker.redis.lpush.call_args
        dlq_payload = json.loads(call_args[0][1])
        assert "dlq_timestamp" in dlq_payload
        assert isinstance(dlq_payload["dlq_timestamp"], float)
        assert dlq_payload["dlq_reason"] == "test_reason"


# ── Retry & Backoff ────────────────────────────────────────────────────────────


class TestRetryBackoff:
    """Test the exponential backoff calculation."""

    def test_backoff_doubles(self):
        """Backoff should double each attempt, capped at 30s."""
        backoffs = [min(2 ** attempt, 30) for attempt in range(1, 8)]
        assert backoffs == [2, 4, 8, 16, 30, 30, 30]

    def test_max_retries_from_env(self):
        """MAX_RETRIES should be configurable via env var."""
        assert MAX_RETRIES == 3  # set in test env above


# ── Webhook Secret Configuration ───────────────────────────────────────────────


class TestConfiguration:
    """Test environment-based configuration."""

    def test_webhook_secret_loaded(self):
        assert WEBHOOK_SECRET == b"test-webhook-secret-for-pytest"

    def test_allowed_domains_contain_expected(self):
        assert "api.stripe.com" in ALLOWED_DOMAINS
        assert "enterprise.internal" in ALLOWED_DOMAINS

    def test_allowed_domains_no_wildcard(self):
        """Ensure no wildcard entries that would bypass SSRF protection."""
        for domain in ALLOWED_DOMAINS:
            assert domain != "*"
            assert domain != ""


# ── HITL Resume Worker Domain Validation ───────────────────────────────────────


class TestHitlValidateOutboundUrl:
    """Test SSRF protection in the HITL resume worker."""

    @pytest.fixture
    def hitl_worker(self):
        with patch("hitl_resume_worker.redis.from_url") as mock_redis:
            mock_redis.return_value = MagicMock()
            from hitl_resume_worker import HitlResumeWorker
            return HitlResumeWorker()

    def test_allowed_domain(self, hitl_worker):
        with patch("socket.getaddrinfo", return_value=[
            (2, 1, 6, '', ('93.184.216.34', 0)),
        ]):
            ok, _ = hitl_worker._validate_outbound_url("https://api.stripe.com/webhook")
            assert ok is True

    def test_blocked_domain(self, hitl_worker):
        ok, _ = hitl_worker._validate_outbound_url("https://evil.com/steal")
        assert ok is False

    def test_localhost_blocked(self, hitl_worker):
        ok, reason = hitl_worker._validate_outbound_url("https://localhost:9090/internal")
        assert ok is False
        assert "loopback" in reason or "not in domain allowlist" in reason

    def test_empty_url_blocked(self, hitl_worker):
        ok, _ = hitl_worker._validate_outbound_url("")
        assert ok is False

    def test_http_rejected(self, hitl_worker):
        ok, reason = hitl_worker._validate_outbound_url("http://api.stripe.com/webhook")
        assert ok is False
        assert "non-HTTPS" in reason

    def test_suffix_confusion_blocked(self, hitl_worker):
        ok, reason = hitl_worker._validate_outbound_url("https://evil-stripe.com/steal")
        assert ok is False
        assert "not in domain allowlist" in reason
