# © 2026 Affinity Ops Ltd. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Tests for cicada_guard.client — CicadaClient core functionality.
"""

import json
from unittest.mock import MagicMock, patch, PropertyMock

import pytest
import requests

from cicada_guard.client import CicadaClient
from cicada_guard.retry import (
    CicadaBlockedError,
    CicadaConnectionError,
    CicadaRateLimitedError,
    RetryConfig,
)
from cicada_guard.user_context import UserContext


# ── Fixtures ─────────────────────────────────────────────────────


def _mock_response(status_code=200, text="ok", json_data=None, headers=None):
    response = MagicMock(spec=requests.Response)
    response.status_code = status_code
    response.text = text
    response.headers = headers or {}
    if json_data:
        response.json.return_value = json_data
    return response


def _client(**kwargs):
    """Create a CicadaClient with sensible defaults for testing."""
    defaults = {
        "gateway_url": "http://localhost:8080",
        "session_token": "test-token-abc123",
        "agent_id": "agent-001",
        "tenant_id": "tenant-nexus",
        "retry_config": RetryConfig(max_retries=0),  # No retries in unit tests
    }
    defaults.update(kwargs)
    return CicadaClient(**defaults)


# ── Client Construction ──────────────────────────────────────────


class TestClientConstruction:
    """Tests for CicadaClient initialization."""

    def test_default_headers(self):
        client = _client()
        headers = client._base_headers()
        assert headers["Authorization"] == "Bearer test-token-abc123"
        assert headers["X-Cicada-Agent-ID"] == "agent-001"
        assert "cicada-guard-python" in headers["User-Agent"]

    def test_tenant_header_included(self):
        client = _client(tenant_id="tenant-xyz")
        headers = client._base_headers()
        assert headers["X-Cicada-Tenant-ID"] == "tenant-xyz"

    def test_tenant_header_excluded_when_empty(self):
        client = _client(tenant_id="")
        headers = client._base_headers()
        assert "X-Cicada-Tenant-ID" not in headers

    def test_gateway_url_trailing_slash_stripped(self):
        client = _client(gateway_url="http://gw.local:8080/")
        assert client.gateway_url == "http://gw.local:8080"

    def test_session_uses_ssl_verify(self):
        client = _client(verify_ssl=False)
        assert client._session.verify is False

    def test_default_retry_config(self):
        client = CicadaClient(
            gateway_url="http://gw",
            session_token="tok",
        )
        assert client.retry_config.max_retries == 3

    def test_custom_retry_config(self):
        config = RetryConfig(max_retries=5, backoff_base=2.0)
        client = _client(retry_config=config)
        assert client.retry_config.max_retries == 5

    def test_default_user_context(self):
        ctx = UserContext(user_id="u1")
        client = _client(default_user_context=ctx)
        assert client.default_user_context is ctx


# ── proxy_call ───────────────────────────────────────────────────


class TestProxyCall:
    """Tests for the proxy_call method."""

    @patch("cicada_guard.client.retry_request")
    def test_sends_to_proxy_endpoint(self, mock_retry):
        mock_retry.return_value = _mock_response(200)
        client = _client()

        client.proxy_call("POST", "https://api.stripe.com/v1/charges")

        call_kwargs = mock_retry.call_args
        assert call_kwargs[1]["url"] == "http://localhost:8080/v1/proxy"

    @patch("cicada_guard.client.retry_request")
    def test_target_url_header_set(self, mock_retry):
        mock_retry.return_value = _mock_response(200)
        client = _client()

        client.proxy_call("GET", "https://api.example.com/data")

        headers = mock_retry.call_args[1]["headers"]
        assert headers["X-Cicada-Target-URL"] == "https://api.example.com/data"

    @patch("cicada_guard.client.retry_request")
    def test_provenance_header_set(self, mock_retry):
        mock_retry.return_value = _mock_response(200)
        client = _client()

        client.proxy_call("POST", "https://api.example.com", provenance="user")

        headers = mock_retry.call_args[1]["headers"]
        assert headers["X-Cicada-Content-Provenance"] == "user"

    @patch("cicada_guard.client.retry_request")
    def test_dict_body_serialized_as_json(self, mock_retry):
        mock_retry.return_value = _mock_response(200)
        client = _client()

        client.proxy_call("POST", "https://api.example.com", body={"key": "value"})

        call_kwargs = mock_retry.call_args[1]
        assert json.loads(call_kwargs["data"]) == {"key": "value"}
        assert call_kwargs["headers"]["Content-Type"] == "application/json"

    @patch("cicada_guard.client.retry_request")
    def test_string_body_encoded(self, mock_retry):
        mock_retry.return_value = _mock_response(200)
        client = _client()

        client.proxy_call("POST", "https://api.example.com", body="raw data")

        call_kwargs = mock_retry.call_args[1]
        assert call_kwargs["data"] == b"raw data"

    @patch("cicada_guard.client.retry_request")
    def test_bytes_body_passed_through(self, mock_retry):
        mock_retry.return_value = _mock_response(200)
        client = _client()

        raw = b"\x00\x01\x02"
        client.proxy_call("POST", "https://api.example.com", body=raw)

        assert mock_retry.call_args[1]["data"] is raw

    @patch("cicada_guard.client.retry_request")
    def test_user_context_injected(self, mock_retry):
        mock_retry.return_value = _mock_response(200)
        client = _client()
        ctx = UserContext(user_id="usr_42", email="a@b.com")

        client.proxy_call("GET", "https://api.example.com", user_context=ctx)

        headers = mock_retry.call_args[1]["headers"]
        assert "X-Cicada-User-Context" in headers

    @patch("cicada_guard.client.retry_request")
    def test_default_user_context_used(self, mock_retry):
        mock_retry.return_value = _mock_response(200)
        ctx = UserContext(user_id="default_user")
        client = _client(default_user_context=ctx)

        client.proxy_call("GET", "https://api.example.com")

        headers = mock_retry.call_args[1]["headers"]
        assert "X-Cicada-User-Context" in headers

    @patch("cicada_guard.client.retry_request")
    def test_per_call_context_overrides_default(self, mock_retry):
        mock_retry.return_value = _mock_response(200)
        default_ctx = UserContext(user_id="default")
        override_ctx = UserContext(user_id="override")
        client = _client(default_user_context=default_ctx)

        client.proxy_call("GET", "https://api.example.com", user_context=override_ctx)

        headers = mock_retry.call_args[1]["headers"]
        header_val = headers["X-Cicada-User-Context"]
        import base64
        decoded = json.loads(base64.urlsafe_b64decode(header_val))
        assert decoded["user_id"] == "override"

    @patch("cicada_guard.client.retry_request")
    def test_raise_on_block_403(self, mock_retry):
        mock_retry.return_value = _mock_response(403, text="blocked: injection")
        client = _client()

        with pytest.raises(CicadaBlockedError):
            client.proxy_call("POST", "https://api.example.com", raise_on_block=True)

    @patch("cicada_guard.client.retry_request")
    def test_raise_on_block_429(self, mock_retry):
        mock_retry.return_value = _mock_response(429, text="rate limited")
        client = _client()

        with pytest.raises(CicadaRateLimitedError):
            client.proxy_call("POST", "https://api.example.com", raise_on_block=True)

    @patch("cicada_guard.client.retry_request")
    def test_no_raise_on_block_returns_response(self, mock_retry):
        """Default behaviour: return the 403 response without raising."""
        mock_retry.return_value = _mock_response(403)
        client = _client()

        result = client.proxy_call("POST", "https://api.example.com")
        assert result.status_code == 403

    @patch("cicada_guard.client.retry_request")
    def test_custom_timeout(self, mock_retry):
        mock_retry.return_value = _mock_response(200)
        client = _client(timeout=10.0)

        client.proxy_call("GET", "https://api.example.com", timeout=60.0)

        assert mock_retry.call_args[1]["timeout"] == 60.0

    @patch("cicada_guard.client.retry_request")
    def test_additional_headers_merged(self, mock_retry):
        mock_retry.return_value = _mock_response(200)
        client = _client()

        client.proxy_call(
            "GET", "https://api.example.com",
            headers={"X-Custom": "value"},
        )

        headers = mock_retry.call_args[1]["headers"]
        assert headers["X-Custom"] == "value"


# ── proxy_llm_call ───────────────────────────────────────────────


class TestProxyLLMCall:
    """Tests for the proxy_llm_call method."""

    @patch("cicada_guard.client.retry_request")
    def test_sends_to_llm_proxy_endpoint(self, mock_retry):
        mock_retry.return_value = _mock_response(200)
        client = _client()

        client.proxy_llm_call(
            messages=[{"role": "user", "content": "hello"}],
            model="gpt-4",
        )

        assert mock_retry.call_args[1]["url"] == "http://localhost:8080/v1/llm/proxy"

    @patch("cicada_guard.client.retry_request")
    def test_provider_header_set(self, mock_retry):
        mock_retry.return_value = _mock_response(200)
        client = _client()

        client.proxy_llm_call(
            messages=[{"role": "user", "content": "hi"}],
            provider_base_url="https://api.anthropic.com",
        )

        headers = mock_retry.call_args[1]["headers"]
        assert headers["X-Cicada-LLM-Provider"] == "https://api.anthropic.com"

    @patch("cicada_guard.client.retry_request")
    def test_user_context_on_llm_call(self, mock_retry):
        mock_retry.return_value = _mock_response(200)
        client = _client()
        ctx = UserContext(user_id="u1")

        client.proxy_llm_call(
            messages=[{"role": "user", "content": "test"}],
            user_context=ctx,
        )

        headers = mock_retry.call_args[1]["headers"]
        assert "X-Cicada-User-Context" in headers


# ── health_check ─────────────────────────────────────────────────


class TestHealthCheck:

    def test_successful_health_check(self):
        client = _client()
        client._session.get = MagicMock(return_value=_mock_response(
            200, json_data={"status": "ok", "version": "1.0.0"}
        ))

        result = client.health_check()
        assert result["status"] == "ok"

    def test_unreachable_health_check(self):
        client = _client()
        client._session.get = MagicMock(side_effect=ConnectionError("refused"))

        result = client.health_check()
        assert result["status"] == "unreachable"
        assert "refused" in result["error"]


# ── get_agent_status ─────────────────────────────────────────────


class TestGetAgentStatus:

    def test_returns_agent_status(self):
        client = _client()
        client._session.get = MagicMock(return_value=_mock_response(
            200, json_data={"trust_score": 0.92, "violations": 0}
        ))

        result = client.get_agent_status()
        assert result["trust_score"] == 0.92
