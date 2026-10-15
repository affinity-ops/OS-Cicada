# © 2026 Affinity Ops Ltd. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Tests for cicada_guard.user_context — User-context propagation.
"""

import base64
import json

import pytest

from cicada_guard.user_context import UserContext


# ── Helper to create a minimal JWT ───────────────────────────────


def _make_jwt(payload: dict) -> str:
    """Create a minimal unsigned JWT with the given payload for testing."""
    header = base64.urlsafe_b64encode(json.dumps({"alg": "none"}).encode()).rstrip(b"=").decode()
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    return f"{header}.{body}.signature"


# ── UserContext construction ─────────────────────────────────────


class TestUserContextConstruction:
    """Tests for UserContext creation and field assignment."""

    def test_default_values(self):
        ctx = UserContext()
        assert ctx.user_id == ""
        assert ctx.email == ""
        assert ctx.name == ""
        assert ctx.idp_issuer == ""
        assert ctx.roles == []
        assert ctx.metadata == {}

    def test_explicit_values(self):
        ctx = UserContext(
            user_id="usr_123",
            email="alice@acme.com",
            name="Alice Chen",
            idp_issuer="https://login.acme.com",
            roles=["admin", "operator"],
            metadata={"department": "engineering"},
        )
        assert ctx.user_id == "usr_123"
        assert ctx.email == "alice@acme.com"
        assert ctx.roles == ["admin", "operator"]

    def test_repr(self):
        ctx = UserContext(user_id="u1", email="a@b.com", idp_issuer="https://x.com")
        r = repr(ctx)
        assert "u1" in r
        assert "a@b.com" in r


# ── from_oauth_token ─────────────────────────────────────────────


class TestFromOAuthToken:
    """Tests for JWT extraction from OAuth tokens."""

    def test_standard_claims(self):
        token = _make_jwt({
            "sub": "usr_42",
            "email": "bob@corp.io",
            "name": "Bob Smith",
            "iss": "https://accounts.google.com",
            "roles": ["developer"],
        })
        ctx = UserContext.from_oauth_token(token)
        assert ctx.user_id == "usr_42"
        assert ctx.email == "bob@corp.io"
        assert ctx.name == "Bob Smith"
        assert ctx.idp_issuer == "https://accounts.google.com"
        assert ctx.roles == ["developer"]

    def test_groups_claim_fallback(self):
        """Some IdPs use 'groups' instead of 'roles'."""
        token = _make_jwt({"sub": "u1", "groups": ["admins", "ops"]})
        ctx = UserContext.from_oauth_token(token)
        assert ctx.roles == ["admins", "ops"]

    def test_act_claim_delegation(self):
        """RFC 8693 actor claim — tracks delegation chain."""
        token = _make_jwt({
            "sub": "agent_service",
            "iss": "https://idp.example.com",
            "act": {"sub": "human_user_99", "client_id": "portal_web"},
        })
        ctx = UserContext.from_oauth_token(token)
        assert ctx.metadata["delegator_sub"] == "human_user_99"
        assert ctx.metadata["delegator_client_id"] == "portal_web"

    def test_missing_claims_no_validate(self):
        """Missing claims should not raise when validate=False."""
        token = _make_jwt({})
        ctx = UserContext.from_oauth_token(token, validate=False)
        assert ctx.user_id == ""

    def test_missing_sub_validate_raises(self):
        token = _make_jwt({"iss": "https://idp.example.com"})
        with pytest.raises(ValueError, match="sub"):
            UserContext.from_oauth_token(token, validate=True)

    def test_missing_iss_validate_raises(self):
        token = _make_jwt({"sub": "u1"})
        with pytest.raises(ValueError, match="iss"):
            UserContext.from_oauth_token(token, validate=True)

    def test_invalid_jwt_format(self):
        with pytest.raises(ValueError, match="Invalid JWT format"):
            UserContext.from_oauth_token("not-a-jwt")

    def test_malformed_payload_raises(self):
        """JWT with invalid base64 payload."""
        with pytest.raises(ValueError, match="Failed to decode"):
            UserContext.from_oauth_token("header.!!!invalid!!!.signature")


# ── from_claims ──────────────────────────────────────────────────


class TestFromClaims:
    """Tests for creating UserContext from a pre-validated claims dict."""

    def test_standard_claims(self):
        ctx = UserContext.from_claims({
            "sub": "u1",
            "email": "a@b.com",
            "name": "A B",
            "iss": "https://idp.com",
            "roles": ["admin"],
        })
        assert ctx.user_id == "u1"
        assert ctx.email == "a@b.com"
        assert ctx.idp_issuer == "https://idp.com"

    def test_alternate_field_names(self):
        """Some systems use user_id, display_name, issuer."""
        ctx = UserContext.from_claims({
            "user_id": "u2",
            "display_name": "Bob",
            "issuer": "https://okta.com",
            "groups": ["operators"],
        })
        assert ctx.user_id == "u2"
        assert ctx.name == "Bob"
        assert ctx.idp_issuer == "https://okta.com"
        assert ctx.roles == ["operators"]

    def test_extra_claims_become_metadata(self):
        ctx = UserContext.from_claims({
            "sub": "u1",
            "department": "eng",
            "cost_centre": "CC-42",
        })
        assert ctx.metadata["department"] == "eng"
        assert ctx.metadata["cost_centre"] == "CC-42"


# ── Header serialization ────────────────────────────────────────


class TestHeaderSerialization:
    """Tests for X-Cicada-User-Context header encoding."""

    def test_to_header_value_roundtrip(self):
        ctx = UserContext(
            user_id="usr_99",
            email="test@corp.io",
            name="Test User",
            idp_issuer="https://auth.corp.io",
            roles=["admin"],
        )
        header_value = ctx.to_header_value()

        # Decode and verify
        decoded = json.loads(base64.urlsafe_b64decode(header_value))
        assert decoded["user_id"] == "usr_99"
        assert decoded["email"] == "test@corp.io"
        assert decoded["roles"] == ["admin"]

    def test_to_headers_dict(self):
        ctx = UserContext(user_id="u1")
        headers = ctx.to_headers()
        assert "X-Cicada-User-Context" in headers
        assert len(headers["X-Cicada-User-Context"]) > 0

    def test_empty_roles_omitted(self):
        ctx = UserContext(user_id="u1")
        header_value = ctx.to_header_value()
        decoded = json.loads(base64.urlsafe_b64decode(header_value))
        assert "roles" not in decoded

    def test_metadata_included_when_present(self):
        ctx = UserContext(user_id="u1", metadata={"dept": "eng"})
        header_value = ctx.to_header_value()
        decoded = json.loads(base64.urlsafe_b64decode(header_value))
        assert decoded["metadata"]["dept"] == "eng"


# ── Validation ───────────────────────────────────────────────────


class TestValidation:

    def test_valid_context(self):
        ctx = UserContext(user_id="u1", idp_issuer="https://idp.com")
        assert ctx.validate() == []

    def test_missing_user_id(self):
        ctx = UserContext(idp_issuer="https://idp.com")
        issues = ctx.validate()
        assert any("user_id" in i for i in issues)

    def test_missing_idp_issuer(self):
        ctx = UserContext(user_id="u1")
        issues = ctx.validate()
        assert any("idp_issuer" in i for i in issues)
