# © 2026 Affinity Ops Ltd. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""
cicada_guard.user_context — User-context propagation for delegated agent actions.

When an AI agent acts on behalf of a human user, the Sentry Gateway needs to
know which user initiated the action. This enables:

    1. "Agent X on behalf of User Y" in the action ledger
    2. User-scoped velocity limits (per-user rate limiting)
    3. HITL escalation targeted to the correct human
    4. Compliance audit trails that link agent actions to human principals

The Gateway reads the X-Cicada-User-Context header, validates the JWT claims,
and records the user identity alongside the agent identity in the ledger.

Usage:
    from cicada_guard.user_context import UserContext

    # From an OAuth access token (user authenticated via IdP)
    ctx = UserContext.from_oauth_token(access_token)

    # From manual identity fields (when you know the user)
    ctx = UserContext(
        user_id="usr_12345",
        email="alice@acme.com",
        name="Alice Chen",
        idp_issuer="https://login.acme.com"
    )

    # Attach to every proxy call
    client.proxy_call("POST", url, body=data, user_context=ctx)
"""

import base64
import json
import logging
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger("cicada_guard.user_context")


@dataclass
class UserContext:
    """
    Represents the human user on whose behalf an agent is acting.

    This is propagated to the Sentry Gateway via the X-Cicada-User-Context
    header. The Gateway validates the structure and records it in the action
    ledger alongside the agent identity.

    Attributes:
        user_id: Unique identifier for the user (from IdP or internal system).
        email: User's email address.
        name: User's display name.
        idp_issuer: The issuer URL of the IdP that authenticated the user
                    (e.g. https://accounts.google.com, https://login.okta.com).
        roles: User's roles/groups from the IdP claims.
        metadata: Additional key-value metadata to include in the audit trail.
    """
    user_id: str = ""
    email: str = ""
    name: str = ""
    idp_issuer: str = ""
    roles: list[str] = field(default_factory=list)
    metadata: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_oauth_token(
        cls,
        access_token: str,
        validate: bool = False,
    ) -> "UserContext":
        """
        Extract user context from an OAuth access token (JWT).

        This performs a basic decode of the JWT payload to extract
        standard claims (sub, email, name, iss). It does NOT validate
        the token signature — that's the IdP's / Gateway's responsibility.

        Args:
            access_token: A JWT access token.
            validate: If True, raise on missing required claims.

        Returns:
            UserContext with fields populated from JWT claims.

        Raises:
            ValueError: If the token format is invalid or required claims are missing.
        """
        try:
            parts = access_token.split(".")
            if len(parts) != 3:
                raise ValueError(f"Invalid JWT format: expected 3 parts, got {len(parts)}")

            # Decode the payload (part 1) — add padding
            payload_b64 = parts[1]
            padding = 4 - len(payload_b64) % 4
            if padding != 4:
                payload_b64 += "=" * padding

            payload = json.loads(base64.urlsafe_b64decode(payload_b64))

        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise ValueError(f"Failed to decode JWT payload: {e}") from e

        ctx = cls(
            user_id=str(payload.get("sub", "")),
            email=payload.get("email", ""),
            name=payload.get("name", ""),
            idp_issuer=payload.get("iss", ""),
            roles=payload.get("roles", payload.get("groups", [])),
        )

        # Include act claim if present (delegation chain per RFC 8693)
        act_claim = payload.get("act")
        if act_claim and isinstance(act_claim, dict):
            ctx.metadata["delegator_sub"] = str(act_claim.get("sub", ""))
            ctx.metadata["delegator_client_id"] = str(act_claim.get("client_id", ""))

        if validate:
            if not ctx.user_id:
                raise ValueError("JWT missing required 'sub' claim")
            if not ctx.idp_issuer:
                raise ValueError("JWT missing required 'iss' claim")

        return ctx

    @classmethod
    def from_claims(cls, claims: dict[str, Any]) -> "UserContext":
        """
        Create user context from a pre-validated claims dict.

        Useful when the calling framework has already validated and
        decoded the user's authentication token.

        Args:
            claims: Dictionary of user claims.

        Returns:
            UserContext populated from the claims.
        """
        return cls(
            user_id=str(claims.get("sub", claims.get("user_id", ""))),
            email=claims.get("email", ""),
            name=claims.get("name", claims.get("display_name", "")),
            idp_issuer=claims.get("iss", claims.get("issuer", "")),
            roles=claims.get("roles", claims.get("groups", [])),
            metadata={
                k: str(v) for k, v in claims.items()
                if k not in {"sub", "user_id", "email", "name", "display_name",
                             "iss", "issuer", "roles", "groups", "exp", "iat", "nbf"}
            },
        )

    def to_header_value(self) -> str:
        """
        Serialize this context to the X-Cicada-User-Context header value.

        Format: Base64-encoded JSON for compact transport.

        Returns:
            Base64-encoded JSON string.
        """
        payload = {
            "user_id": self.user_id,
            "email": self.email,
            "name": self.name,
            "idp_issuer": self.idp_issuer,
        }
        if self.roles:
            payload["roles"] = self.roles
        if self.metadata:
            payload["metadata"] = self.metadata

        json_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(json_bytes).decode("ascii")

    def to_headers(self) -> dict[str, str]:
        """
        Return the headers dict to inject into a proxy_call.

        Returns:
            Dict with the X-Cicada-User-Context header.
        """
        return {"X-Cicada-User-Context": self.to_header_value()}

    def validate(self) -> list[str]:
        """
        Validate the user context for completeness.

        Returns:
            List of validation issues. Empty list means valid.
        """
        issues = []
        if not self.user_id:
            issues.append("user_id is required")
        if not self.idp_issuer:
            issues.append("idp_issuer is required for audit trail compliance")
        return issues

    def __repr__(self) -> str:
        return (
            f"UserContext(user_id={self.user_id!r}, "
            f"email={self.email!r}, "
            f"idp_issuer={self.idp_issuer!r})"
        )
