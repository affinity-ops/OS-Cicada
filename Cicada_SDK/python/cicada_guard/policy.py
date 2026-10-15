# © 2026 Affinity Ops Ltd. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""
cicada_guard.policy — cicada.yaml parser and validator.

Loads the declarative policy file, validates it against the JSON Schema,
and provides structured access to all governance settings.
"""

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

# Path to the bundled JSON Schema for validation
_SCHEMA_PATH = Path(__file__).parent.parent.parent / "schema" / "cicada-policy-v1.json"


@dataclass
class ToolDeclaration:
    """A single tool declaration from the tools[] array."""
    name: str
    url_patterns: list[str]
    methods: list[str]
    description: str = ""
    destructive: bool = False
    risk_level: str = "medium"
    input_schema: Optional[dict] = None
    allowed_upstreams: list[str] = field(default_factory=list)
    criticality_level: str = "low"


@dataclass
class VelocityConfig:
    """Velocity limits for Layer 5 (Circuit Breaker)."""
    max_reads_per_minute: int = 100
    max_writes_per_minute: int = 20
    max_deletes_per_minute: int = 5
    circuit_breaker_threshold: int = 10


@dataclass
class HITLConfig:
    """Human-in-the-loop configuration for Layer 7."""
    enabled: bool = False
    webhook_url: str = ""
    timeout_seconds: int = 3600
    auto_deny_on_timeout: bool = True
    risk_threshold: float = 0.6


@dataclass
class EnforcementConfig:
    """Enforcement settings for the seven-layer pipeline."""
    velocity: VelocityConfig = field(default_factory=VelocityConfig)
    hitl: HITLConfig = field(default_factory=HITLConfig)
    shadow_mode: bool = False
    destructive_capability: bool = False


@dataclass
class ProvenanceConfig:
    """Content provenance and integrity settings."""
    evar_binding: bool = True
    content_tagging: bool = False
    audit_retention_days: int = 365


@dataclass
class ComplianceConfig:
    """Compliance and regulatory settings."""
    frameworks: list[str] = field(default_factory=list)
    regulatory_region: str = "GLOBAL"
    budget_cap_usd: Optional[float] = None
    cost_centre: str = ""


@dataclass
class IdentityConfig:
    """Agent identity metadata."""
    name: str = ""
    description: str = ""
    type: str = "autonomous"
    role: str = "processor"
    owner: str = ""
    business_unit: str = ""
    data_classification: str = "internal"
    criticality: str = "medium"


@dataclass
class CicadaPolicy:
    """
    Parsed representation of a cicada.yaml policy file.

    This is the central configuration object for the SDK. It provides
    structured access to all governance settings defined in the policy file.
    """
    api_version: str = "cicada/v1"
    kind: str = "AgentPolicy"
    identity: IdentityConfig = field(default_factory=IdentityConfig)
    tools: list[ToolDeclaration] = field(default_factory=list)
    enforcement: EnforcementConfig = field(default_factory=EnforcementConfig)
    provenance: ProvenanceConfig = field(default_factory=ProvenanceConfig)
    compliance: ComplianceConfig = field(default_factory=ComplianceConfig)

    @property
    def agent_name(self) -> str:
        return self.identity.name

    @property
    def hitl_enabled(self) -> bool:
        return self.enforcement.hitl.enabled

    @property
    def is_destructive(self) -> bool:
        """True if the agent or any of its tools have destructive capability."""
        if self.enforcement.destructive_capability:
            return True
        return any(t.destructive for t in self.tools)

    @property
    def allowed_urls(self) -> list[str]:
        """Flat list of all allowed URL patterns across all tools."""
        urls = []
        for tool in self.tools:
            urls.extend(tool.url_patterns)
        return urls

    def validate(self) -> list[str]:
        """
        Validate the policy for logical consistency.

        Returns a list of warning/error messages. An empty list means
        the policy is valid.
        """
        issues = []

        if not self.identity.name:
            issues.append("identity.name is required")

        if not self.identity.owner:
            issues.append("identity.owner is required")

        if not self.tools:
            issues.append("at least one tool must be declared")

        # Destructive agents must have HITL enabled
        if self.is_destructive and not self.hitl_enabled:
            issues.append(
                "agent has destructive capabilities but HITL is not enabled — "
                "the Sentry Gateway will block all write operations. "
                "Set enforcement.hitl.enabled=true to allow destructive actions "
                "with human review."
            )

        # High/critical criticality should have HITL
        if self.identity.criticality in ("high", "critical") and not self.hitl_enabled:
            issues.append(
                f"agent criticality is '{self.identity.criticality}' but HITL is not enabled — "
                "consider enabling HITL for high-risk agents"
            )

        # Check for DELETE methods without destructive flag
        for tool in self.tools:
            if "DELETE" in tool.methods and not tool.destructive:
                issues.append(
                    f"tool '{tool.name}' allows DELETE but destructive=false — "
                    "consider setting destructive=true"
                )
            if tool.criticality_level == "high" and not self.hitl_enabled:
                issues.append(
                    f"tool '{tool.name}' has criticality_level=high but HITL is not enabled — "
                    "the Sentry Gateway will enforce mandatory CIBA holds on this tool"
                )

        return issues


def load_policy(path: str | Path | None = None) -> CicadaPolicy:
    """
    Load and parse a cicada.yaml policy file.

    Args:
        path: Path to the policy file. Defaults to ./cicada.yaml or the
              CICADA_POLICY_PATH environment variable.

    Returns:
        A validated CicadaPolicy object.

    Raises:
        FileNotFoundError: If the policy file does not exist.
        ValueError: If the policy file is invalid YAML or fails schema validation.
    """
    if path is None:
        path = os.environ.get("CICADA_POLICY_PATH", "cicada.yaml")

    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Policy file not found: {path}")

    with open(path) as f:
        raw = yaml.safe_load(f)

    if not isinstance(raw, dict):
        raise ValueError(f"Policy file must be a YAML mapping, got {type(raw).__name__}")

    # Validate against JSON Schema if jsonschema is available
    try:
        import jsonschema
        if _SCHEMA_PATH.exists():
            with open(_SCHEMA_PATH) as sf:
                schema = json.load(sf)
            jsonschema.validate(instance=raw, schema=schema)
    except ImportError:
        pass  # jsonschema not installed — skip schema validation
    except jsonschema.ValidationError as e:
        raise ValueError(f"Policy validation error: {e.message}") from e

    return _parse_policy(raw)


def _parse_policy(raw: dict[str, Any]) -> CicadaPolicy:
    """Parse raw YAML dict into a CicadaPolicy dataclass."""
    policy = CicadaPolicy()
    policy.api_version = raw.get("apiVersion", "cicada/v1")
    policy.kind = raw.get("kind", "AgentPolicy")

    # Identity
    identity_raw = raw.get("identity", {})
    policy.identity = IdentityConfig(
        name=identity_raw.get("name", ""),
        description=identity_raw.get("description", ""),
        type=identity_raw.get("type", "autonomous"),
        role=identity_raw.get("role", "processor"),
        owner=identity_raw.get("owner", ""),
        business_unit=identity_raw.get("business_unit", ""),
        data_classification=identity_raw.get("data_classification", "internal"),
        criticality=identity_raw.get("criticality", "medium"),
    )

    # Tools
    policy.tools = []
    for tool_raw in raw.get("tools", []):
        policy.tools.append(ToolDeclaration(
            name=tool_raw.get("name", ""),
            url_patterns=tool_raw.get("url_patterns", []),
            methods=tool_raw.get("methods", ["GET"]),
            description=tool_raw.get("description", ""),
            destructive=tool_raw.get("destructive", False),
            risk_level=tool_raw.get("risk_level", "medium"),
            input_schema=tool_raw.get("input_schema"),
            allowed_upstreams=tool_raw.get("allowed_upstreams", []),
            criticality_level=tool_raw.get("criticality_level", "low"),
        ))

    # Enforcement
    enforcement_raw = raw.get("enforcement", {})
    velocity_raw = enforcement_raw.get("velocity", {})
    hitl_raw = enforcement_raw.get("hitl", {})
    policy.enforcement = EnforcementConfig(
        velocity=VelocityConfig(
            max_reads_per_minute=velocity_raw.get("max_reads_per_minute", 100),
            max_writes_per_minute=velocity_raw.get("max_writes_per_minute", 20),
            max_deletes_per_minute=velocity_raw.get("max_deletes_per_minute", 5),
            circuit_breaker_threshold=velocity_raw.get("circuit_breaker_threshold", 10),
        ),
        hitl=HITLConfig(
            enabled=hitl_raw.get("enabled", False),
            webhook_url=hitl_raw.get("webhook_url", ""),
            timeout_seconds=hitl_raw.get("timeout_seconds", 3600),
            auto_deny_on_timeout=hitl_raw.get("auto_deny_on_timeout", True),
            risk_threshold=hitl_raw.get("risk_threshold", 0.6),
        ),
        shadow_mode=enforcement_raw.get("shadow_mode", False),
        destructive_capability=enforcement_raw.get("destructive_capability", False),
    )

    # Provenance
    prov_raw = raw.get("provenance", {})
    policy.provenance = ProvenanceConfig(
        evar_binding=prov_raw.get("evar_binding", True),
        content_tagging=prov_raw.get("content_tagging", False),
        audit_retention_days=prov_raw.get("audit_retention_days", 365),
    )

    # Compliance
    comp_raw = raw.get("compliance", {})
    policy.compliance = ComplianceConfig(
        frameworks=comp_raw.get("frameworks", []),
        regulatory_region=comp_raw.get("regulatory_region", "GLOBAL"),
        budget_cap_usd=comp_raw.get("budget_cap_usd"),
        cost_centre=comp_raw.get("cost_centre", ""),
    )

    return policy
