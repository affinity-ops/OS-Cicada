# © 2026 Affinity Ops Ltd. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Tests for cicada_guard.policy — Policy loading, parsing, and validation.
"""

import os
import tempfile
from pathlib import Path

import pytest
import yaml

from cicada_guard.policy import (
    CicadaPolicy,
    ComplianceConfig,
    EnforcementConfig,
    HITLConfig,
    IdentityConfig,
    ProvenanceConfig,
    ToolDeclaration,
    VelocityConfig,
    load_policy,
    _parse_policy,
)


# ── Fixtures ─────────────────────────────────────────────────────


MINIMAL_POLICY = {
    "apiVersion": "cicada/v1",
    "kind": "AgentPolicy",
    "identity": {
        "name": "test-agent",
        "owner": "alice@acme.com",
    },
    "tools": [
        {
            "name": "stripe-api",
            "url_patterns": ["https://api.stripe.com/*"],
            "methods": ["GET", "POST"],
        }
    ],
}


FULL_POLICY = {
    "apiVersion": "cicada/v1",
    "kind": "AgentPolicy",
    "identity": {
        "name": "invoice-processor",
        "description": "Processes invoices from Stripe",
        "type": "autonomous",
        "role": "processor",
        "owner": "bob@corp.io",
        "business_unit": "finance",
        "data_classification": "confidential",
        "criticality": "high",
    },
    "tools": [
        {
            "name": "stripe-charges",
            "url_patterns": ["https://api.stripe.com/v1/charges*"],
            "methods": ["GET", "POST"],
            "description": "Create and read charges",
            "destructive": False,
            "risk_level": "medium",
        },
        {
            "name": "stripe-refunds",
            "url_patterns": ["https://api.stripe.com/v1/refunds*"],
            "methods": ["POST", "DELETE"],
            "destructive": True,
            "risk_level": "high",
        },
    ],
    "enforcement": {
        "velocity": {
            "max_reads_per_minute": 200,
            "max_writes_per_minute": 50,
            "max_deletes_per_minute": 10,
            "circuit_breaker_threshold": 20,
        },
        "hitl": {
            "enabled": True,
            "webhook_url": "https://hooks.slack.com/cicada",
            "timeout_seconds": 1800,
            "auto_deny_on_timeout": True,
            "risk_threshold": 0.8,
        },
        "shadow_mode": False,
        "destructive_capability": True,
    },
    "provenance": {
        "evar_binding": True,
        "content_tagging": True,
        "audit_retention_days": 730,
    },
    "compliance": {
        "frameworks": ["SOC2", "ISO27001"],
        "regulatory_region": "EU",
        "budget_cap_usd": 1000.0,
        "cost_centre": "CC-42",
    },
}


def _write_yaml(data: dict, path: Path):
    with open(path, "w") as f:
        yaml.dump(data, f)


# ── Policy Parsing ───────────────────────────────────────────────


class TestParsing:
    """Tests for _parse_policy and field mapping."""

    def test_minimal_policy(self):
        policy = _parse_policy(MINIMAL_POLICY)
        assert policy.identity.name == "test-agent"
        assert policy.identity.owner == "alice@acme.com"
        assert len(policy.tools) == 1

    def test_full_policy_identity(self):
        policy = _parse_policy(FULL_POLICY)
        assert policy.identity.name == "invoice-processor"
        assert policy.identity.data_classification == "confidential"
        assert policy.identity.criticality == "high"

    def test_full_policy_tools(self):
        policy = _parse_policy(FULL_POLICY)
        assert len(policy.tools) == 2
        assert policy.tools[0].name == "stripe-charges"
        assert policy.tools[1].destructive is True
        assert "DELETE" in policy.tools[1].methods

    def test_full_policy_enforcement(self):
        policy = _parse_policy(FULL_POLICY)
        assert policy.enforcement.velocity.max_reads_per_minute == 200
        assert policy.enforcement.hitl.enabled is True
        assert policy.enforcement.hitl.risk_threshold == 0.8

    def test_full_policy_provenance(self):
        policy = _parse_policy(FULL_POLICY)
        assert policy.provenance.content_tagging is True
        assert policy.provenance.audit_retention_days == 730

    def test_full_policy_compliance(self):
        policy = _parse_policy(FULL_POLICY)
        assert "SOC2" in policy.compliance.frameworks
        assert policy.compliance.regulatory_region == "EU"
        assert policy.compliance.budget_cap_usd == 1000.0

    def test_default_values_for_missing_sections(self):
        policy = _parse_policy({"identity": {"name": "bare"}})
        assert policy.enforcement.velocity.max_reads_per_minute == 100
        assert policy.enforcement.hitl.enabled is False
        assert policy.provenance.evar_binding is True
        assert policy.compliance.regulatory_region == "GLOBAL"


# ── Policy Properties ────────────────────────────────────────────


class TestPolicyProperties:

    def test_agent_name(self):
        policy = _parse_policy(MINIMAL_POLICY)
        assert policy.agent_name == "test-agent"

    def test_hitl_enabled(self):
        policy = _parse_policy(FULL_POLICY)
        assert policy.hitl_enabled is True

    def test_hitl_disabled_by_default(self):
        policy = _parse_policy(MINIMAL_POLICY)
        assert policy.hitl_enabled is False

    def test_is_destructive_from_enforcement(self):
        policy = _parse_policy(FULL_POLICY)
        assert policy.is_destructive is True

    def test_is_destructive_from_tool(self):
        data = {**MINIMAL_POLICY, "tools": [
            {"name": "t1", "url_patterns": ["http://x"], "methods": ["DELETE"], "destructive": True}
        ]}
        policy = _parse_policy(data)
        assert policy.is_destructive is True

    def test_not_destructive(self):
        policy = _parse_policy(MINIMAL_POLICY)
        assert policy.is_destructive is False

    def test_allowed_urls(self):
        policy = _parse_policy(FULL_POLICY)
        urls = policy.allowed_urls
        assert "https://api.stripe.com/v1/charges*" in urls
        assert "https://api.stripe.com/v1/refunds*" in urls


# ── Policy Validation ────────────────────────────────────────────


class TestValidation:

    def test_valid_policy_no_issues(self):
        policy = _parse_policy(FULL_POLICY)
        issues = policy.validate()
        assert issues == []

    def test_missing_name(self):
        data = {**MINIMAL_POLICY, "identity": {"owner": "x"}}
        policy = _parse_policy(data)
        issues = policy.validate()
        assert any("name" in i for i in issues)

    def test_missing_owner(self):
        data = {**MINIMAL_POLICY, "identity": {"name": "x"}}
        policy = _parse_policy(data)
        issues = policy.validate()
        assert any("owner" in i for i in issues)

    def test_no_tools_warning(self):
        data = {**MINIMAL_POLICY, "tools": []}
        policy = _parse_policy(data)
        issues = policy.validate()
        assert any("tool" in i for i in issues)

    def test_destructive_without_hitl_warning(self):
        data = {**MINIMAL_POLICY}
        data["enforcement"] = {"destructive_capability": True, "hitl": {"enabled": False}}
        policy = _parse_policy(data)
        issues = policy.validate()
        assert any("HITL" in i for i in issues)

    def test_high_criticality_without_hitl_warning(self):
        data = {**MINIMAL_POLICY}
        data["identity"]["criticality"] = "critical"
        policy = _parse_policy(data)
        issues = policy.validate()
        assert any("criticality" in i for i in issues)

    def test_delete_without_destructive_flag(self):
        data = {**MINIMAL_POLICY, "tools": [
            {"name": "t1", "url_patterns": ["http://x"], "methods": ["DELETE"], "destructive": False}
        ]}
        policy = _parse_policy(data)
        issues = policy.validate()
        assert any("DELETE" in i for i in issues)


# ── load_policy ──────────────────────────────────────────────────


class TestLoadPolicy:

    def test_load_from_file(self, tmp_path):
        policy_file = tmp_path / "cicada.yaml"
        _write_yaml(MINIMAL_POLICY, policy_file)

        policy = load_policy(policy_file)
        assert policy.identity.name == "test-agent"

    def test_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            load_policy("/nonexistent/cicada.yaml")

    def test_invalid_yaml(self, tmp_path):
        policy_file = tmp_path / "cicada.yaml"
        policy_file.write_text("not: [valid: yaml: {{{{")

        with pytest.raises(Exception):  # yaml.scanner.ScannerError
            load_policy(policy_file)

    def test_non_mapping_yaml(self, tmp_path):
        policy_file = tmp_path / "cicada.yaml"
        policy_file.write_text("- just\n- a\n- list\n")

        with pytest.raises(ValueError, match="mapping"):
            load_policy(policy_file)

    def test_env_variable_path(self, tmp_path, monkeypatch):
        policy_file = tmp_path / "custom.yaml"
        _write_yaml(MINIMAL_POLICY, policy_file)
        monkeypatch.setenv("CICADA_POLICY_PATH", str(policy_file))

        policy = load_policy(None)
        assert policy.identity.name == "test-agent"
