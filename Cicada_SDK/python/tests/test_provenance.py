# © 2026 Affinity Ops Ltd. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Tests for cicada_guard.provenance — Content provenance tagging.
"""

import hashlib

import pytest

from cicada_guard.provenance import (
    ProvenanceTag,
    tag_developer,
    tag_retrieved,
    tag_tool_result,
    tag_user_input,
    _hash_content,
)


class TestHashContent:
    def test_deterministic(self):
        assert _hash_content("hello") == _hash_content("hello")

    def test_different_inputs(self):
        assert _hash_content("a") != _hash_content("b")

    def test_matches_sha256(self):
        expected = hashlib.sha256("test".encode()).hexdigest()
        assert _hash_content("test") == expected


class TestProvenanceTag:
    def test_to_header_value(self):
        tag = ProvenanceTag(trust_level="retrieved")
        assert tag.to_header_value() == "retrieved"

    def test_to_metadata(self):
        tag = ProvenanceTag(
            trust_level="tool_result",
            tool_name="stripe-api",
            source_url="https://api.stripe.com",
        )
        meta = tag.to_metadata()
        assert meta["trust_level"] == "tool_result"
        assert meta["tool_name"] == "stripe-api"
        assert meta["source_url"] == "https://api.stripe.com"
        assert "timestamp" in meta
        assert "content_hash" in meta


class TestTagRetrieved:
    def test_tags_with_correct_trust_level(self):
        content, tag = tag_retrieved("some html", source_url="https://example.com")
        assert content == "some html"
        assert tag.trust_level == "retrieved"
        assert tag.source_url == "https://example.com"
        assert tag.source_type == "web"

    def test_custom_source_type(self):
        _, tag = tag_retrieved("pdf data", source_type="pdf")
        assert tag.source_type == "pdf"

    def test_content_hash_set(self):
        _, tag = tag_retrieved("test content")
        assert tag.content_hash == _hash_content("test content")


class TestTagToolResult:
    def test_tags_with_correct_trust_level(self):
        content, tag = tag_tool_result('{"data": 1}', tool_name="stripe-api")
        assert content == '{"data": 1}'
        assert tag.trust_level == "tool_result"
        assert tag.tool_name == "stripe-api"


class TestTagUserInput:
    def test_tags_with_user_trust(self):
        _, tag = tag_user_input("Hello, I need help")
        assert tag.trust_level == "user"
        assert tag.source_type == "user_input"


class TestTagDeveloper:
    def test_tags_with_developer_trust(self):
        _, tag = tag_developer("You are a helpful assistant")
        assert tag.trust_level == "developer"
        assert tag.source_type == "developer_authored"
