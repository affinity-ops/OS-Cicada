# © 2026 Affinity Ops Ltd. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""
cicada_guard.provenance — Content provenance tagging for RAG pipelines.

This module provides helpers for AI agents that retrieve external content
(web pages, PDFs, emails, database records) and include it in their LLM
context windows. Content tagged with provenance metadata receives elevated
scrutiny at the Sentry Gateway's injection scanner.

Why this matters:
    Indirect Prompt Injection (IPI) payloads are embedded in external data
    that agents retrieve and process. The Gateway scans the messages[] array
    for injection patterns, but without provenance tagging, it treats all
    non-system messages equally. Tagging retrieved content as 'retrieved'
    provenance triggers elevated scan sensitivity — the blocking threshold
    drops from High to Medium severity.

Usage:
    from cicada_guard.provenance import tag_retrieved, tag_tool_result

    # Tag content retrieved from a web page
    tagged = tag_retrieved(scraped_html, source_url="https://example.com")

    # Tag content returned by a tool/function call
    tagged = tag_tool_result(api_response, tool_name="stripe-api")
"""

import hashlib
import time
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ProvenanceTag:
    """
    Metadata tag for content provenance tracking.

    Attached to retrieved content to enable trust-level-aware scanning
    at the Sentry Gateway.
    """
    trust_level: str  # 'system', 'developer', 'user', 'tool_result', 'retrieved'
    source_url: str = ""
    source_type: str = ""  # 'web', 'pdf', 'email', 'database', 'api', 'file'
    tool_name: str = ""
    timestamp: float = field(default_factory=time.time)
    content_hash: str = ""  # SHA-256 of the original content for tamper detection

    def to_header_value(self) -> str:
        """Return the value for the X-Cicada-Content-Provenance header."""
        return self.trust_level

    def to_metadata(self) -> dict:
        """Return full provenance metadata for audit logging."""
        return {
            "trust_level": self.trust_level,
            "source_url": self.source_url,
            "source_type": self.source_type,
            "tool_name": self.tool_name,
            "timestamp": self.timestamp,
            "content_hash": self.content_hash,
        }


def _hash_content(content: str) -> str:
    """SHA-256 hash of content for tamper detection."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def tag_retrieved(
    content: str,
    source_url: str = "",
    source_type: str = "web",
) -> tuple[str, ProvenanceTag]:
    """
    Tag content retrieved from an external source.

    This marks the content as 'retrieved' provenance, triggering elevated
    scan sensitivity at the Sentry Gateway. The content itself is returned
    unchanged — only the provenance metadata is attached.

    Args:
        content: The retrieved content (HTML, text, JSON, etc.).
        source_url: URL the content was retrieved from.
        source_type: Type of source ('web', 'pdf', 'email', 'database', 'api', 'file').

    Returns:
        Tuple of (content, provenance_tag). The content is unchanged;
        the tag should be passed to client.proxy_llm_call() or included
        in the X-Cicada-Content-Provenance header.
    """
    tag = ProvenanceTag(
        trust_level="retrieved",
        source_url=source_url,
        source_type=source_type,
        content_hash=_hash_content(content),
    )
    return content, tag


def tag_tool_result(
    content: str,
    tool_name: str = "",
    source_url: str = "",
) -> tuple[str, ProvenanceTag]:
    """
    Tag content returned by a tool/function call.

    Tool results are semi-trusted: they come from declared tools, but the
    content itself may contain injected instructions (e.g. a search API
    returning a page with embedded IPI payloads).

    Args:
        content: The tool result content.
        tool_name: Name of the tool that produced this content.
        source_url: URL the tool called (if applicable).

    Returns:
        Tuple of (content, provenance_tag).
    """
    tag = ProvenanceTag(
        trust_level="tool_result",
        tool_name=tool_name,
        source_url=source_url,
        content_hash=_hash_content(content),
    )
    return content, tag


def tag_user_input(content: str) -> tuple[str, ProvenanceTag]:
    """
    Tag content from an end-user (chat messages, form inputs).

    User input is semi-trusted: it comes from authenticated users but
    may contain direct injection attempts.
    """
    tag = ProvenanceTag(
        trust_level="user",
        source_type="user_input",
        content_hash=_hash_content(content),
    )
    return content, tag


def tag_developer(content: str) -> tuple[str, ProvenanceTag]:
    """
    Tag content authored by the developer (system prompts, templates).

    Developer content is trusted and receives standard scan sensitivity.
    """
    tag = ProvenanceTag(
        trust_level="developer",
        source_type="developer_authored",
        content_hash=_hash_content(content),
    )
    return content, tag
