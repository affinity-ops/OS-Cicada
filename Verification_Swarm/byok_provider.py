# © 2026 Affinity Ops Ltd. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""
BYOK (Bring Your Own Key) Provider

Retrieves per-tenant encrypted LLM API keys from the tenant_keys table,
decrypts them from Laravel's AES-256-CBC Crypt format, and provides
short-lived OpenAI client instances scoped to a single verification job.

Cicada never stores raw keys in memory beyond the job lifecycle.
Cicada never incurs LLM token costs — the tenant pays.
"""
import os
import json
import hmac
import hashlib
import base64
import logging
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import psycopg2
from openai import OpenAI

logger = logging.getLogger("BYOKProvider")

DATABASE_URL = os.environ.get("CICADA_POSTGRES_URL", "")

def _get_laravel_key() -> bytes:
    """
    Read LARAVEL_APP_KEY from the environment and decode to raw 32 bytes.

    The key is read dynamically on every call — NOT cached at module level.
    Caching at import time means a key rotation or late env-var injection
    (e.g. Docker secret mount) would be silently ignored for the lifetime
    of the process, causing every decryption to fail with a MAC mismatch.
    """
    key_str = os.environ.get("LARAVEL_APP_KEY", "")
    if not key_str:
        raise RuntimeError("LARAVEL_APP_KEY is not set. Cannot decrypt tenant keys.")
    if key_str.startswith("base64:"):
        key_str = key_str[7:]
    return base64.b64decode(key_str)


def _decrypt_laravel_aes_cbc(payload_encrypted: str) -> str:
    """
    Decrypt a value encrypted by Laravel's Crypt::encryptString().

    Laravel stores ciphertext as base64-encoded JSON:
      {"iv":"<b64>","value":"<b64>","mac":"<sha256-hmac>","tag":""}
    """
    key = _get_laravel_key()

    # Outer base64 decode → JSON
    raw_json = base64.b64decode(payload_encrypted).decode("utf-8")
    payload = json.loads(raw_json)

    iv_b64    = payload["iv"]
    value_b64 = payload["value"]
    stored_mac = payload["mac"]

    # Verify HMAC-SHA256 integrity before decrypting.
    # Laravel computes: hash_hmac('sha256', base64_iv . base64_value, raw_key)
    # Python 3 equivalent uses hmac.new() with digestmod as a callable.
    mac_input = (iv_b64 + value_b64).encode("utf-8")
    expected_mac = hmac.new(key, mac_input, digestmod=hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_mac, stored_mac):
        raise RuntimeError("BYOK decryption failed: MAC mismatch — possible tampering or wrong key.")

    iv         = base64.b64decode(iv_b64)
    ciphertext = base64.b64decode(value_b64)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()

    return plaintext.decode("utf-8")


def fetch_tenant_api_key(tenant_id: str, provider: str = "openai") -> str:
    """
    Retrieve and decrypt a tenant's LLM API key from the tenant_keys table.

    Args:
        tenant_id: UUID of the tenant
        provider:  LLM provider name (e.g., 'openai', 'anthropic')

    Returns:
        Decrypted API key string

    Raises:
        ValueError: If tenant has no key configured for the given provider
        RuntimeError: If decryption fails
    """
    if not DATABASE_URL:
        raise RuntimeError("CICADA_POSTGRES_URL is not set.")

    conn = psycopg2.connect(DATABASE_URL)
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT tk.payload_encrypted
                FROM tenant_keys tk
                JOIN tenants t ON t.id = tk.tenant_id
                WHERE tk.tenant_id = %s
                  AND tk.provider = %s
                  AND t.status = 'active'
                LIMIT 1
                """,
                (tenant_id, provider),
            )
            row = cur.fetchone()
            if not row:
                raise ValueError(
                    f"No {provider} API key found for tenant {tenant_id}. "
                    f"The tenant must configure their BYOK keys before submitting verification jobs."
                )

            payload_encrypted = row[0]
            return _decrypt_laravel_aes_cbc(payload_encrypted)
    finally:
        conn.close()


def get_tenant_openai_client(tenant_id: str) -> OpenAI:
    """
    Create a short-lived OpenAI-compatible client using the tenant's own API key.
    Supports multiple providers via OpenAI SDK's base_url parameter:
      - openai:    api.openai.com (default)
      - google:    generativelanguage.googleapis.com (OpenAI-compatible)
      - anthropic: api.anthropic.com (OpenAI-compatible)
    This client should be used for a single job and then discarded.
    """
    # Try providers in order of preference
    providers_to_try = ["openai", "google", "anthropic"]

    if not DATABASE_URL:
        raise RuntimeError("CICADA_POSTGRES_URL is not set.")

    conn = psycopg2.connect(DATABASE_URL)
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT tk.provider, tk.payload_encrypted
                FROM tenant_keys tk
                JOIN tenants t ON t.id = tk.tenant_id
                WHERE tk.tenant_id = %s
                  AND t.status = 'active'
                ORDER BY tk.updated_at DESC
                LIMIT 1
                """,
                (tenant_id,),
            )
            row = cur.fetchone()
            if not row:
                raise ValueError(
                    f"No API key found for tenant {tenant_id}. "
                    f"The tenant must configure their BYOK keys before submitting verification jobs."
                )

            provider = row[0]
            payload_encrypted = row[1]
    finally:
        conn.close()

    api_key = _decrypt_laravel_aes_cbc(payload_encrypted)

    # Configure OpenAI SDK for the appropriate provider
    if provider in ("google", "gemini"):
        client = OpenAI(
            api_key=api_key,
            base_url="https://generativelanguage.googleapis.com/v1beta/openai/",
        )
        logger.info(f"Created BYOK Gemini client for tenant {tenant_id} (via OpenAI-compat)")
    elif provider == "anthropic":
        client = OpenAI(
            api_key=api_key,
            base_url="https://api.anthropic.com/v1/",
        )
        logger.info(f"Created BYOK Anthropic client for tenant {tenant_id} (via OpenAI-compat)")
    else:
        client = OpenAI(api_key=api_key)
        logger.info(f"Created BYOK OpenAI client for tenant {tenant_id}")

    return client
