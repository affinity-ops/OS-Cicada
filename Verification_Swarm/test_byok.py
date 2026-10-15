# © 2026 Affinity Ops Ltd. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""
BYOK Compatibility Test

Verifies that byok_provider._decrypt_laravel_aes_cbc() correctly decrypts
payloads produced by Laravel's Crypt::encryptString().

This test does NOT require a running Laravel app or database. It generates a
Laravel-format AES-256-CBC encrypted payload in Python using the same algorithm
Laravel uses, then verifies our decryption round-trips the plaintext correctly.

This proves that:
  1. The key derivation from APP_KEY is correct.
  2. The HMAC-SHA256 MAC verification matches Laravel's hash_hmac().
  3. The AES-256-CBC decryption and PKCS7 unpadding produce the original plaintext.

Run: python test_byok.py
Expected: PASS on all assertions, exit code 0.
"""

import os
import json
import hmac
import hashlib
import base64
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend


# ── Helpers that replicate Laravel's Crypt::encryptString() ──────────────────

def _laravel_encrypt(plaintext: str, raw_key: bytes) -> str:
    """
    Encrypt a string exactly as Laravel's Crypt::encryptString() does:
      1. Random 16-byte IV
      2. AES-256-CBC with PKCS7 padding
      3. HMAC-SHA256 of base64(IV) + base64(ciphertext) using raw key
      4. JSON-encode {iv, value, mac, tag} and base64-encode the whole thing
    """
    iv = secrets.token_bytes(16)

    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode("utf-8")) + padder.finalize()

    cipher = Cipher(algorithms.AES(raw_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    iv_b64    = base64.b64encode(iv).decode("utf-8")
    value_b64 = base64.b64encode(ciphertext).decode("utf-8")

    mac_input = (iv_b64 + value_b64).encode("utf-8")
    mac = hmac.new(raw_key, mac_input, digestmod=hashlib.sha256).hexdigest()

    payload = json.dumps({"iv": iv_b64, "value": value_b64, "mac": mac, "tag": ""})
    return base64.b64encode(payload.encode("utf-8")).decode("utf-8")


# ── Tests ─────────────────────────────────────────────────────────────────────

def test_round_trip_basic():
    """Standard OpenAI API key format round-trips correctly."""
    raw_key = secrets.token_bytes(32)
    app_key = "base64:" + base64.b64encode(raw_key).decode("utf-8")
    os.environ["LARAVEL_APP_KEY"] = app_key

    plaintext = "sk-proj-abc123XYZ789realOpenAIkeyformat"
    encrypted = _laravel_encrypt(plaintext, raw_key)

    from byok_provider import _decrypt_laravel_aes_cbc
    decrypted = _decrypt_laravel_aes_cbc(encrypted)

    assert decrypted == plaintext, f"Expected {plaintext!r}, got {decrypted!r}"
    print("  PASS  test_round_trip_basic")


def test_round_trip_anthropic_key():
    """Anthropic key format (sk-ant-...) round-trips correctly."""
    raw_key = secrets.token_bytes(32)
    app_key = "base64:" + base64.b64encode(raw_key).decode("utf-8")
    os.environ["LARAVEL_APP_KEY"] = app_key

    plaintext = "sk-ant-api03-verylongkeyvaluehere1234567890abcdefghijklmnop"
    encrypted = _laravel_encrypt(plaintext, raw_key)

    from byok_provider import _decrypt_laravel_aes_cbc
    decrypted = _decrypt_laravel_aes_cbc(encrypted)

    assert decrypted == plaintext, f"Expected {plaintext!r}, got {decrypted!r}"
    print("  PASS  test_round_trip_anthropic_key")


def test_round_trip_unicode():
    """Non-ASCII characters in the key value survive the round trip."""
    raw_key = secrets.token_bytes(32)
    app_key = "base64:" + base64.b64encode(raw_key).decode("utf-8")
    os.environ["LARAVEL_APP_KEY"] = app_key

    plaintext = "key_with_special_chars_£€¥_and_symbols"
    encrypted = _laravel_encrypt(plaintext, raw_key)

    from byok_provider import _decrypt_laravel_aes_cbc
    decrypted = _decrypt_laravel_aes_cbc(encrypted)

    assert decrypted == plaintext, f"Expected {plaintext!r}, got {decrypted!r}"
    print("  PASS  test_round_trip_unicode")


def test_mac_tamper_detection():
    """Tampered ciphertext is rejected by MAC verification."""
    raw_key = secrets.token_bytes(32)
    app_key = "base64:" + base64.b64encode(raw_key).decode("utf-8")
    os.environ["LARAVEL_APP_KEY"] = app_key

    plaintext = "sk-legitimate-key-value"
    encrypted = _laravel_encrypt(plaintext, raw_key)

    # Decode, flip a byte in the ciphertext, re-encode
    raw_json = base64.b64decode(encrypted).decode("utf-8")
    payload = json.loads(raw_json)
    ct_bytes = bytearray(base64.b64decode(payload["value"]))
    ct_bytes[0] ^= 0xFF  # flip bits in first byte
    payload["value"] = base64.b64encode(bytes(ct_bytes)).decode("utf-8")
    tampered = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("utf-8")

    from byok_provider import _decrypt_laravel_aes_cbc
    try:
        _decrypt_laravel_aes_cbc(tampered)
        assert False, "Should have raised RuntimeError on tampered payload"
    except RuntimeError as e:
        assert "MAC mismatch" in str(e), f"Unexpected error: {e}"
    print("  PASS  test_mac_tamper_detection")


def test_wrong_key_rejected():
    """Payload encrypted with one key cannot be decrypted with a different key."""
    raw_key_a = secrets.token_bytes(32)
    raw_key_b = secrets.token_bytes(32)

    encrypted = _laravel_encrypt("secret-api-key-value", raw_key_a)

    # Set environment to key B
    os.environ["LARAVEL_APP_KEY"] = "base64:" + base64.b64encode(raw_key_b).decode("utf-8")

    from importlib import reload
    import byok_provider
    reload(byok_provider)  # reload so it picks up the new env var

    try:
        byok_provider._decrypt_laravel_aes_cbc(encrypted)
        assert False, "Should have raised RuntimeError with wrong key"
    except RuntimeError as e:
        assert "MAC mismatch" in str(e), f"Unexpected error: {e}"
    print("  PASS  test_wrong_key_rejected")


def test_key_without_base64_prefix():
    """APP_KEY without 'base64:' prefix is handled correctly."""
    raw_key = secrets.token_bytes(32)
    # Set WITHOUT the base64: prefix (some older Laravel setups omit it)
    os.environ["LARAVEL_APP_KEY"] = base64.b64encode(raw_key).decode("utf-8")

    plaintext = "sk-no-prefix-test-key-value"
    encrypted = _laravel_encrypt(plaintext, raw_key)

    from importlib import reload
    import byok_provider
    reload(byok_provider)

    decrypted = byok_provider._decrypt_laravel_aes_cbc(encrypted)
    assert decrypted == plaintext, f"Expected {plaintext!r}, got {decrypted!r}"
    print("  PASS  test_key_without_base64_prefix")


if __name__ == "__main__":
    print("\nRunning BYOK Laravel compatibility tests...\n")
    failures = []
    tests = [
        test_round_trip_basic,
        test_round_trip_anthropic_key,
        test_round_trip_unicode,
        test_mac_tamper_detection,
        test_wrong_key_rejected,
        test_key_without_base64_prefix,
    ]
    for t in tests:
        try:
            t()
        except Exception as e:
            print(f"  FAIL  {t.__name__}: {e}")
            failures.append(t.__name__)

    print(f"\n{'='*50}")
    if failures:
        print(f"FAILED: {len(failures)}/{len(tests)} tests")
        for f in failures:
            print(f"  - {f}")
        exit(1)
    else:
        print(f"ALL PASSED: {len(tests)}/{len(tests)} tests")
        exit(0)
