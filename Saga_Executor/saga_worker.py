# © 2026 Affinity Ops Ltd. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import logging
import os
import json
import time
import hmac
import hashlib
import uuid
import redis
import requests

logger = logging.getLogger("SagaWorker")
logging.basicConfig(level=logging.INFO, format="%(asctime)s - [%(name)s] %(message)s")

# Load from environment — no hardcoded secrets
WEBHOOK_SECRET = os.environ.get("CICADA_WEBHOOK_SECRET", "").encode()
if not WEBHOOK_SECRET:
    logger.error("CICADA_WEBHOOK_SECRET is not set! Webhook signatures will fail.")

MAX_RETRIES = int(os.environ.get("CICADA_SAGA_MAX_RETRIES", "5"))
DLQ_NAME = "cicada_saga_dlq"

# SSRF protection: only allow webhooks to these domains
ALLOWED_DOMAINS = set(
    os.environ.get("CICADA_ALLOWED_WEBHOOK_DOMAINS", "enterprise.internal,api.stripe.com").split(",")
)


class SagaWorker:
    def __init__(self):
        redis_url = os.environ.get("CICADA_REDIS_URL", "redis://localhost:6379")
        self.redis = redis.from_url(redis_url)
        self.session = requests.Session()
        self.session.timeout = 15
        self.session.max_redirects = 0  # Prevent redirect-based SSRF
        self.idempotency_set = "cicada_saga_idempotency"

    def listen(self):
        """Block on Redis queue and process saga rollback jobs."""
        try:
            self.redis.ping()
            logger.info("Connected to Redis. Listening on 'cicada_rollback_queue'...")
        except redis.ConnectionError as e:
            logger.error(f"Cannot connect to Redis: {e}")
            raise

        while True:
            try:
                _, raw = self.redis.brpop("cicada_rollback_queue", timeout=0)
                job = json.loads(raw)
                self._process_job(job)
            except json.JSONDecodeError as e:
                logger.error(f"Invalid JSON from queue: {e}")
            except Exception as e:
                logger.error(f"Saga processing error: {e}")

    def _process_job(self, job: dict):
        rollback_id = job.get("rollback_id", "unknown")
        trace_id = job.get("trace_id", "unknown")
        revert_route = job.get("revert_route", "")
        failed_action = job.get("failed_action", "")

        logger.info(f"Processing saga rollback: {rollback_id} (trace: {trace_id})")

        # Idempotency check — prevent duplicate processing
        if self.redis.sismember(self.idempotency_set, rollback_id):
            logger.warning(f"Duplicate rollback {rollback_id} — already processed. Skipping.")
            return

        # SSRF protection — full outbound URL validation
        url_ok, ssrf_reason = self._validate_outbound_url(revert_route)
        if not url_ok:
            logger.error(f"SSRF blocked: {revert_route} — {ssrf_reason}")
            self._send_to_dlq(job, f"ssrf_blocked: {ssrf_reason}")
            return

        # Attempt execution with exponential backoff
        for attempt in range(1, MAX_RETRIES + 1):
            success = self._execute_webhook(revert_route, trace_id, failed_action, rollback_id)
            if success:
                self.redis.sadd(self.idempotency_set, rollback_id)
                logger.info(f"Saga {rollback_id} completed successfully on attempt {attempt}")
                return

            backoff = min(2 ** attempt, 30)
            logger.warning(f"Saga {rollback_id} attempt {attempt}/{MAX_RETRIES} failed. Retrying in {backoff}s...")
            time.sleep(backoff)

        # All retries exhausted — send to DLQ
        logger.error(f"Saga {rollback_id} FAILED after {MAX_RETRIES} attempts. Moving to DLQ.")
        self._send_to_dlq(job, "max_retries_exhausted")

    def _execute_webhook(self, url: str, trace_id: str, action: str, rollback_id: str) -> bool:
        """Execute a real HTTP POST to the revert endpoint with HMAC signature."""
        nonce = str(uuid.uuid4())
        timestamp = str(int(time.time()))

        payload = json.dumps({
            "rollback_id": rollback_id,
            "trace_id": trace_id,
            "failed_action": action,
            "nonce": nonce,
            "timestamp": timestamp,
        })

        # HMAC-SHA256 signature for replay protection
        sig_input = f"{timestamp}:{nonce}:{payload}"
        signature = hmac.new(WEBHOOK_SECRET, sig_input.encode(), hashlib.sha256).hexdigest()

        headers = {
            "Content-Type": "application/json",
            "X-Cicada-Signature": signature,
            "X-Cicada-Timestamp": timestamp,
            "X-Cicada-Nonce": nonce,
        }

        try:
            resp = self.session.post(url, data=payload, headers=headers)
            if 200 <= resp.status_code < 300:
                return True
            else:
                logger.warning(f"Webhook returned {resp.status_code}: {resp.text[:200]}")
                return False
        except requests.RequestException as e:
            logger.error(f"Webhook request failed: {e}")
            return False

    def _validate_outbound_url(self, raw_url: str) -> tuple[bool, str]:
        """SSRF protection — port of Go ValidateOutboundURL().

        Enforces:
          1. HTTPS scheme required (HTTP rejected)
          2. Loopback addresses blocked (localhost, 127.0.0.1, ::1, 0.0.0.0)
          3. DNS resolution — all resolved IPs checked against private/link-local
          4. Domain allowlist — if ALLOWED_DOMAINS is set, host must match exactly
             (dot-prefixed to prevent suffix confusion: evil-stripe.com ≠ stripe.com)

        Returns (True, "") on success or (False, reason) on rejection.
        """
        import ipaddress
        import socket
        from urllib.parse import urlparse

        # ── 1. Parse URL ────────────────────────────────────────────────
        try:
            parsed = urlparse(raw_url)
        except Exception as e:
            return False, f"invalid URL {raw_url!r}: {e}"

        # ── 2. Scheme check — HTTPS only ────────────────────────────────
        if parsed.scheme != "https":
            return False, f"non-HTTPS scheme {parsed.scheme!r} — only HTTPS permitted"

        host = parsed.hostname or ""
        if not host:
            return False, "missing hostname"

        # ── 3. Domain allowlist (additional restriction, not a bypass) ──
        if ALLOWED_DOMAINS:
            domain_allowed = any(
                host == domain or host.endswith("." + domain)
                for domain in ALLOWED_DOMAINS
            )
            if not domain_allowed:
                return False, f"host {host!r} not in domain allowlist"

        # ── 4. Loopback hostname check ──────────────────────────────────
        if host in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
            return False, f"loopback address {host!r} blocked"

        # ── 5. DNS resolution + private IP check ────────────────────────
        try:
            results = socket.getaddrinfo(host, None)
        except socket.gaierror as e:
            return False, f"DNS resolution failed for {host!r}: {e}"

        for family, _type, _proto, _canonname, sockaddr in results:
            ip_str = sockaddr[0]
            try:
                ip = ipaddress.ip_address(ip_str)
            except ValueError:
                continue
            if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved:
                return False, f"host {host!r} resolves to private/loopback IP {ip_str} — blocked"

        return True, ""

    def _send_to_dlq(self, job: dict, reason: str):
        """Push failed jobs to the dead letter queue for manual review."""
        job["dlq_reason"] = reason
        job["dlq_timestamp"] = time.time()
        self.redis.lpush(DLQ_NAME, json.dumps(job))


if __name__ == "__main__":
    worker = SagaWorker()
    worker.listen()
