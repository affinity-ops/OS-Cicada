// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Tests for @cicada/sdk/retry — Resilience layer.
 *
 * Uses Node.js built-in test runner (--test).
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  CicadaBlockedError,
  CicadaRateLimitedError,
  CicadaHITLPendingError,
  CicadaConnectionError,
  NON_RETRYABLE_STATUS,
  DEFAULT_RETRY_CONFIG,
  calculateDelay,
  retryFetch,
} = require('./retry');


// ── Exception Hierarchy ──────────────────────────────────────────

describe('Exception hierarchy', () => {
  it('CicadaBlockedError has correct properties', () => {
    const err = new CicadaBlockedError('blocked', { status: 403 });
    assert.equal(err.name, 'CicadaBlockedError');
    assert.equal(err.statusCode, 403);
    assert.ok(err instanceof Error);
  });

  it('CicadaRateLimitedError has correct properties', () => {
    const err = new CicadaRateLimitedError('limited', { status: 429 });
    assert.equal(err.name, 'CicadaRateLimitedError');
    assert.equal(err.statusCode, 429);
  });

  it('CicadaHITLPendingError has correct properties', () => {
    const err = new CicadaHITLPendingError('pending', { status: 202 });
    assert.equal(err.name, 'CicadaHITLPendingError');
    assert.equal(err.statusCode, 202);
  });

  it('CicadaConnectionError stores cause', () => {
    const cause = new TypeError('fetch failed');
    const err = new CicadaConnectionError('conn failed', cause);
    assert.equal(err.name, 'CicadaConnectionError');
    assert.equal(err.cause, cause);
  });
});


// ── Non-Retryable Status ─────────────────────────────────────────

describe('NON_RETRYABLE_STATUS', () => {
  it('contains policy enforcement codes', () => {
    assert.ok(NON_RETRYABLE_STATUS.has(403));
    assert.ok(NON_RETRYABLE_STATUS.has(429));
  });

  it('contains client error codes', () => {
    assert.ok(NON_RETRYABLE_STATUS.has(400));
    assert.ok(NON_RETRYABLE_STATUS.has(401));
    assert.ok(NON_RETRYABLE_STATUS.has(404));
    assert.ok(NON_RETRYABLE_STATUS.has(422));
  });

  it('does not contain retryable codes', () => {
    assert.ok(!NON_RETRYABLE_STATUS.has(500));
    assert.ok(!NON_RETRYABLE_STATUS.has(502));
    assert.ok(!NON_RETRYABLE_STATUS.has(503));
  });
});


// ── calculateDelay ───────────────────────────────────────────────

describe('calculateDelay', () => {
  it('increases exponentially', () => {
    const config = { ...DEFAULT_RETRY_CONFIG, jitterFactor: 0 };
    const d0 = calculateDelay(0, config);
    const d1 = calculateDelay(1, config);
    const d2 = calculateDelay(2, config);

    assert.equal(d0, 500);
    assert.equal(d1, 1000);
    assert.equal(d2, 2000);
  });

  it('respects maxDelayMs', () => {
    const config = { ...DEFAULT_RETRY_CONFIG, jitterFactor: 0, maxDelayMs: 1000 };
    const d5 = calculateDelay(5, config);
    assert.equal(d5, 1000);
  });

  it('adds jitter within bounds', () => {
    const config = { ...DEFAULT_RETRY_CONFIG, jitterFactor: 0.25 };
    for (let i = 0; i < 20; i++) {
      const delay = calculateDelay(0, config);
      assert.ok(delay >= 500, `delay ${delay} < 500`);
      assert.ok(delay <= 625, `delay ${delay} > 625`);
    }
  });
});


// ── retryFetch ───────────────────────────────────────────────────

describe('retryFetch', () => {
  it('returns on first success', async () => {
    let calls = 0;
    const result = await retryFetch(() => {
      calls++;
      return Promise.resolve({ ok: true, status: 200 });
    }, { maxRetries: 3 });

    assert.equal(calls, 1);
    assert.equal(result.status, 200);
  });

  it('returns non-retryable status immediately (403)', async () => {
    let calls = 0;
    const result = await retryFetch(() => {
      calls++;
      return Promise.resolve({ ok: false, status: 403 });
    }, { maxRetries: 3 });

    assert.equal(calls, 1);
    assert.equal(result.status, 403);
  });

  it('returns non-retryable status immediately (429)', async () => {
    let calls = 0;
    const result = await retryFetch(() => {
      calls++;
      return Promise.resolve({ ok: false, status: 429 });
    }, { maxRetries: 3 });

    assert.equal(calls, 1);
    assert.equal(result.status, 429);
  });

  it('retries on 500 and eventually succeeds', async () => {
    let calls = 0;
    const result = await retryFetch(() => {
      calls++;
      if (calls < 3) return Promise.resolve({ ok: false, status: 500 });
      return Promise.resolve({ ok: true, status: 200 });
    }, { maxRetries: 3, baseDelayMs: 1, maxDelayMs: 5, jitterFactor: 0 });

    assert.equal(calls, 3);
    assert.equal(result.status, 200);
  });

  it('returns last 500 response when retries exhausted', async () => {
    let calls = 0;
    const result = await retryFetch(() => {
      calls++;
      return Promise.resolve({ ok: false, status: 500 });
    }, { maxRetries: 2, baseDelayMs: 1, maxDelayMs: 5, jitterFactor: 0 });

    assert.equal(calls, 3); // 1 initial + 2 retries
    assert.equal(result.status, 500);
  });

  it('throws CicadaConnectionError when all retries fail with network error', async () => {
    let calls = 0;
    await assert.rejects(
      async () => {
        await retryFetch(() => {
          calls++;
          throw new TypeError('fetch failed');
        }, { maxRetries: 2, baseDelayMs: 1, maxDelayMs: 5, jitterFactor: 0 });
      },
      (err) => {
        assert.ok(err instanceof CicadaConnectionError);
        assert.ok(err.message.includes('retries exhausted'));
        return true;
      }
    );

    assert.equal(calls, 3);
  });

  it('recovers from network error on retry', async () => {
    let calls = 0;
    const result = await retryFetch(() => {
      calls++;
      if (calls === 1) throw new TypeError('fetch failed');
      return Promise.resolve({ ok: true, status: 200 });
    }, { maxRetries: 2, baseDelayMs: 1, maxDelayMs: 5, jitterFactor: 0 });

    assert.equal(calls, 2);
    assert.equal(result.status, 200);
  });
});
