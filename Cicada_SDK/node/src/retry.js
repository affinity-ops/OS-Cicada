// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @cicada/sdk/retry — Resilience layer for transient failure recovery.
 *
 * Implements exponential backoff with jitter for 5xx and network errors.
 * Policy enforcement responses (403/429) are NEVER retried — they
 * represent deliberate Gateway decisions, not transient failures.
 */

/**
 * Typed error classes for Cicada Gateway responses.
 * These allow downstream code to distinguish between enforcement
 * decisions and infrastructure failures.
 */
class CicadaBlockedError extends Error {
  constructor(message, response) {
    super(message);
    this.name = 'CicadaBlockedError';
    this.statusCode = 403;
    this.response = response;
  }
}

class CicadaRateLimitedError extends Error {
  constructor(message, response) {
    super(message);
    this.name = 'CicadaRateLimitedError';
    this.statusCode = 429;
    this.response = response;
  }
}

class CicadaHITLPendingError extends Error {
  constructor(message, response) {
    super(message);
    this.name = 'CicadaHITLPendingError';
    this.statusCode = 202;
    this.response = response;
  }
}

class CicadaConnectionError extends Error {
  constructor(message, cause) {
    super(message);
    this.name = 'CicadaConnectionError';
    this.cause = cause;
  }
}

/** Status codes that represent final Gateway decisions — never retry. */
const NON_RETRYABLE_STATUS = new Set([400, 401, 403, 404, 422, 429]);

/**
 * Default retry configuration.
 *
 * @typedef {Object} RetryConfig
 * @property {number} maxRetries - Maximum retry attempts (default: 3)
 * @property {number} baseDelayMs - Initial delay in ms (default: 500)
 * @property {number} maxDelayMs - Maximum delay cap in ms (default: 30000)
 * @property {number} jitterFactor - Random jitter range 0-1 (default: 0.25)
 */
const DEFAULT_RETRY_CONFIG = {
  maxRetries: 3,
  baseDelayMs: 500,
  maxDelayMs: 30000,
  jitterFactor: 0.25,
};

/**
 * Calculate delay for attempt N using exponential backoff + jitter.
 *
 * @param {number} attempt - Zero-indexed attempt number
 * @param {RetryConfig} config - Retry configuration
 * @returns {number} Delay in milliseconds
 */
function calculateDelay(attempt, config) {
  const exponential = config.baseDelayMs * Math.pow(2, attempt);
  const capped = Math.min(exponential, config.maxDelayMs);
  const jitter = capped * config.jitterFactor * Math.random();
  return capped + jitter;
}

/**
 * Execute a fetch request with retry logic.
 *
 * Retries on:
 *   - 5xx server errors
 *   - Network/connection errors
 *   - Timeout errors
 *
 * Does NOT retry on:
 *   - 403 (policy block — deliberate Gateway decision)
 *   - 429 (velocity limit — deliberate Gateway decision)
 *   - 400/401/404/422 (client errors)
 *   - 2xx (success)
 *
 * @param {Function} fetchFn - Async function that performs the fetch
 * @param {RetryConfig} [config] - Retry configuration
 * @returns {Promise<Response>} The final response
 * @throws {CicadaConnectionError} If all retries exhausted on network error
 */
async function retryFetch(fetchFn, config = {}) {
  const opts = { ...DEFAULT_RETRY_CONFIG, ...config };

  let lastError;

  for (let attempt = 0; attempt <= opts.maxRetries; attempt++) {
    try {
      const response = await fetchFn();

      // Non-retryable status — return immediately
      if (NON_RETRYABLE_STATUS.has(response.status)) {
        return response;
      }

      // Success — return
      if (response.ok) {
        return response;
      }

      // 5xx — retryable
      if (response.status >= 500 && attempt < opts.maxRetries) {
        const delay = calculateDelay(attempt, opts);
        console.warn(
          `[cicada] Retrying (${attempt + 1}/${opts.maxRetries}) after ${response.status} — wait ${Math.round(delay)}ms`
        );
        await sleep(delay);
        continue;
      }

      // Exhausted retries or non-5xx error
      return response;

    } catch (err) {
      lastError = err;

      // Network/timeout errors are retryable
      if (attempt < opts.maxRetries) {
        const delay = calculateDelay(attempt, opts);
        console.warn(
          `[cicada] Retrying (${attempt + 1}/${opts.maxRetries}) after ${err.name}: ${err.message} — wait ${Math.round(delay)}ms`
        );
        await sleep(delay);
        continue;
      }
    }
  }

  // All retries exhausted with network error
  throw new CicadaConnectionError(
    `All ${opts.maxRetries} retries exhausted: ${lastError?.message}`,
    lastError,
  );
}

/**
 * Sleep for a given number of milliseconds.
 * @param {number} ms
 * @returns {Promise<void>}
 */
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

module.exports = {
  CicadaBlockedError,
  CicadaRateLimitedError,
  CicadaHITLPendingError,
  CicadaConnectionError,
  NON_RETRYABLE_STATUS,
  DEFAULT_RETRY_CONFIG,
  calculateDelay,
  retryFetch,
};
