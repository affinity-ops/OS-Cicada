// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Operator-authenticated fetch wrapper.
 *
 * Wraps the standard `fetch()` with the X-Operator-Key header required
 * by the hardened Core API. The key is read from NEXT_PUBLIC_OPERATOR_KEY.
 *
 * If no key is configured, calls proceed without the header (backward compatible —
 * the API's OperatorAuth middleware also allows unauthenticated requests when
 * OPERATOR_API_KEY is not set on the server side).
 *
 * Usage: Replace `fetch(url)` with `operatorFetch(url)` in all Dashboard pages.
 */

const OPERATOR_KEY = process.env.NEXT_PUBLIC_OPERATOR_KEY || '';

export function operatorFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  const headers = new Headers(init?.headers);

  // Always set Accept for consistent JSON responses
  if (!headers.has('Accept')) {
    headers.set('Accept', 'application/json');
  }

  // Inject operator key if configured
  if (OPERATOR_KEY) {
    headers.set('X-Operator-Key', OPERATOR_KEY);
  }

  return fetch(input, { ...init, headers });
}
