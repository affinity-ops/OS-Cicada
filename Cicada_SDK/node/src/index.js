// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @cicada/sdk — Node.js SDK for the Cicada AI Agent Governance Platform.
 *
 * This package routes all HTTP calls through the Cicada Sentry Gateway
 * for seven-layer enforcement. Uses native fetch (Node 18+) — no external
 * HTTP dependencies.
 *
 * v0.2.0: Added retry/resilience, user-context propagation, AutoGen adapter.
 *
 * @example
 * const { CicadaClient, loadPolicy, UserContext, retryFetch } = require('@cicada/sdk');
 *
 * const client = CicadaClient.fromYaml('cicada.yaml');
 * const response = await client.proxyCall('POST', 'https://api.stripe.com/v1/charges', {
 *   amount: 2000,
 *   currency: 'usd',
 * });
 */

const { CicadaClient } = require('./client');
const { loadPolicy, CicadaPolicy } = require('./policy');
const {
  CicadaBlockedError,
  CicadaRateLimitedError,
  CicadaHITLPendingError,
  CicadaConnectionError,
  retryFetch,
  DEFAULT_RETRY_CONFIG,
} = require('./retry');
const { UserContext } = require('./user-context');
const { CicadaMemory } = require('./memory');

module.exports = {
  // Core
  CicadaClient,
  loadPolicy,
  CicadaPolicy,

  // Resilience
  CicadaBlockedError,
  CicadaRateLimitedError,
  CicadaHITLPendingError,
  CicadaConnectionError,
  retryFetch,
  DEFAULT_RETRY_CONFIG,

  // User Context
  UserContext,

  // Memory Sanitisation (ASI06)
  CicadaMemory,
};
