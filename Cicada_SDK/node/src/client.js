// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @cicada/sdk — Core client for the Cicada Sentry Gateway.
 *
 * Uses native fetch (Node 18+) for HTTP calls. All requests route through
 * the Gateway with Ed25519 session authentication, content provenance
 * headers, and seven-layer enforcement.
 */

const { loadPolicy } = require('./policy');
const { retryFetch, CicadaBlockedError, CicadaRateLimitedError, CicadaHITLPendingError } = require('./retry');
const { UserContext } = require('./user-context');

/**
 * Client for the Cicada Sentry Gateway.
 *
 * @example
 * const client = CicadaClient.fromYaml('cicada.yaml');
 * const resp = await client.proxyCall('GET', 'https://api.stripe.com/v1/charges/ch_123');
 */
class CicadaClient {
  /**
   * @param {Object} options
   * @param {string} options.gatewayUrl - Base URL of the Sentry Gateway
   * @param {string} options.sessionToken - Ed25519 JWT session token
   * @param {string} [options.agentId] - Agent ID
   * @param {string} [options.tenantId] - Tenant ID
   * @param {import('./policy').CicadaPolicy} [options.policy] - Parsed policy
   * @param {number} [options.timeout=30000] - Request timeout in ms
   */
  constructor({ gatewayUrl, sessionToken, agentId = '', tenantId = '', policy = null, timeout = 30000, retryConfig = {}, defaultUserContext = null, memoryContext = null }) {
    this.gatewayUrl = gatewayUrl.replace(/\/+$/, '');
    this.sessionToken = sessionToken;
    this.agentId = agentId;
    this.tenantId = tenantId;
    this.policy = policy;
    this.timeout = timeout;
    this.retryConfig = retryConfig;
    this.defaultUserContext = defaultUserContext;
    this.memoryContext = memoryContext;
  }

  /**
   * Create a CicadaClient from a cicada.yaml policy file.
   *
   * @param {string} [policyPath='cicada.yaml'] - Path to policy file
   * @param {Object} [overrides] - Override gateway URL and session token
   * @returns {CicadaClient}
   */
  static fromYaml(policyPath = 'cicada.yaml', overrides = {}) {
    const policy = loadPolicy(policyPath);

    const gatewayUrl = overrides.gatewayUrl || process.env.CICADA_GATEWAY_URL || 'http://localhost:8080';
    const sessionToken = overrides.sessionToken || process.env.CICADA_SESSION_TOKEN || '';

    if (!sessionToken) {
      throw new Error(
        'Session token is required. Set CICADA_SESSION_TOKEN env var ' +
        'or pass overrides.sessionToken to fromYaml().'
      );
    }

    // Validate and warn
    const issues = policy.validate();
    for (const issue of issues) {
      console.warn(`[cicada] Policy warning: ${issue}`);
    }

    return new CicadaClient({
      gatewayUrl,
      sessionToken,
      agentId: policy.agentName,
      policy,
    });
  }

  /**
   * Base headers for all requests.
   * Includes MCP-compatible identity headers for cross-platform tool invocation.
   * @returns {Object}
   * @private
   */
  _baseHeaders() {
    const headers = {
      'Authorization': `Bearer ${this.sessionToken}`,
      'X-Cicada-Agent-ID': this.agentId,
      'User-Agent': '@cicada/sdk-node/0.3.0',

      // MCP-compatible identity headers (ASI08 cross-platform identity)
      // X-Cicada-MCP-Client-ID: the agent's EVAR identity for MCP tool servers
      // X-Cicada-MCP-Session-Hash: SHA-256 of session token (zero-knowledge — the
      //   gateway validates this without the MCP server seeing the actual token)
      'X-Cicada-MCP-Client-ID': this.agentId,
      'X-Cicada-MCP-Session-Hash': this._sessionHash(),
    };
    if (this.tenantId) {
      headers['X-Cicada-Tenant-ID'] = this.tenantId;
    }
    // Inter-agent chain tracking (ASI07)
    if (this._chainHeader) {
      headers['X-Cicada-Agent-Chain'] = this._chainHeader;
    }
    return headers;
  }

  /**
   * SHA-256 hash of the session token for zero-knowledge MCP identity.
   * Cached after first computation.
   * @returns {string} Hex-encoded SHA-256 hash
   * @private
   */
  _sessionHash() {
    if (!this._cachedSessionHash) {
      const crypto = require('crypto');
      this._cachedSessionHash = crypto
        .createHash('sha256')
        .update(this.sessionToken)
        .digest('hex');
    }
    return this._cachedSessionHash;
  }

  /**
   * Create a delegated client for inter-agent chain tracking (ASI07).
   *
   * Returns a new CicadaClient pre-configured with the X-Cicada-Agent-Chain
   * header containing the upstream agent's identity. The gateway verifies
   * the chain cryptographically — a compromised agent cannot forge or reset
   * the chain depth.
   *
   * Uses AsyncLocalStorage internally to propagate the chain header across
   * async execution contexts (Promise.all, setTimeout, etc.).
   *
   * @param {string} chainHeader - The X-Cicada-Agent-Chain header from the upstream response
   * @returns {CicadaClient} A new client with chain tracking enabled
   */
  delegateFrom(chainHeader) {
    const delegated = new CicadaClient({
      gatewayUrl: this.gatewayUrl,
      sessionToken: this.sessionToken,
      agentId: this.agentId,
      tenantId: this.tenantId,
      policy: this.policy,
      timeout: this.timeout,
      retryConfig: this.retryConfig,
      defaultUserContext: this.defaultUserContext,
    });
    delegated._chainHeader = chainHeader;
    return delegated;
  }


  /**
   * Route an HTTP call through the Cicada Sentry Gateway.
   *
   * @param {string} method - HTTP method (GET, POST, PUT, PATCH, DELETE)
   * @param {string} targetUrl - Target API URL
   * @param {Object|string|null} [body=null] - Request body
   * @param {Object} [options={}] - Additional options
   * @param {string} [options.provenance='developer'] - Content provenance level
   * @param {Object} [options.headers={}] - Additional headers
   * @param {number} [options.timeout] - Override timeout
   * @returns {Promise<Response>}
   */
  async proxyCall(method, targetUrl, body = null, options = {}) {
    const {
      provenance = 'developer',
      headers: extraHeaders = {},
      timeout = this.timeout,
      userContext = null,
      raiseOnBlock = false,
    } = options;

    const url = `${this.gatewayUrl}/v1/proxy`;

    const headers = {
      ...this._baseHeaders(),
      'X-Cicada-Target-URL': targetUrl,
      'X-Cicada-Content-Provenance': provenance,
      ...extraHeaders,
    };

    // Inject user-context header (per-call > default)
    const ctx = userContext || this.defaultUserContext;
    if (ctx) {
      Object.assign(headers, ctx.toHeaders());
    }

    const fetchOptions = {
      method: method.toUpperCase(),
      headers,
      signal: AbortSignal.timeout(timeout),
    };

    if (body !== null && body !== undefined) {
      if (typeof body === 'object') {
        fetchOptions.body = JSON.stringify(body);
        headers['Content-Type'] = headers['Content-Type'] || 'application/json';
      } else {
        fetchOptions.body = body;
      }
    }

    const response = await retryFetch(
      () => fetch(url, fetchOptions),
      this.retryConfig,
    );

    // Enforcement decision handling
    if (response.status === 403) {
      const text = await response.clone().text();
      console.warn(`[cicada] Gateway blocked: ${method} ${targetUrl} → ${text.slice(0, 200)}`);
      if (raiseOnBlock) {
        throw new CicadaBlockedError(`Gateway blocked: ${text.slice(0, 200)}`, response);
      }
    } else if (response.status === 429) {
      console.warn(`[cicada] Velocity limit: ${method} ${targetUrl}`);
      if (raiseOnBlock) {
        throw new CicadaRateLimitedError('Velocity limit exceeded', response);
      }
    } else if (response.status === 202) {
      console.info(`[cicada] HITL suspended: ${method} ${targetUrl}`);
      if (raiseOnBlock) {
        throw new CicadaHITLPendingError('Awaiting HITL approval', response);
      }
    }

    // ── Context Rot Prevention: Gateway-to-SDK Flush Feedback Loop ──────────
    // When the Sentry Gateway detects a memory-degrading event (injection scan,
    // skill boundary breach, schema mutation), it signals the SDK to purge
    // contaminated context frames via the X-Cicada-Memory-Action response header.
    const memoryAction = response.headers.get('x-cicada-memory-action');
    if (memoryAction === 'flush') {
      const flushReason = response.headers.get('x-cicada-flush-reason') || 'unknown_governance_trigger';
      console.warn(`[cicada] Anti-Rot: Gateway commanded memory flush. Reason: ${flushReason}`);

      if (this.memoryContext && typeof this.memoryContext.flushActiveWindow === 'function') {
        // Async — fire and forget. The flush is non-blocking to avoid
        // delaying the response to the agent's main execution loop.
        this.memoryContext.flushActiveWindow(flushReason).catch(err => {
          console.error(`[cicada] Memory flush error: ${err.message}`);
        });
      }
    }

    return response;
  }

  /**
   * Execute an agent operation bound to a specific declarative skill contract.
   *
   * Injects the X-Cicada-Target-Skill header so the Sentry Gateway resolves
   * the target capability against the agent's cached skill graph (Layer 1d).
   * The gateway verifies: (1) the skill is declared in cicada.yaml,
   * (2) the upstream agent chain is authorised, (3) the payload matches the
   * input_schema, and (4) high-criticality skills trigger CIBA holds.
   *
   * @param {string} skillName - The target capability name registered in cicada.yaml tools[].name
   * @param {string} targetUrl - Target API URL
   * @param {Object} payload - The structured data payload to forward
   * @param {Object} [options={}] - Additional options (passed through to proxyCall)
   * @returns {Promise<Response>}
   */
  async invokeSkill(skillName, targetUrl, payload, options = {}) {
    return this.proxyCall('POST', targetUrl, payload, {
      ...options,
      headers: {
        ...options.headers,
        'X-Cicada-Target-Skill': skillName,
      },
    });
  }

  /**
   * Route an LLM API call through the Cicada LLM proxy.
   *
   * @param {Array<{role: string, content: string}>} messages - LLM messages
   * @param {Object} [options={}]
   * @param {string} [options.model='gpt-4'] - Model identifier
   * @param {string} [options.providerBaseUrl] - LLM provider base URL
   * @returns {Promise<Response>}
   */
  async proxyLLMCall(messages, options = {}) {
    const {
      model = 'gpt-4',
      providerBaseUrl = 'https://api.openai.com',
      userContext = null,
      ...rest
    } = options;

    const url = `${this.gatewayUrl}/v1/llm/proxy`;

    const headers = {
      ...this._baseHeaders(),
      'X-Cicada-LLM-Provider': providerBaseUrl,
      'Content-Type': 'application/json',
    };

    // Inject user-context header
    const ctx = userContext || this.defaultUserContext;
    if (ctx) {
      Object.assign(headers, ctx.toHeaders());
    }

    // Extended retry config for LLM calls (longer timeouts)
    const llmRetry = {
      ...this.retryConfig,
      baseDelayMs: (this.retryConfig.baseDelayMs || 500) * 2,
      maxDelayMs: (this.retryConfig.maxDelayMs || 30000) * 2,
    };

    const response = await retryFetch(
      () => fetch(url, {
        method: 'POST',
        headers,
        body: JSON.stringify({ model, messages, ...rest }),
        signal: AbortSignal.timeout(this.timeout * 3),
      }),
      llmRetry,
    );

    return response;
  }

  /**
   * Check the Gateway's health status.
   * @returns {Promise<Object>}
   */
  async healthCheck() {
    try {
      const response = await fetch(`${this.gatewayUrl}/healthz`, {
        headers: this._baseHeaders(),
        signal: AbortSignal.timeout(5000),
      });
      return await response.json();
    } catch (err) {
      return { status: 'unreachable', error: err.message };
    }
  }

  /**
   * Get agent status (trust score, violations, etc).
   * @returns {Promise<Object>}
   */
  async getAgentStatus() {
    const response = await fetch(
      `${this.gatewayUrl}/v1/agent/${this.agentId}/status`,
      {
        headers: this._baseHeaders(),
        signal: AbortSignal.timeout(10000),
      }
    );
    if (!response.ok) {
      throw new Error(`Agent status check failed: ${response.status}`);
    }
    return await response.json();
  }
}

module.exports = { CicadaClient };
