// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @cicada/sdk/memory — Agent memory sanitisation and trust scoring.
 *
 * Wraps agent memory stores (in-memory, Redis, vector DB) with:
 *   - TTL enforcement — expired entries return null
 *   - Trust-level injection scanning — blocks tainted content before storage
 *   - Provenance tracking — every entry records its origin
 *   - Context Flush Events — notifies the agent runtime when tainted entries
 *     are detected during periodic re-scans
 *   - Post-retrieval re-scanning — for vector DB adapters, scans top-K
 *     results after retrieval but before prompt formatting
 *
 * Integration:
 *   const { CicadaMemory } = require('@cicada/sdk');
 *   const memory = new CicadaMemory({ adapter: 'memory' });
 *   await memory.store('context', userInput, { trustLevel: 'user', ttl: 300 });
 *   const entry = await memory.retrieve('context');
 */

const EventEmitter = require('events');

// ── Injection indicator patterns ──────────────────────────────────────────────
// Mirrors the Go injection scanner's indicators. Compiled once at require time.
const INJECTION_PATTERNS = [
  /ignore\s+(all\s+)?previous/i,
  /you\s+are\s+now/i,
  /new\s+instructions?/i,
  /system\s*:\s*/i,
  /forget\s+(everything|all|your)/i,
  /override\s+(your|the|all)/i,
  /do\s+not\s+(tell|reveal|mention|say)/i,
  /(execute|run|perform)\s+(this|the\s+following)/i,
  /transfer\s+\$?\d+/i,
  /send\s+(me|to)\s+(the|this|your)/i,
  /paypal\.me/i,
  /api[_\s]?key/i,
  /secret[_\s]?(key|token)/i,
  /curl\s+/i,
  /wget\s+/i,
  /rm\s+-rf/i,
  /sudo\s+/i,
  /\bexfiltrate\b/i,
  /\bbase64\s+encode\b/i,
];

// Trust levels ordered from most trusted to least trusted.
// 'developer' content is never scanned (trusted authoring).
// All other levels are scanned with increasing strictness.
const TRUST_LEVELS = ['developer', 'user', 'retrieved', 'external'];

/**
 * Check if text contains injection indicator patterns.
 * @param {string} text - Content to scan
 * @returns {{ detected: boolean, pattern: string }}
 */
function scanForInjection(text) {
  if (typeof text !== 'string') return { detected: false, pattern: '' };
  for (const pattern of INJECTION_PATTERNS) {
    if (pattern.test(text)) {
      return { detected: true, pattern: pattern.source };
    }
  }
  return { detected: false, pattern: '' };
}

/**
 * @typedef {Object} MemoryEntry
 * @property {string} key - Storage key
 * @property {*} content - Stored content
 * @property {string} trustLevel - Trust level at time of storage
 * @property {string} provenance - Origin tag
 * @property {number} storedAt - Unix timestamp (ms) when stored
 * @property {number|null} expiresAt - Unix timestamp (ms) when entry expires, or null for no expiry
 */

class CicadaMemory extends EventEmitter {
  /**
   * @param {Object} [options]
   * @param {'memory'|'redis'|'custom'} [options.adapter='memory'] - Storage backend
   * @param {Object} [options.redisClient] - Redis client (required for 'redis' adapter)
   * @param {Object} [options.customStore] - Custom store implementing get/set/delete/scan
   * @param {number} [options.defaultTTL=0] - Default TTL in seconds (0 = no expiry)
   * @param {string} [options.defaultTrustLevel='user'] - Default trust level
   */
  constructor(options = {}) {
    super();
    this.defaultTTL = options.defaultTTL || 0;
    this.defaultTrustLevel = options.defaultTrustLevel || 'user';

    // Initialise the storage backend.
    const adapter = options.adapter || 'memory';
    if (adapter === 'memory') {
      this._store = new Map();
    } else if (adapter === 'redis') {
      if (!options.redisClient) throw new Error('redisClient required for redis adapter');
      this._redis = options.redisClient;
    } else if (adapter === 'custom') {
      if (!options.customStore) throw new Error('customStore required for custom adapter');
      this._custom = options.customStore;
    }

    this._adapter = adapter;
    this._scanLog = []; // Audit trail of scan events
  }

  /**
   * Store content with trust scoring, TTL, and injection scanning.
   *
   * @param {string} key - Storage key
   * @param {*} content - Content to store
   * @param {Object} [options]
   * @param {number} [options.ttl] - TTL in seconds (overrides default)
   * @param {string} [options.trustLevel] - Trust level
   * @param {string} [options.provenance='unknown'] - Origin tag for audit
   * @returns {Promise<{ stored: boolean, blocked: boolean, reason: string }>}
   */
  async store(key, content, options = {}) {
    const trustLevel = options.trustLevel || this.defaultTrustLevel;
    const ttl = options.ttl !== undefined ? options.ttl : this.defaultTTL;
    const provenance = options.provenance || 'unknown';
    const contentStr = typeof content === 'string' ? content : JSON.stringify(content);

    // Developer-authored content is trusted — skip scanning.
    if (trustLevel !== 'developer') {
      const scan = scanForInjection(contentStr);
      if (scan.detected) {
        this._scanLog.push({
          key,
          action: 'blocked_on_store',
          trustLevel,
          pattern: scan.pattern,
          timestamp: Date.now(),
        });

        this.emit('injection_blocked', {
          key,
          trustLevel,
          provenance,
          pattern: scan.pattern,
        });

        return { stored: false, blocked: true, reason: `Injection pattern detected: ${scan.pattern}` };
      }
    }

    const entry = {
      key,
      content,
      trustLevel,
      provenance,
      storedAt: Date.now(),
      expiresAt: ttl > 0 ? Date.now() + (ttl * 1000) : null,
    };

    await this._setEntry(key, entry);
    return { stored: true, blocked: false, reason: '' };
  }

  /**
   * Retrieve content by key. Returns null if expired or not found.
   *
   * @param {string} key - Storage key
   * @returns {Promise<MemoryEntry|null>}
   */
  async retrieve(key) {
    const entry = await this._getEntry(key);
    if (!entry) return null;

    // Check TTL expiry.
    if (entry.expiresAt && Date.now() > entry.expiresAt) {
      await this._deleteEntry(key);

      this._scanLog.push({
        key,
        action: 'expired',
        trustLevel: entry.trustLevel,
        timestamp: Date.now(),
      });

      return null;
    }

    return entry;
  }

  /**
   * Re-scan all stored entries against the current pattern set.
   * Returns a list of tainted entries and emits a 'context_flush' event
   * for each one, signalling the agent runtime to purge the entry
   * from the active LLM context window.
   *
   * @returns {Promise<Array<{ key: string, pattern: string }>>}
   */
  async scanMemory() {
    const tainted = [];
    const entries = await this._getAllEntries();

    for (const entry of entries) {
      if (entry.trustLevel === 'developer') continue;

      const contentStr = typeof entry.content === 'string'
        ? entry.content
        : JSON.stringify(entry.content);

      const scan = scanForInjection(contentStr);
      if (scan.detected) {
        tainted.push({ key: entry.key, pattern: scan.pattern });

        this._scanLog.push({
          key: entry.key,
          action: 'tainted_on_rescan',
          trustLevel: entry.trustLevel,
          pattern: scan.pattern,
          timestamp: Date.now(),
        });

        // Context Flush Event: the agent runtime must remove this entry
        // from the active LLM chat history array immediately.
        this.emit('context_flush', {
          key: entry.key,
          reason: `Tainted entry detected: ${scan.pattern}`,
          entry,
        });
      }
    }

    return tainted;
  }

  /**
   * Post-retrieval re-scan for vector DB results.
   * Scans an array of retrieved documents (top-K results from a vector DB)
   * and filters out any that contain injection patterns BEFORE they are
   * formatted into the prompt template.
   *
   * @param {Array<{ content: string, metadata?: Object }>} documents - Retrieved documents
   * @param {string} [trustLevel='retrieved'] - Trust level for all documents
   * @returns {{ clean: Array, tainted: Array<{ content: string, pattern: string }> }}
   */
  scanRetrievedDocuments(documents, trustLevel = 'retrieved') {
    const clean = [];
    const tainted = [];

    for (const doc of documents) {
      const contentStr = typeof doc.content === 'string'
        ? doc.content
        : JSON.stringify(doc.content);

      if (trustLevel === 'developer') {
        clean.push(doc);
        continue;
      }

      const scan = scanForInjection(contentStr);
      if (scan.detected) {
        tainted.push({ content: contentStr, pattern: scan.pattern, metadata: doc.metadata });

        this._scanLog.push({
          key: 'vector_retrieval',
          action: 'tainted_retrieval',
          trustLevel,
          pattern: scan.pattern,
          timestamp: Date.now(),
        });

        this.emit('injection_blocked', {
          key: 'vector_retrieval',
          trustLevel,
          provenance: 'vector_db',
          pattern: scan.pattern,
        });
      } else {
        clean.push(doc);
      }
    }

    return { clean, tainted };
  }

  /**
   * Flush the active memory window by purging all non-developer entries.
   *
   * Called by the SDK response interceptor when the Sentry Gateway sends
   * X-Cicada-Memory-Action: flush. This prevents context rot — contaminated
   * or boundary-crossing frames are discarded, leaving only developer-authored
   * invariants intact.
   *
   * @param {string} [reason='unknown'] - The flush reason from X-Cicada-Flush-Reason
   * @returns {Promise<{ purgedCount: number, retainedCount: number }>}
   */
  async flushActiveWindow(reason = 'unknown') {
    const entries = await this._getAllEntries();
    let purgedCount = 0;
    let retainedCount = 0;

    for (const entry of entries) {
      if (entry.trustLevel === 'developer') {
        retainedCount++;
        continue;
      }

      // Purge the untrusted entry
      await this._deleteEntry(entry.key);
      purgedCount++;

      this._scanLog.push({
        key: entry.key,
        action: 'flushed_by_gateway',
        trustLevel: entry.trustLevel,
        reason,
        timestamp: Date.now(),
      });
    }

    this.lastFlushTimestamp = Date.now();
    this.lastFlushReason = reason;

    // Emit completion event for audit observability
    this.emit('context_flush_complete', {
      reason,
      purgedCount,
      retainedCount,
      timestamp: this.lastFlushTimestamp,
    });

    return { purgedCount, retainedCount };
  }

  /**
   * Get the full scan audit log.
   * @returns {Array}
   */
  getAuditLog() {
    return [...this._scanLog];
  }

  // ── Storage backend abstraction ─────────────────────────────────────────────

  async _setEntry(key, entry) {
    if (this._adapter === 'memory') {
      this._store.set(key, entry);
    } else if (this._adapter === 'redis') {
      const ttlMs = entry.expiresAt ? entry.expiresAt - Date.now() : 0;
      const val = JSON.stringify(entry);
      if (ttlMs > 0) {
        await this._redis.set(`cicada:memory:${key}`, val, 'PX', ttlMs);
      } else {
        await this._redis.set(`cicada:memory:${key}`, val);
      }
    } else if (this._custom) {
      await this._custom.set(key, entry);
    }
  }

  async _getEntry(key) {
    if (this._adapter === 'memory') {
      return this._store.get(key) || null;
    } else if (this._adapter === 'redis') {
      const val = await this._redis.get(`cicada:memory:${key}`);
      return val ? JSON.parse(val) : null;
    } else if (this._custom) {
      return await this._custom.get(key);
    }
    return null;
  }

  async _deleteEntry(key) {
    if (this._adapter === 'memory') {
      this._store.delete(key);
    } else if (this._adapter === 'redis') {
      await this._redis.del(`cicada:memory:${key}`);
    } else if (this._custom) {
      await this._custom.delete(key);
    }
  }

  async _getAllEntries() {
    if (this._adapter === 'memory') {
      return Array.from(this._store.values());
    } else if (this._custom && this._custom.scan) {
      return await this._custom.scan();
    }
    // Redis adapter: full scan not implemented for performance reasons.
    // Use the custom adapter with a scan method for bulk operations.
    return [];
  }
}

module.exports = { CicadaMemory, scanForInjection, INJECTION_PATTERNS, TRUST_LEVELS };
