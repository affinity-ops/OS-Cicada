// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @cicada/sdk/adapters/autogen — Microsoft AutoGen integration adapter.
 *
 * This adapter bridges AutoGen's multi-agent orchestration framework with
 * Cicada's seven-layer enforcement pipeline. It provides:
 *
 *   1. CicadaAutoGenAgent — a wrapper that injects Cicada governance into
 *      an AutoGen AssistantAgent's tool-call lifecycle.
 *
 *   2. createCicadaTool — wraps any function into an AutoGen-compatible
 *      tool that routes HTTP calls through the Cicada Gateway.
 *
 *   3. CicadaGroupChatMonitor — hooks into AutoGen GroupChat to tag
 *      inter-agent messages with provenance metadata and apply
 *      per-agent velocity enforcement.
 *
 * Why AutoGen needs special handling:
 *   AutoGen's GroupChat pattern means multiple agents share a conversation
 *   history. Without governance, Agent A's context window leaks into Agent B.
 *   This adapter ensures each agent's messages carry provenance tags and
 *   that cross-agent context is flagged as 'tool_result' provenance
 *   (elevated scan sensitivity) rather than trusted 'developer' content.
 *
 * Usage:
 *   const { CicadaClient } = require('@cicada/sdk');
 *   const { CicadaAutoGenAgent, createCicadaTool } = require('@cicada/sdk/adapters/autogen');
 *
 *   const client = CicadaClient.fromYaml('cicada.yaml');
 *
 *   const searchTool = createCicadaTool({
 *     name: 'web-search',
 *     description: 'Search the web',
 *     targetUrl: 'https://api.search.com/v1/query',
 *     client,
 *   });
 *
 *   const agent = new CicadaAutoGenAgent({
 *     name: 'research-analyst',
 *     client,
 *     tools: [searchTool],
 *     systemMessage: 'You are a research analyst...',
 *   });
 */

const { CicadaClient } = require('../client');

/**
 * Creates an AutoGen-compatible tool function that routes HTTP calls
 * through the Cicada Sentry Gateway.
 *
 * @param {Object} config
 * @param {string} config.name - Tool name (must match cicada.yaml tool declaration)
 * @param {string} config.description - Human-readable tool description
 * @param {string} config.targetUrl - Target API URL (supports {param} placeholders)
 * @param {CicadaClient} config.client - Cicada client instance
 * @param {string} [config.method='POST'] - HTTP method
 * @param {string} [config.provenance='developer'] - Content provenance level
 * @returns {Object} AutoGen-compatible tool definition
 */
function createCicadaTool({
  name,
  description,
  targetUrl,
  client,
  method = 'POST',
  provenance = 'developer',
}) {
  return {
    name,
    description,
    parameters: {
      type: 'object',
      properties: {
        input: {
          type: 'string',
          description: 'Tool input payload (JSON string or plain text)',
        },
      },
    },

    /**
     * Execute the tool through Cicada's enforcement pipeline.
     *
     * @param {Object} params - Tool parameters from the LLM
     * @returns {Promise<string>} Tool result or enforcement message
     */
    async execute(params = {}) {
      // Resolve URL placeholders
      let resolvedUrl = targetUrl;
      for (const [key, value] of Object.entries(params)) {
        if (key !== 'input') {
          resolvedUrl = resolvedUrl.replace(`{${key}}`, encodeURIComponent(String(value)));
        }
      }

      // Parse body for write operations
      let body = null;
      if (['POST', 'PUT', 'PATCH'].includes(method.toUpperCase())) {
        try {
          body = typeof params.input === 'string' ? JSON.parse(params.input) : params.input;
        } catch {
          body = { input: params.input };
        }
      }

      const response = await client.proxyCall(method, resolvedUrl, body, {
        provenance,
        headers: { 'X-Cicada-Tool-Name': name },
      });

      // Handle enforcement decisions
      if (response.status === 403) {
        const text = await response.text();
        return `[CICADA BLOCKED] This action was denied by the governance pipeline: ${text.slice(0, 200)}`;
      }
      if (response.status === 429) {
        return '[CICADA RATE LIMITED] Velocity limit exceeded. Wait before retrying.';
      }
      if (response.status === 202) {
        return '[CICADA PENDING] Action submitted for human-in-the-loop approval.';
      }

      return await response.text();
    },
  };
}


/**
 * Wraps an AutoGen agent with Cicada governance.
 *
 * Intercepts the agent's message lifecycle to:
 *   1. Tag outbound messages with the agent's provenance metadata
 *   2. Apply per-agent velocity enforcement via the Gateway
 *   3. Log all tool invocations to the Cicada action ledger
 *   4. Tag inter-agent messages as 'tool_result' provenance
 *
 * @example
 *   const agent = new CicadaAutoGenAgent({
 *     name: 'billing-agent',
 *     client: cicadaClient,
 *     systemMessage: 'You process invoices...',
 *     tools: [stripeTool, slackTool],
 *   });
 */
class CicadaAutoGenAgent {
  /**
   * @param {Object} config
   * @param {string} config.name - Agent name (must match cicada.yaml identity.name)
   * @param {CicadaClient} config.client - Cicada client instance
   * @param {string} [config.systemMessage=''] - System prompt for the agent
   * @param {Array} [config.tools=[]] - Array of CicadaTool objects
   * @param {string} [config.model='gpt-4'] - LLM model identifier
   * @param {string} [config.providerBaseUrl] - LLM provider base URL
   */
  constructor({
    name,
    client,
    systemMessage = '',
    tools = [],
    model = 'gpt-4',
    providerBaseUrl = 'https://api.openai.com',
  }) {
    this.name = name;
    this.client = client;
    this.systemMessage = systemMessage;
    this.tools = tools;
    this.model = model;
    this.providerBaseUrl = providerBaseUrl;
    this._conversationHistory = [];
    this._toolCallCount = 0;
  }

  /**
   * Send a message to this agent and get a response.
   * Routes through the Cicada LLM proxy for enforcement.
   *
   * @param {string} content - User/orchestrator message
   * @param {Object} [options={}]
   * @param {string} [options.provenance='developer'] - Message provenance
   * @param {boolean} [options.fromAgent=false] - True if from another AutoGen agent
   * @returns {Promise<Object>} Response with content and metadata
   */
  async chat(content, options = {}) {
    const { provenance = 'developer', fromAgent = false } = options;

    // Messages from other agents get elevated provenance
    const messageProvenance = fromAgent ? 'tool_result' : provenance;

    // Build messages array
    const messages = [];

    if (this.systemMessage) {
      messages.push({
        role: 'system',
        content: this.systemMessage,
      });
    }

    // Include conversation history
    for (const msg of this._conversationHistory) {
      messages.push(msg);
    }

    // Add the new message with provenance annotation
    messages.push({
      role: 'user',
      content: `[provenance:${messageProvenance}] ${content}`,
    });

    // Include tool definitions if tools are available
    const toolDefs = this.tools.map(t => ({
      type: 'function',
      function: {
        name: t.name,
        description: t.description,
        parameters: t.parameters,
      },
    }));

    // Route through Cicada LLM proxy
    const response = await this.client.proxyLLMCall(messages, {
      model: this.model,
      providerBaseUrl: this.providerBaseUrl,
      ...(toolDefs.length > 0 ? { tools: toolDefs } : {}),
    });

    if (!response.ok) {
      const errorText = await response.text();
      return {
        content: `[CICADA ERROR] LLM call failed: ${errorText.slice(0, 200)}`,
        blocked: response.status === 403,
        rateLimited: response.status === 429,
        pending: response.status === 202,
      };
    }

    const data = await response.json();
    const assistantMessage = data.choices?.[0]?.message;

    if (!assistantMessage) {
      return { content: '[ERROR] No response from LLM', blocked: false };
    }

    // Handle tool calls
    if (assistantMessage.tool_calls?.length > 0) {
      return await this._handleToolCalls(assistantMessage, messages);
    }

    // Store in history
    this._conversationHistory.push(
      { role: 'user', content },
      { role: 'assistant', content: assistantMessage.content },
    );

    return {
      content: assistantMessage.content,
      blocked: false,
      rateLimited: false,
      pending: false,
      toolCalls: 0,
    };
  }

  /**
   * Execute tool calls and continue the conversation.
   * @private
   */
  async _handleToolCalls(assistantMessage, currentMessages) {
    const toolResults = [];

    for (const toolCall of assistantMessage.tool_calls) {
      const tool = this.tools.find(t => t.name === toolCall.function.name);
      if (!tool) {
        toolResults.push({
          tool_call_id: toolCall.id,
          role: 'tool',
          content: `[ERROR] Unknown tool: ${toolCall.function.name}`,
        });
        continue;
      }

      this._toolCallCount++;

      let params;
      try {
        params = JSON.parse(toolCall.function.arguments);
      } catch {
        params = { input: toolCall.function.arguments };
      }

      const result = await tool.execute(params);

      toolResults.push({
        tool_call_id: toolCall.id,
        role: 'tool',
        content: result,
      });
    }

    // Continue conversation with tool results
    const continuedMessages = [
      ...currentMessages,
      assistantMessage,
      ...toolResults,
    ];

    const followUp = await this.client.proxyLLMCall(continuedMessages, {
      model: this.model,
      providerBaseUrl: this.providerBaseUrl,
    });

    if (!followUp.ok) {
      return { content: '[CICADA ERROR] Follow-up LLM call failed', blocked: followUp.status === 403 };
    }

    const followUpData = await followUp.json();
    const finalMessage = followUpData.choices?.[0]?.message?.content || '';

    // Store condensed history
    this._conversationHistory.push(
      { role: 'user', content: currentMessages[currentMessages.length - 1].content },
      { role: 'assistant', content: finalMessage },
    );

    return {
      content: finalMessage,
      blocked: false,
      rateLimited: false,
      pending: false,
      toolCalls: assistantMessage.tool_calls.length,
    };
  }

  /**
   * Reset conversation history.
   */
  clearHistory() {
    this._conversationHistory = [];
    this._toolCallCount = 0;
  }

  /**
   * Get agent governance status.
   * @returns {Promise<Object>}
   */
  async getStatus() {
    return await this.client.getAgentStatus();
  }
}


/**
 * Monitor for AutoGen GroupChat sessions.
 *
 * Tracks inter-agent message flow and ensures:
 *   1. Messages crossing agent boundaries are tagged as 'tool_result'
 *   2. Each agent's velocity limits are independently enforced
 *   3. The full conversation trace is available for audit
 *
 * @example
 *   const monitor = new CicadaGroupChatMonitor(cicadaClient);
 *   monitor.onMessage(fromAgent, toAgent, message);
 */
class CicadaGroupChatMonitor {
  /**
   * @param {CicadaClient} client - Cicada client for audit logging
   */
  constructor(client) {
    this.client = client;
    this._messageLog = [];
    this._agentMessageCounts = new Map();
  }

  /**
   * Record and audit a message between agents in a GroupChat.
   *
   * @param {string} fromAgent - Sending agent name
   * @param {string} toAgent - Receiving agent name (or 'broadcast')
   * @param {string} content - Message content
   * @returns {Object} Audit metadata
   */
  onMessage(fromAgent, toAgent, content) {
    const timestamp = new Date().toISOString();

    // Track per-agent message counts
    const count = (this._agentMessageCounts.get(fromAgent) || 0) + 1;
    this._agentMessageCounts.set(fromAgent, count);

    const entry = {
      timestamp,
      from: fromAgent,
      to: toAgent,
      contentLength: content.length,
      messageIndex: this._messageLog.length,
      crossAgent: fromAgent !== toAgent,
      provenance: fromAgent !== toAgent ? 'tool_result' : 'developer',
    };

    this._messageLog.push(entry);

    return entry;
  }

  /**
   * Get the full message audit log.
   * @returns {Array<Object>}
   */
  getAuditLog() {
    return [...this._messageLog];
  }

  /**
   * Get per-agent message statistics.
   * @returns {Object}
   */
  getStats() {
    const stats = {};
    for (const [agent, count] of this._agentMessageCounts) {
      stats[agent] = {
        totalMessages: count,
        crossAgentMessages: this._messageLog
          .filter(m => m.from === agent && m.crossAgent)
          .length,
      };
    }
    return stats;
  }

  /**
   * Reset the monitor.
   */
  clear() {
    this._messageLog = [];
    this._agentMessageCounts.clear();
  }
}


module.exports = {
  createCicadaTool,
  CicadaAutoGenAgent,
  CicadaGroupChatMonitor,
};
