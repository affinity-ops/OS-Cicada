// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package mcpserver implements a production-grade Model Context Protocol (MCP)
// server over HTTP for the Cicada Sentry Gateway.
//
// What this is:
// MCP is the standard protocol that allows AI models (Claude, GPT-4 with tools,
// Gemini) to call external tools via a structured JSON-RPC 2.0 interface.
// This server exposes Cicada's security control plane as MCP tools so that
// Aegis-0 — or any MCP-compatible model — can interact with the platform
// without a custom HTTP client.
//
// Three logical server groups (all served at one HTTP endpoint):
//
//   Telemetry tools:
//     get_threat_signals   — returns current V01–V10 anomaly counts
//     get_agent_velocity   — returns a specific agent's write/delete rate
//     list_quarantined     — lists agents currently in gossip quarantine
//
//   Registry tools:
//     get_agent            — fetches an agent record by ID
//     get_tenant           — fetches a tenant record by ID
//
//   Control tools (privileged — require HITL confirmation in Aegis-0):
//     quarantine_agent     — quarantines an agent via gossip mesh
//     release_agent        — releases a quarantined agent
//     trigger_rollback     — enqueues a saga rollback for a trace
//     engage_ghost_mode    — routes an agent to shadow sandbox
//     release_ghost_mode   — returns agent to normal routing
//
// Protocol:
// MCP over HTTP (streamable transport). Clients POST JSON-RPC 2.0 messages to
// /v1/mcp and receive synchronous JSON-RPC responses. This is the "server-sent
// events" transport simplified to request-response for tool calls (SSE streaming
// is only required for LLM sampling, which this server does not expose).
//
// Authentication:
// Requests must carry Authorization: Bearer <CICADA_AEGIS_TOKEN>.
// The endpoint additionally enforces IP boundary checks via CICADA_AEGIS_ALLOWED_IPS.
package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// ── JSON-RPC 2.0 wire types ────────────────────────────────────────────────────

type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"` // string or number per spec
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  interface{}     `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Standard JSON-RPC error codes
const (
	errParse          = -32700
	errInvalidRequest = -32600
	errMethodNotFound = -32601
	errInvalidParams  = -32602
	errInternal       = -32603
)

// ── Tool definitions ───────────────────────────────────────────────────────────

type ToolDef struct {
	Name        string     `json:"name"`
	Description string     `json:"description"`
	InputSchema JSONSchema  `json:"inputSchema"`
}

type JSONSchema struct {
	Type       string              `json:"type"`
	Properties map[string]Property `json:"properties,omitempty"`
	Required   []string            `json:"required,omitempty"`
}

type Property struct {
	Type        string `json:"type"`
	Description string `json:"description"`
}

var allTools = []ToolDef{
	// Telemetry ────────────────────────────────────────────────────────────────
	{
		Name:        "get_threat_signals",
		Description: "Returns aggregated anomaly counts across all 10 threat vectors (V01–V10) over a rolling time window. Call this first to assess current platform threat level before deciding on any control action.",
		InputSchema: JSONSchema{
			Type: "object",
			Properties: map[string]Property{
				"window_minutes": {Type: "integer", Description: "Rolling window in minutes for anomaly counts. Default 60."},
			},
		},
	},
	{
		Name:        "get_agent_velocity",
		Description: "Returns the current write and delete call rate for a specific agent in the last 60 seconds. Use this to confirm velocity anomaly before engaging ghost mode or quarantine.",
		InputSchema: JSONSchema{
			Type:     "object",
			Required: []string{"agent_id"},
			Properties: map[string]Property{
				"agent_id": {Type: "string", Description: "UUID of the agent to inspect."},
			},
		},
	},
	{
		Name:        "list_quarantined",
		Description: "Lists all agent IDs currently quarantined in the gossip mesh. An empty list means all agents are currently admitted.",
		InputSchema: JSONSchema{Type: "object"},
	},
	// Registry ─────────────────────────────────────────────────────────────────
	{
		Name:        "get_agent",
		Description: "Retrieves the full agent record including trust tier, role, declared tools, and revocation state. Use this to investigate a suspicious agent before taking action.",
		InputSchema: JSONSchema{
			Type:     "object",
			Required: []string{"agent_id"},
			Properties: map[string]Property{
				"agent_id": {Type: "string", Description: "UUID of the agent."},
			},
		},
	},
	{
		Name:        "get_tenant",
		Description: "Retrieves a tenant record including plan, status, and company email. Use this to identify the company behind a suspicious agent.",
		InputSchema: JSONSchema{
			Type:     "object",
			Required: []string{"tenant_id"},
			Properties: map[string]Property{
				"tenant_id": {Type: "string", Description: "UUID of the tenant."},
			},
		},
	},
	// Control (privileged) ─────────────────────────────────────────────────────
	{
		Name:        "quarantine_agent",
		Description: "Quarantines an agent via the gossip mesh. All subsequent proxy calls from this agent are blocked immediately and across all gateway nodes. This action is logged to the audit ledger. For irreversible infrastructure-wide actions, request human confirmation before calling.",
		InputSchema: JSONSchema{
			Type:     "object",
			Required: []string{"agent_id", "reason"},
			Properties: map[string]Property{
				"agent_id": {Type: "string", Description: "UUID of the agent to quarantine."},
				"reason":   {Type: "string", Description: "Human-readable reason for quarantine. Written to audit ledger."},
			},
		},
	},
	{
		Name:        "release_agent",
		Description: "Releases an agent from gossip mesh quarantine. Only call after confirming the agent is safe or the threat has been mitigated.",
		InputSchema: JSONSchema{
			Type:     "object",
			Required: []string{"agent_id"},
			Properties: map[string]Property{
				"agent_id": {Type: "string", Description: "UUID of the agent to release."},
			},
		},
	},
	{
		Name:        "trigger_rollback",
		Description: "Enqueues a saga compensating transaction to reverse the effects of a specific proxy action. Use when an agent has executed a damaging write and the revert route is known.",
		InputSchema: JSONSchema{
			Type:     "object",
			Required: []string{"trace_id", "failed_action", "revert_route"},
			Properties: map[string]Property{
				"trace_id":      {Type: "string", Description: "Trace ID from the action_ledger of the action to reverse."},
				"failed_action": {Type: "string", Description: "Description of the action that must be compensated."},
				"revert_route":  {Type: "string", Description: "Full URL of the compensation endpoint (must be in allowlisted domains)."},
			},
		},
	},
	{
		Name:        "engage_ghost_mode",
		Description: "Routes all proxy calls for an agent to the shadow sandbox instead of the real target API. The agent receives plausible-looking responses and does not know it is being diverted. Use for observation when evidence is suspicious but not conclusive.",
		InputSchema: JSONSchema{
			Type:     "object",
			Required: []string{"agent_id"},
			Properties: map[string]Property{
				"agent_id": {Type: "string", Description: "UUID of the agent to divert."},
			},
		},
	},
	{
		Name:        "release_ghost_mode",
		Description: "Returns an agent from shadow sandbox routing to normal proxy routing. Call after investigation is complete and the agent is determined to be safe.",
		InputSchema: JSONSchema{
			Type:     "object",
			Required: []string{"agent_id"},
			Properties: map[string]Property{
				"agent_id": {Type: "string", Description: "UUID of the agent to restore."},
			},
		},
	},
	{
		Name:        "submit_policy_revision",
		Description: "Submits a new revision of an OPA Rego policy to the store. This creates an inactive version. You must activate it separately. Use to version control Aegis-0 policy edits.",
		InputSchema: JSONSchema{
			Type:     "object",
			Required: []string{"policy_name", "content", "author"},
			Properties: map[string]Property{
				"policy_name": {Type: "string", Description: "Name of the policy (e.g., 'authz.rego')."},
				"content":     {Type: "string", Description: "The raw Rego code content."},
				"author":      {Type: "string", Description: "Identifier of who makes the change."},
			},
		},
	},
	{
		Name:        "activate_policy",
		Description: "Activates a submitted policy version to take immediate effect. This demotes the currently active policy and hot-reloads the evaluation engine.",
		InputSchema: JSONSchema{
			Type:     "object",
			Required: []string{"policy_name", "version"},
			Properties: map[string]Property{
				"policy_name": {Type: "string", Description: "Name of the policy (e.g., 'authz.rego')."},
				"version":     {Type: "integer", Description: "The version number to activate."},
			},
		},
	},
}

// ── Dependency injection ───────────────────────────────────────────────────────
// The MCP server needs access to platform internals. These are set by main.go
// at startup. Using function variables rather than a struct avoids tight
// coupling while keeping dependencies explicit.

// QuarantineFn quarantines an agent in the gossip mesh.
var QuarantineFn func(agentID string)

// ReleaseFn releases an agent from gossip mesh quarantine.
var ReleaseFn func(agentID string)

// GetQuarantinedFn lists currently quarantined agent IDs.
var GetQuarantinedFn func() []string

// GetAgentFn queries an agent record from PostgreSQL.
var GetAgentFn func(ctx context.Context, agentID string) (map[string]interface{}, error)

// GetTenantFn queries a tenant record from PostgreSQL.
var GetTenantFn func(ctx context.Context, tenantID string) (map[string]interface{}, error)

// TriggerRollbackFn enqueues a saga rollback.
var TriggerRollbackFn func(ctx context.Context, traceID, failedAction, revertRoute string) (string, error)

// EngageGhostModeFn registers an agent in ghost mode.
var EngageGhostModeFn func(ctx context.Context, agentID string) error

// ReleaseGhostModeFn removes an agent from ghost mode.
var ReleaseGhostModeFn func(ctx context.Context, agentID string) error

// GetVelocityFn returns an agent's current write/delete counters.
var GetVelocityFn func(ctx context.Context, agentID string) map[string]int64

// GetThreatSignalsFn fetches threat signals from the Core API or aggregates locally.
var GetThreatSignalsFn func(ctx context.Context, windowMinutes int) (map[string]interface{}, error)

// SubmitPolicyRevisionFn submits a new policy revision.
var SubmitPolicyRevisionFn func(ctx context.Context, name, content, author string) (int, error)

// ActivatePolicyFn activates a specific policy version.
var ActivatePolicyFn func(ctx context.Context, name string, version int) error

// ── HTTP Handler ───────────────────────────────────────────────────────────────

// Handler returns the HTTP handler for the MCP server endpoint.
// Mount at POST /v1/mcp.
func Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// IP boundary enforcement — identical to handleMCPExecution
		remoteIP, _, _ := net.SplitHostPort(r.RemoteAddr)
		if remoteIP == "" {
			remoteIP = r.RemoteAddr
		}
		allowedIPs := map[string]bool{"127.0.0.1": true, "::1": true}
		if extra := os.Getenv("CICADA_AEGIS_ALLOWED_IPS"); extra != "" {
			for _, ip := range strings.Split(extra, ",") {
				allowedIPs[strings.TrimSpace(ip)] = true
			}
		}
		if !allowedIPs[remoteIP] {
			writeError(w, nil, errInvalidRequest, "unauthorized node perimeter")
			return
		}

		// Bearer token authentication
		expectedToken := os.Getenv("CICADA_AEGIS_TOKEN")
		if expectedToken == "" {
			writeError(w, nil, errInternal, "CICADA_AEGIS_TOKEN not configured")
			return
		}
		auth := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if auth != expectedToken {
			writeError(w, nil, errInvalidRequest, "invalid master signature")
			return
		}

		var req Request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, nil, errParse, "invalid JSON")
			return
		}

		if req.JSONRPC != "2.0" {
			writeError(w, req.ID, errInvalidRequest, "jsonrpc must be \"2.0\"")
			return
		}

		// Set MCP-required headers for streamable transport
		w.Header().Set("Content-Type", "application/json")

		switch req.Method {
		case "initialize":
			writeResult(w, req.ID, map[string]interface{}{
				"protocolVersion": "2024-11-05",
				"capabilities": map[string]interface{}{
					"tools": map[string]bool{"listChanged": false},
				},
				"serverInfo": map[string]string{
					"name":    "cicada-sentry-mcp",
					"version": "1.0.0",
				},
			})

		case "tools/list":
			writeResult(w, req.ID, map[string]interface{}{"tools": allTools})

		case "tools/call":
			handleToolCall(w, r.Context(), req)

		case "ping":
			writeResult(w, req.ID, map[string]string{"status": "pong"})

		default:
			writeError(w, req.ID, errMethodNotFound, fmt.Sprintf("method not found: %s", req.Method))
		}
	}
}

// ── Tool dispatch ──────────────────────────────────────────────────────────────

func handleToolCall(w http.ResponseWriter, ctx context.Context, req Request) {
	var params struct {
		Name      string                 `json:"name"`
		Arguments map[string]interface{} `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		writeError(w, req.ID, errInvalidParams, "invalid tool call params")
		return
	}

	log.Printf("[MCP] Tool call: %s args=%v", params.Name, params.Arguments)

	switch params.Name {

	// ── Telemetry ────────────────────────────────────────────────────────────
	case "get_threat_signals":
		window := 60
		if v, ok := params.Arguments["window_minutes"].(float64); ok {
			window = int(v)
		}
		if GetThreatSignalsFn == nil {
			writeError(w, req.ID, errInternal, "threat signal function not wired")
			return
		}
		signals, err := GetThreatSignalsFn(ctx, window)
		if err != nil {
			writeError(w, req.ID, errInternal, err.Error())
			return
		}
		writeToolResult(w, req.ID, signals)

	case "get_agent_velocity":
		agentID, ok := params.Arguments["agent_id"].(string)
		if !ok || agentID == "" {
			writeError(w, req.ID, errInvalidParams, "agent_id required")
			return
		}
		if GetVelocityFn == nil {
			writeToolResult(w, req.ID, map[string]interface{}{"note": "velocity function not wired"})
			return
		}
		rates := GetVelocityFn(ctx, agentID)
		writeToolResult(w, req.ID, map[string]interface{}{
			"agent_id":        agentID,
			"write_calls_60s": rates["write"],
			"delete_calls_60s": rates["delete"],
			"window_seconds":  60,
		})

	case "list_quarantined":
		var list []string
		if GetQuarantinedFn != nil {
			list = GetQuarantinedFn()
		}
		writeToolResult(w, req.ID, map[string]interface{}{
			"quarantined_agents": list,
			"count":              len(list),
		})

	// ── Registry ─────────────────────────────────────────────────────────────
	case "get_agent":
		agentID, ok := params.Arguments["agent_id"].(string)
		if !ok || agentID == "" {
			writeError(w, req.ID, errInvalidParams, "agent_id required")
			return
		}
		if GetAgentFn == nil {
			writeError(w, req.ID, errInternal, "agent query function not wired")
			return
		}
		agent, err := GetAgentFn(ctx, agentID)
		if err != nil {
			writeError(w, req.ID, errInternal, err.Error())
			return
		}
		writeToolResult(w, req.ID, agent)

	case "get_tenant":
		tenantID, ok := params.Arguments["tenant_id"].(string)
		if !ok || tenantID == "" {
			writeError(w, req.ID, errInvalidParams, "tenant_id required")
			return
		}
		if GetTenantFn == nil {
			writeError(w, req.ID, errInternal, "tenant query function not wired")
			return
		}
		tenant, err := GetTenantFn(ctx, tenantID)
		if err != nil {
			writeError(w, req.ID, errInternal, err.Error())
			return
		}
		writeToolResult(w, req.ID, tenant)

	// ── Control ───────────────────────────────────────────────────────────────
	case "quarantine_agent":
		agentID, ok := params.Arguments["agent_id"].(string)
		reason, _ := params.Arguments["reason"].(string)
		if !ok || agentID == "" {
			writeError(w, req.ID, errInvalidParams, "agent_id and reason required")
			return
		}
		if QuarantineFn == nil {
			writeError(w, req.ID, errInternal, "quarantine function not wired")
			return
		}
		QuarantineFn(agentID)
		log.Printf("[MCP CONTROL] Agent %s quarantined. Reason: %s", agentID, reason)
		writeToolResult(w, req.ID, map[string]interface{}{
			"status":   "quarantined",
			"agent_id": agentID,
			"reason":   reason,
			"at":       time.Now().UTC().Format(time.RFC3339),
		})

	case "release_agent":
		agentID, ok := params.Arguments["agent_id"].(string)
		if !ok || agentID == "" {
			writeError(w, req.ID, errInvalidParams, "agent_id required")
			return
		}
		if ReleaseFn == nil {
			writeError(w, req.ID, errInternal, "release function not wired")
			return
		}
		ReleaseFn(agentID)
		log.Printf("[MCP CONTROL] Agent %s released from quarantine", agentID)
		writeToolResult(w, req.ID, map[string]interface{}{
			"status":   "released",
			"agent_id": agentID,
		})

	case "trigger_rollback":
		traceID, _ := params.Arguments["trace_id"].(string)
		failedAction, _ := params.Arguments["failed_action"].(string)
		revertRoute, _ := params.Arguments["revert_route"].(string)
		if traceID == "" || failedAction == "" || revertRoute == "" {
			writeError(w, req.ID, errInvalidParams, "trace_id, failed_action, and revert_route required")
			return
		}
		if TriggerRollbackFn == nil {
			writeError(w, req.ID, errInternal, "rollback function not wired")
			return
		}
		rollbackID, err := TriggerRollbackFn(ctx, traceID, failedAction, revertRoute)
		if err != nil {
			writeError(w, req.ID, errInternal, fmt.Sprintf("rollback enqueue failed: %s", err.Error()))
			return
		}
		log.Printf("[MCP CONTROL] Saga rollback enqueued for trace %s rollback_id %s", traceID, rollbackID)
		writeToolResult(w, req.ID, map[string]interface{}{
			"status":      "enqueued",
			"rollback_id": rollbackID,
			"trace_id":    traceID,
		})

	case "engage_ghost_mode":
		agentID, ok := params.Arguments["agent_id"].(string)
		if !ok || agentID == "" {
			writeError(w, req.ID, errInvalidParams, "agent_id required")
			return
		}
		if EngageGhostModeFn == nil {
			writeError(w, req.ID, errInternal, "ghost mode function not wired")
			return
		}
		if err := EngageGhostModeFn(ctx, agentID); err != nil {
			writeError(w, req.ID, errInternal, err.Error())
			return
		}
		log.Printf("[MCP CONTROL] Agent %s entered ghost mode", agentID)
		writeToolResult(w, req.ID, map[string]interface{}{
			"status":   "ghost_mode_active",
			"agent_id": agentID,
		})

	case "release_ghost_mode":
		agentID, ok := params.Arguments["agent_id"].(string)
		if !ok || agentID == "" {
			writeError(w, req.ID, errInvalidParams, "agent_id required")
			return
		}
		if ReleaseGhostModeFn == nil {
			writeError(w, req.ID, errInternal, "ghost mode release function not wired")
			return
		}
		if err := ReleaseGhostModeFn(ctx, agentID); err != nil {
			writeError(w, req.ID, errInternal, err.Error())
			return
		}
		log.Printf("[MCP CONTROL] Agent %s released from ghost mode", agentID)
		writeToolResult(w, req.ID, map[string]interface{}{
			"status":   "normal_routing_restored",
			"agent_id": agentID,
		})

	case "submit_policy_revision":
		name, _ := params.Arguments["policy_name"].(string)
		content, _ := params.Arguments["content"].(string)
		author, _ := params.Arguments["author"].(string)
		if name == "" || content == "" || author == "" {
			writeError(w, req.ID, errInvalidParams, "policy_name, content, and author required")
			return
		}
		if SubmitPolicyRevisionFn == nil {
			writeError(w, req.ID, errInternal, "submit policy function not wired")
			return
		}
		version, err := SubmitPolicyRevisionFn(ctx, name, content, author)
		if err != nil {
			writeError(w, req.ID, errInternal, err.Error())
			return
		}
		log.Printf("[MCP CONTROL] Policy %s revision %d submitted by %s", name, version, author)
		writeToolResult(w, req.ID, map[string]interface{}{
			"status":      "revision_submitted",
			"policy_name": name,
			"version":     version,
		})

	case "activate_policy":
		name, _ := params.Arguments["policy_name"].(string)
		versionFloat, ok := params.Arguments["version"].(float64)
		if !ok || name == "" {
			writeError(w, req.ID, errInvalidParams, "policy_name and version required")
			return
		}
		version := int(versionFloat)
		if ActivatePolicyFn == nil {
			writeError(w, req.ID, errInternal, "activate policy function not wired")
			return
		}
		if err := ActivatePolicyFn(ctx, name, version); err != nil {
			writeError(w, req.ID, errInternal, err.Error())
			return
		}
		log.Printf("[MCP CONTROL] Policy %s version %d activated", name, version)
		writeToolResult(w, req.ID, map[string]interface{}{
			"status":      "policy_activated",
			"policy_name": name,
			"version":     version,
		})

	default:
		writeError(w, req.ID, errMethodNotFound, fmt.Sprintf("unknown tool: %s", params.Name))
	}
}

// ── Response helpers ───────────────────────────────────────────────────────────

func writeResult(w http.ResponseWriter, id json.RawMessage, result interface{}) {
	json.NewEncoder(w).Encode(Response{JSONRPC: "2.0", ID: id, Result: result})
}

// writeToolResult wraps a result in the MCP tools/call content envelope.
func writeToolResult(w http.ResponseWriter, id json.RawMessage, data interface{}) {
	body, _ := json.Marshal(data)
	writeResult(w, id, map[string]interface{}{
		"content": []map[string]interface{}{
			{"type": "text", "text": string(body)},
		},
	})
}

func writeError(w http.ResponseWriter, id json.RawMessage, code int, msg string) {
	if id == nil {
		id = json.RawMessage("null")
	}
	json.NewEncoder(w).Encode(Response{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &RPCError{Code: code, Message: msg},
	})
}
