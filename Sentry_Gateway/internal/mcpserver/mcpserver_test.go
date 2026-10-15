// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// helper to build a JSON-RPC 2.0 request body
func rpcBody(method string, params interface{}) *bytes.Buffer {
	body := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  method,
	}
	if params != nil {
		raw, _ := json.Marshal(params)
		body["params"] = json.RawMessage(raw)
	}
	b, _ := json.Marshal(body)
	return bytes.NewBuffer(b)
}

func authedRequest(t *testing.T, method string, params interface{}) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/mcp", rpcBody(method, params))
	req.Header.Set("Authorization", "Bearer test-aegis-token")
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "127.0.0.1:12345"
	return req
}

func setup(t *testing.T) {
	t.Helper()
	os.Setenv("CICADA_AEGIS_TOKEN", "test-aegis-token")
	t.Cleanup(func() { os.Unsetenv("CICADA_AEGIS_TOKEN") })
}

func parseResponse(t *testing.T, w *httptest.ResponseRecorder) Response {
	t.Helper()
	var resp Response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode MCP response: %v", err)
	}
	return resp
}

// ── Authentication ────────────────────────────────────────────────────────────

func TestMCP_RejectsMissingToken(t *testing.T) {
	setup(t)
	handler := Handler()
	req := httptest.NewRequest(http.MethodPost, "/v1/mcp", rpcBody("ping", nil))
	req.RemoteAddr = "127.0.0.1:12345"
	// No Authorization header
	w := httptest.NewRecorder()
	handler(w, req)

	resp := parseResponse(t, w)
	if resp.Error == nil {
		t.Fatal("expected error for missing auth token")
	}
	if resp.Error.Message != "invalid master signature" {
		t.Errorf("error message = %q", resp.Error.Message)
	}
}

func TestMCP_RejectsWrongToken(t *testing.T) {
	setup(t)
	handler := Handler()
	req := httptest.NewRequest(http.MethodPost, "/v1/mcp", rpcBody("ping", nil))
	req.Header.Set("Authorization", "Bearer wrong-token")
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	handler(w, req)

	resp := parseResponse(t, w)
	if resp.Error == nil {
		t.Fatal("expected error for wrong auth token")
	}
}

func TestMCP_RejectsUnauthorizedIP(t *testing.T) {
	setup(t)
	handler := Handler()
	req := httptest.NewRequest(http.MethodPost, "/v1/mcp", rpcBody("ping", nil))
	req.Header.Set("Authorization", "Bearer test-aegis-token")
	req.RemoteAddr = "203.0.113.1:12345" // external IP not in allowlist
	w := httptest.NewRecorder()
	handler(w, req)

	resp := parseResponse(t, w)
	if resp.Error == nil {
		t.Fatal("expected error for unauthorized IP")
	}
	if resp.Error.Message != "unauthorized node perimeter" {
		t.Errorf("error message = %q", resp.Error.Message)
	}
}

// ── Protocol ──────────────────────────────────────────────────────────────────

func TestMCP_Ping(t *testing.T) {
	setup(t)
	handler := Handler()
	w := httptest.NewRecorder()
	handler(w, authedRequest(t, "ping", nil))

	resp := parseResponse(t, w)
	if resp.Error != nil {
		t.Fatalf("ping should not error: %v", resp.Error)
	}
	result, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatal("ping result should be a map")
	}
	if result["status"] != "pong" {
		t.Errorf("ping status = %q", result["status"])
	}
}

func TestMCP_Initialize(t *testing.T) {
	setup(t)
	handler := Handler()
	w := httptest.NewRecorder()
	handler(w, authedRequest(t, "initialize", nil))

	resp := parseResponse(t, w)
	if resp.Error != nil {
		t.Fatalf("initialize should not error: %v", resp.Error)
	}
	result := resp.Result.(map[string]interface{})
	if result["protocolVersion"] != "2024-11-05" {
		t.Errorf("protocolVersion = %q", result["protocolVersion"])
	}
	serverInfo := result["serverInfo"].(map[string]interface{})
	if serverInfo["name"] != "cicada-sentry-mcp" {
		t.Errorf("server name = %q", serverInfo["name"])
	}
}

func TestMCP_ToolsList(t *testing.T) {
	setup(t)
	handler := Handler()
	w := httptest.NewRecorder()
	handler(w, authedRequest(t, "tools/list", nil))

	resp := parseResponse(t, w)
	if resp.Error != nil {
		t.Fatalf("tools/list should not error: %v", resp.Error)
	}
	result := resp.Result.(map[string]interface{})
	tools := result["tools"].([]interface{})
	if len(tools) != len(allTools) {
		t.Errorf("expected %d tools, got %d", len(allTools), len(tools))
	}
}

func TestMCP_InvalidJSONRPCVersion(t *testing.T) {
	setup(t)
	handler := Handler()
	body := `{"jsonrpc": "1.0", "id": 1, "method": "ping"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/mcp", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer test-aegis-token")
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	handler(w, req)

	resp := parseResponse(t, w)
	if resp.Error == nil {
		t.Fatal("should reject non-2.0 jsonrpc version")
	}
}

func TestMCP_UnknownMethod(t *testing.T) {
	setup(t)
	handler := Handler()
	w := httptest.NewRecorder()
	handler(w, authedRequest(t, "nonexistent/method", nil))

	resp := parseResponse(t, w)
	if resp.Error == nil {
		t.Fatal("should error on unknown method")
	}
	if resp.Error.Code != errMethodNotFound {
		t.Errorf("error code = %d, want %d", resp.Error.Code, errMethodNotFound)
	}
}

// ── Tool calls with mocked dependencies ───────────────────────────────────────

func TestMCP_QuarantineAgent(t *testing.T) {
	setup(t)
	var quarantinedID string
	QuarantineFn = func(agentID string) { quarantinedID = agentID }
	defer func() { QuarantineFn = nil }()

	handler := Handler()
	w := httptest.NewRecorder()
	handler(w, authedRequest(t, "tools/call", map[string]interface{}{
		"name":      "quarantine_agent",
		"arguments": map[string]interface{}{"agent_id": "agent-rogue-1", "reason": "anomalous velocity detected"},
	}))

	resp := parseResponse(t, w)
	if resp.Error != nil {
		t.Fatalf("quarantine should not error: %v", resp.Error)
	}
	if quarantinedID != "agent-rogue-1" {
		t.Errorf("quarantine function received agent_id = %q, want 'agent-rogue-1'", quarantinedID)
	}
}

func TestMCP_ReleaseAgent(t *testing.T) {
	setup(t)
	var releasedID string
	ReleaseFn = func(agentID string) { releasedID = agentID }
	defer func() { ReleaseFn = nil }()

	handler := Handler()
	w := httptest.NewRecorder()
	handler(w, authedRequest(t, "tools/call", map[string]interface{}{
		"name":      "release_agent",
		"arguments": map[string]interface{}{"agent_id": "agent-safe-1"},
	}))

	resp := parseResponse(t, w)
	if resp.Error != nil {
		t.Fatalf("release should not error: %v", resp.Error)
	}
	if releasedID != "agent-safe-1" {
		t.Errorf("release function received agent_id = %q", releasedID)
	}
}

func TestMCP_EngageGhostMode(t *testing.T) {
	setup(t)
	var ghostedID string
	EngageGhostModeFn = func(ctx context.Context, agentID string) error {
		ghostedID = agentID
		return nil
	}
	defer func() { EngageGhostModeFn = nil }()

	handler := Handler()
	w := httptest.NewRecorder()
	handler(w, authedRequest(t, "tools/call", map[string]interface{}{
		"name":      "engage_ghost_mode",
		"arguments": map[string]interface{}{"agent_id": "agent-suspect-1"},
	}))

	resp := parseResponse(t, w)
	if resp.Error != nil {
		t.Fatalf("ghost mode should not error: %v", resp.Error)
	}
	if ghostedID != "agent-suspect-1" {
		t.Errorf("ghost mode received agent_id = %q", ghostedID)
	}
}

func TestMCP_ReleaseGhostMode(t *testing.T) {
	setup(t)
	var releasedID string
	ReleaseGhostModeFn = func(ctx context.Context, agentID string) error {
		releasedID = agentID
		return nil
	}
	defer func() { ReleaseGhostModeFn = nil }()

	handler := Handler()
	w := httptest.NewRecorder()
	handler(w, authedRequest(t, "tools/call", map[string]interface{}{
		"name":      "release_ghost_mode",
		"arguments": map[string]interface{}{"agent_id": "agent-clear-1"},
	}))

	resp := parseResponse(t, w)
	if resp.Error != nil {
		t.Fatalf("release ghost mode should not error: %v", resp.Error)
	}
	if releasedID != "agent-clear-1" {
		t.Errorf("ghost mode release received agent_id = %q", releasedID)
	}
}

func TestMCP_TriggerRollback(t *testing.T) {
	setup(t)
	TriggerRollbackFn = func(ctx context.Context, traceID, failedAction, revertRoute string) (string, error) {
		return "rollback-id-123", nil
	}
	defer func() { TriggerRollbackFn = nil }()

	handler := Handler()
	w := httptest.NewRecorder()
	handler(w, authedRequest(t, "tools/call", map[string]interface{}{
		"name": "trigger_rollback",
		"arguments": map[string]interface{}{
			"trace_id":      "trace-abc",
			"failed_action": "DELETE /v1/users/456",
			"revert_route":  "https://api.stripe.com/v1/users",
		},
	}))

	resp := parseResponse(t, w)
	if resp.Error != nil {
		t.Fatalf("rollback should not error: %v", resp.Error)
	}
}

func TestMCP_ListQuarantined(t *testing.T) {
	setup(t)
	GetQuarantinedFn = func() []string {
		return []string{"agent-bad-1", "agent-bad-2"}
	}
	defer func() { GetQuarantinedFn = nil }()

	handler := Handler()
	w := httptest.NewRecorder()
	handler(w, authedRequest(t, "tools/call", map[string]interface{}{
		"name":      "list_quarantined",
		"arguments": map[string]interface{}{},
	}))

	resp := parseResponse(t, w)
	if resp.Error != nil {
		t.Fatalf("list_quarantined should not error: %v", resp.Error)
	}
}

// ── Missing dependencies return errors, not panics ────────────────────────────

func TestMCP_QuarantineMissingFn(t *testing.T) {
	setup(t)
	QuarantineFn = nil // not wired

	handler := Handler()
	w := httptest.NewRecorder()
	handler(w, authedRequest(t, "tools/call", map[string]interface{}{
		"name":      "quarantine_agent",
		"arguments": map[string]interface{}{"agent_id": "agent-1", "reason": "test"},
	}))

	resp := parseResponse(t, w)
	if resp.Error == nil {
		t.Fatal("should error when quarantine function is not wired")
	}
	if resp.Error.Code != errInternal {
		t.Errorf("error code = %d, want %d", resp.Error.Code, errInternal)
	}
}

func TestMCP_GetAgentMissingFn(t *testing.T) {
	setup(t)
	GetAgentFn = nil

	handler := Handler()
	w := httptest.NewRecorder()
	handler(w, authedRequest(t, "tools/call", map[string]interface{}{
		"name":      "get_agent",
		"arguments": map[string]interface{}{"agent_id": "agent-1"},
	}))

	resp := parseResponse(t, w)
	if resp.Error == nil {
		t.Fatal("should error when get_agent function is not wired")
	}
}

// ── Missing required parameters ───────────────────────────────────────────────

func TestMCP_QuarantineMissingAgentID(t *testing.T) {
	setup(t)
	QuarantineFn = func(agentID string) {}
	defer func() { QuarantineFn = nil }()

	handler := Handler()
	w := httptest.NewRecorder()
	handler(w, authedRequest(t, "tools/call", map[string]interface{}{
		"name":      "quarantine_agent",
		"arguments": map[string]interface{}{"reason": "no agent id"},
	}))

	resp := parseResponse(t, w)
	if resp.Error == nil {
		t.Fatal("should error when agent_id is missing")
	}
	if resp.Error.Code != errInvalidParams {
		t.Errorf("error code = %d, want %d", resp.Error.Code, errInvalidParams)
	}
}

func TestMCP_GetAgentMissingAgentID(t *testing.T) {
	setup(t)
	GetAgentFn = func(ctx context.Context, agentID string) (map[string]interface{}, error) {
		return nil, fmt.Errorf("not found")
	}
	defer func() { GetAgentFn = nil }()

	handler := Handler()
	w := httptest.NewRecorder()
	handler(w, authedRequest(t, "tools/call", map[string]interface{}{
		"name":      "get_agent",
		"arguments": map[string]interface{}{},
	}))

	resp := parseResponse(t, w)
	if resp.Error == nil {
		t.Fatal("should error when agent_id is missing")
	}
}

func TestMCP_UnknownTool(t *testing.T) {
	setup(t)
	handler := Handler()
	w := httptest.NewRecorder()
	handler(w, authedRequest(t, "tools/call", map[string]interface{}{
		"name":      "nonexistent_tool",
		"arguments": map[string]interface{}{},
	}))

	resp := parseResponse(t, w)
	if resp.Error == nil {
		t.Fatal("should error on unknown tool")
	}
	if resp.Error.Code != errMethodNotFound {
		t.Errorf("error code = %d, want %d", resp.Error.Code, errMethodNotFound)
	}
}

// ── Tool definitions integrity ────────────────────────────────────────────────

func TestAllTools_HaveDescriptions(t *testing.T) {
	for _, tool := range allTools {
		if tool.Name == "" {
			t.Error("tool with empty name")
		}
		if tool.Description == "" {
			t.Errorf("tool %q has empty description", tool.Name)
		}
	}
}

func TestAllTools_ControlToolsHaveRequiredParams(t *testing.T) {
	controlTools := []string{"quarantine_agent", "release_agent", "trigger_rollback", "engage_ghost_mode", "release_ghost_mode"}
	for _, name := range controlTools {
		found := false
		for _, tool := range allTools {
			if tool.Name == name {
				found = true
				if len(tool.InputSchema.Required) == 0 {
					t.Errorf("control tool %q should have required parameters", name)
				}
			}
		}
		if !found {
			t.Errorf("control tool %q not found in allTools", name)
		}
	}
}
