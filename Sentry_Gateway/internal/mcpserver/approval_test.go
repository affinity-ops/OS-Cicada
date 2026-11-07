// Copyright 2026 Patrick Matthews and Patrick Matthews (Affinity Ops / Affinity Smart AI)
// SPDX-License-Identifier: Apache-2.0

package mcpserver

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

const testOperatorToken = "test-operator-token"

func setupOperator(t *testing.T) {
	t.Helper()
	os.Setenv("CICADA_OPERATOR_APPROVAL_TOKEN", testOperatorToken)
	t.Cleanup(func() {
		os.Unsetenv("CICADA_OPERATOR_APPROVAL_TOKEN")
		approvalsMu.Lock()
		approvals = map[string]*approval{}
		approvalsMu.Unlock()
		nowFn = time.Now
	})
}

func callTool(t *testing.T, tool string, args map[string]interface{}) Response {
	t.Helper()
	w := httptest.NewRecorder()
	Handler()(w, authedRequest(t, "tools/call", map[string]interface{}{"name": tool, "arguments": args}))
	return parseResponse(t, w)
}

func resultMap(t *testing.T, resp Response) map[string]interface{} {
	t.Helper()
	if resp.Error != nil {
		t.Fatalf("unexpected RPC error: %+v", resp.Error)
	}
	// writeToolResult wraps data as MCP content: {"content":[{"type":"text","text":"<json>"}]}
	m, _ := resp.Result.(map[string]interface{})
	if content, ok := m["content"].([]interface{}); ok && len(content) > 0 {
		item, _ := content[0].(map[string]interface{})
		if txt, ok := item["text"].(string); ok {
			var inner map[string]interface{}
			if json.Unmarshal([]byte(txt), &inner) == nil {
				return inner
			}
		}
	}
	return m
}

func decide(t *testing.T, id, decision, token string) int {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"approval_id": id, "decision": decision, "operator": "patrick"})
	req := httptest.NewRequest(http.MethodPost, "/v1/mcp/approvals/decide", bytes.NewReader(body))
	req.Header.Set("X-Cicada-Operator-Token", token)
	w := httptest.NewRecorder()
	ApprovalsHandler()(w, req)
	return w.Code
}

// callWithApproval runs the full flow: held -> human approves -> identical retry executes.
func callWithApproval(t *testing.T, tool string, args map[string]interface{}) Response {
	t.Helper()
	setupOperator(t)
	first := resultMap(t, callTool(t, tool, args))
	if first["status"] != "approval_required" {
		t.Fatalf("%s should be held for approval, got %v", tool, first)
	}
	id := first["approval_id"].(string)
	if code := decide(t, id, "approve", testOperatorToken); code != http.StatusOK {
		t.Fatalf("approve returned %d", code)
	}
	retry := map[string]interface{}{}
	for k, v := range args {
		retry[k] = v
	}
	retry["approval_id"] = id
	return callTool(t, tool, retry)
}

func TestApproval_RefusedWhenNoOperatorTokenConfigured(t *testing.T) {
	setup(t)
	called := false
	ReleaseFn = func(string) { called = true }
	defer func() { ReleaseFn = nil }()

	resp := callTool(t, "release_agent", map[string]interface{}{"agent_id": "a1"})
	if resp.Error == nil {
		t.Fatal("gated tool must be refused when no human can approve it")
	}
	if called {
		t.Fatal("release executed without approval")
	}
}

func TestApproval_HeldUntilApproved(t *testing.T) {
	setup(t)
	setupOperator(t)
	called := false
	ReleaseFn = func(string) { called = true }
	defer func() { ReleaseFn = nil }()

	first := resultMap(t, callTool(t, "release_agent", map[string]interface{}{"agent_id": "a1"}))
	if first["status"] != "approval_required" || called {
		t.Fatalf("expected hold with no side effect, got %v (called=%v)", first, called)
	}
	id := first["approval_id"].(string)

	// Retrying before approval still does nothing.
	again := resultMap(t, callTool(t, "release_agent", map[string]interface{}{"agent_id": "a1", "approval_id": id}))
	if again["status"] != "approval_required" || called {
		t.Fatalf("retry before approval must stay held, got %v", again)
	}
}

func TestApproval_AIBearerTokenCannotApprove(t *testing.T) {
	setup(t)
	setupOperator(t)
	first := resultMap(t, callTool(t, "release_agent", map[string]interface{}{"agent_id": "a1"}))
	id := first["approval_id"].(string)
	if code := decide(t, id, "approve", "test-aegis-token"); code != http.StatusUnauthorized {
		t.Fatalf("the AI's own token must not approve; got %d", code)
	}
}

func TestApproval_BoundToExactArguments(t *testing.T) {
	setup(t)
	setupOperator(t)
	var released string
	ReleaseFn = func(id string) { released = id }
	defer func() { ReleaseFn = nil }()

	first := resultMap(t, callTool(t, "release_agent", map[string]interface{}{"agent_id": "harmless"}))
	id := first["approval_id"].(string)
	decide(t, id, "approve", testOperatorToken)

	resp := callTool(t, "release_agent", map[string]interface{}{"agent_id": "rogue-99", "approval_id": id})
	if resp.Error == nil || released != "" {
		t.Fatalf("approval for one agent must not release another (released=%q)", released)
	}
	resp = callTool(t, "activate_policy", map[string]interface{}{"agent_id": "harmless", "approval_id": id})
	if resp.Error == nil {
		t.Fatal("approval must not transfer to a different tool")
	}
}

func TestApproval_SingleUse(t *testing.T) {
	setup(t)
	count := 0
	ReleaseFn = func(string) { count++ }
	defer func() { ReleaseFn = nil }()

	resp := callWithApproval(t, "release_agent", map[string]interface{}{"agent_id": "a1"})
	if resp.Error != nil || count != 1 {
		t.Fatalf("approved call should execute once: err=%v count=%d", resp.Error, count)
	}
	// Find the consumed id by re-running: any reuse must fail.
	replay := callTool(t, "release_agent", map[string]interface{}{"agent_id": "a1", "approval_id": "apr_reused"})
	if replay.Error == nil || count != 1 {
		t.Fatal("unknown/consumed approval must be rejected")
	}
}

func TestApproval_DeniedAndExpired(t *testing.T) {
	setup(t)
	setupOperator(t)
	called := false
	ReleaseFn = func(string) { called = true }
	defer func() { ReleaseFn = nil }()

	first := resultMap(t, callTool(t, "release_agent", map[string]interface{}{"agent_id": "a1"}))
	id := first["approval_id"].(string)
	decide(t, id, "deny", testOperatorToken)
	if resp := callTool(t, "release_agent", map[string]interface{}{"agent_id": "a1", "approval_id": id}); resp.Error == nil || called {
		t.Fatal("denied action must not execute")
	}

	first = resultMap(t, callTool(t, "release_agent", map[string]interface{}{"agent_id": "a2"}))
	id = first["approval_id"].(string)
	decide(t, id, "approve", testOperatorToken)
	nowFn = func() time.Time { return time.Now().Add(approvalTTL + time.Minute) }
	if resp := callTool(t, "release_agent", map[string]interface{}{"agent_id": "a2", "approval_id": id}); resp.Error == nil || called {
		t.Fatal("expired approval must not execute")
	}
}

func TestApproval_RestrictiveToolsStayImmediate(t *testing.T) {
	setup(t)
	var q string
	QuarantineFn = func(id string) { q = id }
	defer func() { QuarantineFn = nil }()
	resp := callTool(t, "quarantine_agent", map[string]interface{}{"agent_id": "a1", "reason": "test"})
	if resp.Error != nil || q != "a1" {
		t.Fatal("quarantine is protective and must not wait for approval")
	}
}
