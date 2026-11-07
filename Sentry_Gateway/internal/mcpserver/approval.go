// Copyright 2026 Patrick Matthews and Affinity Ops Ltd.
// SPDX-License-Identifier: Apache-2.0

package mcpserver

// Server-side human approval for privileged MCP control tools.
//
// The MCP bearer token (CICADA_AEGIS_TOKEN) is held by an AI operator agent
// (Aegis-0). Previously, "require HITL confirmation" was only text in the tool
// description, so a manipulated or mistaken model could release a quarantined
// agent or activate a policy on its own. Now:
//
//  1. A call to a gated tool without a valid approval_id does nothing and
//     returns {"status":"approval_required","approval_id":...}.
//  2. A human approves it with a DIFFERENT credential,
//     CICADA_OPERATOR_APPROVAL_TOKEN, via POST /v1/mcp/approvals/decide.
//     The AI never holds this token.
//  3. The AI retries the identical call with arguments.approval_id. The
//     approval is single-use, expires, and is bound to the exact tool name and
//     arguments (SHA-256 of the canonical JSON), so it cannot be reused for a
//     different agent or policy.
//
// If CICADA_OPERATOR_APPROVAL_TOKEN is not set, gated tools are refused
// outright (fail closed).
//
// Approvals are held in memory on the node that issued them. In a multi-node
// deployment, route the retry to the same node (or approve on that node).

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// gatedTools loosen security controls or act on external systems.
var gatedTools = map[string]bool{
	"release_agent":      true,
	"release_ghost_mode": true,
	"trigger_rollback":   true,
	"activate_policy":    true,
}

// IsGatedTool reports whether a tool requires out-of-band human approval.
func IsGatedTool(name string) bool { return gatedTools[name] }

const approvalTTL = 10 * time.Minute

type approval struct {
	ID        string    `json:"approval_id"`
	Tool      string    `json:"tool"`
	Arguments any       `json:"arguments"`
	ArgsHash  string    `json:"args_hash"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Status    string    `json:"status"` // pending | approved | denied
	DecidedBy string    `json:"decided_by,omitempty"`
}

var (
	approvalsMu sync.Mutex
	approvals   = map[string]*approval{}
	nowFn       = time.Now
)

func operatorToken() string { return os.Getenv("CICADA_OPERATOR_APPROVAL_TOKEN") }

// argsHash binds an approval to the exact tool + arguments. approval_id itself
// is excluded. json.Marshal sorts map keys, so the encoding is canonical.
func argsHash(tool string, args map[string]interface{}) string {
	clean := make(map[string]interface{}, len(args))
	for k, v := range args {
		if k != "approval_id" {
			clean[k] = v
		}
	}
	b, _ := json.Marshal(clean)
	sum := sha256.Sum256(append([]byte(tool+"\x00"), b...))
	return hex.EncodeToString(sum[:])
}

func newApprovalID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return "apr_" + hex.EncodeToString(b)
}

func pruneLocked(now time.Time) {
	for id, a := range approvals {
		if now.After(a.ExpiresAt) {
			delete(approvals, id)
		}
	}
}

// checkApproval returns ("", nil) when the call may proceed (and consumes the
// approval). Otherwise it returns a pending approval ID to hand back to the
// caller, or a refusal message.
func checkApproval(tool string, args map[string]interface{}) (pendingID string, refusal string) {
	if operatorToken() == "" {
		return "", "privileged tool refused: CICADA_OPERATOR_APPROVAL_TOKEN is not configured, so no human can approve it"
	}
	hash := argsHash(tool, args)
	now := nowFn()

	approvalsMu.Lock()
	defer approvalsMu.Unlock()
	pruneLocked(now)

	if id, _ := args["approval_id"].(string); id != "" {
		a, ok := approvals[id]
		switch {
		case !ok:
			return "", "approval_id unknown or expired"
		case a.Tool != tool || a.ArgsHash != hash:
			return "", "approval_id was issued for a different tool call; arguments must match exactly"
		case a.Status == "denied":
			delete(approvals, id)
			return "", "operator denied this action"
		case a.Status != "approved":
			return a.ID, ""
		}
		delete(approvals, id) // single use
		return "", ""
	}

	a := &approval{
		ID: newApprovalID(), Tool: tool, Arguments: args, ArgsHash: hash,
		CreatedAt: now, ExpiresAt: now.Add(approvalTTL), Status: "pending",
	}
	approvals[a.ID] = a
	return a.ID, ""
}

func operatorAuthorized(r *http.Request) bool {
	want := operatorToken()
	got := r.Header.Get("X-Cicada-Operator-Token")
	return want != "" && subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// ApprovalsHandler serves the human side of the approval flow:
//
//	GET  /v1/mcp/approvals         list pending approvals (tool + arguments)
//	POST /v1/mcp/approvals/decide  {"approval_id":"...","decision":"approve"|"deny","operator":"name"}
//
// Both require X-Cicada-Operator-Token: <CICADA_OPERATOR_APPROVAL_TOKEN>.
func ApprovalsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if !operatorAuthorized(r) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"operator approval token required"}`))
			return
		}
		approvalsMu.Lock()
		defer approvalsMu.Unlock()
		pruneLocked(nowFn())

		if r.Method == http.MethodGet {
			out := []*approval{}
			for _, a := range approvals {
				if a.Status == "pending" {
					out = append(out, a)
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"pending": out})
			return
		}

		var body struct {
			ApprovalID string `json:"approval_id"`
			Decision   string `json:"decision"`
			Operator   string `json:"operator"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid JSON"}`))
			return
		}
		a, ok := approvals[body.ApprovalID]
		if !ok || a.Status != "pending" {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"no pending approval with that id"}`))
			return
		}
		switch strings.ToLower(body.Decision) {
		case "approve":
			a.Status = "approved"
		case "deny":
			a.Status = "denied"
		default:
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"decision must be approve or deny"}`))
			return
		}
		a.DecidedBy = body.Operator
		_ = json.NewEncoder(w).Encode(a)
	}
}
