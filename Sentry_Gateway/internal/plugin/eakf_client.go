// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/asai/cicada/sentry/internal/ciba"
	"github.com/asai/cicada/sentry/internal/output"
	"github.com/asai/cicada/sentry/internal/pipeline"
	eakfv1 "github.com/asai/cicada/sentry/pkg/eakf/v1"
	"google.golang.org/grpc"
)

// codeExecEndpoint is the tool execution URL path that triggers EAKF
// interception. Matches the interception point defined in the blueprint.
//
// Source: EPHEMERAL_AGENT_KERNEL_FIREWALL.md §3.1, line 80 —
// "POST /v1/tools/execute_code".
const codeExecEndpoint = "/v1/tools/execute_code"

// policyManifestField is the JSON key within the agent's session token
// or request metadata that carries the EAKF enablement flag.
const policyManifestField = "eakf_enabled"

// EAKFClient implements the Interceptor interface as a thin gRPC client
// wrapping the generated proto stubs for the eakfd daemon.
//
// Source: EPHEMERAL_AGENT_KERNEL_FIREWALL.md §7.4, lines 286–290 —
// Option A: Decoupled gRPC Service Daemon (recommended).
type EAKFClient struct {
	client eakfv1.EphemeralAgentKernelFirewallClient
}

// NewEAKFClient creates a new EAKF interceptor from an existing gRPC
// connection. The connection is managed by PluginManager and shared
// across the interceptor's lifetime.
func NewEAKFClient(conn *grpc.ClientConn) *EAKFClient {
	return &EAKFClient{
		client: eakfv1.NewEphemeralAgentKernelFirewallClient(conn),
	}
}

// Name returns "eakf" — the plugin identifier used for registry lookup
// and CICADA_PLUGINS matching.
func (c *EAKFClient) Name() string {
	return "eakf"
}

// EventFilter determines whether a request should be routed to EAKF.
//
// Returns true when BOTH conditions are met:
//   1. The request targets the code execution endpoint (POST /v1/tools/execute_code).
//   2. The agent's policy manifest declares eakf_enabled: true.
//
// The OPA pre-check at Layer 4e determines sandbox escalation before
// EventFilter is called — EventFilter is the plugin's own secondary
// confirmation, not a replacement for OPA.
//
// Source: §3.1, line 80 and §4, lines 119–121.
func (c *EAKFClient) EventFilter(req pipeline.Request) bool {
	// Condition 1: target URL matches code execution endpoint.
	if !strings.HasSuffix(req.TargetURL, codeExecEndpoint) {
		return false
	}

	// Condition 2: agent policy requests sandboxed execution.
	// The agent's body may carry the policy manifest inline for tool
	// execution requests. Parse and check for eakf_enabled flag.
	if req.Body == "" {
		return false
	}

	var manifest struct {
		EAKFEnabled bool `json:"eakf_enabled"`
	}
	if err := json.Unmarshal([]byte(req.Body), &manifest); err != nil {
		return false
	}

	return manifest.EAKFEnabled
}

// Intercept delegates the code execution request to eakfd over gRPC,
// translating pipeline.Request to ExecuteRequest and ExecuteResponse
// back to Result.
//
// After receiving the response, Intercept inspects the execution outcome
// and dispatches the appropriate threat alerts:
//   - eakf_redaction_alert: when redacted_keys or redacted_ips are non-empty (§7.7A, line 408)
//   - eakf_policy_violation: when execution_success is false (§7.7A, line 407)
//   - STATUS_PARTIAL_APPLY: triggers CIBA saga recovery (§7.7B, lines 411–418)
//
// Source: §4, lines 163–178 (sequence diagram, happy path).
func (c *EAKFClient) Intercept(ctx context.Context, req pipeline.Request) (Result, error) {
	// Build the ExecuteRequest from pipeline.Request fields.
	execReq := c.buildExecuteRequest(req)

	// Call eakfd over the persistent UDS connection.
	resp, err := c.client.Execute(ctx, execReq)
	if err != nil {
		log.Printf("[EAKF] gRPC Execute call failed for agent=%s: %v", req.AgentID, err)
		return Result{
			Handled: true,
			Blocked: true,
			Reason:  fmt.Sprintf("eakfd execution failed: %v", err),
		}, err
	}

	// Dispatch telemetry alerts based on response content.
	c.dispatchAlerts(req, resp)

	// Handle CIBA saga recovery for partial applies (§7.7B).
	if resp.Status == eakfv1.ExecuteResponse_STATUS_PARTIAL_APPLY {
		c.handlePartialApply(ctx, req, resp)
	}

	// Map ExecuteResponse to Result.
	result := Result{
		Handled: true,
		Blocked: isBlockedStatus(resp.Status),
		Reason:  formatReason(resp),
		Stdout:  resp.SanitizedStdout,
		Stderr:  resp.SanitizedStderr,
	}

	log.Printf("[EAKF] Execution complete for saga=%s agent=%s: status=%s exit_code=%d redacted_keys=%d redacted_ips=%d",
		resp.SagaId, req.AgentID, resp.Status.String(), resp.ExitCode,
		len(resp.RedactedKeys), len(resp.RedactedIps))

	return result, nil
}

// buildExecuteRequest translates a pipeline.Request into a protobuf
// ExecuteRequest. Fields are mapped from the agent's body payload and
// policy metadata.
func (c *EAKFClient) buildExecuteRequest(req pipeline.Request) *eakfv1.ExecuteRequest {
	// Parse the request body for execution-specific fields.
	var body struct {
		SagaID              string   `json:"saga_id"`
		Payload             string   `json:"payload"`
		RuntimeHint         string   `json:"runtime_hint"`
		TimeoutSeconds      int32    `json:"timeout_seconds"`
		MaxMemoryMB         int32    `json:"max_memory_mb"`
		MaxCPUs             int32    `json:"max_cpus"`
		AllowedEgressDomains []string `json:"allowed_egress_domains"`
		AllowedInfraScopes  []string `json:"allowed_infra_scopes"`
	}
	json.Unmarshal([]byte(req.Body), &body)

	// Defaults for omitted fields.
	if body.TimeoutSeconds <= 0 {
		body.TimeoutSeconds = 5 // Sync fast-path default (§3.5, line 92)
	}
	if body.MaxMemoryMB <= 0 {
		body.MaxMemoryMB = 512
	}
	if body.MaxCPUs <= 0 {
		body.MaxCPUs = 1
	}

	return &eakfv1.ExecuteRequest{
		SagaId:               body.SagaID,
		AgentId:              req.AgentID,
		TenantId:             req.TenantID,
		Payload:              body.Payload,
		RuntimeHint:          body.RuntimeHint,
		TimeoutSeconds:       body.TimeoutSeconds,
		MaxMemoryMb:          body.MaxMemoryMB,
		MaxCpus:              body.MaxCPUs,
		AllowedEgressDomains: body.AllowedEgressDomains,
		AllowedInfraScopes:   body.AllowedInfraScopes,
		PolicyManifestJson:   []byte(req.Body), // Full body as opaque manifest (§7.5, line 338)
	}
}

// dispatchAlerts inspects the ExecuteResponse and emits the appropriate
// threat alerts through the gateway's core auditing pipeline.
//
// Source: §7.7A, lines 406–409 — "The Sentry Gateway catches this response
// and automatically dispatches a structured JSON alert event
// (eakf_policy_violation or eakf_redaction_alert) to the Core API via
// internal/output/threat_alert.go."
func (c *EAKFClient) dispatchAlerts(req pipeline.Request, resp *eakfv1.ExecuteResponse) {
	// Alert 1: Redaction telemetry — secrets, state maps, or private IPs were scrubbed.
	if len(resp.RedactedKeys) > 0 || len(resp.RedactedIps) > 0 {
		summary := fmt.Sprintf("EAKF scrubbing engine redacted %d keys and %d private IPs from execution output (saga=%s)",
			len(resp.RedactedKeys), len(resp.RedactedIps), resp.SagaId)

		go output.EmitThreatAlert(
			"eakf_redaction_alert",
			"medium",
			req.TenantID,
			req.AgentID,
			req.TargetURL,
			summary,
			"Review redacted content in EAKF telemetry logs",
			"", // traceID populated by gateway request context
			map[string]any{},
		)

		log.Printf("[EAKF] Redaction alert dispatched: %s", summary)
	}

	// Alert 2: Policy violation — execution failed due to sandbox policy breach.
	if !resp.ExecutionSuccess {
		severity := "high"
		if resp.Status == eakfv1.ExecuteResponse_STATUS_PARTIAL_APPLY {
			severity = "critical"
		}

		summary := fmt.Sprintf("EAKF execution failed: status=%s exit_code=%d (saga=%s)",
			resp.Status.String(), resp.ExitCode, resp.SagaId)

		go output.EmitThreatAlert(
			"eakf_policy_violation",
			severity,
			req.TenantID,
			req.AgentID,
			req.TargetURL,
			summary,
			"Investigate execution failure and review agent policy manifest",
			"",
			map[string]any{},
		)

		log.Printf("[EAKF] Policy violation alert dispatched: %s", summary)
	}
}

// handlePartialApply initiates the CIBA saga recovery flow for executions
// that terminated mid-apply (e.g., a Terraform apply that created some
// resources but crashed before completion).
//
// The four-step recovery flow (§7.7B, lines 411–418):
//   1. Lock remote state (S3 or Consul) — handled by eakfd before returning STATUS_PARTIAL_APPLY
//   2. Create a pending recovery Saga
//   3. Send emergency Aegis CIBA notification to operator mobile devices
//   4. Operator authorises rollback or release (or 120s timeout → fail-closed)
func (c *EAKFClient) handlePartialApply(ctx context.Context, req pipeline.Request, resp *eakfv1.ExecuteResponse) {
	log.Printf("[EAKF] STATUS_PARTIAL_APPLY detected for saga=%s agent=%s — initiating CIBA recovery",
		resp.SagaId, req.AgentID)

	// Step 1: Remote state locking is performed by eakfd before it returns
	// STATUS_PARTIAL_APPLY. The lock is held until the operator responds.

	// Steps 2–3: Dispatch CIBA notification for human-in-the-loop recovery.
	// The operator reviews stdout/stderr and authorises either:
	//   - Rollback (Destroy): gateway calls eakfd → new sandbox → terraform destroy
	//   - Operational Release (Override): gateway releases lock, manual CLI recovery
	//
	// Source: §7.7B, line 418 — "default: 120s" CIBA timeout.
	cibaReq := ciba.Request{
		TraceID:   resp.SagaId,
		AgentID:   req.AgentID,
		TenantID:  req.TenantID,
		ActionSummary: fmt.Sprintf(
			"EAKF PARTIAL APPLY: Execution saga %s terminated mid-apply. "+
				"Infrastructure state may be inconsistent. Remote state lock is held. "+
				"Approve ROLLBACK (terraform destroy in new sandbox) or RELEASE (manual CLI recovery).",
			resp.SagaId,
		),
		PayloadPreview: truncateForPreview(resp.SanitizedStdout, 500),
		RiskScore:      1.0, // Maximum risk — partial infrastructure state
		RiskReason:     "STATUS_PARTIAL_APPLY: infrastructure mutation incomplete, state lock held",
		TimeoutSeconds: 120, // §7.7B, line 418
	}

	// CIBA runs synchronously — the recovery flow blocks until the operator
	// responds or the timeout expires.
	cibaResult := ciba.Authorize(ctx, cibaReq)

	switch cibaResult.Status {
	case "approved":
		log.Printf("[EAKF] CIBA APPROVED rollback for saga=%s by %s — initiating destroy",
			resp.SagaId, cibaResult.RespondedBy)
		// The gateway would call eakfd.Execute() again with a destroy payload
		// in a new sandbox. This is orchestrated by the saga executor in
		// production — for now we log the approval and the saga executor
		// picks up the pending recovery saga from the database.

	case "denied":
		log.Printf("[EAKF] CIBA DENIED rollback for saga=%s by %s — releasing to manual recovery",
			resp.SagaId, cibaResult.RespondedBy)
		// Operator chose manual CLI recovery. Release the state lock
		// marker and allow the DevOps team to handle it directly.

	case "expired":
		// §7.7B, line 418: "the lock remains held, and all subsequent
		// execution calls are blocked until manual resolution."
		log.Printf("[EAKF] CIBA TIMEOUT for saga=%s — fail-closed, state lock held",
			resp.SagaId)

		go output.EmitThreatAlert(
			"eakf_policy_violation",
			"critical",
			req.TenantID,
			req.AgentID,
			"",
			fmt.Sprintf("CIBA timeout on PARTIAL_APPLY recovery (saga=%s). "+
				"State lock held. All subsequent execution blocked until manual resolution.", resp.SagaId),
			"IMMEDIATE: Manual DevOps intervention required to resolve state lock",
			resp.SagaId,
			map[string]any{},
		)

	default:
		log.Printf("[EAKF] CIBA error for saga=%s: status=%s err=%v",
			resp.SagaId, cibaResult.Status, cibaResult.Err)
	}
}

// isBlockedStatus returns true for execution statuses that should block the
// agent from receiving the result and continuing its reasoning loop.
func isBlockedStatus(status eakfv1.ExecuteResponse_Status) bool {
	switch status {
	case eakfv1.ExecuteResponse_STATUS_FAILED,
		eakfv1.ExecuteResponse_STATUS_TIMEOUT,
		eakfv1.ExecuteResponse_STATUS_PARTIAL_APPLY:
		return true
	default:
		return false
	}
}

// formatReason produces a human-readable reason string from an ExecuteResponse.
func formatReason(resp *eakfv1.ExecuteResponse) string {
	switch resp.Status {
	case eakfv1.ExecuteResponse_STATUS_SUCCESS:
		return "execution completed successfully"
	case eakfv1.ExecuteResponse_STATUS_FAILED:
		return fmt.Sprintf("execution failed with exit code %d", resp.ExitCode)
	case eakfv1.ExecuteResponse_STATUS_PARTIAL_APPLY:
		return fmt.Sprintf("partial apply — infrastructure state inconsistent (exit code %d)", resp.ExitCode)
	case eakfv1.ExecuteResponse_STATUS_TIMEOUT:
		return "execution exceeded timeout limit"
	default:
		return "unspecified execution status"
	}
}

// truncateForPreview truncates a string to maxLen characters for CIBA
// payload previews, appending an ellipsis if truncated.
func truncateForPreview(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
