// © 2026 Patrick Matthews (Affinity Ops / Affinity Smart AI)
// SPDX-License-Identifier: Apache-2.0

// Package pipeline provides a composable, testable representation of the
// Sentry Gateway's multi-layer admission pipeline.
//
// In production, the pipeline runs inside handleAgentRequest in main.go.
// This package extracts the decision logic from the HTTP handler so each layer
// can be tested independently AND as a composite chain without starting the
// full gateway or requiring PostgreSQL/Redis.
//
// Layer ordering matches main.go handleAgentRequest (lines 549–962):
//   1. Injection scan (prompt injection in outbound body)
//   2. Semantic intent (agent description vs. target URL/method alignment)
//   3. Velocity (adaptive rate limiting with semantic impact multipliers)
//   4. Drift guard (instruction drift analysis — flags context shifts for CIBA)
//   5. Prerequisite (Forward Saga — tool-chain ordering enforcement)
//   6. Tool scope (Atomic Tool Scoping — method-to-facet binding)
//
// Each layer is wrapped in an OpenTelemetry child span that records the
// decision outcome (admitted/blocked), score, and reason. This enables the
// "which layer blocked it, why, and how long did it take?" query in Grafana.
//
// Layers that require live infrastructure (token verification, gossip mesh,
// FGA, OPA, ghost mode) are intentionally excluded — those rely on DB/Redis
// state and are tested via the integration suite in tests/integration_test.go.
package pipeline

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/asai/cicada/sentry/internal/blastradius"
	"github.com/asai/cicada/sentry/internal/drift"
	"github.com/asai/cicada/sentry/internal/hitl"
	"github.com/asai/cicada/sentry/internal/injection"
	"github.com/asai/cicada/sentry/internal/prerequisite"
	"github.com/asai/cicada/sentry/internal/semantic"
	"github.com/asai/cicada/sentry/internal/taint"
	"github.com/asai/cicada/sentry/internal/toolscope"
	"github.com/asai/cicada/sentry/internal/tracing"
	"github.com/asai/cicada/sentry/internal/txprofile"
	"github.com/asai/cicada/sentry/internal/velocity"
)

// Request represents the fields of an inbound proxy call that the admission
// pipeline evaluates. These are extracted from HTTP headers and body in main.go.
type Request struct {
	AgentID          string
	TenantID         string
	AgentDescription string   // from agents.description
	AgentType        string   // from agents.agent_type
	TargetURL        string   // X-Cicada-Target-URL header
	HTTPMethod       string   // upstream method (GET/POST/DELETE etc.)
	Body             string   // raw request body
	Scopes           []string // from session token
	Provenance       string   // X-Cicada-Content-Provenance
	ActionSummary    string   // agent's reasoning trace or action description for drift analysis
	ToolID           string   // X-Cicada-Tool-ID header (for prerequisite checking)

	// PrerequisiteMap maps tool_id → required prerequisite tool_id.
	// Populated from agent_tools table (cached in session token in production).
	// Empty string value = no prerequisite. Missing key = unknown tool.
	PrerequisiteMap map[string]string

	// LedgerCheckFn returns true if the given tool_id has been successfully
	// completed by this agent within the prerequisite window.
	// In production: queries action_ledger. In tests: injected function.
	LedgerCheckFn func(prerequisiteToolID string) bool

	// ToolScopeMap maps tool_id → declared scope (read/write/delete/transact).
	// Populated from agent_tools.tool_scope (cached in session token in production).
	// Empty string value = unrestricted. Missing key = unknown tool.
	ToolScopeMap map[string]string

	// EndpointCriticality is the criticality classification for the target
	// resource/skill ("CRITICAL", "HIGH", "MEDIUM", "LOW"). Defaults to "MEDIUM".
	EndpointCriticality string

	// TxProfile is the agent's historical multivariate transaction profile
	// (loaded from Redis in production; cold-start safe when empty).
	TxProfile txprofile.AgentProfile

	// EAKFEnabled indicates whether the server-side agent or tool manifest
	// mandates Ephemeral Agent Kernel Firewall (eakfd) sandboxing.
	// Never populated from the untrusted client request body.
	EAKFEnabled bool
}

// LayerResult captures one layer's decision and reason.
type LayerResult struct {
	Layer   string  // human-readable layer name
	Blocked bool    // true = this layer would deny the request
	Reason  string  // why
	Score   float64 // risk or alignment score (layer-specific)
}

// PipelineResult captures the composite admission decision.
type PipelineResult struct {
	Admitted        bool                          // true = request passes all blocking layers
	BlockedBy       string                        // name of the first layer that blocked (empty if admitted)
	BlockReason     string                        // reason from the blocking layer
	LayerResults    []LayerResult                 // ordered results from every layer
	DriftDetected   bool                          // true = drift guard flagged a context shift (triggers CIBA)
	DriftReason     string                        // human-readable explanation for the CIBA notification
	DriftScore      float64                       // cosine similarity score (0.0 = total shift, 1.0 = identical)
	ForceCIBA         bool                          // true = any escalation layer (Drift, BlastRadius, DestructiveAction, TxProfile, CaMeL Taint) requires human sign-off
	CIBAReasons       []string                      // aggregated reasons requiring CIBA sign-off
	BlastEstimate     blastradius.Estimate          // Layer 7 blast-radius assessment
	DestructiveAction hitl.DestructiveActionInfo    // Layer 7 destructive action classification
	TxFeatures        txprofile.TransactionFeatures // Layer 8 extracted transaction features
	TxProfileResult txprofile.ProfileResult       // Layer 8 multivariate & deontic rule assessment
	TaintResult     taint.CapabilityResult        // Layer 9 CaMeL session taint assessment
}

// Evaluate runs the request through the local admission layers in order.
// It stops at the first blocking layer (fail-fast) but still records all
// layer evaluations for audit purposes.
//
// Each layer is wrapped in an OpenTelemetry child span. When a TracerProvider
// is configured, every span records:
//   - pipeline.layer:    layer name (e.g. "injection_scan")
//   - pipeline.blocked:  whether this layer blocked the request
//   - pipeline.score:    risk/alignment score (layer-specific)
//   - pipeline.reason:   human-readable decision reason
//   - pipeline.agent_id: the agent being evaluated
//
// Without a TracerProvider, these are no-op spans with zero overhead.
func Evaluate(ctx context.Context, req Request) PipelineResult {
	tracer := tracing.Tracer("pipeline")

	// Parent span wrapping the entire pipeline evaluation.
	ctx, pipelineSpan := tracer.Start(ctx, "pipeline.evaluate",
		trace.WithAttributes(
			attribute.String("pipeline.agent_id", req.AgentID),
			attribute.String("pipeline.tenant_id", req.TenantID),
			attribute.String("pipeline.method", req.HTTPMethod),
			attribute.String("pipeline.target_url", req.TargetURL),
			attribute.String("pipeline.tool_id", req.ToolID),
		),
	)
	defer pipelineSpan.End()

	result := PipelineResult{Admitted: true}

	// ── Layer 1: Prompt Injection Scan ────────────────────────────────────
	if req.Body != "" {
		ctx1, span := tracer.Start(ctx, "pipeline.layer.injection_scan")
		provenance := injection.ParseProvenance(req.Provenance)
		injResult := injection.ScanWithProvenance(req.Body, "", provenance)
		lr := LayerResult{
			Layer:   "injection_scan",
			Blocked: injResult.Block,
			Score:   injResult.Score,
		}
		if injResult.Block {
			lr.Reason = injection.Summary(injResult.Findings)
		}
		setLayerSpanAttributes(span, lr, req.AgentID)
		span.End()
		_ = ctx1 // span context unused beyond this layer

		result.LayerResults = append(result.LayerResults, lr)
		if injResult.Block {
			result.Admitted = false
			result.BlockedBy = "injection_scan"
			result.BlockReason = lr.Reason
			pipelineSpan.SetAttributes(attribute.String("pipeline.blocked_by", "injection_scan"))
			pipelineSpan.SetStatus(codes.Error, "blocked: "+lr.Reason)
			return result
		}
	}

	// ── Layer 2: Semantic Intent Check ────────────────────────────────────
	ctx2, span2 := tracer.Start(ctx, "pipeline.layer.semantic_intent")
	semanticResult := semantic.Check(req.AgentDescription, req.AgentType, req.TargetURL, req.HTTPMethod)
	lr := LayerResult{
		Layer:   "semantic_intent",
		Blocked: semanticResult.Block,
		Score:   semanticResult.Score,
		Reason:  semanticResult.Reason,
	}
	setLayerSpanAttributes(span2, lr, req.AgentID)
	span2.End()
	_ = ctx2

	result.LayerResults = append(result.LayerResults, lr)
	if semanticResult.Block {
		result.Admitted = false
		result.BlockedBy = "semantic_intent"
		result.BlockReason = semanticResult.Reason
		pipelineSpan.SetAttributes(attribute.String("pipeline.blocked_by", "semantic_intent"))
		pipelineSpan.SetStatus(codes.Error, "blocked: "+semanticResult.Reason)
		return result
	}

	// ── Layer 3: Velocity Circuit Breaker (Impact-Weighted) ───────────────
	// CheckWithImpact replaces Check: it computes the semantic impact of the
	// request (bulk URL? large array payload?) and multiplies the Redis counter
	// by that weight. A single bulk-delete costs 100x in the velocity window.
	// Without Redis, falls open (Exceeded=false).
	ctx3, span3 := tracer.Start(ctx, "pipeline.layer.velocity")
	velResult := velocity.CheckWithImpact(ctx3, req.AgentID, req.HTTPMethod, req.TargetURL, req.Body)
	velReason := velResult.CounterType
	if velResult.ImpactMultiplier > 1 {
		velReason = fmt.Sprintf("%s (impact=%dx: %s)", velResult.CounterType, velResult.ImpactMultiplier, velResult.ImpactReason)
	}
	velLayer := LayerResult{
		Layer:   "velocity",
		Blocked: velResult.Exceeded,
		Score:   velResult.ZScore,
		Reason:  velReason,
	}
	setLayerSpanAttributes(span3, velLayer, req.AgentID)
	span3.SetAttributes(attribute.Int64("pipeline.velocity.impact_multiplier", velResult.ImpactMultiplier))
	span3.End()

	result.LayerResults = append(result.LayerResults, velLayer)
	if velResult.Exceeded {
		result.Admitted = false
		result.BlockedBy = "velocity"
		result.BlockReason = "velocity limit exceeded"
		pipelineSpan.SetAttributes(attribute.String("pipeline.blocked_by", "velocity"))
		pipelineSpan.SetStatus(codes.Error, "blocked: velocity limit exceeded")
		return result
	}

	// ── Layer 4: Drift Guard (Instruction Drift Analysis) ────────────────
	// Unlike other layers, drift does NOT block. It detects when an agent's
	// current action diverges from its recent behavioural baseline and flags
	// the request for CIBA escalation. The operator is asked to confirm the
	// "facet switch" before the action proceeds.
	//
	// Why not block: facet switches can be legitimate. A support agent might
	// escalate from reading a record to updating it. The drift guard flags
	// the shift — the human decides.
	ctx4, span4 := tracer.Start(ctx, "pipeline.layer.drift_guard")
	driftResult := drift.Check(ctx4, req.AgentID, req.TargetURL, req.HTTPMethod, req.ActionSummary)
	driftLayer := LayerResult{
		Layer:   "drift_guard",
		Blocked: false, // drift never blocks — it escalates via CIBA
		Score:   driftResult.Similarity,
		Reason:  driftResult.Reason,
	}
	setLayerSpanAttributes(span4, driftLayer, req.AgentID)
	span4.SetAttributes(attribute.Bool("pipeline.drift.detected", driftResult.DriftDetected))
	span4.End()

	result.LayerResults = append(result.LayerResults, driftLayer)
	if driftResult.DriftDetected {
		result.DriftDetected = true
		result.DriftReason = driftResult.Reason
		result.DriftScore = driftResult.Similarity
		result.ForceCIBA = true
		result.CIBAReasons = append(result.CIBAReasons, driftResult.Reason)
	}

	// ── Layer 5: Prerequisite Check (Forward Saga Enforcement) ──────────
	// The "Prerequisite Sieve" queries the action ledger to verify that the
	// agent has completed required prior steps before allowing a destructive
	// tool call. Example: "storage:delete_volume" requires "storage:verify_backup"
	// to have been executed successfully within the last 10 minutes.
	//
	// Fail-closed rule: if the agent has a registered prerequisite/tool manifest
	// (len(req.PrerequisiteMap) > 0 || len(req.ToolScopeMap) > 0) and no declared
	// tool resolved from the request (req.ToolID == "" or not in the manifest),
	// the request is denied rather than skipping Layers 5 and 6.
	if len(req.PrerequisiteMap) > 0 {
		ctx5, span5 := tracer.Start(ctx, "pipeline.layer.prerequisite")
		_, inManifest := req.PrerequisiteMap[req.ToolID]
		var preResult prerequisite.Result
		if req.ToolID == "" || !inManifest {
			preResult = prerequisite.Result{
				Passed: false,
				ToolID: req.ToolID,
				Reason: fmt.Sprintf("UNREGISTERED TOOL: agent has a registered tool manifest, but request (%s %s, tool_id=%q) did not resolve to any declared tool", req.HTTPMethod, req.TargetURL, req.ToolID),
			}
		} else {
			preResult = prerequisite.CheckDeterministic(req.ToolID, req.PrerequisiteMap, req.LedgerCheckFn)
		}
		preLayer := LayerResult{
			Layer:   "prerequisite",
			Blocked: !preResult.Passed,
			Reason:  preResult.Reason,
		}
		setLayerSpanAttributes(span5, preLayer, req.AgentID)
		span5.SetAttributes(attribute.String("pipeline.prerequisite.tool_id", req.ToolID))
		span5.End()
		_ = ctx5

		result.LayerResults = append(result.LayerResults, preLayer)
		if !preResult.Passed {
			blockedBy := "prerequisite"
			if req.ToolID == "" || !inManifest {
				blockedBy = "tool_scope"
			}
			result.Admitted = false
			result.BlockedBy = blockedBy
			result.BlockReason = preResult.Reason
			pipelineSpan.SetAttributes(attribute.String("pipeline.blocked_by", blockedBy))
			pipelineSpan.SetStatus(codes.Error, "blocked: "+preResult.Reason)
			return result
		}
	}

	// ── Layer 6: Tool Scope Enforcement (Atomic Tool Scoping) ───────────
	// Validates that the HTTP method of the request matches the tool's declared
	// scope. A tool scoped to "read" cannot be used in a POST/DELETE. This is
	// the "facet binding" — each personality of a multi-faceted agent is locked
	// to specific HTTP verbs.
	//
	// Why this is separate from semantic intent: semantic checks whether the
	// call makes sense for the agent's purpose. Tool scope checks whether the
	// specific tool is allowed to use this HTTP method.
	if len(req.ToolScopeMap) > 0 {
		ctx6, span6 := tracer.Start(ctx, "pipeline.layer.tool_scope")
		scope, inScopeManifest := req.ToolScopeMap[req.ToolID]
		var scopeResult toolscope.Result
		if req.ToolID == "" || !inScopeManifest {
			scopeResult = toolscope.Result{
				Passed:     false,
				ToolID:     req.ToolID,
				HTTPMethod: req.HTTPMethod,
				Reason:     fmt.Sprintf("UNREGISTERED TOOL: agent has a registered tool scope manifest, but request (%s %s, tool_id=%q) did not resolve to any declared tool", req.HTTPMethod, req.TargetURL, req.ToolID),
			}
		} else {
			scopeResult = toolscope.Check(req.ToolID, scope, req.HTTPMethod)
		}
		scopeLayer := LayerResult{
			Layer:   "tool_scope",
			Blocked: !scopeResult.Passed,
			Reason:  scopeResult.Reason,
		}
		setLayerSpanAttributes(span6, scopeLayer, req.AgentID)
		span6.SetAttributes(
			attribute.String("pipeline.tool_scope.declared", scope),
			attribute.String("pipeline.tool_scope.tool_id", req.ToolID),
		)
		span6.End()
		_ = ctx6

		result.LayerResults = append(result.LayerResults, scopeLayer)
		if !scopeResult.Passed {
			result.Admitted = false
			result.BlockedBy = "tool_scope"
			result.BlockReason = scopeResult.Reason
			pipelineSpan.SetAttributes(attribute.String("pipeline.blocked_by", "tool_scope"))
			pipelineSpan.SetStatus(codes.Error, "blocked: "+scopeResult.Reason)
			return result
		}
	}

	// ── Layer 7: Blast-Radius Estimation (Pre-Execution Impact Analysis) ─
	// Inspects destructive payloads (unbounded SQL WHERE 1=1 / DELETE without
	// WHERE, destructive shell commands rm -rf, bulk API flags, large JSON
	// arrays, CRITICAL endpoint tags) and forces CIBA human approval when the
	// single-shot blast radius is high.
	ctx7, span7 := tracer.Start(ctx, "pipeline.layer.blast_radius")
	blastEst := blastradius.Analyze(req.EndpointCriticality, req.HTTPMethod, req.Body, req.TargetURL)
	destructiveInfo := hitl.ClassifyDestructiveAction(req.HTTPMethod, req.TargetURL, req.Body)
	if destructiveInfo.IsDestructive && (destructiveInfo.Severity == "critical" || destructiveInfo.Severity == "high") {
		blastEst.ForceCIBA = true
		if blastEst.Score < 0.75 {
			blastEst.Score = 0.75
		}
	}
	blastLayer := LayerResult{
		Layer:   "blast_radius",
		Blocked: false,
		Score:   blastEst.Score,
		Reason:  blastEst.Summary,
	}
	setLayerSpanAttributes(span7, blastLayer, req.AgentID)
	span7.SetAttributes(
		attribute.Bool("pipeline.blast_radius.force_ciba", blastEst.ForceCIBA),
		attribute.Int("pipeline.blast_radius.estimated_records", blastEst.EstimatedRecords),
		attribute.Bool("pipeline.destructive_action.detected", destructiveInfo.IsDestructive),
		attribute.String("pipeline.destructive_action.type", destructiveInfo.ActionType),
	)
	span7.End()
	_ = ctx7

	result.BlastEstimate = blastEst
	result.DestructiveAction = destructiveInfo
	result.LayerResults = append(result.LayerResults, blastLayer)
	if blastEst.ForceCIBA {
		result.ForceCIBA = true
		if destructiveInfo.IsDestructive {
			result.CIBAReasons = append(result.CIBAReasons, fmt.Sprintf("%s (%s: %s)", blastEst.Summary, destructiveInfo.ActionType, destructiveInfo.ActionDescription))
		} else {
			result.CIBAReasons = append(result.CIBAReasons, blastEst.Summary)
		}
	}

	// ── Layer 8: Multivariate Transaction Profiling & Deontic Never-Rules ─
	// Defends against business-aligned semantic manipulation ("ultrathink"
	// attacks) by extracting structured transaction features (RecipientID,
	// Amount, Currency, ActionType) and evaluating deterministic Deontic
	// Never-Rules + historical z-score/new-entity anomalies.
	ctx8, span8 := tracer.Start(ctx, "pipeline.layer.tx_profile")
	txFeatures := txprofile.ExtractFeatures(req.Body, req.TargetURL, req.HTTPMethod)
	txRes := txprofile.Analyze(txFeatures, req.TxProfile)
	txLayer := LayerResult{
		Layer:   "tx_profile",
		Blocked: false,
		Score:   txRes.AnomalyScore,
		Reason:  txRes.Summary,
	}
	setLayerSpanAttributes(span8, txLayer, req.AgentID)
	span8.SetAttributes(
		attribute.Bool("pipeline.tx_profile.force_ciba", txRes.ForceCIBA),
		attribute.String("pipeline.tx_profile.deontic_violation", txRes.DeonticViolation),
		attribute.Float64("pipeline.tx_profile.amount", txFeatures.Amount),
		attribute.String("pipeline.tx_profile.recipient", txFeatures.RecipientID),
	)
	span8.End()
	_ = ctx8

	result.TxFeatures = txFeatures
	result.TxProfileResult = txRes
	result.LayerResults = append(result.LayerResults, txLayer)
	if txRes.ForceCIBA {
		result.ForceCIBA = true
		result.CIBAReasons = append(result.CIBAReasons, txRes.Summary)
	}

	// ── Layer 9: CaMeL Session Taint & Capability Enforcement ─────────────
	// Enforces information-flow capability restrictions: if the agent session
	// previously ingested untrusted content (via /v1/llm/proxy tool_result,
	// retrieved RAG context, or external GET), any state-mutating request
	// (POST/PUT/PATCH/DELETE) is escalated to CIBA regardless of semantic score.
	ctx9, span9 := tracer.Start(ctx, "pipeline.layer.camel_taint")
	taintRes := taint.CheckCapability(ctx9, req.AgentID, req.HTTPMethod, req.TargetURL, req.Provenance)
	var taintScore float64
	if taintRes.ForceCIBA {
		taintScore = 1.0
	} else if taintRes.Tainted {
		taintScore = 0.5
	}
	taintLayer := LayerResult{
		Layer:   "camel_taint",
		Blocked: false,
		Score:   taintScore,
		Reason:  taintRes.Reason,
	}
	setLayerSpanAttributes(span9, taintLayer, req.AgentID)
	span9.SetAttributes(
		attribute.Bool("pipeline.camel_taint.tainted", taintRes.Tainted),
		attribute.Bool("pipeline.camel_taint.force_ciba", taintRes.ForceCIBA),
	)
	span9.End()

	result.TaintResult = taintRes
	result.LayerResults = append(result.LayerResults, taintLayer)
	if taintRes.ForceCIBA {
		result.ForceCIBA = true
		result.CIBAReasons = append(result.CIBAReasons, taintRes.Reason)
	}

	// All layers passed.
	pipelineSpan.SetAttributes(
		attribute.Bool("pipeline.admitted", true),
		attribute.Bool("pipeline.force_ciba", result.ForceCIBA),
	)
	pipelineSpan.SetStatus(codes.Ok, "admitted")
	return result
}

// setLayerSpanAttributes records the standard pipeline telemetry attributes on
// a layer's child span. Called by every layer after evaluation.
func setLayerSpanAttributes(span trace.Span, lr LayerResult, agentID string) {
	span.SetAttributes(
		attribute.String("pipeline.layer", lr.Layer),
		attribute.Bool("pipeline.blocked", lr.Blocked),
		attribute.Float64("pipeline.score", lr.Score),
		attribute.String("pipeline.reason", lr.Reason),
		attribute.String("pipeline.agent_id", agentID),
	)
	if lr.Blocked {
		span.SetStatus(codes.Error, "blocked: "+lr.Reason)
	}
}

