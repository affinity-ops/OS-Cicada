// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package plugin provides the extension boundary for optional execution-plane
// plugins in the Sentry Gateway.
//
// The gateway's admission pipeline (internal/pipeline) handles network-layer
// enforcement. Plugins extend enforcement into the compute plane — for example,
// the EAKF plugin sandboxes code execution in ephemeral microVMs.
//
// This package defines:
//   - Interceptor: the abstract plugin contract (§4, lines 114–134 of
//     EPHEMERAL_AGENT_KERNEL_FIREWALL.md)
//   - Result: the structured outcome returned by interceptors
//   - PluginManager: the registry and health-monitoring surface
//
// Plugins are dynamically registered at gateway boot based on the
// CICADA_PLUGINS environment variable. No compile-time dependencies on
// plugin implementations exist in the gateway core.
package plugin

import (
	"context"

	"github.com/asai/cicada/sentry/internal/pipeline"
)

// Interceptor defines the contract for optional execution-plane plugins.
//
// The interface is intentionally small (three methods). Health checking is
// the PluginManager's responsibility, not the interceptor's — the manager
// probes the underlying connection and exposes health state through
// GetInterceptor's error return.
//
// Source: EPHEMERAL_AGENT_KERNEL_FIREWALL.md §4, lines 114–127.
type Interceptor interface {
	// Name returns the unique identifier of the plugin (e.g. "eakf").
	Name() string

	// EventFilter evaluates whether the request matches the plugin's trigger
	// criteria (e.g., matching a target URL like "/v1/tools/execute_code" or
	// checking if the agent's policy has requested sandboxed compute).
	EventFilter(req pipeline.Request) bool

	// Intercept handles the execution flow. For EAKF, this delegates execution
	// to the gRPC daemon socket and returns a structured result.
	Intercept(ctx context.Context, req pipeline.Request) (Result, error)
}

// Result captures the outcome of an interceptor's execution.
//
// Source: EPHEMERAL_AGENT_KERNEL_FIREWALL.md §4, lines 128–134.
type Result struct {
	// Handled is true if the interceptor processed the request, regardless of
	// whether it succeeded or failed. False means the interceptor declined to
	// handle the request (e.g. EventFilter returned true but the payload was
	// not a valid execution request).
	Handled bool

	// Blocked is true if the interceptor determined the request should be
	// denied. For EAKF, this is set when the execution status is FAILED,
	// TIMEOUT, or PARTIAL_APPLY.
	Blocked bool

	// Reason provides a human-readable explanation for the decision.
	Reason string

	// Stdout contains the sanitised standard output from the sandboxed
	// execution, with credentials, state maps, and private IPs stripped.
	Stdout string

	// Stderr contains the sanitised standard error from the sandboxed execution.
	Stderr string
}
