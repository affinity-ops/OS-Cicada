// © 2026 Affinity Ops Ltd.
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/open-policy-agent/opa/rego"
)

// Default embedded policy evaluating basic agent scope rights and spend limits.
const defaultPolicy = `
package cicada.agent.authz

default allow = false

# Allow if the target action matches the agent's EVAR allowed scopes
allow {
    some i
    input.evar_scopes[i] == input.action_scope
    not is_blacklisted
    not is_over_budget
}

is_blacklisted {
    input.agent_status == "revoked"
}

is_over_budget {
    input.action_cost + input.current_spend > input.spend_limit
}
`

// Engine encapsulates the prepared OPA Rego query for lightning fast evaluations
type Engine struct {
	mu    sync.RWMutex
	query rego.PreparedEvalQuery
}

// NewEngine initializes the OPA policy natively in-memory to prevent network overhead.
// When regoContent is empty, it falls back to the embedded defaultPolicy.
func NewEngine(ctx context.Context, regoContent string) (*Engine, error) {
	if regoContent == "" {
		regoContent = defaultPolicy
	}
	query, err := compileRego(ctx, regoContent)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare OPA Rego query: %w", err)
	}

	return &Engine{query: query}, nil
}

// RefreshEngine compiles a new policy and hot-swaps it atomically
func (e *Engine) RefreshEngine(ctx context.Context, regoContent string) error {
	query, err := compileRego(ctx, regoContent)
	if err != nil {
		return fmt.Errorf("failed to prepare OPA Rego query during refresh: %w", err)
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	e.query = query
	return nil
}

// compileRego encapsulates the OPA compilation logic
func compileRego(ctx context.Context, content string) (rego.PreparedEvalQuery, error) {
	return rego.New(
		rego.Query("data.cicada.agent.authz.allow"),
		rego.Module("authz.rego", content),
	).PrepareForEval(ctx)
}

// Evaluate runs the incoming payload against the embedded Rego policy
// Expected sub-1ms execution time.
func (e *Engine) Evaluate(ctx context.Context, input map[string]interface{}) (bool, error) {
	e.mu.RLock()
	query := e.query
	e.mu.RUnlock()

	results, err := query.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return false, fmt.Errorf("policy evaluation error: %w", err)
	}

	if len(results) == 0 {
		return false, errors.New("policy evaluation yielded no results")
	}

	allowed, ok := results[0].Expressions[0].Value.(bool)
	if !ok {
		return false, errors.New("policy returned non-boolean result")
	}

	return allowed, nil
}
