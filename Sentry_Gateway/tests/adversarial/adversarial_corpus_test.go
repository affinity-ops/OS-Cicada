// © 2026 Patrick Matthews (Affinity Ops / Affinity Smart AI)
// SPDX-License-Identifier: Apache-2.0

// Package adversarial provides a reproducible, checkable adversarial benchmark
// suite that evaluates Cicada's multi-layer enforcement engines against the
// published attack corpus in corpus.json.
package adversarial

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/asai/cicada/sentry/internal/canary"
	"github.com/asai/cicada/sentry/internal/pipeline"
	"github.com/asai/cicada/sentry/internal/ssrf"
	"github.com/asai/cicada/sentry/internal/taint"
)

type CorpusCase struct {
	ID                  string `json:"id"`
	Category            string `json:"category"`
	Description         string `json:"description"`
	Method              string `json:"method"`
	TargetURL           string `json:"target_url"`
	AgentDescription    string `json:"agent_description"`
	AgentType           string `json:"agent_type"`
	Body                string `json:"body"`
	Provenance          string `json:"provenance"`
	ExpectBlocked       bool   `json:"expect_blocked"`
	ExpectLayer         string `json:"expect_layer"`
	ExpectForceCIBA     bool   `json:"expect_force_ciba"`
	ExpectSSRFBlock     bool   `json:"expect_ssrf_block"`
	ExpectCanaryTrigger bool   `json:"expect_canary_trigger"`
}

func TestAdversarialCorpus(t *testing.T) {
	t.Setenv("CICADA_SIMULATION_MODE", "true")
	t.Setenv("CICADA_DEV_MODE", "true")

	raw, err := os.ReadFile("corpus.json")
	if err != nil {
		t.Fatalf("failed to read corpus.json: %v", err)
	}

	var cases []CorpusCase
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatalf("failed to parse corpus.json: %v", err)
	}
	if len(cases) < 20 {
		t.Fatalf("expected at least 20 adversarial/control cases in corpus.json, got %d", len(cases))
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.ID+"_"+tc.Category, func(t *testing.T) {
			ctx := context.Background()
			agentID := "adv-bench-" + tc.ID
			defer taint.ClearTaint(ctx, agentID)

			if tc.ExpectSSRFBlock {
				err := ssrf.ValidateOutboundURL(tc.TargetURL, nil)
				if err == nil {
					t.Fatalf("[%s] expected SSRF guard to block %q, but it was allowed", tc.ID, tc.TargetURL)
				}
				return
			}

			if tc.ExpectCanaryTrigger {
				found, matched := canary.ContainsCanaryToken(tc.Body)
				if !found || matched == "" {
					t.Fatalf("[%s] expected canary honeytoken trigger on body %q, got found=%v", tc.ID, tc.Body, found)
				}
				return
			}

			desc := tc.AgentDescription
			if desc == "" {
				desc = "General operations agent for API workflows, database queries, storage, and billing"
			}
			aType := tc.AgentType
			if aType == "" {
				aType = "general"
			}

			res := pipeline.Evaluate(ctx, pipeline.Request{
				AgentID:          agentID,
				TenantID:         "tenant-bench",
				AgentDescription: desc,
				AgentType:        aType,
				TargetURL:        tc.TargetURL,
				HTTPMethod:       tc.Method,
				Body:             tc.Body,
				Provenance:       tc.Provenance,
			})

			if tc.ExpectBlocked {
				if res.Admitted {
					t.Fatalf("[%s] (%s) expected request to be BLOCKED by %q, but it was ADMITTED",
						tc.ID, tc.Description, tc.ExpectLayer)
				}
				if tc.ExpectLayer != "" && res.BlockedBy != tc.ExpectLayer {
					t.Fatalf("[%s] expected BlockedBy=%q, got %q (reason: %s)",
						tc.ID, tc.ExpectLayer, res.BlockedBy, res.BlockReason)
				}
				return
			}

			if !res.Admitted {
				t.Fatalf("[%s] (%s) expected request to pass blocking layers, but blocked by %s: %s",
					tc.ID, tc.Description, res.BlockedBy, res.BlockReason)
			}

			if tc.ExpectForceCIBA && !res.ForceCIBA {
				t.Fatalf("[%s] (%s) expected ForceCIBA=true, got false", tc.ID, tc.Description)
			}
			if !tc.ExpectForceCIBA && res.ForceCIBA {
				t.Fatalf("[%s] (%s) benign control triggered unexpected ForceCIBA: %v",
					tc.ID, tc.Description, res.CIBAReasons)
			}
		})
	}
}

func TestSubSessionTaintIsolation_And_StrictToolManifest(t *testing.T) {
	t.Setenv("CICADA_SIMULATION_MODE", "true")
	t.Setenv("CICADA_DEV_MODE", "true")

	ctx := context.Background()
	agentID := "shared-support-agent"
	defer taint.ClearTaint(ctx, agentID)
	defer taint.ClearTaint(ctx, taint.ScopeKey(agentID, "sess-untrusted"))
	defer taint.ClearTaint(ctx, taint.ScopeKey(agentID, "sess-clean"))

	// Session A ingests untrusted web content -> Session A is tainted
	taint.MarkTainted(ctx, taint.ScopeKey(agentID, "sess-untrusted"), "web:scrape", "untrusted page")

	// Session A state-mutating POST -> ForceCIBA = true
	resA := pipeline.Evaluate(ctx, pipeline.Request{
		AgentID:          agentID,
		SessionID:        "sess-untrusted",
		TenantID:         "tenant-1",
		AgentDescription: "Internal database records tickets update maintenance agent",
		AgentType:        "database",
		HTTPMethod:       "POST",
		TargetURL:        "https://database.internal.com/v1/records/tickets",
		Body:             `{"note":"update ticket"}`,
	})
	if !resA.ForceCIBA {
		t.Fatal("expected tainted sub-session 'sess-untrusted' to force CIBA on POST")
	}

	// Session B on the SAME agent_id has not ingested untrusted content -> ForceCIBA = false
	resB := pipeline.Evaluate(ctx, pipeline.Request{
		AgentID:          agentID,
		SessionID:        "sess-clean",
		TenantID:         "tenant-1",
		AgentDescription: "Internal database records tickets update maintenance agent",
		AgentType:        "database",
		HTTPMethod:       "POST",
		TargetURL:        "https://database.internal.com/v1/records/tickets",
		Body:             `{"note":"update ticket"}`,
	})
	if resB.ForceCIBA {
		t.Fatalf("clean sub-session 'sess-clean' should not be cross-tainted by 'sess-untrusted': %v", resB.CIBAReasons)
	}

	// Strict tool manifest mode (RequireToolManifest=true): agent with 0 registered tools fails closed at Layer 6
	resStrict := pipeline.Evaluate(ctx, pipeline.Request{
		AgentID:             agentID,
		TenantID:            "tenant-1",
		AgentDescription:    "Internal database records tickets update maintenance agent",
		AgentType:           "database",
		HTTPMethod:          "GET",
		TargetURL:           "https://database.internal.com/v1/records/tickets",
		RequireToolManifest: true,
	})
	if resStrict.Admitted || resStrict.BlockedBy != "tool_scope" {
		t.Fatalf("expected RequireToolManifest=true with empty manifest to block at tool_scope, got admitted=%v blockedBy=%q",
			resStrict.Admitted, resStrict.BlockedBy)
	}
}
