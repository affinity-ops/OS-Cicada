// © 2026 Patrick Matthews (Affinity Ops / Affinity Smart AI)
// SPDX-License-Identifier: Apache-2.0

package taint

import (
	"context"
	"testing"
)

func TestTaint_UntaintedSession_AllowsMutation(t *testing.T) {
	ctx := context.Background()
	agentID := "agent-clean-1"
	ClearTaint(ctx, agentID)

	res := CheckCapability(ctx, agentID, "POST", "https://api.stripe.com/v1/charges", "user")
	if res.Tainted || res.ForceCIBA {
		t.Errorf("untainted session should allow POST without ForceCIBA, got %+v", res)
	}
}

func TestTaint_TaintedSession_EscalatesMutation(t *testing.T) {
	ctx := context.Background()
	agentID := "agent-tainted-1"
	ClearTaint(ctx, agentID)

	// Step 1: Agent ingests untrusted content (e.g., from LLM tool_result or external GET)
	MarkTainted(ctx, agentID, "llm_context:tool_result", "ingested external customer email")

	// Step 2: Read-only GET is still allowed without CIBA
	readRes := CheckCapability(ctx, agentID, "GET", "https://api.stripe.com/v1/charges", "system")
	if !readRes.Tainted {
		t.Error("expected session to report Tainted=true")
	}
	if readRes.ForceCIBA {
		t.Error("read-only GET on tainted session should not ForceCIBA")
	}

	// Step 3: State-mutating POST is forced into CIBA even with clean provenance header
	writeRes := CheckCapability(ctx, agentID, "POST", "https://api.stripe.com/v1/refunds", "system")
	if !writeRes.Tainted || !writeRes.ForceCIBA {
		t.Errorf("tainted session attempting POST must ForceCIBA, got %+v", writeRes)
	}

	// Step 4: Context flush clears taint
	ClearTaint(ctx, agentID)
	afterFlush := CheckCapability(ctx, agentID, "POST", "https://api.stripe.com/v1/refunds", "system")
	if afterFlush.Tainted || afterFlush.ForceCIBA {
		t.Errorf("flushed session should not be tainted, got %+v", afterFlush)
	}
}

func TestTaint_RetrievedProvenance_AutoTaintsAndEscalates(t *testing.T) {
	ctx := context.Background()
	agentID := "agent-rag-1"
	ClearTaint(ctx, agentID)

	res := CheckCapability(ctx, agentID, "DELETE", "https://api.internal.com/v1/users/42", "retrieved")
	if !res.Tainted || !res.ForceCIBA {
		t.Errorf("retrieved provenance on DELETE must auto-taint and ForceCIBA, got %+v", res)
	}
}

func TestShouldTaintOnRead_TrustedVsUntrustedDomains(t *testing.T) {
	t.Setenv("CICADA_TRUSTED_DOMAINS", "api.stripe.com,*.trusted.partner.io")

	// 1. Trusted internal domains do NOT taint on GET
	for _, u := range []string{
		"https://db.internal/v1/users",
		"https://billing.internal.company.com/v1/ledgers",
		"https://orders.svc.cluster.local/api",
		"https://crm.corp/contacts",
		"https://api.stripe.com/v1/customers",
		"https://sub.trusted.partner.io/v1/status",
	} {
		if ShouldTaintOnRead(u, "") {
			t.Errorf("expected trusted domain %q NOT to taint on GET", u)
		}
	}

	// 2. Untrusted external domains DO taint on GET
	for _, u := range []string{
		"https://news.ycombinator.com/item?id=1",
		"https://pastebin.com/raw/abc123",
		"https://untrusted-vendor.example.org/feed.json",
	} {
		if !ShouldTaintOnRead(u, "") {
			t.Errorf("expected untrusted external domain %q to taint on GET", u)
		}
	}

	// 3. Explicit untrusted provenance ("rag", "external") taints even on internal URL
	if !ShouldTaintOnRead("https://db.internal/v1/docs", "rag") {
		t.Error("expected explicit 'rag' provenance to taint even on internal URL")
	}

	// 4. Explicit trusted provenance ("internal", "system") does not taint
	if ShouldTaintOnRead("https://api.partner.example.com/v1/health", "internal") {
		t.Error("expected explicit 'internal' provenance not to taint on GET")
	}
}

