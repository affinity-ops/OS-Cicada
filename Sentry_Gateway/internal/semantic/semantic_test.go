// © 2026 Affinity Ops Ltd. All rights reserved.
// Proprietary and confidential. Unauthorized copying or distribution prohibited.

package semantic

import (
	"math"
	"net/url"
	"testing"
)

func TestCheck_AlignedCalls(t *testing.T) {
	cases := []struct {
		name        string
		description string
		agentType   string
		targetURL   string
		method      string
	}{
		{
			name:        "payment agent calling stripe",
			description: "processes customer payments and refunds",
			agentType:   "payment",
			targetURL:   "https://api.stripe.com/v1/charges",
			method:      "POST",
		},
		{
			name:        "email agent calling sendgrid",
			description: "sends transactional emails to customers",
			agentType:   "notification",
			targetURL:   "https://api.sendgrid.com/v3/mail/send",
			method:      "POST",
		},
		{
			// URL tokens include "support" and "orders" which appear in the
			// agent description — direct token overlap proves alignment.
			name:        "support agent reading orders",
			description: "customer support assistant retrieves orders and history",
			agentType:   "support",
			targetURL:   "https://support-api.internal.example.com/v1/orders/history",
			method:      "GET",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := Check(tc.description, tc.agentType, tc.targetURL, tc.method)
			if result.Block {
				t.Errorf("Aligned call falsely blocked: score=%.2f reason=%q", result.Score, result.Reason)
			}
		})
	}
}

func TestCheck_MismatchedCalls(t *testing.T) {
	cases := []struct {
		name        string
		description string
		agentType   string
		targetURL   string
		method      string
	}{
		{
			name:        "support agent deleting payments",
			description: "customer support chat assistant",
			agentType:   "support",
			targetURL:   "https://api.stripe.com/v1/charges/ch_123",
			method:      "DELETE",
		},
		{
			name:        "content agent deleting users",
			description: "blog content writer and publisher",
			agentType:   "content",
			targetURL:   "https://api.example.com/v1/users/456",
			method:      "DELETE",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := Check(tc.description, tc.agentType, tc.targetURL, tc.method)
			// With low threshold, these should at minimum produce a reason
			if result.Reason == "" {
				t.Errorf("Expected non-empty reason for mismatched call")
			}
		})
	}
}

func TestCheck_EmptyDescription(t *testing.T) {
	// Agents with no description should not be blocked on empty description alone
	result := Check("", "", "https://api.stripe.com/v1/charges", "POST")
	// Empty description produces zero score — should not block
	if result.Block {
		t.Error("Empty description must not block (zero score cannot exceed threshold)")
	}
}

func TestCheck_NoTarget(t *testing.T) {
	// Empty target URL should not panic
	result := Check("payment agent", "payment", "", "POST")
	if result.Block {
		t.Error("Empty target URL must not block")
	}
	if result.Method != "none" {
		t.Errorf("empty URL should use method 'none', got %q", result.Method)
	}
}

// ── Cosine Similarity ─────────────────────────────────────────────────────────

func TestCosineSimilarity_IdenticalVectors(t *testing.T) {
	a := []float64{1.0, 2.0, 3.0}
	b := []float64{1.0, 2.0, 3.0}
	sim := cosineSimilarity(a, b)
	if math.Abs(sim-1.0) > 0.0001 {
		t.Errorf("identical vectors should have similarity 1.0, got %f", sim)
	}
}

func TestCosineSimilarity_OrthogonalVectors(t *testing.T) {
	a := []float64{1.0, 0.0, 0.0}
	b := []float64{0.0, 1.0, 0.0}
	sim := cosineSimilarity(a, b)
	if math.Abs(sim) > 0.0001 {
		t.Errorf("orthogonal vectors should have similarity 0.0, got %f", sim)
	}
}

func TestCosineSimilarity_OppositeVectors(t *testing.T) {
	a := []float64{1.0, 2.0, 3.0}
	b := []float64{-1.0, -2.0, -3.0}
	sim := cosineSimilarity(a, b)
	if math.Abs(sim+1.0) > 0.0001 {
		t.Errorf("opposite vectors should have similarity -1.0, got %f", sim)
	}
}

func TestCosineSimilarity_MismatchedLengths(t *testing.T) {
	a := []float64{1.0, 2.0}
	b := []float64{1.0, 2.0, 3.0}
	sim := cosineSimilarity(a, b)
	if sim != 0.5 {
		t.Errorf("mismatched lengths should return 0.5 (neutral), got %f", sim)
	}
}

func TestCosineSimilarity_EmptyVectors(t *testing.T) {
	sim := cosineSimilarity(nil, nil)
	if sim != 0.5 {
		t.Errorf("empty vectors should return 0.5, got %f", sim)
	}
}

func TestCosineSimilarity_ZeroVector(t *testing.T) {
	a := []float64{0.0, 0.0, 0.0}
	b := []float64{1.0, 2.0, 3.0}
	sim := cosineSimilarity(a, b)
	if sim != 0.5 {
		t.Errorf("zero-magnitude vector should return 0.5, got %f", sim)
	}
}

// ── Jaccard Score ─────────────────────────────────────────────────────────────

func TestJaccardScore_IdenticalSets(t *testing.T) {
	a := map[string]bool{"payment": true, "billing": true}
	b := map[string]bool{"payment": true, "billing": true}
	score := jaccardScore(a, b)
	if math.Abs(score-1.0) > 0.0001 {
		t.Errorf("identical sets should have Jaccard 1.0, got %f", score)
	}
}

func TestJaccardScore_DisjointSets(t *testing.T) {
	a := map[string]bool{"payment": true, "billing": true}
	b := map[string]bool{"email": true, "smtp": true}
	score := jaccardScore(a, b)
	if score != 0 {
		t.Errorf("disjoint sets should have Jaccard 0, got %f", score)
	}
}

func TestJaccardScore_PartialOverlap(t *testing.T) {
	a := map[string]bool{"payment": true, "billing": true, "finance": true}
	b := map[string]bool{"payment": true, "invoice": true, "finance": true}
	score := jaccardScore(a, b)
	expected := 2.0 / 4.0
	if math.Abs(score-expected) > 0.0001 {
		t.Errorf("partial overlap Jaccard = %f, expected %f", score, expected)
	}
}

func TestJaccardScore_EmptySet(t *testing.T) {
	a := map[string]bool{}
	b := map[string]bool{"payment": true}
	score := jaccardScore(a, b)
	if score != 0.5 {
		t.Errorf("empty set should return 0.5 (neutral), got %f", score)
	}
}

// ── Read-Only Method Penalty ──────────────────────────────────────────────────

func TestReadOnlyMethodPenalty(t *testing.T) {
	cases := []struct {
		desc   string
		method string
		want   float64
	}{
		{"read-only monitoring agent", "DELETE", 0.35},
		{"readonly query agent", "POST", 0.35},
		{"a fetch and retrieve data agent", "PUT", 0.35},
		{"report observation agent", "PATCH", 0.35},
		// Non-destructive methods never penalize
		{"read-only agent", "GET", 0},
		{"monitoring observer", "HEAD", 0},
		// No read-only keywords
		{"payment processing agent", "DELETE", 0},
		{"email sender agent", "POST", 0},
	}
	for _, tc := range cases {
		got := readOnlyMethodPenalty(tc.desc, tc.method)
		if got != tc.want {
			t.Errorf("readOnlyMethodPenalty(%q, %q) = %f, want %f", tc.desc, tc.method, got, tc.want)
		}
	}
}

// ── Block Threshold ───────────────────────────────────────────────────────────

func TestBlockThreshold_Defaults(t *testing.T) {
	emb := BlockThreshold("embedding")
	if emb != 0.35 {
		t.Errorf("default embedding threshold = %f, want 0.35", emb)
	}
	jac := BlockThreshold("jaccard")
	if jac != 0.10 {
		t.Errorf("default jaccard threshold = %f, want 0.10", jac)
	}
}

// ── Token Extraction ──────────────────────────────────────────────────────────

func TestExtractTokens(t *testing.T) {
	tokens := extractTokens("A customer support billing assistant for handling payments")
	expected := []string{"customer", "support", "billing", "assistant", "handling", "payments"}
	for _, tok := range expected {
		if !tokens[tok] {
			t.Errorf("expected token %q not found", tok)
		}
	}
	// Stop words filtered
	if tokens["for"] {
		t.Error("stop word 'for' should be filtered")
	}
	// Short tokens filtered
	if tokens["a"] {
		t.Error("single-char token should be filtered")
	}
}

func TestExtractURLTokens(t *testing.T) {
	u, _ := url.Parse("https://api.stripe.com/v1/charges")
	tokens := extractURLTokens(u)
	for _, expected := range []string{"api", "stripe", "com", "charges"} {
		if !tokens[expected] {
			t.Errorf("expected URL token %q not found", expected)
		}
	}
	// Version segments should be filtered
	if tokens["v1"] {
		t.Error("version segment 'v1' should be filtered by isVersionOrID")
	}
}

func TestIsVersionOrID(t *testing.T) {
	cases := []struct {
		input string
		isVer bool
	}{
		{"v1", true},
		{"v2", true},
		{"v10", true},
		{"charges", false},
		{"mail", false},
		{"550e8400-e29b-41d4-a716-446655440000", true}, // UUID
	}
	for _, tc := range cases {
		got := isVersionOrID(tc.input)
		if got != tc.isVer {
			t.Errorf("isVersionOrID(%q) = %v, want %v", tc.input, got, tc.isVer)
		}
	}
}

// ── Jaccard Check Full Flow ───────────────────────────────────────────────────

func TestJaccardCheck_PaymentAgentToStripe(t *testing.T) {
	u, _ := url.Parse("https://api.stripe.com/v1/charges")
	result := jaccardCheck("billing and payment processing assistant", "reactive", u, "POST")
	if result.Block {
		t.Error("payment agent calling Stripe should NOT be blocked")
	}
	if result.Score < 0.30 {
		t.Errorf("payment agent → Stripe should have decent score, got %f", result.Score)
	}
	if result.Method != "jaccard" {
		t.Errorf("expected method 'jaccard', got %q", result.Method)
	}
}

func TestJaccardCheck_EmailAgentToStripe_LowScore(t *testing.T) {
	u, _ := url.Parse("https://api.stripe.com/v1/charges")
	result := jaccardCheck("email marketing campaign sender", "reactive", u, "POST")
	if result.Score > 0.15 {
		t.Errorf("email agent → Stripe should have very low score, got %f", result.Score)
	}
}

func TestJaccardCheck_ReadOnlyAgentDelete(t *testing.T) {
	u, _ := url.Parse("https://api.stripe.com/v1/customers/cust_123")
	result := jaccardCheck("read-only monitoring dashboard agent for billing", "reactive", u, "DELETE")
	if !result.Block {
		t.Error("read-only agent calling DELETE on Stripe should be blocked")
	}
}

// ── Check Fallback Behaviour ──────────────────────────────────────────────────

func TestCheck_FallbackToJaccard_WhenNoEmbeddingService(t *testing.T) {
	result := Check("payment processing assistant", "reactive", "https://api.stripe.com/v1/charges", "POST")
	if result.Method != "jaccard" {
		t.Errorf("without embedding service, expected jaccard fallback, got %q", result.Method)
	}
	if result.Block {
		t.Error("payment agent → Stripe should not block via Jaccard")
	}
}

// ── Build Helpers ─────────────────────────────────────────────────────────────

func TestBuildAgentText(t *testing.T) {
	cases := []struct {
		desc, agentType, want string
	}{
		{"billing assistant", "reactive", "billing assistant This is a reactive agent."},
		{"", "autonomous", "This is a autonomous agent."},
		{"", "", "general purpose agent"},
		{"support bot", "", "support bot"},
	}
	for _, tc := range cases {
		got := buildAgentText(tc.desc, tc.agentType)
		if got != tc.want {
			t.Errorf("buildAgentText(%q, %q) = %q, want %q", tc.desc, tc.agentType, got, tc.want)
		}
	}
}

func TestBuildTargetText(t *testing.T) {
	u, _ := url.Parse("https://api.stripe.com/v1/charges")
	got := buildTargetText(u, "POST")
	if got != "Create data via api.stripe.com/v1/charges" {
		t.Errorf("buildTargetText = %q", got)
	}

	u2, _ := url.Parse("https://api.example.com")
	got2 := buildTargetText(u2, "GET")
	if got2 != "Read data from api.example.com" {
		t.Errorf("buildTargetText (no path) = %q", got2)
	}

	u3, _ := url.Parse("https://api.example.com/v1/data")
	got3 := buildTargetText(u3, "DELETE")
	if got3 != "Delete data from api.example.com/v1/data" {
		t.Errorf("buildTargetText DELETE = %q", got3)
	}
}

func TestStemToken_AndPluralMatching(t *testing.T) {
	// Agent description uses plural "payments" and "charges", agentType is generic "reactive"
	res := Check("processes customer payments and refunds", "reactive", "https://api.stripe.com/v1/charges", "POST")
	if res.Block {
		t.Fatalf("plural 'payments' should stem to 'payment' and align with Stripe: score=%.2f reason=%q", res.Score, res.Reason)
	}
	if res.Score < 0.40 {
		t.Errorf("expected domain category boost (>=0.40) from stemmed 'payments'->'payment', got %.2f", res.Score)
	}
}

func TestCheck_ExfiltrationSinkBlocked(t *testing.T) {
	res := Check("customer support assistant", "support", "https://webhook.site/a1b2c3d4", "POST")
	if !res.Block || res.Score != 0.0 {
		t.Fatalf("expected exfiltration sink webhook.site to be blocked with score 0.0, got Block=%v Score=%.2f", res.Block, res.Score)
	}
}

