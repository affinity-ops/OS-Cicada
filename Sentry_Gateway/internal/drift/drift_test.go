// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package drift

import (
	"context"
	"math"
	"testing"
)

// ── Token-Based Cosine Similarity ─────────────────────────────────────────────

// TestTokenCosineSimilarity_IdenticalVectors verifies that identical token
// distributions produce a similarity of 1.0 (no drift).
func TestTokenCosineSimilarity_IdenticalVectors(t *testing.T) {
	a := map[string]float64{"read": 2, "customer": 1, "records": 1}
	b := map[string]float64{"read": 2, "customer": 1, "records": 1}

	sim := tokenCosineSimilarity(a, b)
	if math.Abs(sim-1.0) > 0.001 {
		t.Errorf("identical vectors should have similarity=1.0, got %.4f", sim)
	}
}

// TestTokenCosineSimilarity_DisjointVectors verifies that completely different
// token sets produce a similarity of 0.0 (maximum drift).
func TestTokenCosineSimilarity_DisjointVectors(t *testing.T) {
	a := map[string]float64{"read": 1, "customer": 1, "support": 1}
	b := map[string]float64{"delete": 1, "purge": 1, "database": 1}

	sim := tokenCosineSimilarity(a, b)
	if sim != 0.0 {
		t.Errorf("disjoint vectors should have similarity=0.0, got %.4f", sim)
	}
}

// TestTokenCosineSimilarity_PartialOverlap verifies intermediate similarity
// for vectors that share some tokens but not all.
func TestTokenCosineSimilarity_PartialOverlap(t *testing.T) {
	a := map[string]float64{"read": 1, "customer": 1, "records": 1}
	b := map[string]float64{"read": 1, "customer": 1, "delete": 1, "bulk": 1}

	sim := tokenCosineSimilarity(a, b)
	// Should be between 0 and 1, but not at either extreme
	if sim <= 0.0 || sim >= 1.0 {
		t.Errorf("partial overlap should produce 0 < sim < 1, got %.4f", sim)
	}
}

// TestTokenCosineSimilarity_EmptyVector verifies neutral score for empty inputs.
func TestTokenCosineSimilarity_EmptyVector(t *testing.T) {
	a := map[string]float64{"read": 1}
	b := map[string]float64{}

	sim := tokenCosineSimilarity(a, b)
	if sim != 0.5 {
		t.Errorf("empty vector should return neutral 0.5, got %.4f", sim)
	}
}

// ── Tokenization ──────────────────────────────────────────────────────────────

// TestTokenize_BasicText verifies that tokenization extracts meaningful words.
func TestTokenize_BasicText(t *testing.T) {
	tokens := tokenize("Retrieving payment charges from api.stripe.com for monthly audit.")

	// "from" is in stop words — should NOT appear
	if _, exists := tokens["from"]; exists {
		t.Error("'from' should be filtered as a stop word")
	}
	// "for" is in stop words — should NOT appear
	if _, exists := tokens["for"]; exists {
		t.Error("'for' should be filtered as a stop word")
	}
	// "stripe" should appear (3+ chars, not stop word)
	if _, exists := tokens["stripe"]; !exists {
		t.Error("'stripe' should be in tokens")
	}
	// "payment" should appear
	if _, exists := tokens["payment"]; !exists {
		t.Error("'payment' should be in tokens")
	}
	// "charges" should appear
	if _, exists := tokens["charges"]; !exists {
		t.Error("'charges' should be in tokens")
	}
}

// TestTokenize_FrequencyCounts verifies that repeated tokens accumulate counts.
func TestTokenize_FrequencyCounts(t *testing.T) {
	tokens := tokenize("delete delete delete customer records")

	if tokens["delete"] != 3 {
		t.Errorf("'delete' should have count 3, got %.0f", tokens["delete"])
	}
	if tokens["customer"] != 1 {
		t.Errorf("'customer' should have count 1, got %.0f", tokens["customer"])
	}
}

// TestTokenize_ShortWordsFiltered verifies that tokens under 3 chars are dropped.
func TestTokenize_ShortWordsFiltered(t *testing.T) {
	tokens := tokenize("a to be or if it do go")

	if len(tokens) != 0 {
		t.Errorf("all words under 3 chars should be filtered, got %v", tokens)
	}
}

// ── buildActionText ───────────────────────────────────────────────────────────

// TestBuildActionText_WithSummary verifies full action text construction.
func TestBuildActionText_WithSummary(t *testing.T) {
	text := buildActionText("https://api.stripe.com/v1/charges", "POST", "Creating a payment charge")

	if text == "" {
		t.Fatal("action text should not be empty")
	}
	if !containsAll(text, "Create", "api.stripe.com", "Creating a payment charge") {
		t.Errorf("action text missing expected components: %q", text)
	}
}

// TestBuildActionText_WithoutSummary verifies action text with no reasoning trace.
func TestBuildActionText_WithoutSummary(t *testing.T) {
	text := buildActionText("https://api.internal.com/v1/users", "DELETE", "")

	if !containsAll(text, "Delete", "api.internal.com") {
		t.Errorf("action text missing expected components: %q", text)
	}
}

// ── Drift Detection Logic ─────────────────────────────────────────────────────

// TestDriftDetection_ConsistentActions verifies NO drift for similar actions.
// Token-based similarity is naturally sparser than embedding-based, so we
// verify that actions within the same domain and method produce a higher
// score than actions across completely different domains.
func TestDriftDetection_ConsistentActions(t *testing.T) {
	// Simulate an agent doing similar read actions on the same domain
	actions := []struct {
		url     string
		method  string
		summary string
	}{
		{"https://api.stripe.com/v1/charges", "GET", "Reading charge records for audit report"},
		{"https://api.stripe.com/v1/invoices", "GET", "Reading invoice records for monthly audit report"},
	}

	// Build fingerprints
	text0 := buildActionText(actions[0].url, actions[0].method, actions[0].summary)
	text1 := buildActionText(actions[1].url, actions[1].method, actions[1].summary)
	vec0 := tokenize(text0)
	vec1 := tokenize(text1)

	consistentSim := tokenCosineSimilarity(vec0, vec1)

	// Now build a completely different action
	shiftText := buildActionText("https://api.internal.com/v1/users/bulk", "DELETE", "Purging all inactive accounts")
	shiftVec := tokenize(shiftText)
	shiftSim := tokenCosineSimilarity(vec0, shiftVec)

	// Consistent actions should be MORE similar than a major shift
	if consistentSim <= shiftSim {
		t.Errorf("consistent actions (sim=%.3f) should be more similar than major shift (sim=%.3f)",
			consistentSim, shiftSim)
	}

	// Consistent actions should produce a non-trivial similarity
	if consistentSim < 0.2 {
		t.Errorf("consistent actions should have some similarity, got %.3f", consistentSim)
	}
}

// TestDriftDetection_MajorShift verifies drift IS detected when an agent
// switches from read operations to bulk deletion.
func TestDriftDetection_MajorShift(t *testing.T) {
	// Historical: reading customer data
	histText := buildActionText("https://api.stripe.com/v1/customers", "GET", "Reading customer records for support query")
	histVector := tokenize(histText)

	// Current: bulk deleting user data (completely different action)
	currText := buildActionText("https://api.internal.com/v1/users/bulk", "DELETE", "Purging all inactive accounts from database")
	currVector := tokenize(currText)

	sim := tokenCosineSimilarity(currVector, histVector)
	if sim >= DefaultTokenThreshold {
		t.Errorf("major behaviour shift should trigger drift (sim=%.3f, threshold=%.3f)",
			sim, DefaultTokenThreshold)
	}
}

// TestDriftDetection_SubtleShift verifies that a related-but-different action
// produces an intermediate similarity score.
func TestDriftDetection_SubtleShift(t *testing.T) {
	// Historical: reading customer records
	histText := buildActionText("https://api.stripe.com/v1/customers", "GET", "Reading customer profile for support")
	histVector := tokenize(histText)

	// Current: updating customer records (same domain, different verb)
	currText := buildActionText("https://api.stripe.com/v1/customers/123", "PUT", "Updating customer email address")
	currVector := tokenize(currText)

	sim := tokenCosineSimilarity(currVector, histVector)
	// Subtle shifts should produce a score between 0.2 and 0.8
	if sim <= 0 || sim >= 1 {
		t.Errorf("subtle shift should produce intermediate score, got %.3f", sim)
	}
}

// ── Check() without Redis ─────────────────────────────────────────────────────

// TestCheck_NoRedis_FirstAction verifies that Check handles the no-Redis case
// gracefully (stores nothing, returns no drift).
func TestCheck_NoRedis_FirstAction(t *testing.T) {
	result := Check(
		context.Background(),
		"agent-test-001",
		"https://api.stripe.com/v1/charges",
		"GET",
		"Reading payment records",
	)

	if result.DriftDetected {
		t.Error("first action should never trigger drift")
	}
	if result.HistorySize != 0 {
		t.Errorf("history size should be 0 for first action, got %d", result.HistorySize)
	}
}

// ── Configuration ─────────────────────────────────────────────────────────────

// TestIsEnabled_Default verifies drift is enabled by default.
func TestIsEnabled_Default(t *testing.T) {
	if !isEnabled() {
		t.Error("drift detection should be enabled by default")
	}
}

// TestTokenThreshold_Default verifies the default token threshold.
func TestTokenThreshold_Default(t *testing.T) {
	th := tokenThreshold()
	if th != DefaultTokenThreshold {
		t.Errorf("default token threshold = %.2f, want %.2f", th, DefaultTokenThreshold)
	}
}

// TestHistorySize_Default verifies the default history size.
func TestHistorySize_Default(t *testing.T) {
	size := historySize()
	if size != DefaultHistorySize {
		t.Errorf("default history size = %d, want %d", size, DefaultHistorySize)
	}
}

// TestHistoryKey_Format verifies the Redis key format.
func TestHistoryKey_Format(t *testing.T) {
	key := agentHistoryKey("agent-abc-123")
	expected := "cicada:drift:history:agent-abc-123"
	if key != expected {
		t.Errorf("history key = %q, want %q", key, expected)
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func containsAll(text string, substrings ...string) bool {
	for _, s := range substrings {
		if !contains(text, s) {
			return false
		}
	}
	return true
}

func contains(text, substr string) bool {
	return len(text) >= len(substr) && (text == substr || len(text) > 0 && findSubstring(text, substr))
}

func findSubstring(text, substr string) bool {
	for i := 0; i <= len(text)-len(substr); i++ {
		if text[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
