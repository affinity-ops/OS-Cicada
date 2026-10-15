// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package semantic

import (
	"testing"
)

// ── Benchmark: Semantic Intent Check Latency ──────────────────────────────────
// Jaccard fallback (no embedding service) is the cold path — must still be fast.
// Run with: go test -bench=. -benchmem ./internal/semantic/

func BenchmarkCheck_AlignedCall(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Check("Processes customer payments via Stripe API", "payment", "https://api.stripe.com/v1/charges", "POST")
	}
}

func BenchmarkCheck_MismatchedCall(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Check("Customer support chat assistant for product questions", "support", "https://api.stripe.com/v1/charges/ch_123", "DELETE")
	}
}

func BenchmarkJaccardScore(b *testing.B) {
	setA := map[string]bool{"payment": true, "stripe": true, "charge": true, "billing": true, "invoice": true}
	setB := map[string]bool{"stripe": true, "charge": true, "payment": true, "customer": true, "refund": true}
	for i := 0; i < b.N; i++ {
		jaccardScore(setA, setB)
	}
}

func BenchmarkExtractTokens(b *testing.B) {
	text := "Processes customer payments via the Stripe billing API for monthly subscription invoices and one-time charges"
	for i := 0; i < b.N; i++ {
		extractTokens(text)
	}
}
