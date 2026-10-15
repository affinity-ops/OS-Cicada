// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package velocity

import (
	"strings"
	"testing"
)

// ── Impact Weight: URL Bulk Detection ─────────────────────────────────────────

func TestComputeImpact_BulkURLSegments(t *testing.T) {
	// Every known bulk indicator should trigger the bulk multiplier
	bulkURLs := []string{
		"https://api.example.com/v1/users/bulk",
		"https://api.example.com/v1/records/batch",
		"https://api.example.com/v1/data/mass-delete",
		"https://api.example.com/v1/data/mass_update",
		"https://api.example.com/v1/users/all",
		"https://api.example.com/v1/cache/purge",
		"https://api.example.com/v1/table/truncate",
		"https://api.example.com/v1/storage/wipe",
	}

	for _, url := range bulkURLs {
		result := ComputeImpact(url, `{"id": 1}`, "DELETE")
		if result.Multiplier < 2 {
			t.Errorf("URL %q should trigger bulk multiplier, got multiplier=%d", url, result.Multiplier)
		}
		if result.Indicator != "bulk_url" {
			t.Errorf("URL %q indicator should be 'bulk_url', got %q", url, result.Indicator)
		}
	}
}

func TestComputeImpact_BulkURL_DefaultMultiplier(t *testing.T) {
	result := ComputeImpact("https://api.example.com/v1/users/bulk", "", "POST")
	if result.Multiplier != int64(defaultBulkMultiplier) {
		t.Errorf("default bulk multiplier = %d, want %d", result.Multiplier, defaultBulkMultiplier)
	}
}

func TestComputeImpact_NormalURL_NoMultiplier(t *testing.T) {
	normalURLs := []string{
		"https://api.example.com/v1/users/123",
		"https://api.example.com/v1/orders",
		"https://api.example.com/v1/products/search",
	}

	for _, url := range normalURLs {
		result := ComputeImpact(url, `{"name": "test"}`, "POST")
		if result.Multiplier != 1 {
			t.Errorf("normal URL %q should have multiplier=1, got %d", url, result.Multiplier)
		}
		if result.Indicator != "none" {
			t.Errorf("normal URL %q indicator should be 'none', got %q", url, result.Indicator)
		}
	}
}

// ── Impact Weight: Array Payload Detection ────────────────────────────────────

func TestComputeImpact_LargeArray_TriggersMultiplier(t *testing.T) {
	// Build a JSON array with 20 elements (exceeds default threshold of 10)
	elements := make([]string, 20)
	for i := range elements {
		elements[i] = `{"id":` + strings.Repeat("1", 1) + `}`
	}
	body := "[" + strings.Join(elements, ",") + "]"

	result := ComputeImpact("https://api.example.com/v1/users", body, "POST")
	if result.Multiplier < 2 {
		t.Errorf("large array payload should trigger multiplier, got %d", result.Multiplier)
	}
	if result.Indicator != "array_payload" {
		t.Errorf("indicator should be 'array_payload', got %q", result.Indicator)
	}
}

func TestComputeImpact_SmallArray_NoMultiplier(t *testing.T) {
	// Array with 3 elements — below default threshold of 10
	body := `[{"id":1},{"id":2},{"id":3}]`
	result := ComputeImpact("https://api.example.com/v1/users", body, "POST")
	if result.Multiplier != 1 {
		t.Errorf("small array should have multiplier=1, got %d", result.Multiplier)
	}
}

func TestComputeImpact_SingleObject_NoMultiplier(t *testing.T) {
	body := `{"name": "test", "email": "test@example.com"}`
	result := ComputeImpact("https://api.example.com/v1/users", body, "POST")
	if result.Multiplier != 1 {
		t.Errorf("single object should have multiplier=1, got %d", result.Multiplier)
	}
	if result.Indicator != "none" {
		t.Errorf("indicator should be 'none', got %q", result.Indicator)
	}
}

func TestComputeImpact_EmptyBody_NoMultiplier(t *testing.T) {
	result := ComputeImpact("https://api.example.com/v1/users/123", "", "DELETE")
	if result.Multiplier != 1 {
		t.Errorf("empty body should have multiplier=1, got %d", result.Multiplier)
	}
}

// ── Impact Weight: HTTP Method Filtering ──────────────────────────────────────

func TestComputeImpact_GETMethod_AlwaysMultiplierOne(t *testing.T) {
	// Even with a bulk URL, GET should not be impact-weighted
	result := ComputeImpact("https://api.example.com/v1/users/bulk", "", "GET")
	if result.Multiplier != 1 {
		t.Errorf("GET should always have multiplier=1, got %d", result.Multiplier)
	}
}

func TestComputeImpact_HEADMethod_AlwaysMultiplierOne(t *testing.T) {
	result := ComputeImpact("https://api.example.com/v1/users/purge", "", "HEAD")
	if result.Multiplier != 1 {
		t.Errorf("HEAD should always have multiplier=1, got %d", result.Multiplier)
	}
}

// ── Impact Weight: URL takes priority over payload ───────────────────────────

func TestComputeImpact_BulkURL_TakesPriority(t *testing.T) {
	// URL says "bulk" AND body is a large array — URL indicator should win
	elements := make([]string, 50)
	for i := range elements {
		elements[i] = `{"id":1}`
	}
	body := "[" + strings.Join(elements, ",") + "]"

	result := ComputeImpact("https://api.example.com/v1/users/bulk", body, "POST")
	if result.Indicator != "bulk_url" {
		t.Errorf("bulk URL should take priority over array payload, got indicator=%q", result.Indicator)
	}
	// Bulk URL multiplier (100) should be higher than array multiplier (10)
	if result.Multiplier != int64(defaultBulkMultiplier) {
		t.Errorf("multiplier should be bulk (%d), got %d", defaultBulkMultiplier, result.Multiplier)
	}
}

// ── countJSONArrayElements ───────────────────────────────────────────────────

func TestCountJSONArrayElements_ValidArray(t *testing.T) {
	n := countJSONArrayElements(`[1,2,3,4,5]`)
	if n != 5 {
		t.Errorf("array count = %d, want 5", n)
	}
}

func TestCountJSONArrayElements_EmptyArray(t *testing.T) {
	n := countJSONArrayElements(`[]`)
	if n != 0 {
		t.Errorf("empty array count = %d, want 0", n)
	}
}

func TestCountJSONArrayElements_InvalidJSON(t *testing.T) {
	n := countJSONArrayElements(`not json at all`)
	if n != 0 {
		t.Errorf("invalid JSON should return 0, got %d", n)
	}
}

func TestCountJSONArrayElements_Object(t *testing.T) {
	// A JSON object is not an array — should return 0
	n := countJSONArrayElements(`{"key": "value"}`)
	if n != 0 {
		t.Errorf("JSON object should return 0, got %d", n)
	}
}

// ── Case insensitivity ───────────────────────────────────────────────────────

func TestComputeImpact_CaseInsensitiveURL(t *testing.T) {
	result := ComputeImpact("https://api.example.com/v1/Users/BULK", "", "DELETE")
	if result.Indicator != "bulk_url" {
		t.Errorf("URL matching should be case-insensitive, got indicator=%q", result.Indicator)
	}
}

func TestComputeImpact_CaseInsensitiveMethod(t *testing.T) {
	result := ComputeImpact("https://api.example.com/v1/users/bulk", "", "delete")
	if result.Multiplier < 2 {
		t.Errorf("method matching should be case-insensitive, got multiplier=%d", result.Multiplier)
	}
}

// ── Config defaults ──────────────────────────────────────────────────────────

func TestBulkMultiplier_Default(t *testing.T) {
	m := bulkMultiplier()
	if m != int64(defaultBulkMultiplier) {
		t.Errorf("default bulk multiplier = %d, want %d", m, defaultBulkMultiplier)
	}
}

func TestArrayMultiplier_Default(t *testing.T) {
	m := arrayMultiplier()
	if m != int64(defaultArrayMultiplier) {
		t.Errorf("default array multiplier = %d, want %d", m, defaultArrayMultiplier)
	}
}

func TestArrayThreshold_Default(t *testing.T) {
	th := arrayThreshold()
	if th != 10 {
		t.Errorf("default array threshold = %d, want 10", th)
	}
}
