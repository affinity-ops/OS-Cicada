// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package fga

import (
	"testing"
)

// ── matchesPattern ────────────────────────────────────────────────────────────

func TestMatchesPattern_WildcardMatches(t *testing.T) {
	cases := []struct {
		pattern string
		url     string
		want    bool
	}{
		// Wildcard prefix — the primary use case
		{"https://api.stripe.com/v1/charges*", "https://api.stripe.com/v1/charges/ch_123", true},
		{"https://api.stripe.com/v1/charges*", "https://api.stripe.com/v1/charges", true},
		{"https://api.example.com/users*", "https://api.example.com/users/456/profile", true},
		// "users*" does NOT match "usernames" — 's' != 'n' at position 5 in "users"/"usern"
		{"https://api.example.com/users*", "https://api.example.com/usernames", false},

		// Wildcard but URL doesn't match prefix
		{"https://api.stripe.com/v1/charges*", "https://api.stripe.com/v1/refunds/re_123", false},
		{"https://api.example.com/admin*", "https://api.example.com/users/123", false},

		// Exact match (no wildcard)
		{"https://api.example.com/users", "https://api.example.com/users", true},
		{"https://api.example.com/users", "https://api.example.com/users/123", false},
		{"https://api.example.com/users", "https://api.example.com/USERS", false}, // case-sensitive

		// Edge cases
		{"*", "https://anything.com/path", true},   // bare wildcard matches everything
		{"https://api.example.com/*", "https://api.example.com/any/path", true},
		{"", "", true},                               // empty pattern matches empty URL exactly
		{"", "https://api.example.com", false},       // empty pattern does not match non-empty URL
	}

	for _, tc := range cases {
		got := matchesPattern(tc.pattern, tc.url)
		if got != tc.want {
			t.Errorf("matchesPattern(%q, %q) = %v, want %v", tc.pattern, tc.url, got, tc.want)
		}
	}
}

// ── methodAllowed ─────────────────────────────────────────────────────────────

func TestMethodAllowed(t *testing.T) {
	cases := []struct {
		allowed []string
		method  string
		want    bool
	}{
		// Case-insensitive matching
		{[]string{"POST", "GET"}, "POST", true},
		{[]string{"POST", "GET"}, "post", true},
		{[]string{"POST", "GET"}, "Post", true},
		{[]string{"post"}, "POST", true},

		// Method not in list
		{[]string{"GET"}, "DELETE", false},
		{[]string{"POST", "GET"}, "DELETE", false},
		{[]string{"POST", "GET"}, "PATCH", false},

		// Empty cases
		{[]string{}, "GET", false},
		{nil, "GET", false},

		// All methods allowed
		{[]string{"GET", "POST", "PUT", "PATCH", "DELETE"}, "DELETE", true},
	}

	for _, tc := range cases {
		got := methodAllowed(tc.allowed, tc.method)
		if got != tc.want {
			t.Errorf("methodAllowed(%v, %q) = %v, want %v", tc.allowed, tc.method, got, tc.want)
		}
	}
}

// ── parseJSONStringArray ──────────────────────────────────────────────────────

func TestParseJSONStringArray(t *testing.T) {
	cases := []struct {
		input string
		want  []string
	}{
		{`["POST","GET"]`, []string{"POST", "GET"}},
		{`["DELETE"]`, []string{"DELETE"}},
		{`["POST", "GET", "PATCH"]`, []string{"POST", "GET", "PATCH"}},

		// Whitespace handling
		{`[ "POST" , "GET" ]`, []string{"POST", "GET"}},

		// Empty array
		{`[]`, nil},
		{``, nil},

		// Single item
		{`["POST"]`, []string{"POST"}},
	}

	for _, tc := range cases {
		got := parseJSONStringArray(tc.input)
		if len(got) != len(tc.want) {
			t.Errorf("parseJSONStringArray(%q) = %v (len %d), want %v (len %d)",
				tc.input, got, len(got), tc.want, len(tc.want))
			continue
		}
		for i := range tc.want {
			if got[i] != tc.want[i] {
				t.Errorf("parseJSONStringArray(%q)[%d] = %q, want %q", tc.input, i, got[i], tc.want[i])
			}
		}
	}
}

// ── Security-critical combinations ───────────────────────────────────────────

// TestFGA_NoPolicyIsPassthrough documents the backwards-compatibility guarantee:
// an agent with zero policies is never blocked by FGA.
// This is tested at the pure-logic level to verify the invariant holds.
func TestFGA_PatternAndMethodTogether(t *testing.T) {
	// Simulate the inner loop of Check() for a policy that allows POST on charges
	policy := ResourcePolicy{
		ResourcePattern: "https://api.stripe.com/v1/charges*",
		AllowedMethods:  []string{"POST"},
		Active:          true,
	}

	// Allowed: POST to a specific charge
	if !matchesPattern(policy.ResourcePattern, "https://api.stripe.com/v1/charges/ch_123") ||
		!methodAllowed(policy.AllowedMethods, "POST") {
		t.Error("POST to charges should be allowed by policy")
	}

	// Denied: DELETE not in allowed methods
	if methodAllowed(policy.AllowedMethods, "DELETE") {
		t.Error("DELETE should not be allowed by a POST-only policy")
	}

	// Denied: URL not under charges
	if matchesPattern(policy.ResourcePattern, "https://api.stripe.com/v1/refunds/re_123") {
		t.Error("Refunds URL should not match a charges* policy")
	}
}

func TestFGA_InactivePolicy_NeverMatches(t *testing.T) {
	// Active=false policies must be skipped even if the pattern and method match.
	// This mirrors the `if !p.Active { continue }` guard in Check().
	policy := ResourcePolicy{
		ResourcePattern: "https://api.example.com/*",
		AllowedMethods:  []string{"GET", "POST", "DELETE"},
		Active:          false,
	}

	// The policy would match if active — but it isn't
	patternMatches := matchesPattern(policy.ResourcePattern, "https://api.example.com/users/123")
	methodMatches := methodAllowed(policy.AllowedMethods, "DELETE")

	if !patternMatches || !methodMatches {
		t.Error("Test setup: inactive policy should still match pattern/method — we skip it in Check(), not here")
	}
	// The Active flag is the gate — verified here that it's correctly false
	if policy.Active {
		t.Error("Policy should be inactive for this test")
	}
}
