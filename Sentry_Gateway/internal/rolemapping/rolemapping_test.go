// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package rolemapping

import (
	"testing"
)

// ── Pattern Matching Tests ───────────────────────────────────────────────────

func TestMatchesPattern_ExactMatch(t *testing.T) {
	if !matchesPattern("engineering", "engineering") {
		t.Error("exact match failed")
	}
}

func TestMatchesPattern_ExactMismatch(t *testing.T) {
	if matchesPattern("engineering", "marketing") {
		t.Error("should not match different group")
	}
}

func TestMatchesPattern_PrefixWildcard(t *testing.T) {
	tests := []struct{ pattern, group string; want bool }{
		{"team-*", "team-backend", true},
		{"team-*", "team-frontend", true},
		{"team-*", "squad-backend", false},
		{"ops-*", "ops-security", true},
		{"ops-*", "operations", false},
	}
	for _, tt := range tests {
		if got := matchesPattern(tt.pattern, tt.group); got != tt.want {
			t.Errorf("matchesPattern(%q, %q) = %v, want %v", tt.pattern, tt.group, got, tt.want)
		}
	}
}

func TestMatchesPattern_SuffixWildcard(t *testing.T) {
	tests := []struct{ pattern, group string; want bool }{
		{"*-readonly", "eng-readonly", true},
		{"*-readonly", "ops-readonly", true},
		{"*-readonly", "eng-admin", false},
		{"*-admins", "security-admins", true},
	}
	for _, tt := range tests {
		if got := matchesPattern(tt.pattern, tt.group); got != tt.want {
			t.Errorf("matchesPattern(%q, %q) = %v, want %v", tt.pattern, tt.group, got, tt.want)
		}
	}
}

func TestMatchesPattern_FullWildcard(t *testing.T) {
	if !matchesPattern("*", "anything") {
		t.Error("* should match everything")
	}
	if !matchesPattern("*", "") {
		t.Error("* should match empty string")
	}
}

func TestMatchesPattern_CaseInsensitive(t *testing.T) {
	if !matchesPattern("Engineering", "engineering") {
		t.Error("case-insensitive match failed")
	}
}

// ── Role Resolution Tests ────────────────────────────────────────────────────

func TestResolveRole_NoMappings(t *testing.T) {
	result := ResolveRole(nil, []string{"eng"}, "viewer")
	if result.ResolvedRole != "viewer" {
		t.Errorf("got %q, want viewer", result.ResolvedRole)
	}
	if !result.DefaultApplied {
		t.Error("default should be applied when no mappings")
	}
}

func TestResolveRole_NoGroups(t *testing.T) {
	mappings := []Mapping{{IdPGroup: "admin", CicadaRole: "admin"}}
	result := ResolveRole(mappings, nil, "viewer")
	if result.ResolvedRole != "viewer" {
		t.Errorf("got %q", result.ResolvedRole)
	}
	if !result.DefaultApplied {
		t.Error("default should be applied with no groups")
	}
}

func TestResolveRole_SingleMatch(t *testing.T) {
	mappings := []Mapping{
		{ID: "r1", IdPGroup: "engineering", CicadaRole: "operator"},
	}
	result := ResolveRole(mappings, []string{"engineering"}, "viewer")
	if result.ResolvedRole != "operator" {
		t.Errorf("got %q, want operator", result.ResolvedRole)
	}
	if result.DefaultApplied {
		t.Error("default should NOT be applied")
	}
}

func TestResolveRole_HighestPrivilegeWins(t *testing.T) {
	mappings := []Mapping{
		{ID: "r1", IdPGroup: "viewers", CicadaRole: "viewer"},
		{ID: "r2", IdPGroup: "ops-team", CicadaRole: "operator"},
		{ID: "r3", IdPGroup: "security-admins", CicadaRole: "admin"},
	}
	groups := []string{"viewers", "ops-team", "security-admins"}
	result := ResolveRole(mappings, groups, "guest")
	if result.ResolvedRole != "admin" {
		t.Errorf("got %q, want admin (highest privilege)", result.ResolvedRole)
	}
}

func TestResolveRole_PrefixWildcard(t *testing.T) {
	mappings := []Mapping{
		{ID: "r1", IdPGroup: "team-*", CicadaRole: "operator"},
	}
	result := ResolveRole(mappings, []string{"team-backend"}, "viewer")
	if result.ResolvedRole != "operator" {
		t.Errorf("got %q, want operator", result.ResolvedRole)
	}
}

func TestResolveRole_SuffixWildcard(t *testing.T) {
	mappings := []Mapping{
		{ID: "r1", IdPGroup: "*-readonly", CicadaRole: "viewer"},
		{ID: "r2", IdPGroup: "*-admin", CicadaRole: "admin"},
	}
	result := ResolveRole(mappings, []string{"eng-admin"}, "viewer")
	if result.ResolvedRole != "admin" {
		t.Errorf("got %q, want admin", result.ResolvedRole)
	}
}

func TestResolveRole_CatchAllWildcard(t *testing.T) {
	mappings := []Mapping{
		{ID: "r1", IdPGroup: "*", CicadaRole: "guest"},
	}
	result := ResolveRole(mappings, []string{"some-unknown-group"}, "viewer")
	if result.ResolvedRole != "guest" {
		t.Errorf("got %q, want guest", result.ResolvedRole)
	}
}

func TestResolveRole_WildcardDoesNotOverrideSpecific(t *testing.T) {
	mappings := []Mapping{
		{ID: "r1", IdPGroup: "*", CicadaRole: "guest"},
		{ID: "r2", IdPGroup: "admins", CicadaRole: "admin"},
	}
	result := ResolveRole(mappings, []string{"admins", "random-group"}, "viewer")
	if result.ResolvedRole != "admin" {
		t.Errorf("got %q, want admin (specific rule should yield higher privilege)", result.ResolvedRole)
	}
}

func TestResolveRole_NoMatchFallsBack(t *testing.T) {
	mappings := []Mapping{
		{ID: "r1", IdPGroup: "engineering", CicadaRole: "operator"},
	}
	result := ResolveRole(mappings, []string{"marketing"}, "viewer")
	if result.ResolvedRole != "viewer" {
		t.Errorf("got %q, want viewer (default)", result.ResolvedRole)
	}
	if !result.DefaultApplied {
		t.Error("default should be applied")
	}
}

func TestResolveRole_SuperAdmin(t *testing.T) {
	mappings := []Mapping{
		{ID: "r1", IdPGroup: "platform-admins", CicadaRole: "super_admin"},
		{ID: "r2", IdPGroup: "engineering", CicadaRole: "admin"},
	}
	result := ResolveRole(mappings, []string{"engineering", "platform-admins"}, "viewer")
	if result.ResolvedRole != "super_admin" {
		t.Errorf("got %q, want super_admin", result.ResolvedRole)
	}
}

// ── Role Normalization Tests ─────────────────────────────────────────────────

func TestNormalizeRole_Valid(t *testing.T) {
	tests := map[string]string{
		"admin": "admin", "viewer": "viewer", "operator": "operator",
		"super_admin": "super_admin", "guest": "guest",
	}
	for input, want := range tests {
		if got := normalizeRole(input); got != want {
			t.Errorf("normalizeRole(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestNormalizeRole_CaseInsensitive(t *testing.T) {
	if normalizeRole("ADMIN") != "admin" {
		t.Error("should be case-insensitive")
	}
}

func TestNormalizeRole_Empty(t *testing.T) {
	if normalizeRole("") != "viewer" {
		t.Error("empty should default to viewer")
	}
}

func TestNormalizeRole_Invalid(t *testing.T) {
	if normalizeRole("root") != "viewer" {
		t.Error("invalid role should default to viewer")
	}
}

// ── Priority Tests ───────────────────────────────────────────────────────────

func TestRolePriority_Ordering(t *testing.T) {
	if RolePriority["guest"] >= RolePriority["viewer"] {
		t.Error("guest should be lower than viewer")
	}
	if RolePriority["viewer"] >= RolePriority["operator"] {
		t.Error("viewer should be lower than operator")
	}
	if RolePriority["operator"] >= RolePriority["admin"] {
		t.Error("operator should be lower than admin")
	}
	if RolePriority["admin"] >= RolePriority["super_admin"] {
		t.Error("admin should be lower than super_admin")
	}
}

// ── Mapping Validation Tests ─────────────────────────────────────────────────

func TestValidRoles_Contains(t *testing.T) {
	for role := range RolePriority {
		if !ValidRoles[role] {
			t.Errorf("role %q in priority map but not in ValidRoles", role)
		}
	}
}

func TestResolveResult_MatchedGroups(t *testing.T) {
	mappings := []Mapping{
		{ID: "r1", IdPGroup: "team-*", CicadaRole: "operator"},
	}
	result := ResolveRole(mappings, []string{"team-backend", "team-frontend"}, "viewer")
	if result.ResolvedRole != "operator" {
		t.Errorf("got %q", result.ResolvedRole)
	}
	// Both groups should match the same rule at the same priority
	if len(result.MatchedGroups) < 1 {
		t.Error("expected at least one matched group")
	}
}
