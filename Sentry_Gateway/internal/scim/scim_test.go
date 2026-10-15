// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package scim

import (
	"testing"
	"time"
)

// ── SCIM Resource Construction Tests ─────────────────────────────────────────

func TestBuildUser_FullAttributes(t *testing.T) {
	u := buildUser("id-1", "ext-1", "admin@example.com", "admin@example.com",
		"Admin User", "Admin", "User", "admin", true,
		time.Now(), time.Now())

	if u.ID != "id-1" {
		t.Errorf("ID = %q", u.ID)
	}
	if u.ExternalID != "ext-1" {
		t.Errorf("ExternalID = %q", u.ExternalID)
	}
	if u.UserName != "admin@example.com" {
		t.Errorf("UserName = %q", u.UserName)
	}
	if !u.Active {
		t.Error("Active should be true")
	}
	if u.Role != "admin" {
		t.Errorf("Role = %q", u.Role)
	}
	if len(u.Schemas) != 1 || u.Schemas[0] != schemaCore {
		t.Errorf("Schemas = %v", u.Schemas)
	}
	if len(u.Emails) != 1 || u.Emails[0].Value != "admin@example.com" {
		t.Errorf("Emails = %v", u.Emails)
	}
	if u.Emails[0].Primary != true {
		t.Error("Primary email should be true")
	}
	if u.Name == nil {
		t.Fatal("Name is nil")
	}
	if u.Name.GivenName != "Admin" {
		t.Errorf("GivenName = %q", u.Name.GivenName)
	}
	if u.Name.FamilyName != "User" {
		t.Errorf("FamilyName = %q", u.Name.FamilyName)
	}
	if u.Name.Formatted != "Admin User" {
		t.Errorf("Formatted = %q", u.Name.Formatted)
	}
	if u.Meta == nil {
		t.Fatal("Meta is nil")
	}
	if u.Meta.ResourceType != "User" {
		t.Errorf("ResourceType = %q", u.Meta.ResourceType)
	}
}

func TestBuildUser_NoName(t *testing.T) {
	u := buildUser("id-2", "", "user@example.com", "user@example.com",
		"User", "", "", "viewer", true,
		time.Now(), time.Now())

	if u.Name != nil {
		t.Error("Name should be nil when given_name and family_name are empty")
	}
}

func TestBuildUser_NoEmail(t *testing.T) {
	u := buildUser("id-3", "", "user", "", "User", "", "", "viewer", true,
		time.Now(), time.Now())

	if len(u.Emails) != 0 {
		t.Error("Emails should be empty when no email provided")
	}
}

func TestBuildUser_Inactive(t *testing.T) {
	u := buildUser("id-4", "", "deactivated@example.com", "deactivated@example.com",
		"Gone", "", "", "viewer", false,
		time.Now(), time.Now())

	if u.Active {
		t.Error("Active should be false")
	}
}

// ── Filter Parsing Tests ─────────────────────────────────────────────────────

func TestExtractFilterValue_Standard(t *testing.T) {
	filter := `userName eq "admin@example.com"`
	if got := extractFilterValue(filter); got != "admin@example.com" {
		t.Errorf("got %q, want admin@example.com", got)
	}
}

func TestExtractFilterValue_Empty(t *testing.T) {
	if got := extractFilterValue(""); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestExtractFilterValue_NoQuotes(t *testing.T) {
	if got := extractFilterValue("userName eq admin"); got != "" {
		t.Errorf("got %q, want empty for unquoted value", got)
	}
}

// ── Schema Constants Tests ───────────────────────────────────────────────────

func TestSchemaConstants(t *testing.T) {
	if schemaCore != "urn:ietf:params:scim:schemas:core:2.0:User" {
		t.Errorf("schemaCore = %q", schemaCore)
	}
	if schemaList != "urn:ietf:params:scim:api:messages:2.0:ListResponse" {
		t.Errorf("schemaList = %q", schemaList)
	}
	if schemaPatch != "urn:ietf:params:scim:api:messages:2.0:PatchOp" {
		t.Errorf("schemaPatch = %q", schemaPatch)
	}
	if schemaError != "urn:ietf:params:scim:api:messages:2.0:Error" {
		t.Errorf("schemaError = %q", schemaError)
	}
}

// ── Error Response Tests ─────────────────────────────────────────────────────

func TestErrorResponse_Structure(t *testing.T) {
	e := ErrorResponse{
		Schemas: []string{schemaError},
		Detail:  "not found",
		Status:  "404",
	}
	if e.Detail != "not found" {
		t.Errorf("Detail = %q", e.Detail)
	}
	if e.Status != "404" {
		t.Errorf("Status = %q", e.Status)
	}
}

// ── PatchOp Tests ────────────────────────────────────────────────────────────

func TestPatchOp_Structure(t *testing.T) {
	p := PatchOp{
		Schemas: []string{schemaPatch},
		Operations: []PatchItem{
			{Op: "replace", Path: "active", Value: false},
		},
	}
	if len(p.Operations) != 1 {
		t.Fatalf("expected 1 operation, got %d", len(p.Operations))
	}
	if p.Operations[0].Op != "replace" {
		t.Errorf("Op = %q", p.Operations[0].Op)
	}
	if p.Operations[0].Path != "active" {
		t.Errorf("Path = %q", p.Operations[0].Path)
	}
}

// ── ListResponse Tests ───────────────────────────────────────────────────────

func TestListResponse_Empty(t *testing.T) {
	resp := ListResponse{
		Schemas:      []string{schemaList},
		TotalResults: 0,
		StartIndex:   1,
		ItemsPerPage: 0,
		Resources:    []User{},
	}
	if resp.TotalResults != 0 {
		t.Error("TotalResults should be 0")
	}
}

func TestListResponse_WithUsers(t *testing.T) {
	u := buildUser("id-1", "", "user@example.com", "user@example.com",
		"User", "Test", "User", "viewer", true, time.Now(), time.Now())

	resp := ListResponse{
		Schemas:      []string{schemaList},
		TotalResults: 1,
		StartIndex:   1,
		ItemsPerPage: 1,
		Resources:    []User{u},
	}
	if resp.TotalResults != 1 {
		t.Error("TotalResults should be 1")
	}
	if resp.Resources[0].UserName != "user@example.com" {
		t.Errorf("UserName = %q", resp.Resources[0].UserName)
	}
}

// ── Meta Tests ───────────────────────────────────────────────────────────────

func TestMeta_Timestamps(t *testing.T) {
	now := time.Now()
	u := buildUser("id-1", "", "u@e.com", "u@e.com", "U", "", "", "viewer", true, now, now)
	if u.Meta.Created == "" {
		t.Error("Created should not be empty")
	}
	if u.Meta.LastModified == "" {
		t.Error("LastModified should not be empty")
	}
}
