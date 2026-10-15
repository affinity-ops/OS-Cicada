// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package toolscope

import (
	"testing"
)

// ── Scope: Read ───────────────────────────────────────────────────────────────

// TestReadScope_GETAllowed verifies that GET is permitted for read-scoped tools.
func TestReadScope_GETAllowed(t *testing.T) {
	result := Check("crm:get_customer", "read", "GET")
	if !result.Passed {
		t.Errorf("GET should be allowed for 'read' scope: %s", result.Reason)
	}
}

// TestReadScope_HEADAllowed verifies HEAD (safe method) is permitted.
func TestReadScope_HEADAllowed(t *testing.T) {
	result := Check("crm:check_customer", "read", "HEAD")
	if !result.Passed {
		t.Errorf("HEAD should be allowed for 'read' scope: %s", result.Reason)
	}
}

// TestReadScope_OPTIONSAllowed verifies OPTIONS (CORS preflight) is permitted.
func TestReadScope_OPTIONSAllowed(t *testing.T) {
	result := Check("crm:options", "read", "OPTIONS")
	if !result.Passed {
		t.Errorf("OPTIONS should be allowed for 'read' scope: %s", result.Reason)
	}
}

// TestReadScope_POSTBlocked verifies that POST is BLOCKED for read-scoped tools.
func TestReadScope_POSTBlocked(t *testing.T) {
	result := Check("crm:get_customer", "read", "POST")
	if result.Passed {
		t.Error("POST should be BLOCKED for 'read' scope — read tools cannot create data")
	}
}

// TestReadScope_DELETEBlocked verifies that DELETE is BLOCKED for read-scoped tools.
func TestReadScope_DELETEBlocked(t *testing.T) {
	result := Check("crm:get_customer", "read", "DELETE")
	if result.Passed {
		t.Error("DELETE should be BLOCKED for 'read' scope — read tools cannot destroy data")
	}
}

// TestReadScope_PUTBlocked verifies that PUT is BLOCKED for read-scoped tools.
func TestReadScope_PUTBlocked(t *testing.T) {
	result := Check("crm:get_customer", "read", "PUT")
	if result.Passed {
		t.Error("PUT should be BLOCKED for 'read' scope")
	}
}

// ── Scope: Write ──────────────────────────────────────────────────────────────

// TestWriteScope_POSTAllowed verifies POST is permitted for write-scoped tools.
func TestWriteScope_POSTAllowed(t *testing.T) {
	result := Check("crm:create_customer", "write", "POST")
	if !result.Passed {
		t.Errorf("POST should be allowed for 'write' scope: %s", result.Reason)
	}
}

// TestWriteScope_PUTAllowed verifies PUT is permitted for write-scoped tools.
func TestWriteScope_PUTAllowed(t *testing.T) {
	result := Check("crm:update_customer", "write", "PUT")
	if !result.Passed {
		t.Errorf("PUT should be allowed for 'write' scope: %s", result.Reason)
	}
}

// TestWriteScope_PATCHAllowed verifies PATCH is permitted for write-scoped tools.
func TestWriteScope_PATCHAllowed(t *testing.T) {
	result := Check("crm:patch_customer", "write", "PATCH")
	if !result.Passed {
		t.Errorf("PATCH should be allowed for 'write' scope: %s", result.Reason)
	}
}

// TestWriteScope_GETBlocked verifies GET is BLOCKED for write-scoped tools.
// Write tools should not be used for read operations (prevents data exfiltration
// through a write facet).
func TestWriteScope_GETBlocked(t *testing.T) {
	result := Check("crm:create_customer", "write", "GET")
	if result.Passed {
		t.Error("GET should be BLOCKED for 'write' scope — write tools cannot read data")
	}
}

// TestWriteScope_DELETEBlocked verifies DELETE is BLOCKED for write-scoped tools.
// Write and Delete are deliberately separate facets — a tool that can create
// should not automatically be able to destroy.
func TestWriteScope_DELETEBlocked(t *testing.T) {
	result := Check("crm:create_customer", "write", "DELETE")
	if result.Passed {
		t.Error("DELETE should be BLOCKED for 'write' scope — write ≠ delete")
	}
}

// ── Scope: Delete ─────────────────────────────────────────────────────────────

// TestDeleteScope_DELETEAllowed verifies DELETE is permitted for delete-scoped tools.
func TestDeleteScope_DELETEAllowed(t *testing.T) {
	result := Check("storage:delete_volume", "delete", "DELETE")
	if !result.Passed {
		t.Errorf("DELETE should be allowed for 'delete' scope: %s", result.Reason)
	}
}

// TestDeleteScope_GETBlocked verifies GET is BLOCKED for delete-scoped tools.
func TestDeleteScope_GETBlocked(t *testing.T) {
	result := Check("storage:delete_volume", "delete", "GET")
	if result.Passed {
		t.Error("GET should be BLOCKED for 'delete' scope — delete tools cannot read data")
	}
}

// TestDeleteScope_POSTBlocked verifies POST is BLOCKED for delete-scoped tools.
func TestDeleteScope_POSTBlocked(t *testing.T) {
	result := Check("storage:delete_volume", "delete", "POST")
	if result.Passed {
		t.Error("POST should be BLOCKED for 'delete' scope — delete tools cannot create data")
	}
}

// ── Scope: Transact ───────────────────────────────────────────────────────────

// TestTransactScope_POSTAllowed verifies POST is permitted for transact-scoped tools.
func TestTransactScope_POSTAllowed(t *testing.T) {
	result := Check("stripe:create_charge", "transact", "POST")
	if !result.Passed {
		t.Errorf("POST should be allowed for 'transact' scope: %s", result.Reason)
	}
}

// TestTransactScope_PUTBlocked verifies PUT is BLOCKED for transact-scoped tools.
// Financial transactions are POST-only — no modifying an existing transaction.
func TestTransactScope_PUTBlocked(t *testing.T) {
	result := Check("stripe:create_charge", "transact", "PUT")
	if result.Passed {
		t.Error("PUT should be BLOCKED for 'transact' scope — transactions are POST-only")
	}
}

// TestTransactScope_DELETEBlocked verifies DELETE is BLOCKED for transact-scoped tools.
func TestTransactScope_DELETEBlocked(t *testing.T) {
	result := Check("stripe:create_charge", "transact", "DELETE")
	if result.Passed {
		t.Error("DELETE should be BLOCKED for 'transact' scope — transactions cannot be deleted")
	}
}

// TestTransactScope_GETBlocked verifies GET is BLOCKED for transact-scoped tools.
func TestTransactScope_GETBlocked(t *testing.T) {
	result := Check("stripe:create_charge", "transact", "GET")
	if result.Passed {
		t.Error("GET should be BLOCKED for 'transact' scope — transact tools only POST")
	}
}

// ── No Scope (Unrestricted) ───────────────────────────────────────────────────

// TestNoScope_AllMethodsAllowed verifies that tools with no scope are unrestricted.
func TestNoScope_AllMethodsAllowed(t *testing.T) {
	methods := []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
	for _, method := range methods {
		result := Check("legacy:unrestricted_tool", "", method)
		if !result.Passed {
			t.Errorf("method %s should be allowed for unrestricted tool: %s", method, result.Reason)
		}
	}
}

// ── Edge Cases ────────────────────────────────────────────────────────────────

// TestEmptyToolID verifies that empty tool_id skips the check.
func TestEmptyToolID(t *testing.T) {
	result := Check("", "read", "DELETE")
	if !result.Passed {
		t.Error("empty tool_id should skip scope check")
	}
}

// TestUnknownScope verifies that unknown scope values are treated as unrestricted.
func TestUnknownScope(t *testing.T) {
	result := Check("tool:test", "admin", "DELETE")
	if !result.Passed {
		t.Errorf("unknown scope 'admin' should be treated as unrestricted: %s", result.Reason)
	}
}

// TestCaseInsensitiveScope verifies case-insensitive scope matching.
func TestCaseInsensitiveScope(t *testing.T) {
	result := Check("crm:get_customer", "READ", "GET")
	if !result.Passed {
		t.Errorf("scope matching should be case-insensitive: %s", result.Reason)
	}
}

// TestCaseInsensitiveMethod verifies case-insensitive method matching.
func TestCaseInsensitiveMethod(t *testing.T) {
	result := Check("crm:get_customer", "read", "get")
	if !result.Passed {
		t.Errorf("method matching should be case-insensitive: %s", result.Reason)
	}
}

// ── Result Fields ─────────────────────────────────────────────────────────────

// TestResultFields_Blocked verifies all fields populated on a scope violation.
func TestResultFields_Blocked(t *testing.T) {
	result := Check("crm:get_customer", "read", "DELETE")

	if result.Passed {
		t.Fatal("expected block")
	}
	if result.ToolID != "crm:get_customer" {
		t.Errorf("ToolID = %q, want 'crm:get_customer'", result.ToolID)
	}
	if result.DeclaredScope != "read" {
		t.Errorf("DeclaredScope = %q, want 'read'", result.DeclaredScope)
	}
	if result.HTTPMethod != "DELETE" {
		t.Errorf("HTTPMethod = %q, want 'DELETE'", result.HTTPMethod)
	}
	if result.Reason == "" {
		t.Error("Reason should not be empty on block")
	}
}

// TestResultFields_Passed verifies all fields populated on a scope pass.
func TestResultFields_Passed(t *testing.T) {
	result := Check("crm:get_customer", "read", "GET")

	if !result.Passed {
		t.Fatal("expected pass")
	}
	if result.DeclaredScope != "read" {
		t.Errorf("DeclaredScope = %q, want 'read'", result.DeclaredScope)
	}
	if result.Reason == "" {
		t.Error("Reason should not be empty on pass")
	}
}

// ── Configuration ─────────────────────────────────────────────────────────────

// TestIsEnabled_Default verifies tool scope enforcement is enabled by default.
func TestIsEnabled_Default(t *testing.T) {
	if !isEnabled() {
		t.Error("tool scope enforcement should be enabled by default")
	}
}
