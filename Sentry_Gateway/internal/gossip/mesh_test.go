// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package gossip

import (
	"testing"
	"time"
)

func TestQuarantineAndRelease(t *testing.T) {
	m := NewMesh("test-node-1", "tenant-alpha")

	if m.IsQuarantined("agent-abc") {
		t.Error("Agent must not be quarantined before any action")
	}

	m.QuarantineAgent("agent-abc")
	if !m.IsQuarantined("agent-abc") {
		t.Error("Agent must be quarantined after QuarantineAgent")
	}

	m.ReleaseAgent("agent-abc")
	if m.IsQuarantined("agent-abc") {
		t.Error("Agent must not be quarantined after ReleaseAgent")
	}
}

func TestQuarantinedList(t *testing.T) {
	m := NewMesh("test-node-2", "tenant-alpha")

	m.QuarantineAgent("agent-1")
	m.QuarantineAgent("agent-2")
	m.QuarantineAgent("agent-3")
	m.ReleaseAgent("agent-2")

	list := m.QuarantinedList()
	if len(list) != 2 {
		t.Errorf("Expected 2 quarantined agents, got %d: %v", len(list), list)
	}

	inList := make(map[string]bool)
	for _, id := range list {
		inList[id] = true
	}
	if !inList["agent-1"] || !inList["agent-3"] {
		t.Errorf("Expected agent-1 and agent-3 in quarantine list, got: %v", list)
	}
	if inList["agent-2"] {
		t.Error("Released agent-2 must not appear in quarantine list")
	}
}

func TestLWWConflictResolution(t *testing.T) {
	m := NewMesh("test-node-3", "tenant-alpha")

	// Apply an older ACTIVE state
	m.ReceiveGossip("agent-x", AgentState{
		TenantID:  "tenant-alpha",
		Status:    "ACTIVE",
		Timestamp: time.Now().UnixNano(),
		NodeID:    "node-a",
	})

	// Apply a newer QUARANTINED state — should win
	m.ReceiveGossip("agent-x", AgentState{
		TenantID:  "tenant-alpha",
		Status:    "QUARANTINED",
		Timestamp: time.Now().UnixNano() + 1000,
		NodeID:    "node-b",
	})

	if !m.IsQuarantined("agent-x") {
		t.Error("Newer QUARANTINED state must win over older ACTIVE state")
	}

	// Apply an even older ACTIVE state — must be rejected
	m.ReceiveGossip("agent-x", AgentState{
		TenantID:  "tenant-alpha",
		Status:    "ACTIVE",
		Timestamp: 1, // ancient timestamp
		NodeID:    "node-c",
	})

	if !m.IsQuarantined("agent-x") {
		t.Error("Older state must not overwrite newer state (LWW violated)")
	}
}

func TestAtomicReadIsolation(t *testing.T) {
	// Verify that reads during concurrent writes do not panic or return nil
	m := NewMesh("test-node-4", "tenant-alpha")

	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			m.QuarantineAgent("concurrent-agent")
			m.ReleaseAgent("concurrent-agent")
		}
		close(done)
	}()

	// Concurrent reads must never panic
	for {
		select {
		case <-done:
			return
		default:
			_ = m.IsQuarantined("concurrent-agent")
			_ = m.QuarantinedList()
		}
	}
}

// ── Phase 1 P2P Mesh: Cross-Tenant Isolation Tests ──────────────────────

func TestCrossTenantQuarantineRejected(t *testing.T) {
	// Gateway belongs to tenant-alpha. Gossip from tenant-beta MUST be rejected.
	m := NewMesh("node-alpha", "tenant-alpha")

	m.ReceiveGossip("agent-123", AgentState{
		TenantID:  "tenant-beta", // foreign tenant
		Status:    "QUARANTINED",
		Timestamp: time.Now().UnixNano(),
		NodeID:    "node-beta",
	})

	if m.IsQuarantined("agent-123") {
		t.Error("Cross-tenant gossip must be REJECTED — agent-123 should NOT be quarantined on tenant-alpha's gateway")
	}
}

func TestSameTenantQuarantineAccepted(t *testing.T) {
	// Gateway belongs to tenant-alpha. Gossip from the same tenant MUST be accepted.
	m := NewMesh("node-alpha-1", "tenant-alpha")

	m.ReceiveGossip("agent-456", AgentState{
		TenantID:  "tenant-alpha", // same tenant
		Status:    "QUARANTINED",
		Timestamp: time.Now().UnixNano(),
		NodeID:    "node-alpha-2",
	})

	if !m.IsQuarantined("agent-456") {
		t.Error("Same-tenant gossip must be ACCEPTED — agent-456 should be quarantined")
	}
}

func TestWireFormatIncludesTenantID(t *testing.T) {
	// Verify that QuarantineAgent includes the tenant in the AgentState
	m := NewMesh("node-wire-test", "tenant-gamma")

	m.QuarantineAgent("agent-wire-789")

	// Verify the stored state includes the tenant ID
	activeMap := m.StatePointer.Load().(map[string]AgentState)
	state, ok := activeMap["agent-wire-789"]
	if !ok {
		t.Fatal("agent-wire-789 must exist in state map after QuarantineAgent")
	}
	if state.TenantID != "tenant-gamma" {
		t.Errorf("Expected TenantID 'tenant-gamma', got '%s'", state.TenantID)
	}
	if state.Status != "QUARANTINED" {
		t.Errorf("Expected Status 'QUARANTINED', got '%s'", state.Status)
	}
}

func TestEmptyTenantIDAccepted(t *testing.T) {
	// Backward compatibility: a gateway with a tenant should accept gossip from
	// nodes that haven't been upgraded yet (empty TenantID). This ensures rolling
	// upgrades don't break intra-company gossip during the migration window.
	m := NewMesh("node-upgraded", "tenant-delta")

	m.ReceiveGossip("agent-legacy", AgentState{
		TenantID:  "", // pre-upgrade node — no tenant in wire format
		Status:    "QUARANTINED",
		Timestamp: time.Now().UnixNano(),
		NodeID:    "node-legacy",
	})

	if !m.IsQuarantined("agent-legacy") {
		t.Error("Empty TenantID gossip must be ACCEPTED for backward compatibility during rolling upgrades")
	}
}

func TestEmptyLocalTenantAcceptsAll(t *testing.T) {
	// A mesh with no local tenant (e.g., test/dev environment without a license)
	// should accept gossip from any tenant for backward compatibility.
	m := NewMesh("node-dev", "")

	m.ReceiveGossip("agent-any", AgentState{
		TenantID:  "tenant-whatever",
		Status:    "QUARANTINED",
		Timestamp: time.Now().UnixNano(),
		NodeID:    "node-external",
	})

	if !m.IsQuarantined("agent-any") {
		t.Error("Gateway with empty LocalTenantID must accept all gossip (dev/test mode)")
	}
}

func BenchmarkIsQuarantined(b *testing.B) {
	m := NewMesh("bench-node", "bench-tenant")
	m.QuarantineAgent("bench-agent")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.IsQuarantined("bench-agent")
	}
}
