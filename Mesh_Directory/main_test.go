// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNodeRegistration(t *testing.T) {
	srv := NewServer()

	body, _ := json.Marshal(RegisterRequest{
		NodeID:      "sentry-acme-01",
		TenantID:    "tenant-acme",
		Endpoint:    "https://sentry.acme.internal:8080",
		Ed25519Pub:  "dGVzdC1lZDI1NTE5LXB1YmxpYy1rZXk=",
		MlDsa65Pub:  "dGVzdC1tbC1kc2E2NS1wdWJsaWMta2V5",
		LicenseTier: "professional",
		Version:     "1.0.0",
		MeshEnabled: true,
	})

	req := httptest.NewRequest("POST", "/v1/mesh/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	srv.handleRegister(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&resp)

	if resp["status"] != "registered" {
		t.Errorf("Expected status 'registered', got %v", resp["status"])
	}
	if resp["node_id"] != "sentry-acme-01" {
		t.Errorf("Expected node_id 'sentry-acme-01', got %v", resp["node_id"])
	}

	if srv.registry.Count() != 1 {
		t.Errorf("Expected 1 registered node, got %d", srv.registry.Count())
	}
}

func TestRegistrationMissingFields(t *testing.T) {
	srv := NewServer()

	// Missing ed25519_pub
	body, _ := json.Marshal(RegisterRequest{
		NodeID:   "node-1",
		TenantID: "tenant-1",
	})

	req := httptest.NewRequest("POST", "/v1/mesh/register", bytes.NewReader(body))
	rr := httptest.NewRecorder()

	srv.handleRegister(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for missing fields, got %d", rr.Code)
	}
}

func TestPeerDiscovery(t *testing.T) {
	srv := NewServer()

	// Register two nodes
	for _, nodeID := range []string{"node-a", "node-b"} {
		srv.registry.Register(&MeshNode{
			NodeID:     nodeID,
			TenantID:   "tenant-" + nodeID,
			Endpoint:   "https://" + nodeID + ":8080",
			Ed25519Pub: "key-" + nodeID,
			MeshEnabled: true,
		})
	}

	// Query peers as node-a — should only see node-b
	req := httptest.NewRequest("GET", "/v1/mesh/peers", nil)
	req.Header.Set("X-Gateway-ID", "node-a")
	rr := httptest.NewRecorder()

	srv.handlePeers(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", rr.Code)
	}

	var resp struct {
		Peers []struct {
			NodeID string `json:"node_id"`
		} `json:"peers"`
		Count int `json:"count"`
	}
	json.NewDecoder(rr.Body).Decode(&resp)

	if resp.Count != 1 {
		t.Errorf("Expected 1 peer (not self), got %d", resp.Count)
	}
	if len(resp.Peers) > 0 && resp.Peers[0].NodeID != "node-b" {
		t.Errorf("Expected peer node-b, got %s", resp.Peers[0].NodeID)
	}
}

func TestPeerStalenessEviction(t *testing.T) {
	srv := NewServer()

	// Register a stale node (last seen 48 hours ago)
	staleNode := &MeshNode{
		NodeID:     "stale-node",
		TenantID:   "tenant-stale",
		Ed25519Pub: "stale-key",
		MeshEnabled: true,
	}
	srv.registry.Register(staleNode)

	// Manually backdate LastSeenAt
	srv.registry.mu.Lock()
	srv.registry.nodes["stale-node"].LastSeenAt = time.Now().Add(-48 * time.Hour)
	srv.registry.mu.Unlock()

	// Register a fresh node
	srv.registry.Register(&MeshNode{
		NodeID:     "fresh-node",
		TenantID:   "tenant-fresh",
		Ed25519Pub: "fresh-key",
		MeshEnabled: true,
	})

	// Query peers — stale node should be excluded
	peers := srv.registry.ActivePeers("", 24*time.Hour)
	if len(peers) != 1 {
		t.Errorf("Expected 1 active peer (stale excluded), got %d", len(peers))
	}
	if len(peers) > 0 && peers[0].NodeID != "fresh-node" {
		t.Errorf("Expected fresh-node, got %s", peers[0].NodeID)
	}
}

func TestThreatIntelRelay(t *testing.T) {
	srv := NewServer()

	signals := []ThreatSignal{
		{
			SignalID:    "sig-1",
			Category:   "prompt_injection",
			Fingerprint: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Severity:   "critical",
			Timestamp:  time.Now().UnixNano(),
			TTL:        int64(24 * time.Hour),
		},
		{
			SignalID:    "sig-2",
			Category:   "exfiltration",
			Fingerprint: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			Severity:   "high",
			Timestamp:  time.Now().UnixNano(),
			TTL:        int64(24 * time.Hour),
		},
	}

	body, _ := json.Marshal(signals)
	req := httptest.NewRequest("POST", "/v1/mesh/intel", bytes.NewReader(body))
	rr := httptest.NewRecorder()

	srv.handleIntelReceive(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	if srv.intel.Count() != 2 {
		t.Errorf("Expected 2 signals in buffer, got %d", srv.intel.Count())
	}
}

func TestThreatIntelFeed(t *testing.T) {
	srv := NewServer()

	// Add signals directly
	srv.intel.Add(ThreatSignal{
		SignalID:    "feed-sig-1",
		Category:   "prompt_injection",
		Fingerprint: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		Severity:   "critical",
		Timestamp:  time.Now().UnixNano(),
		TTL:        int64(24 * time.Hour),
	})

	// Query feed
	req := httptest.NewRequest("GET", "/v1/mesh/intel/feed?since=0", nil)
	rr := httptest.NewRecorder()

	srv.handleIntelFeed(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", rr.Code)
	}

	var resp struct {
		Signals []ThreatSignal `json:"signals"`
		Count   int            `json:"count"`
	}
	json.NewDecoder(rr.Body).Decode(&resp)

	if resp.Count != 1 {
		t.Errorf("Expected 1 signal in feed, got %d", resp.Count)
	}
}

func TestThreatIntelDedup(t *testing.T) {
	srv := NewServer()

	// Same fingerprint from two different sources
	sig := ThreatSignal{
		SignalID:    "dedup-1",
		Category:   "prompt_injection",
		Fingerprint: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		Severity:   "critical",
		Timestamp:  time.Now().UnixNano(),
		TTL:        int64(24 * time.Hour),
	}

	srv.intel.Add(sig)
	sig.SignalID = "dedup-2" // Different signal ID, same fingerprint
	srv.intel.Add(sig)

	if srv.intel.Count() != 1 {
		t.Errorf("Expected 1 signal (deduplicated), got %d", srv.intel.Count())
	}
}

func TestHeartbeatWithMeshDirectives(t *testing.T) {
	srv := NewServer()

	// Register a node first
	srv.registry.Register(&MeshNode{
		NodeID:     "heartbeat-node",
		TenantID:   "tenant-hb",
		Ed25519Pub: "hb-key",
		MeshEnabled: true,
	})

	// Add a threat signal
	srv.intel.Add(ThreatSignal{
		SignalID:    "hb-sig",
		Category:   "credential_scan",
		Fingerprint: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
		Severity:   "high",
		Timestamp:  time.Now().UnixNano(),
		TTL:        int64(24 * time.Hour),
	})

	// Send heartbeat
	req := httptest.NewRequest("POST", "/v1/mesh/heartbeat", nil)
	req.Header.Set("X-Gateway-ID", "heartbeat-node")
	rr := httptest.NewRecorder()

	srv.handleHeartbeat(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", rr.Code)
	}

	var resp struct {
		Status     string `json:"status"`
		Directives struct {
			MeshPeers     []MeshNode     `json:"mesh_peers"`
			ThreatSignals []ThreatSignal `json:"threat_signals"`
		} `json:"directives"`
	}
	json.NewDecoder(rr.Body).Decode(&resp)

	if resp.Status != "ok" {
		t.Errorf("Expected status ok, got %s", resp.Status)
	}
}

func TestHealthEndpoint(t *testing.T) {
	srv := NewServer()

	req := httptest.NewRequest("GET", "/v1/mesh/health", nil)
	rr := httptest.NewRecorder()

	srv.handleHealth(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", rr.Code)
	}

	var resp map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&resp)

	if resp["status"] != "healthy" {
		t.Errorf("Expected status 'healthy', got %v", resp["status"])
	}
}

func TestRingBufferEviction(t *testing.T) {
	buf := NewIntelBuffer(3) // Max 3 signals

	for i := 0; i < 5; i++ {
		buf.Add(ThreatSignal{
			SignalID:    fmt.Sprintf("ring-%d", i),
			Fingerprint: fmt.Sprintf("%064d", i), // Unique fingerprint
			Category:   "test",
			Severity:   "medium",
			Timestamp:  time.Now().UnixNano(),
			TTL:        int64(24 * time.Hour),
		})
	}

	if buf.Count() != 3 {
		t.Errorf("Ring buffer should cap at 3, got %d", buf.Count())
	}
}
